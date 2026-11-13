//! Read-only UPnP: finds the gateway, fetches its description and lists its port mappings.
//! The only requests ever made are an SSDP search, one GET of the description, and
//! GetGenericPortMappingEntry. It never creates or deletes a mapping, asks for the external address or
//! changes anything. It talks to the default gateway only: every address it is given must be that gateway.
use crate::domain::evidence::{RawMapping, UpnpObservation};
use crate::domain::ports::UpnpInspector;
use regex::Regex;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

const SSDP_PORT: u16 = 1900;
const SSDP_MULTICAST: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SEARCH_TARGET: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
const DISCOVERY_WINDOW: Duration = Duration::from_millis(1500);
const IO_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RESPONSE_BYTES: usize = 1 << 20;
const MAX_MAPPINGS: u32 = 200;

/// The one action this module may call.
const ACTION: &str = "GetGenericPortMappingEntry";

static LOCATION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?im)^location:\s*(\S+)").unwrap());
static SERVICE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)<service>(.*?)</service>").unwrap());
static URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^http://([^/:]+)(?::(\d+))?(/.*)?$").unwrap());

/// A parsed `http://host:port/path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub path: String,
}

pub fn parse_url(url: &str) -> Option<Endpoint> {
    let c = URL.captures(url.trim())?;
    Some(Endpoint {
        host: c[1].to_string(),
        port: c.get(2).map_or(Some(80), |p| p.as_str().parse().ok())?,
        path: c.get(3).map_or("/", |p| p.as_str()).to_string(),
    })
}

/// The LOCATION header of an SSDP response.
pub fn parse_ssdp_location(response: &str) -> Option<String> {
    Some(LOCATION.captures(response)?[1].to_string())
}

fn xml_value<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{tag}>"))? + start;
    Some(xml[start..end].trim())
}

/// The WAN connection service of a device description: its type and its control path.
pub fn parse_control(description: &str) -> Option<(String, String)> {
    SERVICE.captures_iter(description).find_map(|block| {
        let block = block.get(1)?.as_str();
        let kind = xml_value(block, "serviceType")?;
        (kind.contains("WANIPConnection") || kind.contains("WANPPPConnection")).then(|| Some((kind.to_string(), xml_value(block, "controlURL")?.to_string()))).flatten()
    })
}

/// One GetGenericPortMappingEntry answer. The mapping's description is deliberately not read.
pub fn parse_mapping(body: &str) -> Option<RawMapping> {
    Some(RawMapping {
        protocol: xml_value(body, "NewProtocol")?.to_string(),
        external_port: xml_value(body, "NewExternalPort")?.parse().ok()?,
        internal_port: xml_value(body, "NewInternalPort")?.parse().ok()?,
        internal_host: xml_value(body, "NewInternalClient")?.to_string(),
    })
}

fn decode_chunked(body: &[u8]) -> Vec<u8> {
    let (mut out, mut rest) = (Vec::new(), body);
    while let Some(line_end) = rest.windows(2).position(|w| w == b"\r\n") {
        let size = std::str::from_utf8(&rest[..line_end]).ok().and_then(|s| usize::from_str_radix(s.split(';').next().unwrap_or("").trim(), 16).ok());
        let Some(size) = size.filter(|s| *s > 0) else { break };
        let start = line_end + 2;
        if rest.len() < start + size {
            break;
        }
        out.extend_from_slice(&rest[start..start + size]);
        rest = rest.get(start + size + 2..).unwrap_or(&[]);
    }
    out
}

/// A minimal HTTP/1.1 client that can only reach the gateway it was made for.
struct GatewayHttp<'a> {
    gateway: &'a str,
}

impl GatewayHttp<'_> {
    fn request(&self, to: &Endpoint, method: &str, headers: &[(&str, String)], body: Option<&str>) -> Option<(u16, String)> {
        if to.host != self.gateway {
            return None;
        }
        let ip: Ipv4Addr = to.host.parse().ok()?;
        let mut stream = TcpStream::connect_timeout(&SocketAddr::from((ip, to.port)), IO_TIMEOUT).ok()?;
        stream.set_read_timeout(Some(IO_TIMEOUT)).ok()?;
        stream.set_write_timeout(Some(IO_TIMEOUT)).ok()?;
        let mut head = format!("{method} {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n", to.path, to.host, to.port);
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        if let Some(body) = body {
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes()).ok()?;
        if let Some(body) = body {
            stream.write_all(body.as_bytes()).ok()?;
        }
        let mut raw = Vec::new();
        let _ = stream.take(MAX_RESPONSE_BYTES as u64).read_to_end(&mut raw);
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
        let headers = String::from_utf8_lossy(&raw[..split]).to_string();
        let status = headers.lines().next()?.split_whitespace().nth(1)?.parse().ok()?;
        let payload = &raw[split + 4..];
        let payload = if headers.to_lowercase().contains("transfer-encoding: chunked") { decode_chunked(payload) } else { payload.to_vec() };
        Some((status, String::from_utf8_lossy(&payload).into_owned()))
    }
}

enum Discovery {
    Found(Endpoint),
    /// A UPnP device answered that is not the gateway.
    Refused,
    Nothing,
}

fn search_message() -> String {
    format!("M-SEARCH * HTTP/1.1\r\nHOST: {SSDP_MULTICAST}:{SSDP_PORT}\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {SEARCH_TARGET}\r\n\r\n")
}

/// Asks the gateway directly first. Only if it stays silent is the multicast group asked, and then any
/// answer from another device is refused rather than followed.
fn discover(gateway: &str) -> Discovery {
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else { return Discovery::Nothing };
    let Ok(ip) = gateway.parse::<Ipv4Addr>() else { return Discovery::Nothing };
    let message = search_message();
    let mut refused = false;

    for (target, window) in [(SocketAddr::from((ip, SSDP_PORT)), DISCOVERY_WINDOW), (SocketAddr::from((SSDP_MULTICAST, SSDP_PORT)), DISCOVERY_WINDOW)] {
        if socket.send_to(message.as_bytes(), target).is_err() {
            continue;
        }
        let deadline = Instant::now() + window;
        let mut buffer = [0u8; 2048];
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            let _ = socket.set_read_timeout(Some(left.max(Duration::from_millis(1))));
            let Ok((n, from)) = socket.recv_from(&mut buffer) else { break };
            let Some(location) = parse_ssdp_location(&String::from_utf8_lossy(&buffer[..n])).and_then(|l| parse_url(&l)) else { continue };
            if from.ip() == std::net::IpAddr::V4(ip) && location.host == gateway {
                return Discovery::Found(location);
            }
            refused = true;
        }
    }
    if refused { Discovery::Refused } else { Discovery::Nothing }
}

fn soap_body(service_type: &str, index: u32) -> String {
    format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{ACTION} xmlns:u=\"{service_type}\"><NewPortMappingIndex>{index}</NewPortMappingIndex></u:{ACTION}></s:Body></s:Envelope>"
    )
}

pub struct NatUpnpInspector;

impl UpnpInspector for NatUpnpInspector {
    fn inspect(&self, gateway: &str) -> UpnpObservation {
        let location = match discover(gateway) {
            Discovery::Found(location) => location,
            Discovery::Refused => return UpnpObservation::Refused,
            Discovery::Nothing => return UpnpObservation::Unknown,
        };
        let http = GatewayHttp { gateway };
        let Some((200, description)) = http.request(&location, "GET", &[], None) else { return UpnpObservation::Unknown };
        let Some((service_type, control)) = parse_control(&description) else { return UpnpObservation::Unknown };

        // The control address may be absolute or relative, but either way it must be the gateway's.
        let control = if control.starts_with("http") {
            parse_url(&control)
        } else if control.starts_with('/') {
            Some(Endpoint { path: control, ..location.clone() })
        } else {
            let dir = location.path.rsplit_once('/').map_or("", |(d, _)| d);
            Some(Endpoint { path: format!("{dir}/{control}"), ..location.clone() })
        };
        let Some(control) = control.filter(|c| c.host == gateway) else { return UpnpObservation::Unknown };

        let mut mappings = Vec::new();
        for index in 0..MAX_MAPPINGS {
            let headers = [
                ("Content-Type", "text/xml; charset=\"utf-8\"".to_string()),
                ("SOAPAction", format!("\"{service_type}#{ACTION}\"")),
            ];
            match http.request(&control, "POST", &headers, Some(&soap_body(&service_type, index))) {
                Some((200, body)) => match parse_mapping(&body) {
                    Some(mapping) => mappings.push(mapping),
                    None => break,
                },
                // The router answers with an error once the index is past the last mapping.
                Some(_) => break,
                None if index == 0 => return UpnpObservation::Unknown,
                None => break,
            }
        }
        UpnpObservation::Detected(mappings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESCRIPTION: &str = r#"<root><device><serviceList>
        <service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><controlURL>/ctl/L3F</controlURL></service>
        <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/IPConn</controlURL></service>
        </serviceList></device></root>"#;

    #[test]
    fn reads_the_ssdp_location_and_urls() {
        let response = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nLocation: http://192.168.1.1:5000/rootDesc.xml\r\nST: x\r\n\r\n";
        assert_eq!(parse_ssdp_location(response).as_deref(), Some("http://192.168.1.1:5000/rootDesc.xml"));
        assert_eq!(parse_url("http://192.168.1.1:5000/rootDesc.xml"), Some(Endpoint { host: "192.168.1.1".into(), port: 5000, path: "/rootDesc.xml".into() }));
        assert_eq!(parse_url("http://192.168.1.1").map(|e| (e.port, e.path)), Some((80, "/".to_string())));
        assert_eq!(parse_url("https://192.168.1.1/x"), None);
        assert_eq!(parse_ssdp_location("HTTP/1.1 200 OK\r\n\r\n"), None);
    }

    #[test]
    fn finds_the_wan_connection_service_and_its_control_path() {
        assert_eq!(parse_control(DESCRIPTION), Some(("urn:schemas-upnp-org:service:WANIPConnection:1".into(), "/ctl/IPConn".into())));
        assert_eq!(parse_control("<root></root>"), None);
    }

    #[test]
    fn reads_a_mapping_and_ignores_its_description() {
        let body = "<s:Envelope><s:Body><u:GetGenericPortMappingEntryResponse><NewRemoteHost></NewRemoteHost><NewExternalPort>8080</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>80</NewInternalPort><NewInternalClient>192.168.1.25</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>my laptop</NewPortMappingDescription></u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>";
        let mapping = parse_mapping(body).unwrap();
        assert_eq!((mapping.protocol.as_str(), mapping.external_port, mapping.internal_port, mapping.internal_host.as_str()), ("TCP", 8080, 80, "192.168.1.25"));
        assert_eq!(parse_mapping("<s:Envelope><s:Body><s:Fault>713</s:Fault></s:Body></s:Envelope>"), None);
    }

    #[test]
    fn decodes_chunked_bodies() {
        assert_eq!(decode_chunked(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"), b"hello world");
    }

    #[test]
    fn the_http_client_refuses_any_host_but_its_gateway() {
        let http = GatewayHttp { gateway: "192.168.1.1" };
        let elsewhere = Endpoint { host: "203.0.113.5".into(), port: 80, path: "/".into() };
        assert_eq!(http.request(&elsewhere, "GET", &[], None), None);
    }

    #[test]
    fn the_only_soap_action_is_the_read_only_one() {
        assert!(soap_body("urn:x", 3).contains("<u:GetGenericPortMappingEntry "));
        assert!(search_message().starts_with("M-SEARCH"));
    }
}
