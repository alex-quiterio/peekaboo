//! Behaviour of the rules together: scoring, findings, reports, speed advice and comparison.
//! The numbers are the ones the TypeScript version produced, so the two stay in step.
use super::compare::*;
use super::evidence::*;
use super::findings::*;
use super::model::*;
use super::report::*;
use super::saved::summarise;
use super::scoring::*;
use super::speed::*;

const GATEWAY: &str = "192.168.1.1";

fn wifi_check(change: impl FnOnce(&mut WifiCheck)) -> WifiCheck {
    let mut wifi = WifiCheck {
        state: WifiState::Known,
        security: SecurityClass::Strong,
        security_mode: Some("WPA2".into()),
        band: Some(WifiBand::Ghz5),
        same_channel_count: Some(0),
        overlapping_count: Some(0),
        nearby_count: Some(12),
        speed: WifiSpeedCheck {
            link_rate_mbps: Some(866),
            signal_dbm: Some(-50),
            noise_dbm: Some(-92),
            signal: Some(SignalQuality::Excellent),
            channel_width_mhz: Some(80),
            standard: Some(WifiStandard::Wifi5),
        },
    };
    change(&mut wifi);
    wifi
}

fn environment(change: impl FnOnce(&mut EnvironmentCheck)) -> EnvironmentCheck {
    let mut env = EnvironmentCheck {
        resolver: ResolverKind::Unknown,
        resolver_provider: None,
        global_ipv6: None,
        tunnel_active: None,
        firewall: Firewall::Unknown,
        stealth_mode: None,
        open_listener_count: None,
        private_hardware_address: None,
        ipv6_from_hardware_address: None,
    };
    change(&mut env);
    env
}

/// Only HTTP (80) answers; everything else is unknown. Scored port weight: 49 of 53.
fn checks(change: impl FnOnce(&mut Checks)) -> Checks {
    let mut c = Checks {
        ports: AUDITED_PORTS.iter().map(|(port, service, _)| PortCheck { port: *port, service: service.to_string(), reachable: *port == 80 }).collect(),
        upnp: UpnpCheck { state: UpnpState::Unknown, mapping_count: None, sensitive_count: None, mappings: vec![] },
        wifi: wifi_check_from(&WifiObservation::default()),
        dns: DnsCheck { status: DnsStatus::Unknown },
        environment: environment(|_| {}),
        latency: LatencyCheck::default(),
    };
    change(&mut c);
    c
}

fn report_of(c: Checks, previous: Option<&Report>) -> Report {
    build_report(c, previous, "2026-01-01T00:00:00.000Z".into(), "test")
}

fn find<'a>(findings: &'a [Finding], id: &str) -> Option<&'a Finding> {
    findings.iter().find(|f| f.id == id)
}

fn line<'a>(score: &'a Score, id: &str) -> &'a ScoreLine {
    score.breakdown.iter().find(|l| l.id == id).unwrap()
}

// ---------- scoring ----------

#[test]
fn scores_only_known_checks_and_reports_coverage_separately() {
    let score = score_checks(&checks(|_| {}));
    assert_eq!((score.total_weight, score.known_weight, score.earned_weight), (123, 53, 49));
    assert_eq!((score.provisional, score.coverage_percent), (Some(92), 43));
}

#[test]
fn informational_ports_are_checked_but_never_scored() {
    let ids: Vec<_> = score_checks(&checks(|_| {})).breakdown.into_iter().map(|l| l.id).collect();
    assert!(!ids.contains(&"port-443".to_string()) && !ids.contains(&"port-53".to_string()));
    let open = checks(|c| c.ports.iter_mut().for_each(|p| p.reachable = p.port == 443));
    assert_eq!(score_checks(&open).provisional, Some(100));
}

#[test]
fn full_coverage_best_case() {
    let score = score_checks(&checks(|c| {
        c.ports.iter_mut().for_each(|p| p.reachable = false);
        c.upnp = UpnpCheck { state: UpnpState::Detected, mapping_count: Some(0), sensitive_count: Some(0), mappings: vec![] };
        c.wifi = wifi_check(|w| w.security_mode = Some("WPA3".into()));
        c.dns.status = DnsStatus::Encrypted;
    }));
    assert_eq!(score.coverage_percent, 100);
    assert_eq!(score.provisional, Some(92)); // UPnP being on at all earns 10 of its 20
}

#[test]
fn channel_congestion_tiers() {
    let earned = |n| line(&score_checks(&checks(|c| c.wifi = wifi_check(|w| w.same_channel_count = Some(n)))), "channel").earned;
    assert_eq!([earned(0), earned(2), earned(3)], [Some(10), Some(5), Some(0)]);
}

// ---------- reports ----------

#[test]
fn top_fixes_are_at_most_three_unique_by_severity_and_never_info() {
    let report = report_of(
        checks(|c| {
            c.ports.iter_mut().for_each(|p| p.reachable = true);
            c.wifi = wifi_check(|w| {
                w.security = SecurityClass::Weak;
                w.security_mode = Some("WEP".into());
                w.same_channel_count = Some(5);
            });
            c.dns.status = DnsStatus::Plaintext;
        }),
        None,
    );
    assert_eq!(report.top_fixes.len(), 3);
    assert!(report.top_fixes[0].contains("Telnet") || report.top_fixes[0].contains("WPA3"));
    let info: Vec<_> = report.findings.iter().filter(|f| f.severity == Severity::Info).cloned().collect();
    assert!(top_fixes(&info).is_empty());
}

#[test]
fn never_claims_internet_exposure_and_always_says_wan_was_untested() {
    let report = report_of(checks(|c| c.ports.iter_mut().for_each(|p| p.reachable = true)), None);
    let json = serde_json::to_string(&report).unwrap().to_lowercase();
    assert!(!json.contains("internet-exposed") && !json.contains("exposed to the internet"));
    assert!(report.findings.iter().any(|f| f.message.contains("WAN exposure was not tested")));
    assert_eq!(report.target, "<private-gateway>");
}

#[test]
fn comparison_only_when_the_previous_score_is_known() {
    let first = report_of(checks(|_| {}), None);
    assert_eq!(first.comparison, None);
    let second = report_of(checks(|c| c.ports.iter_mut().for_each(|p| p.reachable = false)), Some(&first));
    assert_eq!(second.comparison, Some(Comparison { previous_score: 92, current_score: 100, delta: 8 }));
}

#[test]
fn fingerprint_ignores_the_timestamp_and_changes_list_only_what_moved() {
    let a = report_of(checks(|_| {}), None);
    let b = build_report(checks(|_| {}), None, "2026-02-02T00:00:00.000Z".into(), "test");
    assert_eq!(fingerprint(&a), fingerprint(&b));
    let c = report_of(checks(|c| c.dns.status = DnsStatus::Encrypted), None);
    assert_eq!(describe_changes(&a, &c), ["DNS: unknown -> encrypted", "Score: 92 -> 95", "Coverage: 43 -> 59"]);
}

// ---------- this device ----------

#[test]
fn a_reported_encrypted_dns_is_not_trusted_while_a_tunnel_is_connected() {
    let tunnelled = checks(|c| {
        c.dns.status = DnsStatus::Encrypted;
        c.environment = environment(|e| e.tunnel_active = Some(true));
    });
    assert_eq!(effective_dns(&tunnelled), DnsStatus::Unknown);
    assert_eq!(line(&score_checks(&tunnelled), "dns").earned, None);
    let findings = build_findings(&tunnelled);
    let dns = find(&findings, "dns").unwrap();
    assert_eq!(dns.severity, Severity::Low);
    assert!(dns.message.starts_with("DNS: Unknown."));
    assert!(top_fixes(&findings).join(" ").contains("tunnel"));

    let direct = checks(|c| {
        c.dns.status = DnsStatus::Encrypted;
        c.environment = environment(|e| e.tunnel_active = Some(false));
    });
    assert_eq!(effective_dns(&direct), DnsStatus::Encrypted);
    assert_eq!(line(&score_checks(&direct), "dns").earned, Some(20));
    let plain = checks(|c| {
        c.dns.status = DnsStatus::Plaintext;
        c.environment = environment(|e| e.tunnel_active = Some(true));
    });
    assert_eq!(effective_dns(&plain), DnsStatus::Plaintext);
}

#[test]
fn a_tunnel_next_to_plaintext_or_unknown_dns_is_explained_once_without_an_alarm() {
    let with_tunnel = build_findings(&checks(|c| c.environment = environment(|e| e.tunnel_active = Some(true))));
    assert_eq!(find(&with_tunnel, "tunnel").unwrap().severity, Severity::Info);
    assert!(find(&build_findings(&checks(|_| {})), "tunnel").is_none());
}

#[test]
fn a_configured_public_resolver_does_not_contradict_encrypted_dns() {
    let public = |dns| {
        checks(|c| {
            c.dns.status = dns;
            c.environment = environment(|e| {
                e.resolver = ResolverKind::Public;
                e.resolver_provider = Some("OpenDNS".into());
                e.tunnel_active = Some(false);
            });
        })
    };
    let encrypted = build_findings(&public(DnsStatus::Encrypted));
    let message = &find(&encrypted, "resolver").unwrap().message;
    assert!(message.contains("Encrypted DNS overrides that setting") && !message.contains("your ISP can still read them"));
    assert!(find(&build_findings(&public(DnsStatus::Unknown)), "resolver").unwrap().message.contains("your ISP can still read them"));
}

#[test]
fn the_firewall_is_rated_by_what_it_leaves_reachable() {
    let firewall = |firewall, stealth, open| {
        let findings = build_findings(&checks(|c| {
            c.environment = environment(|e| {
                e.firewall = firewall;
                e.stealth_mode = stealth;
                e.open_listener_count = open;
            })
        }));
        find(&findings, "firewall").unwrap().clone()
    };
    let off = firewall(Firewall::Off, None, Some(2));
    assert!(off.severity == Severity::Medium && off.message.contains("At least 2 ports"));
    assert_eq!(firewall(Firewall::Off, None, Some(0)).severity, Severity::Low);
    assert_eq!(firewall(Firewall::Off, None, None).severity, Severity::Low);
    let on = firewall(Firewall::On, Some(false), None);
    assert!(on.severity == Severity::Info && on.message.contains("Stealth mode is off"));
    assert!(firewall(Firewall::Unknown, None, None).message.starts_with("Device firewall: Unknown."));
}

#[test]
fn the_hardware_address_is_reported_only_on_wifi_and_never_stored() {
    let on_wifi = build_findings(&checks(|c| {
        c.wifi = wifi_check(|_| {});
        c.environment = environment(|e| e.private_hardware_address = Some(false));
    }));
    assert!(find(&on_wifi, "hardware-address").unwrap().message.contains("real hardware Wi-Fi address"));
    let off_wifi = build_findings(&checks(|c| c.environment = environment(|e| e.private_hardware_address = Some(false))));
    assert!(find(&off_wifi, "hardware-address").is_none());
    let observed = environment_check_from(
        &EnvironmentObservation {
            device: DeviceObservation { hardware_address_randomised: Some(true), firewall: Some(FirewallObservation { enabled: true, stealth: None }), ..Default::default() },
            ..Default::default()
        },
        GATEWAY,
    );
    assert_eq!((observed.private_hardware_address, observed.firewall, observed.stealth_mode), (Some(true), Firewall::On, None));
}

#[test]
fn an_ipv6_address_built_from_the_hardware_address_is_flagged() {
    let flagged = build_findings(&checks(|c| c.environment = environment(|e| { e.global_ipv6 = Some(true); e.ipv6_from_hardware_address = Some(true); })));
    assert_eq!(find(&flagged, "ipv6-privacy").unwrap().severity, Severity::Low);
    let fine = build_findings(&checks(|c| c.environment = environment(|e| { e.global_ipv6 = Some(true); e.ipv6_from_hardware_address = Some(false); })));
    assert!(find(&fine, "ipv6-privacy").is_none());
}

#[test]
fn watch_mode_notices_device_changes() {
    let before = report_of(checks(|c| c.environment = environment(|e| { e.firewall = Firewall::Off; e.tunnel_active = Some(false); })), None);
    let after = report_of(checks(|c| c.environment = environment(|e| { e.firewall = Firewall::On; e.tunnel_active = Some(true); })), None);
    assert_ne!(fingerprint(&before), fingerprint(&after));
    assert_eq!(describe_changes(&before, &after), ["VPN or tunnel alongside: no -> yes", "Device firewall: off -> on"]);
}

// ---------- speed advice ----------

fn speed_ids(wifi: &WifiCheck) -> Vec<String> {
    speed_findings(wifi).into_iter().map(|f| f.id).collect()
}

#[test]
fn a_healthy_link_gets_no_tips() {
    let findings = speed_findings(&wifi_check(|_| {}));
    assert!(findings.iter().all(|f| f.severity == Severity::Info));
    assert!(findings[0].message.contains("866 Mbps (Wi-Fi 5, 80 MHz channel), which is fast"));
    assert!(speed_tips(&findings).is_empty());
}

#[test]
fn an_unread_link_is_unknown_never_called_slow() {
    let unreadable = speed_findings(&wifi_check(|w| w.state = WifiState::Unknown));
    assert_eq!(unreadable.len(), 1);
    let partial = speed_findings(&wifi_check(|w| w.speed = WifiSpeedCheck::default()));
    assert_eq!(partial.len(), 1);
    assert!(partial[0].message.contains("Unknown"));
}

#[test]
fn a_weak_signal_says_to_fix_the_signal_not_to_change_band() {
    let wifi = wifi_check(|w| {
        w.band = Some(WifiBand::Ghz2);
        w.speed = WifiSpeedCheck { link_rate_mbps: Some(40), signal_dbm: Some(-78), signal: Some(SignalQuality::Weak), channel_width_mhz: Some(20), standard: Some(WifiStandard::Wifi5), noise_dbm: Some(-92) };
    });
    assert_eq!(speed_ids(&wifi), ["speed-link", "speed-signal"]);
    assert!(speed_findings(&wifi)[0].message.contains("which is slow"));
}

#[test]
fn good_signal_on_2_4_ghz_suggests_a_faster_band_and_a_wide_channel_is_flagged() {
    let wifi = wifi_check(|w| {
        w.band = Some(WifiBand::Ghz2);
        w.speed.channel_width_mhz = Some(40);
        w.speed.standard = Some(WifiStandard::Wifi4);
    });
    assert_eq!(speed_ids(&wifi), ["speed-link", "speed-signal", "speed-band", "speed-width", "speed-standard"]);
}

#[test]
fn a_narrow_5_ghz_channel_and_loud_noise_are_flagged() {
    let wifi = wifi_check(|w| {
        w.speed.channel_width_mhz = Some(20);
        w.speed.signal_dbm = Some(-62);
        w.speed.signal = Some(SignalQuality::Good);
        w.speed.noise_dbm = Some(-80);
    });
    assert_eq!(speed_ids(&wifi), ["speed-link", "speed-signal", "speed-noise", "speed-width"]);
    assert_eq!(speed_findings(&wifi).last().unwrap().action.as_deref(), Some("Set the 5 GHz channel width to 80 MHz in the router."));
}

#[test]
fn speed_tips_stay_out_of_the_privacy_top_fixes() {
    let mut findings = speed_findings(&wifi_check(|w| {
        w.speed.signal_dbm = Some(-80);
        w.speed.signal = Some(SignalQuality::Weak);
    }));
    findings.push(Finding { id: "channel".into(), severity: Severity::Low, message: "busy".into(), action: Some("Set the Wi-Fi channel to Auto in the router.".into()) });
    assert_eq!(top_fixes(&findings), ["Set the Wi-Fi channel to Auto in the router."]);
    assert_eq!(speed_tips(&findings).len(), 2);
}

#[test]
fn delay_findings_tell_a_slow_line_from_slow_wifi() {
    let check = |router_ms: Option<u32>, isp_ms: Option<u32>, requested| {
        latency_findings(&LatencyCheck { requested, router_ms, isp_ms, own_hops: isp_ms.map(|_| 1), isp_max_km: max_cable_km(router_ms, isp_ms), ..Default::default() })
            .into_iter()
            .map(|f| format!("{}:{}", f.id, f.severity.label()))
            .collect::<Vec<_>>()
    };
    assert!(check(None, None, false).is_empty());
    assert_eq!(check(None, None, true), ["speed-latency:INFO"]);
    assert_eq!(check(Some(3), Some(9), true), ["speed-latency-router:INFO", "speed-latency:INFO"]);
    assert_eq!(check(Some(35), Some(40), true), ["speed-latency-router:LOW", "speed-latency:INFO"]);
    assert_eq!(check(Some(4), Some(60), true), ["speed-latency-router:INFO", "speed-latency:LOW"]);
    // A router that is slow to answer for itself, while traffic through it is quick, is not a slow link.
    assert_eq!(check(Some(99), Some(24), true), ["speed-latency-router:INFO", "speed-latency:INFO"]);
    assert_eq!(check(Some(30), None, true), ["speed-latency-router:LOW", "speed-latency:INFO"]);
}

#[test]
fn distance_is_an_upper_limit_and_is_withheld_when_the_line_adds_no_measurable_delay() {
    let message = |router_ms, isp_ms| {
        latency_findings(&LatencyCheck { requested: true, router_ms: Some(router_ms), isp_ms: Some(isp_ms), own_hops: Some(1), isp_max_km: max_cable_km(Some(router_ms), Some(isp_ms)), ..Default::default() })
            .pop()
            .unwrap()
            .message
    };
    assert!(message(5, 11).contains("no more than about 600 km of cable away, and usually far closer"));
    assert!(message(99, 24).contains("too small to say anything about distance") && !message(99, 24).contains("km"));
}

// ---------- comparison ----------

fn observation(change: impl FnOnce(&mut WifiObservation)) -> WifiObservation {
    let mut o = WifiObservation {
        connected: true,
        security: "WPA3".into(),
        channel: Some(36),
        frequency_mhz: Some(5180),
        same_channel_count: Some(0),
        overlapping_count: Some(0),
        nearby_count: Some(5),
        link_rate_mbps: Some(866.0),
        signal_dbm: Some(-50.0),
        noise_dbm: Some(-92.0),
        channel_width_mhz: Some(80),
        standard: Some("802.11ac".into()),
    };
    change(&mut o);
    o
}

fn compare_report(wifi: WifiObservation, change: impl FnOnce(&mut Checks)) -> Report {
    report_of(
        checks(|c| {
            c.upnp = UpnpCheck { state: UpnpState::Detected, mapping_count: Some(0), sensitive_count: Some(0), mappings: vec![] };
            c.wifi = wifi_check_from(&wifi);
            c.dns.status = DnsStatus::Encrypted;
            c.environment = environment(|e| e.firewall = Firewall::On);
            change(c);
        }),
        None,
    )
}

fn row<'a>(id: &str, c: &'a ReportComparison) -> &'a ComparisonRow {
    c.rows.iter().find(|r| r.id == id).unwrap()
}

#[test]
fn says_which_side_is_better_on_each_measure_in_the_right_direction() {
    let home = compare_report(observation(|_| {}), |_| {});
    let office = compare_report(
        observation(|o| {
            o.channel = Some(6);
            o.frequency_mhz = Some(2437);
            o.link_rate_mbps = Some(65.0);
            o.signal_dbm = Some(-74.0);
            o.channel_width_mhz = Some(20);
            o.standard = Some("802.11n".into());
            o.same_channel_count = Some(4);
        }),
        |_| {},
    );
    let c = compare_reports(("Home", &home), ("Office", &office));
    assert_eq!((row("link-rate", &c).left.as_deref(), row("link-rate", &c).right.as_deref(), row("link-rate", &c).better), (Some("866 Mbps"), Some("65 Mbps"), Some(Better::Left)));
    assert_eq!(row("signal", &c).better, Some(Better::Left)); // -50 dBm is stronger than -74
    assert_eq!(row("same-channel", &c).better, Some(Better::Left)); // fewer is better
    assert_eq!((row("band", &c).left.as_deref(), row("band", &c).better), (Some("5 GHz"), Some(Better::Left)));
    assert_eq!(row("standard", &c).better, Some(Better::Left));
    assert_eq!(row("security", &c).better, Some(Better::Same));
    assert_eq!(row("nearby", &c).better, None);
    let swapped = compare_reports(("Office", &office), ("Home", &home));
    assert_eq!(row("link-rate", &swapped).better, Some(Better::Right));
}

#[test]
fn unknown_never_wins_and_delay_is_compared_when_both_sides_measured_it() {
    let home = compare_report(observation(|_| {}), |_| {});
    let no_radio = compare_report(observation(|o| { o.link_rate_mbps = None; o.signal_dbm = None; o.channel_width_mhz = None; o.standard = None; }), |_| {});
    let c = compare_reports(("A", &home), ("B", &no_radio));
    assert_eq!((row("link-rate", &c).right.as_deref(), row("link-rate", &c).better), (None, None));

    let timed = |router_ms: u32, isp_ms: u32| {
        compare_report(observation(|_| {}), |c| c.latency = LatencyCheck { requested: true, router_ms: Some(router_ms), isp_ms: Some(isp_ms), own_hops: Some(1), isp_max_km: max_cable_km(Some(router_ms), Some(isp_ms)), ..Default::default() })
    };
    let c = compare_reports(("A", &timed(3, 9)), ("B", &timed(5, 30)));
    assert_eq!((row("isp-delay", &c).left.as_deref(), row("isp-delay", &c).better), (Some("9 ms"), Some(Better::Left)));
    assert_eq!(row("isp-km", &c).better, None);
    assert_eq!(row("isp-delay", &compare_reports(("A", &timed(3, 9)), ("B", &home))).better, None);
}

#[test]
fn a_report_saved_before_speed_existed_reads_as_unknown_instead_of_failing() {
    let mut json: serde_json::Value = serde_json::to_value(compare_report(observation(|_| {}), |_| {})).unwrap();
    json["checks"]["wifi"].as_object_mut().unwrap().remove("speed");
    json["checks"].as_object_mut().unwrap().remove("latency");
    json.as_object_mut().unwrap().remove("speedTips");
    let old: Report = serde_json::from_value(json).unwrap();
    let home = compare_report(observation(|_| {}), |_| {});
    let c = compare_reports(("Old", &old), ("Home", &home));
    assert_eq!((row("link-rate", &c).left.as_deref(), row("link-rate", &c).better), (None, None));
    assert_eq!(row("isp-delay", &c).left, None);
}

#[test]
fn warns_when_the_scores_rest_on_different_amounts_of_evidence_and_lists_one_sided_problems() {
    let home = compare_report(observation(|_| {}), |_| {});
    let thin = compare_report(observation(|_| {}), |c| c.dns.status = DnsStatus::Unknown);
    assert!(compare_reports(("A", &home), ("B", &thin)).notes[0].contains("different evidence"));
    assert!(compare_reports(("A", &home), ("B", &home)).notes.is_empty());

    let weak = compare_report(observation(|o| o.security = "WEP".into()), |_| {});
    let c = compare_reports(("Home", &home), ("Cafe", &weak));
    assert!(c.only_left.is_empty());
    assert!(c.only_right.iter().any(|m| m.contains("Wi-Fi security is weak")));
}

#[test]
fn old_typescript_reports_load_and_summarise() {
    let report: Report = serde_json::from_str(include_str!("../../tests/fixtures/typescript-report.json")).unwrap();
    assert_eq!(report.target, "<private-gateway>");
    assert_eq!(report.checks.ports.len(), AUDITED_PORTS.len());
    // Saved by the TypeScript version, the score must come out the same when recomputed here.
    assert_eq!(score_checks(&report.checks), report.score);
    let saved = super::saved::SavedReport { label: "Home".into(), saved_at: "s".into(), report: report.clone() };
    assert_eq!(summarise(&saved).score, report.score.provisional);
    // And the report written back reads the same: nothing is lost in the round trip.
    let again: Report = serde_json::from_str(&serde_json::to_string_pretty(&report).unwrap()).unwrap();
    assert_eq!(again, report);
}

// ---------- the internet side ----------

fn wan<'a>(findings: &'a [Finding], id: &str) -> &'a Finding {
    find(findings, id).unwrap_or_else(|| panic!("no {id}"))
}

fn timed(cgnat: Option<bool>, own_hops: u32) -> LatencyCheck {
    LatencyCheck { requested: true, router_ms: Some(3), isp_ms: Some(9), own_hops: Some(own_hops), isp_max_km: Some(600), carrier_grade_nat: cgnat }
}

fn mapping(port: u32, sensitive: bool) -> SanitizedMapping {
    SanitizedMapping { label: "<mapping-1>".into(), protocol: "TCP".into(), external_port: port, internal_port: port, internal_host: "192.168.1.x".into(), sensitive }
}

fn forwards(mappings: Vec<SanitizedMapping>) -> UpnpCheck {
    UpnpCheck { state: UpnpState::Detected, mapping_count: Some(mappings.len() as u32), sensitive_count: Some(0), mappings }
}

#[test]
fn says_whether_the_isp_puts_you_behind_carrier_grade_nat() {
    let nat = |latency: LatencyCheck| build_findings(&checks(|c| c.latency = latency));
    assert!(wan(&nat(timed(Some(true), 1)), "wan-nat").message.contains("most likely behind CGNAT"));
    assert!(wan(&nat(timed(Some(false), 1)), "wan-nat").message.contains("ordinary public address"));
    assert!(wan(&nat(timed(Some(false), 2)), "wan-nat").message.contains("double NAT"));
    // Not measured, or no router past ours answered: unknown, never guessed.
    assert!(wan(&nat(LatencyCheck::default()), "wan-nat").message.starts_with("Carrier-grade NAT: Unknown. Run the audit"));
    assert!(wan(&nat(LatencyCheck { requested: true, router_ms: Some(3), ..Default::default() }), "wan-nat").message.contains("could not be told"));
    for latency in [timed(Some(true), 1), LatencyCheck::default()] {
        assert_eq!(wan(&nat(latency), "wan-nat").severity, Severity::Info);
    }
}

#[test]
fn names_the_ports_upnp_forwards_and_what_that_means_for_reach() {
    let with = |upnp: UpnpCheck, latency: LatencyCheck| build_findings(&checks(|c| { c.upnp = upnp; c.latency = latency; }));
    let open = with(forwards(vec![mapping(22, true), mapping(32400, false), mapping(50123, false)]), timed(Some(false), 1));
    let message = &wan(&open, "wan-forwards").message;
    assert!(message.contains("22 (SSH), 32400 (Plex), 50123"), "{message}");
    assert!(message.contains("open to anyone on the internet"));

    let behind = with(forwards(vec![mapping(80, false)]), timed(Some(true), 1));
    assert!(wan(&behind, "wan-forwards").message.contains("probably not reachable from the internet"));
    let unknown = with(forwards(vec![mapping(80, false)]), LatencyCheck::default());
    assert!(wan(&unknown, "wan-forwards").message.contains("If your router has a public address"));
    assert!(wan(&with(forwards(vec![]), LatencyCheck::default()), "wan-forwards").message.contains("holds no port mappings"));
    // UPnP that could not be read says nothing about forwards.
    assert!(find(&build_findings(&checks(|_| {})), "wan-forwards").is_none());
}

#[test]
fn a_long_list_of_forwards_is_shortened_and_repeats_are_listed_once() {
    let many: Vec<_> = (1..=9).map(|i| mapping(40000 + i, false)).chain([mapping(40001, false)]).collect();
    let message = wan(&build_findings(&checks(|c| c.upnp = forwards(many))), "wan-forwards").message.clone();
    assert!(message.contains("40001, 40002, 40003, 40004, 40005, 40006 and 3 more"), "{message}");
}

#[test]
fn a_global_ipv6_address_is_flagged_only_when_something_makes_it_reachable() {
    let ipv6 = |global, firewall, open| {
        build_findings(&checks(|c| c.environment = environment(|e| { e.global_ipv6 = global; e.firewall = firewall; e.open_listener_count = open; })))
    };
    let both = ipv6(Some(true), Firewall::Off, Some(2));
    assert_eq!(wan(&both, "wan-ipv6").severity, Severity::Medium);
    assert!(wan(&both, "wan-ipv6").message.contains("at least 2 ports on it accept connections and its firewall is off"));
    assert_eq!(wan(&ipv6(Some(true), Firewall::On, Some(1)), "wan-ipv6").severity, Severity::Low);
    assert_eq!(wan(&ipv6(Some(true), Firewall::Off, Some(0)), "wan-ipv6").severity, Severity::Low);
    assert!(find(&ipv6(Some(true), Firewall::On, Some(0)), "wan-ipv6").is_none(), "a firewall on and nothing listening is not a finding");
    assert!(find(&ipv6(Some(false), Firewall::Off, Some(5)), "wan-ipv6").is_none(), "no IPv6, no direct reach");
    assert!(find(&ipv6(None, Firewall::Off, Some(5)), "wan-ipv6").is_none());
    assert!(top_fixes(&both).iter().any(|f| f.contains("IPv6 firewall")));
}

#[test]
fn always_explains_how_to_test_from_outside_and_never_claims_a_test_was_made() {
    let findings = build_findings(&checks(|_| {}));
    assert!(wan(&findings, "wan-verify").message.contains("mobile data"));
    assert!(find(&findings, "wan").unwrap().message.contains("WAN exposure was not tested"));
    let json = serde_json::to_string(&build_findings(&checks(|c| { c.upnp = forwards(vec![mapping(22, true)]); c.latency = timed(Some(false), 1); }))).unwrap().to_lowercase();
    assert!(!json.contains("exposed to the internet") && !json.contains("internet-exposed"));
}

#[test]
fn the_nat_situation_is_noticed_by_watch_mode_and_never_scored() {
    let before = report_of(checks(|c| c.latency = timed(Some(false), 1)), None);
    let after = report_of(checks(|c| c.latency = timed(Some(true), 1)), None);
    assert!(describe_changes(&before, &after).contains(&"Behind carrier-grade NAT: no -> yes".to_string()));
    assert_eq!(before.score, report_of(checks(|_| {}), None).score);
}

