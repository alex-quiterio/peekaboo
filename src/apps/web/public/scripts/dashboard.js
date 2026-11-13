// Dashboard client: fetches state from the local server and renders it. No frameworks.
const $ = (id) => document.getElementById(id);

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (key === "class") el.className = value; else el.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child.nodeType ? child : document.createTextNode(String(child)));
  }
  return el;
}

const SEVERITY = ["HIGH", "MEDIUM", "LOW", "INFO"];
const time = (iso) => new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
const selectedDns = () => document.querySelector('input[name="dns"]:checked').value;

function ring(score) {
  const r = 52, c = 2 * Math.PI * r;
  const color = score === null ? "var(--track)" : score >= 80 ? "var(--good)" : score >= 50 ? "var(--warn)" : "var(--bad)";
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 124 124");
  svg.setAttribute("class", "ring");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", score === null ? "Score unknown" : `Provisional score ${score} out of 100`);
  svg.innerHTML =
    `<circle class="bg" cx="62" cy="62" r="${r}"/>` +
    `<circle class="fg" cx="62" cy="62" r="${r}" stroke="${color}" stroke-dasharray="${c}" stroke-dashoffset="${c * (1 - (score ?? 0) / 100)}"/>` +
    `<text x="62" y="62">${score ?? "?"}</text>`;
  return svg;
}

function scoreCard(report) {
  const { score, comparison } = report;
  let trend = h("p", { class: "muted" }, "No earlier audit to compare with yet.");
  if (comparison) {
    const { previousScore, currentScore, delta } = comparison;
    const color = delta > 0 ? "var(--good)" : delta < 0 ? "var(--bad)" : "var(--muted)";
    trend = h("p", {}, "Before/after: ",
      h("span", { class: "delta" }, `${previousScore} → ${currentScore} `),
      h("span", { class: "delta", style: `color:${color}` }, `(${delta > 0 ? "+" : ""}${delta})`));
  }
  return h("div", { class: "card" },
    h("h2", {}, "Provisional score"),
    h("div", { class: "score" }, ring(score.provisional),
      h("div", {},
        h("p", { class: "flush" }, score.provisional === null
          ? "Nothing could be measured, so there is no score."
          : `${score.earnedWeight} of ${score.knownWeight} measurable points earned.`),
        trend)),
    h("div", { class: "coverage" },
      h("div", {}, h("strong", {}, `${score.coveragePercent}% evidence coverage`)),
      h("div", { class: "bar" }, h("i", { style: `width:${score.coveragePercent}%` })),
      h("div", { class: "muted" },
        score.coveragePercent < 100
          ? "Unknown checks are left out of the score, not counted against you. Low coverage means the score rests on little evidence."
          : "Every check produced evidence.")));
}

function fixesCard(report) {
  const body = report.topFixes.length
    ? h("ol", { class: "fixes" }, report.topFixes.map((fix) => h("li", {}, h("span", {}, fix))))
    : h("p", { class: "muted" }, "Nothing to fix among the checks that produced evidence.");
  return h("div", { class: "card" },
    h("h2", {}, "Top fixes"), body,
    report.topFixes.length
      ? h("p", { class: "muted note" },
          "Back up your router settings first, and change one thing at a time. Then run the audit again.")
      : null);
}

function findingsCard(report) {
  const lines = Object.fromEntries(report.score.breakdown.map((line) => [line.id, line]));
  const sorted = [...report.findings].sort((a, b) => SEVERITY.indexOf(a.severity) - SEVERITY.indexOf(b.severity));
  return h("section", { class: "card" },
    h("h2", {}, "Findings"),
    sorted.map((f) => {
      const line = lines[f.id];
      const points = !line ? null : line.earned === null
        ? h("div", { class: "points muted" }, "not scored", h("small", {}, `of ${line.weight}`))
        : h("div", { class: "points" }, `${line.earned} / ${line.weight}`, h("small", {}, "points"));
      return h("div", { class: "finding" },
        h("span", { class: `badge ${f.severity}` }, f.severity),
        h("div", {}, h("div", {}, f.message), f.action ? h("div", { class: "action" }, `Fix: ${f.action}`) : null),
        points);
    }));
}

function mappingsCard(report) {
  const { mappings } = report.checks.upnp;
  if (!mappings.length) return null;
  return h("section", { class: "card" },
    h("h2", {}, "UPnP port mappings"),
    h("p", { class: "muted lead" },
      "Mappings the router reported. Names are replaced with placeholders and addresses are truncated."),
    h("div", { class: "scroll" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Mapping", "Protocol", "External port", "Internal device", "Internal port", "Remote access"].map((t) => h("th", {}, t)))),
      h("tbody", {}, mappings.map((m) => h("tr", {},
        h("td", { class: "mono" }, m.label), h("td", {}, m.protocol), h("td", { class: "mono" }, m.externalPort),
        h("td", { class: "mono" }, m.internalHost), h("td", { class: "mono" }, m.internalPort),
        h("td", {}, m.sensitive ? h("span", { class: "badge HIGH" }, "YES") : "")))))));
}

// The device list lives in this page's memory only. The server does not keep it and nothing saves it.
const devices = { loading: false, list: null, error: null };

function devicesCard() {
  const button = h("button", { class: "ghost", type: "button", id: "devices-btn" },
    devices.loading ? "Looking… (a few seconds)" : devices.list ? "List again" : "List devices");
  button.disabled = devices.loading;
  button.addEventListener("click", listDevices);

  const tags = (d) => [
    d.role === "router" ? h("span", { class: "badge LOW" }, "ROUTER") : null,
    d.role === "this-device" ? h("span", { class: "badge INFO" }, "THIS DEVICE") : null,
    d.randomisedAddress ? h("span", { class: "badge INFO" }, "PRIVATE ADDRESS") : null,
  ];
  let body = null;
  if (devices.error) {
    body = h("p", { class: "notice error" }, devices.error);
  } else if (devices.list) {
    const rows = devices.list.devices;
    body = [
      h("p", { class: "muted" }, `${rows.length} device${rows.length === 1 ? "" : "s"} seen at ${time(devices.list.listedAt)}. ` +
        "Devices that are asleep or ignore the network may be missing."),
      h("div", { class: "scroll" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Device", "Address", "Hardware address", ""].map((t) => h("th", {}, t)))),
        h("tbody", {}, rows.map((d) => h("tr", {},
          h("td", {}, d.name || h("span", { class: "muted" }, "No name given")),
          h("td", { class: "mono" }, d.address), h("td", { class: "mono" }, d.hardwareAddress),
          h("td", { class: "tags" }, tags(d))))))),
    ];
  }
  return h("section", { class: "card" },
    h("div", { class: "card-head" }, h("h2", {}, "Devices on this network"), button),
    h("p", { class: "muted lead" },
      "Sends one empty packet to each address on your own network so every device shows up, then reads this " +
      "computer's list of neighbours and asks the router for names. No device is probed. The list stays on this " +
      "page: it is not saved and is gone when you reload."),
    body);
}

async function listDevices() {
  Object.assign(devices, { loading: true, error: null });
  refresh();
  try {
    devices.list = await call("/api/devices", {});
  } catch (err) {
    Object.assign(devices, { list: null, error: err.message });
  }
  devices.loading = false;
  refresh();
}

function watchCard(watch) {
  if (!watch.enabled && !watch.events.length) return null;
  const status = watch.enabled
    ? `Watching every ${watch.intervalMinutes} minutes. ` +
      (watch.nextRunAt ? `Next check ${time(watch.nextRunAt)}. ` : "") +
      (watch.quietRuns ? `${watch.quietRuns} check${watch.quietRuns === 1 ? "" : "s"} with no change.` : "")
    : "Watch is off. Earlier events from this session are kept below.";
  return h("section", { class: "card" },
    h("h2", {}, "Watch log"),
    h("p", { class: "muted lead" }, status),
    watch.events.map((e) => h("div", { class: "event" },
      h("div", {}, h("span", { class: `badge ${e.kind === "change" ? "MEDIUM" : "INFO"}` },
        e.kind === "change" ? "CHANGED" : "BASELINE"), h("span", { class: "muted" }, time(e.at))),
      h("ul", {}, e.lines.map((line) => h("li", {}, line))))));
}

function render(state) {
  const { report, watch, scanning, error } = state;
  const content = $("content");
  content.replaceChildren();

  $("scan-btn").disabled = scanning;
  $("scan-btn").textContent = scanning ? "Auditing… (about 20 seconds)" : report ? "Run audit again" : "Run audit";
  $("watch-btn").textContent = watch.enabled ? "Stop watch" : "Start 30-minute watch";
  $("watch-btn").dataset.enabled = watch.enabled;
  $("last-run").textContent = report ? `Last audit ${time(report.generatedAt)}` : "";

  if (error) content.append(h("p", { class: "notice error" }, error));
  if (!report) {
    content.append(h("div", { class: "card empty" },
      h("p", {}, "No audit has run yet."),
      h("p", { class: "muted" }, "Run one while connected to a home network you own or administer.")),
      devicesCard());
    return;
  }
  content.append(
    h("div", { class: "grid" }, scoreCard(report), fixesCard(report)),
    findingsCard(report),
    devicesCard(),
    ...[mappingsCard(report), watchCard(watch)].filter(Boolean),
    h("section", { class: "card" }, h("h2", {}, "Privacy"),
      h("ul", { class: "privacy" }, report.privacy.map((line) => h("li", {}, line)))));
}

async function call(path, payload) {
  const res = await fetch(path, payload === undefined ? {} : {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Request failed.");
  return data;
}

let dnsSynced = false;
let fastPoll;
async function refresh(path = "/api/state", payload) {
  try {
    const state = await call(path, payload);
    if (!dnsSynced && state.report) {
      const input = document.querySelector(`input[name="dns"][value="${state.report.checks.dns.status}"]`);
      if (input) input.checked = true;
      dnsSynced = true;
    }
    render(state);
    clearTimeout(fastPoll);
    if (state.scanning) fastPoll = setTimeout(refresh, 2000);
  } catch (err) {
    $("content").replaceChildren(h("p", { class: "notice error" },
      `Could not reach the local audit server. Is "bun start" still running? (${err.message})`));
    $("scan-btn").disabled = false;
  }
}

$("scan-btn").addEventListener("click", () => {
  $("scan-btn").disabled = true;
  $("scan-btn").textContent = "Auditing… (about 20 seconds)";
  refresh("/api/scan", { dns: selectedDns() });
});
$("watch-btn").addEventListener("click", () => {
  refresh("/api/watch", { enabled: $("watch-btn").dataset.enabled !== "true", dns: selectedDns() });
});

refresh();
setInterval(refresh, 20000);
