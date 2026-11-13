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
const selectedOptions = () => ({ dns: selectedDns(), ispLatency: $("isp-latency").checked });

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

// Reports saved before the speed check existed have no speed fields; the card then asks for a new audit.
function speedCard(report) {
  const speed = report.checks.wifi.speed;
  const tips = report.speedTips || [];
  if (!speed) {
    return h("section", { class: "card" }, h("h2", {}, "Wi-Fi speed"),
      h("p", { class: "muted" }, "Run the audit again to measure the Wi-Fi link."));
  }
  const stat = (label, value, unit) => h("div", { class: "stat" },
    h("div", { class: "muted" }, label),
    h("div", { class: "value" }, value === null ? "Unknown" : value, value !== null && unit ? h("small", {}, ` ${unit}`) : null));
  const latency = report.checks.latency;
  return h("section", { class: "card" },
    h("h2", {}, "Wi-Fi speed"),
    h("p", { class: "muted lead" },
      "The link between this device and the router, as this device's radio reports it. Real speed is about half " +
      "the link rate. No speed test is run, so your internet plan's speed is not shown. " +
      (latency && latency.requested ? "" : "Switch on the delay option above to also time the first router on your ISP's side.")),
    h("div", { class: "stats" },
      stat("Link rate", speed.linkRateMbps, "Mbps"),
      stat("Signal", speed.signalDbm, `dBm · ${speed.signal}`),
      stat("Standard", speed.standard),
      stat("Band", report.checks.wifi.band),
      stat("Channel width", speed.channelWidthMhz, "MHz"),
      latency && latency.requested ? [stat("Delay to router", latency.routerMs, "ms"), stat("Delay to ISP", latency.ispMs, "ms"),
        stat("ISP router within", latency.ispMaxKm ?? null, "km at most")] : null),
    h("h3", {}, "Make it faster"),
    tips.length
      ? h("ol", { class: "fixes" }, tips.map((tip) => h("li", {}, h("span", {}, tip))))
      : h("p", { class: "muted" }, speed.linkRateMbps === null
          ? "Nothing to suggest without a link rate."
          : "Nothing to suggest: no setting or signal problem was found."));
}

// Which findings are open. Kept here because the page is redrawn on every refresh.
const openFindings = new Set();

/** The first sentence is the headline; the rest is shown when the finding is opened. */
function splitMessage(message) {
  const end = message.search(/\.\s/);
  return end < 0 ? [message, ""] : [message.slice(0, end + 1), message.slice(end + 2)];
}

function findingRow(f, line) {
  const [title, rest] = splitMessage(f.message);
  const points = !line ? h("div", { class: "points" }) : line.earned === null
    ? h("div", { class: "points muted" }, "not scored", h("small", {}, `of ${line.weight}`))
    : h("div", { class: "points" }, `${line.earned} / ${line.weight}`, h("small", {}, "points"));
  const head = [h("span", { class: `badge ${f.severity}` }, f.severity), h("div", { class: "title" }, title), points];
  if (!rest && !f.action) return h("div", { class: "finding" }, h("div", { class: "row" }, head, h("span", { class: "chev" })));

  const details = h("details", { class: "finding", "data-id": f.id },
    h("summary", { class: "row" }, head, h("span", { class: "chev", "aria-hidden": "true" })),
    h("div", { class: "more" },
      rest ? h("p", {}, rest) : null,
      f.action ? h("p", { class: "action" }, h("strong", {}, "Fix: "), f.action) : null));
  details.open = openFindings.has(f.id);
  details.addEventListener("toggle", () => {
    if (details.open) openFindings.add(f.id); else openFindings.delete(f.id);
    syncToggleAll();
  });
  return details;
}

function syncToggleAll() {
  const button = $("findings-toggle");
  if (!button) return;
  const all = [...document.querySelectorAll("details.finding")];
  const everyOpen = all.length > 0 && all.every((d) => d.open);
  button.textContent = everyOpen ? "Collapse all" : "Expand all";
  button.dataset.open = everyOpen;
}

function findingsCard(report) {
  const lines = Object.fromEntries(report.score.breakdown.map((line) => [line.id, line]));
  const sorted = [...report.findings].sort((a, b) => SEVERITY.indexOf(a.severity) - SEVERITY.indexOf(b.severity));
  const toggle = h("button", { class: "ghost small", type: "button", id: "findings-toggle" }, "Expand all");
  toggle.addEventListener("click", () => {
    const open = toggle.dataset.open !== "true";
    for (const d of document.querySelectorAll("details.finding")) {
      d.open = open;
      if (open) openFindings.add(d.dataset.id); else openFindings.delete(d.dataset.id);
    }
    syncToggleAll();
  });
  return h("section", { class: "card" },
    h("div", { class: "card-head" }, h("h2", {}, "Findings"), toggle),
    h("div", { class: "findings" }, sorted.map((f) => findingRow(f, lines[f.id]))));
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

// Saved reports live in files on this computer. The page asks the server to save, list, delete and compare.
const saved = { list: null, draft: "", busy: false, message: null, error: null, compare: null };
const CURRENT = ""; // the server reads an empty side as "the most recent audit"

function savedBusy(promise) {
  saved.busy = true;
  saved.error = null;
  saved.message = null;
  refresh();
  return promise
    .catch((err) => { saved.error = err.message; })
    .finally(() => { saved.busy = false; refresh(); });
}

function saveCurrent() {
  const label = saved.draft.trim();
  return savedBusy(call("/api/saved", { label }).then((list) => {
    saved.list = list;
    saved.draft = "";
    saved.message = `Saved as "${label}".`;
  }));
}

function deleteSaved(label) {
  if (!confirm(`Delete the saved report "${label}"? This cannot be undone.`)) return;
  savedBusy(call("/api/saved/delete", { label }).then((list) => {
    saved.list = list;
    if (saved.compare && (saved.compare.left === label || saved.compare.right === label)) saved.compare = null;
  }));
}

function runCompare(left, right) {
  saved.compare = { left, right, result: null };
  return savedBusy(call("/api/compare", { left, right }).then((result) => {
    saved.compare = { left, right, result };
  }).catch((err) => {
    saved.compare = { left, right, result: null };
    throw err;
  }));
}

async function loadSaved() {
  try { saved.list = await call("/api/saved"); } catch (err) { saved.error = err.message; }
  refresh();
}

function comparisonCard() {
  const { left, right, result } = saved.compare;
  const choices = [[CURRENT, "Current audit"], ...(saved.list || []).map((s) => [s.label, s.label])];
  const picker = (value, onChange, label) => {
    const select = h("select", { "aria-label": label }, choices.map(([v, text]) => {
      const option = h("option", { value: v }, text);
      if (v === value) option.selected = true;
      return option;
    }));
    select.addEventListener("change", () => onChange(select.value));
    return select;
  };

  const cell = (value, better) => h("div", { class: `cell${better ? " better" : ""}` },
    value === null ? h("span", { class: "muted" }, "Unknown") : value,
    better ? h("span", { class: "mark", title: "Better", "aria-label": "better" }, " ✓") : null);

  const head = result ? [
    h("p", { class: "muted lead" },
      `${result.left.name} is better on ${result.wins.left} measure${result.wins.left === 1 ? "" : "s"}, ` +
      `${result.right.name} on ${result.wins.right}. Unknown values are never counted, and a tie counts for neither.`),
    ...result.notes.map((note) => h("p", { class: "notice" }, note)),
    h("div", { class: "cmp" },
      h("div", { class: "cmp-row cmp-head" }, h("div", {}), h("div", {}, result.left.name), h("div", {}, result.right.name)),
      result.rows.map((row) => h("div", { class: "cmp-row" },
        h("div", { class: "cmp-label" }, row.label),
        cell(row.left, row.better === "left"), cell(row.right, row.better === "right")))),
    result.onlyLeft.length || result.onlyRight.length ? h("div", { class: "only" },
      [[result.left.name, result.onlyLeft], [result.right.name, result.onlyRight]].filter(([, list]) => list.length)
        .map(([name, list]) => h("div", {}, h("h3", {}, `Only on ${name}`), h("ul", {}, list.map((m) => h("li", {}, m)))))) : null,
  ] : h("p", { class: "muted" }, saved.error ? "" : "Comparing…");

  const close = h("button", { class: "ghost small", type: "button" }, "Close");
  close.addEventListener("click", () => { saved.compare = null; refresh(); });
  return h("section", { class: "card" },
    h("div", { class: "card-head" }, h("h2", {}, "Comparison"), close),
    h("div", { class: "pickers" },
      picker(left, (v) => runCompare(v, saved.compare.right), "First report"),
      h("span", { class: "muted" }, "against"),
      picker(right, (v) => runCompare(saved.compare.left, v), "Second report")),
    head);
}

function savedCard(report) {
  const input = h("input", { type: "text", maxlength: "40", placeholder: "Name, for example Home or Amsterdam work", "aria-label": "Name for this report" });
  input.value = saved.draft;
  input.addEventListener("input", () => { saved.draft = input.value; button.disabled = saved.busy || !report || !saved.draft.trim(); });
  input.addEventListener("keydown", (e) => { if (e.key === "Enter" && !button.disabled) saveCurrent(); });
  const button = h("button", { type: "button" }, "Save this audit");
  button.disabled = saved.busy || !report || !saved.draft.trim();
  button.addEventListener("click", saveCurrent);

  const list = saved.list || [];
  const rows = list.map((s) => {
    const compare = h("button", { class: "ghost small", type: "button" }, "Compare");
    compare.disabled = saved.busy || (!report && list.length < 2);
    // With a current audit, compare against it; otherwise this report against the next most recent one.
    compare.addEventListener("click", () => runCompare(report ? CURRENT : s.label, report ? s.label : (list.find((o) => o.label !== s.label) || {}).label || CURRENT));
    const del = h("button", { class: "ghost small danger", type: "button" }, "Delete");
    del.disabled = saved.busy;
    del.addEventListener("click", () => deleteSaved(s.label));
    return h("div", { class: "saved-row" },
      h("div", { class: "saved-name" }, h("strong", {}, s.label),
        h("span", { class: "muted" }, `score ${s.score ?? "unknown"} · audited ${time(s.generatedAt)}`)),
      h("div", { class: "saved-actions" }, compare, del));
  });

  return [
    h("section", { class: "card" },
      h("h2", {}, "Saved reports"),
      h("p", { class: "muted lead" },
        "Keep this audit under a name, then compare it with another network later, for example your home Wi-Fi with " +
        "your office Wi-Fi. Reports are saved as files on this computer in the same sanitized form as the audit: no " +
        "network names or addresses. Saving under an existing name replaces it."),
      h("div", { class: "save-form" }, input, button),
      saved.error ? h("p", { class: "notice error" }, saved.error) : null,
      saved.message ? h("p", { class: "notice" }, saved.message) : null,
      list.length ? h("div", { class: "saved-list" }, rows)
        : saved.list ? h("p", { class: "muted" }, "Nothing saved yet.") : null),
    saved.compare ? comparisonCard() : null,
  ];
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

// While an audit runs, the old results are dimmed and locked so they are not mistaken for new ones.
function setLoading(on) {
  $("progress").hidden = !on;
  $("content").classList.toggle("loading", on);
  $("content").toggleAttribute("inert", on);
  $("content").setAttribute("aria-busy", String(on));
}

function render(state) {
  const { report, watch, scanning, error } = state;
  const content = $("content");
  content.replaceChildren();

  setLoading(scanning);
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
      ...savedCard(null).filter(Boolean),
      devicesCard());
    return;
  }
  content.append(
    h("div", { class: "grid" }, scoreCard(report), fixesCard(report)),
    speedCard(report),
    findingsCard(report),
    ...savedCard(report).filter(Boolean),
    devicesCard(),
    ...[mappingsCard(report), watchCard(watch)].filter(Boolean),
    h("section", { class: "card" }, h("h2", {}, "Privacy"),
      h("ul", { class: "privacy" }, report.privacy.map((line) => h("li", {}, line)))));
  syncToggleAll();
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
      const timed = state.report.checks.latency && state.report.checks.latency.requested;
      document.querySelector(`input[name="isp"][value="${timed ? "on" : "off"}"]`).checked = true;
      dnsSynced = true;
    }
    render(state);
    clearTimeout(fastPoll);
    if (state.scanning) fastPoll = setTimeout(refresh, 2000);
  } catch (err) {
    $("content").replaceChildren(h("p", { class: "notice error" },
      `Could not reach the local audit server. Is "bun start" still running? (${err.message})`));
    $("scan-btn").disabled = false;
    setLoading(false);
  }
}

$("scan-btn").addEventListener("click", () => {
  $("scan-btn").disabled = true;
  $("scan-btn").textContent = "Auditing… (about 20 seconds)";
  setLoading(true);
  refresh("/api/scan", selectedOptions());
});
$("watch-btn").addEventListener("click", () => {
  refresh("/api/watch", { enabled: $("watch-btn").dataset.enabled !== "true", ...selectedOptions() });
});

refresh();
loadSaved();
setInterval(() => {
  // Redrawing the page would take the cursor out of a name that is being typed.
  const active = document.activeElement;
  if (active && active.tagName === "INPUT" && $("content").contains(active)) return;
  refresh();
}, 20000);
