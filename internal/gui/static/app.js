"use strict";

// ---- helpers ---------------------------------------------------------------

const $ = (sel) => document.querySelector(sel);

function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null && v !== false) e.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}

async function api(path, body) {
  const opts = { credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    opts.method = "POST";
    opts.headers["Content-Type"] = "application/json";
    opts.headers["X-Mihomac"] = "1";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function showError(node, err) {
  node.textContent = err ? err.message || String(err) : "";
  node.hidden = !err;
}

const fmtTime = (s) => new Date(s).toLocaleTimeString();
const fmtBytes = (n) => n >= 1 << 20 ? (n / (1 << 20)).toFixed(1) + " MB" : n >= 1024 ? (n / 1024).toFixed(1) + " KB" : n + " B";
const dest = (c) => {
  const h = c.host || c.dest_ip || "?";
  return (h.includes(":") ? `[${h}]` : h) + ":" + c.dest_port;
};

function describeSource(s) {
  if (!s || !s.kind) return "";
  const note = s.note ? ` (${s.note})` : "";
  switch (s.kind) {
    case "user": return `your rule ${s.name}${note}`;
    case "bypass": return `built-in bypass${note}`;
    case "pack": return `${s.name} pack`;
    case "config": return `config file #${s.index}`;
  }
  return s.kind;
}

// ---- tabs ------------------------------------------------------------------

let currentTab = "overview";
for (const b of document.querySelectorAll("nav button")) {
  b.addEventListener("click", () => {
    currentTab = b.dataset.tab;
    for (const x of document.querySelectorAll("nav button")) x.classList.toggle("active", x === b);
    for (const s of document.querySelectorAll("main > section")) s.hidden = s.id !== "tab-" + currentTab;
    refresh();
  });
}

// ---- overview --------------------------------------------------------------

const modeHelp = {
  "tun": "Captures every app, including CLI tools that ignore proxy settings. Needs the privileged helper.",
  "system-proxy": "Sets the macOS system proxy. Apps that honor it are proxied; nothing else changes. Needs the privileged helper.",
  "port-only": "Only the mixed port at 127.0.0.1. Nothing on the system changes; point apps at it yourself.",
};

async function loadStatus() {
  const state = $("#state");
  let s;
  try {
    s = await api("/api/status");
  } catch (e) {
    state.textContent = "offline";
    state.className = "pill bad";
    return;
  }
  $("#instance").textContent = `${s.instance} · ${s.channel} build`;
  state.textContent = s.mihomo_version ? `${s.mode} · running` : "core unreachable";
  state.className = "pill " + (s.mihomo_version ? "ok" : "bad");

  const needsHelper = (m) => m !== "port-only" && !s.helper.available;
  $("#modes").replaceChildren(...s.modes.map((m) => el("button", {
    class: m === s.mode ? "active" : "",
    disabled: needsHelper(m) ? "" : null,
    title: needsHelper(m) ? "Install the privileged helper first" : modeHelp[m],
    onclick: () => switchMode(m),
  }, m)));
  $("#mode-help").textContent = modeHelp[s.mode] +
    (s.helper.available ? "" : " The privileged helper isn't installed, so only port-only mode is available (sudo make install-helper).");

  const rows = [
    ["Proxy", `http / socks5 127.0.0.1:${s.mixed_port}`],
    ["TUN device", s.mode === "tun" ? s.tun_device : `${s.tun_device} (off)`],
    ["Core", `mihomo ${s.core_version}` + (s.mihomo_version ? ` (reports ${s.mihomo_version})` : "")],
    ["Helper", s.helper.available ? `available (${s.helper.version})` : "not available"],
    ["Rules", Object.entries(s.rules || {}).map(([k, v]) => `${v} ${k}`).join(", ")],
    ["Config", s.config_path],
    ["Started", new Date(s.started_at).toLocaleString()],
  ];
  $("#status").replaceChildren(...rows.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]));

  $("#warnings-card").hidden = !(s.warnings && s.warnings.length);
  $("#warnings").replaceChildren(...(s.warnings || []).map((w) => el("li", {}, w)));
  $("#events").replaceChildren(...(s.events || []).slice().reverse().map((e) =>
    el("li", {}, el("time", {}, fmtTime(e.time)), e.message)));
}

async function switchMode(mode) {
  const errNode = $("#mode-error");
  showError(errNode, null);
  $("#state").textContent = `switching to ${mode}…`;
  try {
    await api("/api/mode", { mode });
  } catch (e) {
    showError(errNode, e);
  }
  loadStatus();
}

// ---- connections -----------------------------------------------------------

let selectedConn = null;
$("#conn-filter").addEventListener("input", () => loadConnections());

async function loadConnections() {
  if ($("#conn-pause").checked) return;
  const q = encodeURIComponent($("#conn-filter").value);
  let conns;
  try { conns = await api(`/api/connections?limit=300&q=${q}`); } catch { return; }
  const tbody = $("#conn-table tbody");
  tbody.replaceChildren(...conns.map((c) => el("tr", {
    class: [c.end ? "closed" : "", c.id === selectedConn ? "active" : ""].join(" "),
    onclick: () => { selectedConn = c.id; loadDetail(); loadConnections(); },
  },
  el("td", {}, fmtTime(c.start)),
  el("td", {}, c.process || "–"),
  el("td", { class: "mono" }, dest(c)),
  el("td", { class: "mono" }, c.rule + (c.rule_payload ? "," + c.rule_payload : "")),
  el("td", {}, (c.chains || []).join(" ← ")),
  el("td", {}, fmtBytes(c.download)),
  )));
  if (!conns.length) tbody.append(el("tr", {}, el("td", { colspan: 6, class: "muted" }, "No connections yet.")));
}

async function loadDetail() {
  const box = $("#conn-detail");
  if (!selectedConn) return;
  let d;
  try { d = await api(`/api/connections/${encodeURIComponent(selectedConn)}`); } catch (e) {
    box.replaceChildren(el("p", { class: "error" }, e.message));
    return;
  }
  const c = d.connection, x = d.explanation;
  const url = (c.dest_port === "443" ? "https://" : "http://") + (c.host || c.dest_ip) + "/";
  box.replaceChildren(
    el("h2", {}, "Why did this go here?"),
    el("p", {}, x.summary),
    el("ol", { class: "path" }, x.path.map((s) => el("li", {},
      el("div", { class: "kind" }, s.kind), el("div", { class: "mono" }, s.label),
      s.detail ? el("div", { class: "muted small" }, s.detail) : null))),
    el("dl", {},
      el("dt", {}, "Status"), el("dd", {}, c.end ? `closed after ${((new Date(c.end) - new Date(c.start)) / 1000).toFixed(1)} s` : "open"),
      el("dt", {}, "Traffic"), el("dd", {}, `${fmtBytes(c.upload)} up · ${fmtBytes(c.download)} down`),
      el("dt", {}, "Inbound"), el("dd", {}, `${c.inbound} from ${c.source}`),
      c.process_path ? [el("dt", {}, "Process"), el("dd", { class: "mono" }, c.process_path)] : null,
    ),
    d.logs && d.logs.length ? [el("h2", { style: "margin-top:12px" }, "Core log"),
      el("ul", { class: "events" }, d.logs.map((l) => el("li", {}, el("time", {}, fmtTime(l.time)), `[${l.level}] ${l.message}`)))] : null,
    el("p", {}, el("button", { class: "link", onclick: () => runProbe(url, box) }, "Is the proxy the cause? Compare direct vs proxied")),
  );
}

// ---- rules -----------------------------------------------------------------

async function loadRules() {
  let v;
  try { v = await api("/api/rules"); } catch { return; }

  const typeSel = $("#rule-type");
  if (!typeSel.options.length) {
    typeSel.replaceChildren(...v.types.map((t) => el("option", { value: t }, t)));
    typeSel.addEventListener("change", updateValueHints);
  }

  $("#packs").replaceChildren(...Object.keys(v.packs).sort().map((name) => {
    const on = (v.set.packs || []).includes(name);
    return el("label", { class: "pack" },
      el("input", { type: "checkbox", checked: on ? "" : null, onchange: (e) => changeRules(e.target.checked ? { enable_packs: [name] } : { disable_packs: [name] }) }),
      el("strong", {}, name), el("span", { class: "muted" }, v.packs[name].description));
  }));

  const userRules = v.set.rules || [];
  $("#rules-table tbody").replaceChildren(...(v.compiled || []).map((r) => {
    let remove = null;
    if (r.source.kind === "user") {
      const rule = userRules[r.source.index - 1];
      remove = el("button", { class: "link danger", onclick: () => changeRules({ remove: [{ type: rule.type, value: rule.value, target: rule.target }] }) }, "remove");
    }
    return el("tr", {}, el("td", {}, r.position), el("td", { class: "mono wrap" }, r.line), el("td", {}, describeSource(r.source)), el("td", {}, remove));
  }));
}

async function updateValueHints() {
  const t = $("#rule-type").value;
  $("#rule-value").placeholder = {
    "domain": "api.example.com", "domain-suffix": "example.com", "domain-keyword": "example",
    "ip-cidr": "10.20.0.0/16", "process-name": "curl", "process-path": "/usr/bin/curl", "app": "/Applications/Safari.app",
  }[t] || "value";
  if (t === "app" && !$("#app-list").options.length) {
    try {
      const apps = await api("/api/apps");
      $("#app-list").replaceChildren(...apps.map((a) => el("option", { value: a.path }, a.name)));
    } catch { /* the picker is optional */ }
  }
}

async function loadTargets() {
  let nodes = [], ifaces = [];
  try { nodes = await api("/api/nodes"); } catch { /* ignore */ }
  try { ifaces = await api("/api/interfaces"); } catch { /* ignore */ }
  const builtin = ["Direct", "Reject", "RejectDrop", "Pass", "PassRule", "Compatible"];
  const names = new Set(["DIRECT", "REJECT",
    ...nodes.filter((n) => !builtin.includes(n.type) && !n.name.startsWith("iface:")).map((n) => n.name),
    ...ifaces.filter((i) => i.name.startsWith("en") && i.addrs && i.addrs.length).map((i) => "iface:" + i.name)]);
  $("#target-list").replaceChildren(...[...names].map((n) => el("option", { value: n })));
}

$("#rule-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const rule = { type: $("#rule-type").value, value: $("#rule-value").value.trim(), target: $("#rule-target").value.trim() };
  const note = $("#rule-note").value.trim();
  if (note) rule.note = note;
  if (await changeRules({ add: [rule] })) e.target.reset();
});

async function changeRules(change) {
  const errNode = $("#rule-error");
  showError(errNode, null);
  try {
    await api("/api/rules/change", change);
  } catch (e) {
    showError(errNode, e);
    loadRules();
    return false;
  }
  loadRules();
  return true;
}

async function loadProposals() {
  let ps;
  try { ps = await api("/api/proposals"); } catch { return; }
  const pending = ps.filter((p) => p.status === "pending");
  const badge = $("#pending-badge");
  badge.hidden = !pending.length;
  badge.textContent = pending.length;
  $("#proposals-card").hidden = !pending.length;
  $("#proposals").replaceChildren(...pending.map((p) => el("div", { class: "proposal" },
    el("div", {}, el("strong", {}, p.summary || "(no summary)"), " ",
      el("span", { class: "muted small" }, `from ${p.origin === "agent" ? "an AI assistant (MCP)" : "you"} · ${new Date(p.created).toLocaleString()} · ${p.id}`)),
    el("pre", { class: "mono" }, p.diff),
    el("div", { class: "actions" },
      el("button", { class: "primary", onclick: () => decide(p.id, "apply") }, "Apply"),
      el("button", { onclick: () => decide(p.id, "reject") }, "Reject")),
  )));
}

async function decide(id, decision) {
  try { await api(`/api/proposals/${id}/${decision}`, {}); } catch (e) { alert(e.message); }
  loadProposals();
  loadRules();
}

// ---- network ---------------------------------------------------------------

async function loadNetwork() {
  try {
    const ifs = await api("/api/interfaces");
    $("#iface-table tbody").replaceChildren(...ifs.map((i) => el("tr", {},
      el("td", { class: "mono" }, i.name + (i.up ? "" : " (down)")), el("td", {}, i.role),
      el("td", { class: "mono wrap" }, (i.addrs || []).join(", ") || "–"), el("td", {}, i.routes))));
  } catch { /* ignore */ }
  try {
    const nodes = await api("/api/nodes");
    $("#node-table tbody").replaceChildren(...nodes.map((n) => el("tr", {},
      el("td", {}, n.name), el("td", {}, n.type), el("td", {}, n.now || ""),
      el("td", {}, n.delay_ms ? `${n.delay_ms} ms` : "–"))));
  } catch { /* ignore */ }
}

async function loadInstances() {
  let list;
  try { list = await api("/api/instances"); } catch { return; }
  $("#instance-table tbody").replaceChildren(...list.map((i) => el("tr", { class: i.current ? "active" : "" },
    el("td", {}, i.name, i.label !== i.name ? ` (${i.label})` : "", i.current ? " · this one" : ""),
    el("td", {}, i.running ? `running (pid ${i.pid})` : "stopped"), el("td", {}, i.mode || "–"),
    el("td", { class: "mono" }, i.core_version), el("td", { class: "mono" }, i.mixed_port), el("td", { class: "mono" }, i.tun_device))));
  const sel = $("#log-instance");
  if (sel.options.length !== list.length) {
    const keep = sel.value;
    sel.replaceChildren(...list.map((i) => el("option", { value: i.name }, i.name)));
    sel.value = keep || (list.find((i) => i.current) || list[0]).name;
  }
}

async function loadLog() {
  const q = new URLSearchParams({ instance: $("#log-instance").value, source: $("#log-source").value, lines: "200" });
  try {
    const r = await api("/api/logs?" + q);
    $("#log-output").textContent = r.lines.length ? r.lines.join("\n") : "(empty)";
  } catch (e) {
    $("#log-output").textContent = e.message;
  }
}
$("#log-refresh").addEventListener("click", loadLog);
$("#log-instance").addEventListener("change", loadLog);
$("#log-source").addEventListener("change", loadLog);

$("#probe-form").addEventListener("submit", (e) => {
  e.preventDefault();
  runProbe($("#probe-url").value, $("#probe-result"));
});

async function runProbe(url, box) {
  const out = el("div", { class: "verdict" }, `Probing ${url} …`);
  box.append(out);
  try {
    const r = await api("/api/probe", { url });
    const line = (label, a) => el("div", {}, `${label}: `,
      a.ok ? el("span", { class: "ok-text" }, `HTTP ${a.status} in ${a.millis} ms`) : el("span", { class: "bad-text" }, `failed after ${a.millis} ms: ${a.error || "HTTP " + a.status}`));
    out.replaceChildren(line(`Direct (via ${r.direct_interface})`, r.direct), line("Through the proxy", r.proxied), el("p", {}, el("strong", {}, r.verdict)));
  } catch (e) {
    out.replaceChildren(el("span", { class: "error" }, e.message));
  }
}

// ---- refresh loop ----------------------------------------------------------

function refresh() {
  loadStatus();
  loadProposals();
  if (currentTab === "connections") { loadConnections(); if (selectedConn) loadDetail(); }
  if (currentTab === "rules") { loadRules(); loadTargets(); updateValueHints(); }
  if (currentTab === "network") { loadNetwork(); loadInstances(); }
}

refresh();
setInterval(() => {
  if (document.hidden) return;
  loadStatus();
  loadProposals();
  if (currentTab === "connections") loadConnections();
}, 2000);
