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
      el("strong", {}, name), packBadge(v.packs[name], v.set.library || []),
      el("span", { class: "muted" }, v.packs[name].description),
      isInstalled(name, v.set.library || []) ? el("button", { type: "button", class: "link danger", onclick: (e) => { e.preventDefault(); removePack(name); } }, "remove") : null);
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

const isInstalled = (name, lib) => lib.some((p) => p.name === name);
const packBadge = (p, lib) => el("span", { class: "muted small" }, isInstalled(p.name, lib) ? `v${p.version}${p.author ? " by " + p.author : ""}` : "built-in");

async function removePack(name) {
  try {
    const diff = (await api("/api/rules/preview", { remove_packs: [name] })).diff;
    if (!confirm(diff + "\nRemove this pack?")) return;
  } catch { if (!confirm(`Remove pack ${name}?`)) return; }
  changeRules({ remove_packs: [name] });
}

let packChange = null;
function packRequest() {
  const body = { enable: $("#pack-enable").checked, map: {} };
  const url = $("#pack-url").value.trim();
  if (url) body.url = url; else body.yaml = $("#pack-yaml").value;
  for (const i of document.querySelectorAll("#pack-map input")) if (i.value.trim()) body.map[i.dataset.name] = i.value.trim();
  return body;
}

$("#pack-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  packChange = null;
  $("#pack-preview").hidden = true;
  showError($("#pack-error"), null);
  try {
    const r = await api("/api/packs/preview", packRequest());
    if (r.placeholders && r.placeholders.length) {
      const have = Object.fromEntries([...document.querySelectorAll("#pack-map input")].map((i) => [i.dataset.name, i.value]));
      $("#pack-map").replaceChildren(el("p", { class: "muted small" }, "This pack sends some traffic to targets you choose. Map each placeholder to DIRECT, REJECT, or one of your proxies or groups, then preview again."),
        ...r.placeholders.map((ph) => el("label", { class: "pack" }, el("strong", {}, ph),
          el("input", { "data-name": ph.slice(1), list: "target-list", placeholder: "target", value: have[ph.slice(1)] || "" }))));
      return;
    }
    packChange = r.change;
    $("#pack-diff").textContent = r.diff;
    $("#pack-preview").hidden = false;
  } catch (err) { showError($("#pack-error"), err); }
});

$("#pack-apply").addEventListener("click", async () => {
  if (!packChange) return;
  if (await changeRules(packChange)) {
    packChange = null;
    $("#pack-preview").hidden = true;
    $("#pack-form").reset();
    $("#pack-map").replaceChildren();
  }
});

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
      el("td", {}, n.delay_ms ? `${n.delay_ms} ms` : "–"),
      el("td", {}, n.health ? el("span", { class: "state " + n.health }, n.health) : "–"))));
  } catch { /* ignore */ }
  loadHealth();
  loadGroups();
}

async function loadHealth() {
  let v;
  try { v = await api("/api/health"); } catch { return; }
  $("#health-overview").replaceChildren(...(v.overview || []).map((t) => el("p", { class: "verdict" }, t)));
  $("#health-table tbody").replaceChildren(...v.nodes.map((s) => el("tr", { onclick: () => showNodeHealth(s.node) },
    el("td", {}, s.node), el("td", {}, el("span", { class: "state " + s.state }, s.state)),
    el("td", {}, s.uptime_24h < 0 ? "–" : Math.round(s.uptime_24h * 100) + "%"),
    el("td", {}, s.avg_delay_ms ? s.avg_delay_ms + " ms" : "–"), el("td", { class: "wrap" }, s.reason || ""))));
  if (!v.nodes.length) $("#health-table tbody").append(el("tr", {}, el("td", { colspan: 5, class: "muted" }, "No checks yet; the first round runs shortly after start.")));
}

async function showNodeHealth(node) {
  const box = $("#health-detail");
  try {
    const nh = await api("/api/health/" + encodeURIComponent(node));
    box.replaceChildren(el("h2", { class: "spaced" }, `${node}: recent checks`),
      el("ul", { class: "events" }, nh.checks.slice(0, 30).map((c) => el("li", {}, el("time", {}, new Date(c.time).toLocaleString()),
        c.ok ? `ok, ${c.delay_ms} ms` : `FAILED (${c.kind}, ${c.stage}): ${c.detail}`))));
  } catch (e) { box.replaceChildren(el("p", { class: "error" }, e.message)); }
}

$("#health-check").addEventListener("click", async () => {
  const st = $("#health-status");
  st.textContent = "Checking…";
  try { await api("/api/health/check", {}); st.textContent = ""; } catch (e) { st.textContent = e.message; }
  loadHealth();
});

async function loadGroups() {
  let v;
  try { v = await api("/api/rules"); } catch { return; }
  const groups = v.set.groups || [];
  $("#groups").replaceChildren(...(groups.length ? groups.map((g) => el("div", { class: "pack" },
    el("strong", {}, g.name), el("span", { class: "muted" }, `${g.type} · ${g.members.join(", ")}`),
    el("button", { class: "link danger", onclick: () => confirm(`Remove group ${g.name}?`) && applyGroupChange({ remove_groups: [g.name] }) }, "remove")))
    : [el("p", { class: "muted" }, "No failover groups yet. A group switches between nodes automatically; use its name as a rule target.")]));
}

async function applyGroupChange(change) {
  try { await api("/api/rules/change", change); loadGroups(); return true; } catch (e) { alert(e.message); return false; }
}

let groupChange = null;
$("#group-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  showError($("#group-error"), null);
  $("#group-preview").hidden = true;
  const g = { name: $("#group-name").value.trim(), type: $("#group-type").value,
    members: $("#group-members").value.split(",").map((m) => m.trim()).filter(Boolean) };
  if ($("#group-tolerance").value) g.tolerance = Number($("#group-tolerance").value);
  if ($("#group-interval").value) g.interval = Number($("#group-interval").value);
  groupChange = { set_groups: [g] };
  try {
    $("#group-diff").textContent = (await api("/api/rules/preview", groupChange)).diff;
    $("#group-preview").hidden = false;
  } catch (err) { showError($("#group-error"), err); }
});
$("#group-apply").addEventListener("click", async () => {
  if (groupChange && await applyGroupChange(groupChange)) { groupChange = null; $("#group-preview").hidden = true; $("#group-form").reset(); }
});

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

// ---- servers ---------------------------------------------------------------

const pctBar = (v, warnAt = 85) => el("span", { class: "meter" + (v >= warnAt ? " hot" : ""), title: Math.round(v) + "%" },
  el("span", { class: "meter-fill", "data-w": Math.min(100, Math.round(v)) }));
function fillMeters(root) { for (const m of root.querySelectorAll(".meter-fill")) m.style.width = m.dataset.w + "%"; }
const fmtDur = (s) => s >= 86400 ? Math.floor(s / 86400) + " d" : s >= 3600 ? Math.floor(s / 3600) + " h" : Math.floor(s / 60) + " min";

async function loadMachines() {
  let ms;
  try { ms = await api("/api/vps/machines"); } catch (e) { $("#machines").replaceChildren(el("p", { class: "error" }, e.message)); return; }
  const box = $("#machines");
  if (!ms.length) { box.replaceChildren(el("p", { class: "muted" }, "No servers yet. Set one up below.")); return; }
  box.replaceChildren(...ms.map(machineCard));
  fillMeters(box);
}

function machineCard(m) {
  const l = m.last, mt = l && l.metrics;
  const state = l ? l.state : "unknown";
  const actions = [
    ["Check now", () => machineCheck(m)], ["Restart proxy", () => machineAction(m, "restart")], ["Update core", () => machineAction(m, "upgrade")],
    ["Rotate credentials", () => machineAction(m, "rotate")], ["Reboot", () => machineAction(m, "reboot")], ["Share…", () => machineShare(m)],
    ["Quota…", () => machineQuota(m)], ["Turn off password login", () => machineDisablePw(m)], ["Remove…", () => machineRemove(m)],
  ].map(([label, fn]) => el("button", { type: "button", class: "link", onclick: fn }, label));
  return el("div", { class: "machine" },
    el("div", { class: "machine-head" }, el("strong", {}, m.name), " ", el("span", { class: "muted" }, `${m.host}:${m.port}`), " ",
      el("span", { class: "state " + (state === "online" ? "healthy" : state === "degraded" ? "degraded" : "down") }, state),
      m.has_key ? null : el("span", { class: "warn-text small" }, " no stored key"),
      m.node_name ? el("span", { class: "muted small" }, ` · node ${m.node_name}`) : null),
    l && l.error ? el("p", { class: "error small" }, l.error) : null,
    ...(l && l.reasons || []).map((r) => el("p", { class: "warn-text small" }, "⚠ " + r)),
    mt ? el("dl", { class: "machine-metrics" },
      el("dt", {}, "CPU"), el("dd", {}, pctBar(mt.cpu_percent), ` ${Math.round(mt.cpu_percent)}%`),
      el("dt", {}, "Memory"), el("dd", {}, pctBar(mt.mem_used_percent), ` ${Math.round(mt.mem_used_percent)}% of ${mt.mem_total_mb} MB`),
      el("dt", {}, "Disk"), el("dd", {}, pctBar(mt.disk_used_percent, 90), ` ${Math.round(mt.disk_used_percent)}% of ${mt.disk_total_gb.toFixed(0)} GB`),
      el("dt", {}, "Load · uptime"), el("dd", {}, `${mt.load1.toFixed(2)} ${mt.load5.toFixed(2)} ${mt.load15.toFixed(2)} · ${fmtDur(mt.uptime_seconds)}`),
      el("dt", {}, "Network"), el("dd", {}, `↓ ${fmtBytes(mt.rx_bps)}/s  ↑ ${fmtBytes(mt.tx_bps)}/s`),
      el("dt", {}, "Traffic this period"), el("dd", {}, m.quota.gb ? [pctBar(m.quota_percent), ` ${m.traffic_used_gb.toFixed(1)} of ${m.quota.gb} GB`] : `${m.traffic_used_gb.toFixed(1)} GB (no allowance set)`),
      el("dt", {}, "Proxy service"), el("dd", {}, `${mt.service_active ? "running" : "NOT running"}${mt.service_version ? " · sing-box " + mt.service_version : ""}${mt.listening && mt.listening.length ? " · ports " + mt.listening.join(", ") : ""}`),
      ...(mt.certs || []).flatMap((c) => [el("dt", {}, "Certificate"), el("dd", {}, `${c.path} expires ${new Date(c.expires).toLocaleDateString()}`)]),
    ) : el("p", { class: "muted small" }, l ? "" : "Not checked yet."),
    l ? el("p", { class: "muted small" }, "Checked " + fmtTime(l.time)) : null,
    el("div", { class: "machine-actions" }, actions));
}

const panel = () => $("#machine-panel");
function showPanel(...children) { panel().hidden = false; panel().replaceChildren(...children.filter((c) => c !== null && c !== undefined), el("p", {}, el("button", { class: "link", type: "button", onclick: () => { panel().hidden = true; } }, "Close"))); panel().scrollIntoView({ block: "nearest" }); }

async function machineCheck(m) {
  showPanel(el("p", {}, `Checking ${m.name}…`));
  try { await api(`/api/vps/machines/${m.id}/check`, {}); panel().hidden = true; } catch (e) { showPanel(el("p", { class: "error" }, e.message)); }
  loadMachines();
}

function planView(prev) {
  return [
    prev.blocked && prev.blocked.length ? el("div", { class: "verdict" }, ...prev.blocked.map((b) => el("p", { class: "error" }, "✗ " + b))) : null,
    el("ol", { class: "plan" }, prev.steps.map((s) => el("li", {}, el("strong", {}, s.title), el("div", { class: "muted small" }, s.why),
      el("pre", { class: "mono" }, "$ " + s.cmd + (s.file ? `\n\n# writes ${s.file}:\n${s.body}` : ""))))),
  ];
}

async function machineAction(m, kind) {
  showPanel(el("p", {}, "Connecting to preview…"));
  let prev;
  try { prev = await api(`/api/vps/machines/${m.id}/preview`, { kind }); } catch (e) { showPanel(el("p", { class: "error" }, e.message)); return; }
  const runBtn = el("button", { class: "primary", type: "button", disabled: prev.blocked.length ? "" : null, onclick: async () => {
    runBtn.disabled = true;
    try { const { job_id } = await api(`/api/vps/machines/${m.id}/run`, { plan_id: prev.plan_id }); followJob(job_id, loadMachines); } catch (e) { showPanel(el("p", { class: "error" }, e.message)); }
  } }, `Run: ${kind}`);
  showPanel(el("h2", {}, `${kind} on ${m.name}`), el("p", { class: "muted" }, "This is exactly what will run on the server."), ...planView(prev), runBtn);
}

async function followJob(id, done) {
  const log = el("pre", { class: "mono log" }), status = el("p", {});
  showPanel(status, log);
  for (;;) {
    let j;
    try { j = await api("/api/vps/jobs/" + id); } catch (e) { status.textContent = e.message; return; }
    log.textContent = j.log.map((l) => l.text).join("\n");
    log.scrollTop = log.scrollHeight;
    status.textContent = j.done ? (j.error ? "Failed: " + j.error : "Done.") : `Step ${j.step + 1} of ${j.steps}: ${j.current}`;
    status.className = j.error ? "error" : "";
    if (j.done) {
      if (j.outcome) {
        const o = j.outcome;
        panel().insertBefore(el("div", { class: "verdict" },
          o.node ? el("p", {}, `Node “${o.node}” imported${o.latency_ms ? `; ${o.latency_ms} ms end to end through it` : ""}.`) : null,
          o.egress_ip ? el("p", {}, `Traffic leaves from ${o.egress_ip}; DNS on the server ${o.dns_ok ? "works" : "FAILED"}.`) : null,
          ...(o.notes || []).map((n) => el("p", {}, "• " + n))), log);
      }
      if (done) done();
      return;
    }
    await new Promise((r) => setTimeout(r, 800));
  }
}

async function machineShare(m) {
  try {
    const s = await api(`/api/vps/machines/${m.id}/share`);
    showPanel(el("h2", {}, `Share ${m.node_name || m.name}`), el("p", { class: "warn-text" }, "These contain the node's credentials. Anyone with them can use your server."),
      el("img", { src: "data:image/png;base64," + s.qr_png, width: 240, height: 240, alt: "QR code of the share link" }),
      el("h2", { class: "spaced" }, "Share link"), el("pre", { class: "mono wrap" }, s.link),
      el("h2", { class: "spaced" }, "Subscription (base64)"), el("pre", { class: "mono wrap" }, s.subscription),
      el("p", { class: "muted small" }, "To invalidate these, rotate the server's credentials."));
  } catch (e) { showPanel(el("p", { class: "error" }, e.message)); }
}

function machineQuota(m) {
  const gb = el("input", { type: "number", min: 0, value: m.quota.gb || "", placeholder: "GB per month" });
  const day = el("input", { type: "number", min: 1, max: 28, value: m.quota.reset_day || 1, placeholder: "reset day" });
  showPanel(el("h2", {}, `Traffic allowance for ${m.name}`), el("div", { class: "toolbar" }, gb, day,
    el("button", { class: "primary", type: "button", onclick: async () => {
      try { await api(`/api/vps/machines/${m.id}/quota`, { gb: Number(gb.value) || 0, reset_day: Number(day.value) || 1 }); panel().hidden = true; loadMachines(); } catch (e) { alert(e.message); }
    } }, "Save")));
}

async function machineDisablePw(m) {
  if (!confirm(`Turn off SSH password login on ${m.name}? Only this Mac's key will work afterwards.`)) return;
  try { const r = await api(`/api/vps/machines/${m.id}/disable-password`, { confirm: true }); showPanel(el("p", {}, r.result)); } catch (e) { showPanel(el("p", { class: "error" }, e.message)); }
}

function machineRemove(m) {
  const un = el("input", { type: "checkbox" });
  showPanel(el("h2", {}, `Remove ${m.name}`), el("p", {}, "Forgets this server, its stored key, and its imported node on this Mac."),
    el("label", { class: "muted" }, un, " Also remove the proxy from the server"),
    el("p", {}, el("button", { class: "primary danger-btn", type: "button", onclick: async () => {
      try { await api(`/api/vps/machines/${m.id}/remove`, { confirm: true, uninstall: un.checked }); panel().hidden = true; loadMachines(); } catch (e) { showPanel(el("p", { class: "error" }, e.message)); }
    } }, "Remove")));
}

let vpsPlan = null;
$("#vps-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("#vps-error"), out = $("#vps-plan");
  showError(err, null); out.hidden = true; $("#vps-log").hidden = true; vpsPlan = null;
  const body = { host: $("#vps-host").value.trim(), password: $("#vps-password").value, name: $("#vps-name").value.trim(),
    port: Number($("#vps-ssh-port").value) || 0, node_port: Number($("#vps-node-port").value) || 0, sni: $("#vps-sni").value.trim(), sha256: $("#vps-sha").value.trim(), mode: $("#vps-mode").value };
  out.hidden = false; out.replaceChildren(el("p", {}, "Connecting and checking the server (read-only)…"));
  try { vpsPlan = await api("/api/vps/preflight", body); } catch (x) { out.hidden = true; showError(err, x); return; }
  const r = vpsPlan.report;
  const confirmBox = el("input", { type: "checkbox" });
  const run = el("button", { class: "primary", type: "button", disabled: "", onclick: async () => {
    run.disabled = true;
    try {
      const { job_id } = await api("/api/vps/setup", { plan_id: vpsPlan.plan_id, host_key: vpsPlan.host_key });
      $("#vps-password").value = "";
      const log = $("#vps-log"); log.hidden = false;
      for (;;) {
        const j = await api("/api/vps/jobs/" + job_id);
        log.textContent = j.log.map((l) => l.text).join("\n"); log.scrollTop = log.scrollHeight;
        if (j.done) {
          out.replaceChildren(j.error ? el("p", { class: "error" }, "Failed: " + j.error) : el("div", { class: "verdict" },
            j.outcome && j.outcome.node ? el("p", {}, `Node “${j.outcome.node}” is imported${j.outcome.latency_ms ? ` and answers in ${j.outcome.latency_ms} ms end to end` : ""}.`) : null,
            ...((j.outcome && j.outcome.notes) || []).map((n) => el("p", {}, "• " + n))));
          loadMachines();
          return;
        }
        out.replaceChildren(el("p", {}, `Step ${j.step + 1} of ${j.steps}: ${j.current}`));
        await new Promise((res) => setTimeout(res, 800));
      }
    } catch (x) { showError(err, x); run.disabled = false; }
  } }, "Run setup");
  confirmBox.addEventListener("change", () => { run.disabled = !confirmBox.checked || vpsPlan.blocked.length > 0; });
  out.replaceChildren(
    el("p", {}, `${r.os || "Unknown OS"} · ${r.arch} · ${r.mem_mb} MB memory · ${r.disk_free_mb} MB free · mode: `, el("strong", {}, vpsPlan.mode)),
    el("ul", { class: "events" }, (r.issues || []).map((i) => el("li", { class: i.severity === "error" ? "error" : i.severity === "warning" ? "warn-text" : "" }, `${{ error: "✗", warning: "!", info: "·" }[i.severity]} ${i.message}`))),
    ...planView(vpsPlan),
    el("div", { class: "verdict" }, el("p", {}, "The server's SSH fingerprint is ", el("code", {}, vpsPlan.host_key), ". Compare it with your provider's console if it shows one; a mismatch means you aren't talking to your server."),
      el("label", {}, confirmBox, " The fingerprint is right and I want to run this plan")),
    run);
});

// Import nodes
let importPrev = null;
$("#import-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("#import-error"), out = $("#import-preview");
  showError(err, null); out.hidden = true; importPrev = null;
  const body = {};
  const file = $("#import-image").files[0];
  if (file) body.image = await new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(r.result); r.onerror = rej; r.readAsDataURL(file); });
  else body.text = $("#import-text").value;
  try { importPrev = await api("/api/vps/import", body); } catch (x) { showError(err, x); return; }
  out.hidden = false;
  out.replaceChildren(
    ...importPrev.errors.map((m) => el("p", { class: "warn-text small" }, "Skipped: " + m)),
    el("table", {}, el("tbody", {}, importPrev.nodes.map((n) => el("tr", {}, el("td", {}, n.name), el("td", {}, n.type), el("td", { class: "mono" }, `${n.server}:${n.port}`),
      el("td", {}, n.insecure ? el("span", { class: "warn-text" }, "certificate checks OFF") : ""))))),
    importPrev.nodes.length ? el("p", {}, el("button", { class: "primary", type: "button", onclick: async () => {
      try { const r = await api("/api/vps/import/apply", { import_id: importPrev.import_id }); out.replaceChildren(el("p", {}, "Imported: " + r.imported.join(", ") + (r.warning ? ". " + r.warning : ""))); $("#import-form").reset(); } catch (x) { showError(err, x); }
    } }, `Import ${importPrev.nodes.length} node${importPrev.nodes.length === 1 ? "" : "s"}`)) : null);
});

// ---- traffic ---------------------------------------------------------------

const SVGNS = "http://www.w3.org/2000/svg";
function svg(tag, attrs = {}, ...children) {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v);
  }
  for (const c of children.flat()) if (c !== null && c !== undefined) e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return e;
}

const fmtRate = (bps) => fmtBytes(Math.round(bps)) + "/s";
const trInputs = ["#tr-view", "#tr-mode", "#tr-range", "#tr-proto", "#tr-routing", "#tr-process", "#tr-iface", "#tr-rule", "#tr-node"];

function trQuery(extra = {}) {
  const f = {
    view: $("#tr-view").value, mode: $("#tr-mode").value, proto: $("#tr-proto").value, routing: $("#tr-routing").value,
    process: $("#tr-process").value.trim(), iface: $("#tr-iface").value.trim(), rule: $("#tr-rule").value.trim(), node: $("#tr-node").value.trim(),
    ...extra,
  };
  if (f.mode === "history") f.range = $("#tr-range").value;
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(f)) if (v) p.set(k, v);
  return p.toString();
}

for (const sel of trInputs) {
  $(sel).addEventListener(sel.endsWith("view") || sel.includes("mode") || sel.includes("range") || sel.includes("proto") || sel.includes("routing") ? "change" : "input", () => {
    $("#tr-range").hidden = $("#tr-mode").value !== "history";
    loadTraffic();
  });
}
$("#tr-clear").addEventListener("click", () => {
  for (const sel of ["#tr-proto", "#tr-routing", "#tr-process", "#tr-iface", "#tr-rule", "#tr-node"]) $(sel).value = "";
  loadTraffic();
});
$("#tr-forget").addEventListener("click", async () => {
  if (!confirm("Delete all stored traffic history for this instance?")) return;
  try { await api("/api/traffic/clear", {}); } catch (e) { alert(e.message); }
  loadTraffic();
});

// Clicking a box filters by what it stands for.
function filterFromNode(n) {
  if (n.label.startsWith("other (")) return;
  const set = (sel, v) => { $(sel).value = v; };
  switch (n.layer) {
    case "process": set("#tr-process", n.label); break;
    case "protocol": set("#tr-proto", n.label.startsWith("Unix") ? "unix" : n.label.split(/[ /]/)[0].toLowerCase()); break;
    case "tunnel": case "nic": if (n.label !== "not captured") set("#tr-iface", n.label); break;
    case "rule": set("#tr-rule", n.label.includes(" ") ? n.label.split(" ").slice(1).join(" ") : n.label); break;
    case "node": set("#tr-node", n.label.includes(" → ") ? n.label.split(" → ").pop() : n.label); break;
    default: return;
  }
  loadTraffic();
}

function drawSankey(box, data) {
  const layers = data.layers.filter((l) => data.nodes.some((n) => n.layer === l));
  if (!data.nodes.length) {
    box.replaceChildren(el("p", { class: "muted" }, "No flows match these filters."));
    return;
  }
  const W = Math.max(box.clientWidth, 900), H = 480, top = 24, nodeW = 14, gap = 8, labelW = 190;
  const stepX = layers.length > 1 ? (W - labelW - nodeW) / (layers.length - 1) : 0;

  const byId = new Map(data.nodes.map((n) => [n.id, { ...n, in: 0, out: 0, outLinks: [], inLinks: [] }]));
  for (const l of data.links) {
    const a = byId.get(l.source), b = byId.get(l.target);
    if (!a || !b) continue;
    a.out += l.value; b.in += l.value;
    const link = { ...l, a, b };
    a.outLinks.push(link); b.inLinks.push(link);
  }
  const cols = layers.map((l) => [...byId.values()].filter((n) => n.layer === l));
  for (const n of byId.values()) n.value = Math.max(n.in, n.out, 1);

  const ky = Math.min(...cols.map((c) => (H - top - gap * (c.length - 1)) / c.reduce((s, n) => s + n.value, 0)));
  cols.forEach((col, i) => {
    let y = top;
    for (const n of col) {
      n.x = i * stepX; n.y = y; n.h = Math.max(n.value * ky, 6);
      y += n.h + gap;
    }
  });
  for (const n of byId.values()) {
    n.outLinks.sort((p, q) => p.b.y - q.b.y);
    n.inLinks.sort((p, q) => p.a.y - q.a.y);
    let oy = n.y, iy = n.y;
    for (const l of n.outLinks) { l.w = Math.max(l.value * ky, 2); l.y0 = oy + l.w / 2; oy += l.w; }
    for (const l of n.inLinks) { l.w = Math.max(l.value * ky, 2); l.y1 = iy + l.w / 2; iy += l.w; }
  }

  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Traffic flow diagram" });
  layers.forEach((l, i) => root.append(svg("text", { class: "layer-title", x: i * stepX, y: 12 }, l)));
  for (const n of byId.values()) for (const l of n.outLinks) {
    const x0 = l.a.x + nodeW, x1 = l.b.x, xm = (x0 + x1) / 2;
    root.append(svg("path", { class: "link" + (l.a.alert && l.b.alert ? " alert" : ""), d: `M${x0},${l.y0} C${xm},${l.y0} ${xm},${l.y1} ${x1},${l.y1}`, "stroke-width": l.w },
      svg("title", {}, `${l.a.label} → ${l.b.label}\n${l.flows} flow${l.flows === 1 ? "" : "s"}, ${fmtBytes(l.value)}`)));
  }
  for (const n of byId.values()) {
    root.append(svg("g", { class: "node" + (n.alert ? " alert" : ""), onclick: () => filterFromNode(n) },
      svg("rect", { x: n.x, y: n.y, width: nodeW, height: n.h }),
      svg("text", { x: n.x + nodeW + 4, y: n.y + Math.min(n.h / 2, 14) + 4 }, n.label.length > 30 ? n.label.slice(0, 29) + "…" : n.label),
      svg("title", {}, `${n.label}\n${n.flows} flow${n.flows === 1 ? "" : "s"}, ${fmtBytes(n.bytes)}${n.alert ? "\n⚠ has a surprise on its path" : ""}`)));
  }
  box.replaceChildren(root);
}

const ANOMALY_TITLE = {
  "bypassed-tun": "Bypassed TUN",
  "other-vpn": "Through another VPN",
  "wrong-nic": "Wrong NIC",
};

async function loadTraffic() {
  let v;
  try { v = await api("/api/traffic?" + trQuery()); } catch (e) {
    $("#tr-sankey").replaceChildren(el("p", { class: "error" }, e.message));
    return;
  }
  drawSankey($("#tr-sankey"), v.sankey);
  const warn = $("#tr-warnings");
  warn.hidden = !(v.warnings && v.warnings.length);
  warn.textContent = (v.warnings || []).join(" · ");
  $("#tr-summary").textContent = `${v.flows} flow${v.flows === 1 ? "" : "s"}` +
    (v.mode === "live" ? ", updated " + fmtTime(v.updated) : "") +
    (v.tun ? ` · TUN ${v.tun}` : " · not in TUN mode: only traffic that reaches the proxy port is attributed to rules");

  $("#tr-anomalies-card").hidden = !v.anomalies.length;
  $("#tr-anomalies").replaceChildren(...v.anomalies.map((a) => el("li", {}, el("strong", {}, ANOMALY_TITLE[a.kind] || a.kind), `: ${a.process} → ${a.remote}. ${a.detail}`)));

  $("#tr-proc-table tbody").replaceChildren(...v.processes.map((p) => el("tr", { onclick: () => { $("#tr-process").value = p.name; loadTraffic(); } },
    el("td", {}, p.name), el("td", {}, p.flows), el("td", {}, p.tcp), el("td", {}, p.udp), el("td", {}, p.unix),
    el("td", {}, fmtBytes(p.upload)), el("td", {}, fmtBytes(p.download)),
    el("td", {}, el("span", { class: "bar", "data-w": Math.round(p.proxied_share * 100) }), ` ${Math.round(p.proxied_share * 100)}%`))));
  for (const b of document.querySelectorAll("#tr-proc-table .bar")) b.style.width = Math.max(1, Number(b.dataset.w) * 0.6) + "px";

  loadTrafficFlows();
  loadTrafficIfaces();
}

let trSelected = null;
async function loadTrafficFlows() {
  let flows;
  try { flows = await api("/api/traffic/flows?limit=100&" + trQuery()); } catch { return; }
  const path = (f) => [f.ingress, f.rule && (f.rule + (f.rule_payload ? " " + f.rule_payload : "")), f.node && (f.group && f.group !== f.node ? f.group + " → " + f.node : f.node), f.egress]
    .filter(Boolean).join(" → ") || (f.internal ? "local IPC" : "–");
  $("#tr-flow-table tbody").replaceChildren(...flows.map((f) => el("tr", { class: f.id === trSelected ? "active" : "", onclick: () => { trSelected = f.id; showFlow(f); loadTrafficFlows(); } },
    el("td", {}, (f.process.name || "?") + (f.process.pid ? ` (${f.process.pid})` : "")),
    el("td", {}, f.proto + (f.app ? "/" + f.app : "") + (f.family && f.family !== "unix" ? " · " + f.family : "")),
    el("td", { class: "mono wrap" }, path(f), f.anomalies && f.anomalies.length ? el("span", { class: "warn-text", title: f.anomalies.map((a) => a.detail).join("\n") }, " ⚠") : null),
    el("td", { class: "mono wrap" }, f.host ? `${f.host} (${f.remote})` : f.remote || f.local || "–"),
    el("td", {}, f.bytes_unknown ? "–" : fmtBytes(f.upload + f.download)))));
  if (!flows.length) $("#tr-flow-table tbody").append(el("tr", {}, el("td", { colspan: 5, class: "muted" }, "No flows.")));
}

function showFlow(f) {
  const p = f.process;
  const rows = [
    ["Process", `${p.name}${p.pid ? " · pid " + p.pid : ""}`], ["Executable", p.path], ["App bundle", p.bundle && `${p.bundle}${p.bundle_id ? " (" + p.bundle_id + ")" : ""}`],
    ["Parent", p.parent_name && `${p.parent_name} · pid ${p.parent_pid}`], ["Signed by", p.signature],
    ["Socket", `${f.proto}${f.app ? "/" + f.app : ""} ${f.family} ${f.local || ""}${f.remote ? " → " + f.remote : ""}${f.state ? " [" + f.state + "]" : ""}`],
    ["Captured by", f.ingress || (f.entered_tun ? "TUN" : "not captured")], ["Rule", f.rule && `${f.rule} ${f.rule_payload || ""}`],
    ["Node", f.node && (f.group ? `${f.group} → ${f.node}` : f.node)], ["Leaves via", f.egress && `${f.egress}${f.next_hop ? " (next hop " + f.next_hop + ")" : ""}`],
    ["Traffic", f.bytes_unknown ? "unknown (seen only in the socket table)" : `${fmtBytes(f.upload)} up · ${fmtBytes(f.download)} down`],
  ].filter((r) => r[1]);
  const box = $("#tr-flow-detail");
  box.replaceChildren(
    el("dl", {}, rows.flatMap(([k, v]) => [el("dt", {}, k), el("dd", { class: "mono wrap" }, v)])),
    ...(f.anomalies || []).map((a) => el("p", { class: "warn-text" }, `⚠ ${ANOMALY_TITLE[a.kind] || a.kind}: ${a.detail}`)),
    f.id.startsWith("conn-") ? el("p", {}, el("button", { class: "link", onclick: () => openDiagnostics(f.id.slice(5)) }, "Open in Connections: why did this go here?")) : null);
}

function openDiagnostics(id) {
  selectedConn = id;
  document.querySelector('nav button[data-tab="connections"]').click();
}

async function loadTrafficIfaces() {
  let v;
  try { v = await api("/api/traffic/interfaces?window=1m"); } catch { return; }
  $("#tr-iface-table tbody").replaceChildren(...v.interfaces.map((i) => el("tr", { onclick: () => { $("#tr-iface").value = i.name; loadTraffic(); } },
    el("td", { class: "mono" }, i.name), el("td", {}, i.role), el("td", {}, i.up ? "up" : "down"),
    el("td", {}, i.rate ? fmtRate(i.rate.in_bps) : "–"), el("td", {}, i.rate ? fmtRate(i.rate.out_bps) : "–"),
    el("td", {}, i.rate ? `${i.rate.errors} / ${i.rate.drops}` : "–"),
    el("td", { class: "mono wrap" }, (i.route_list || []).slice(0, 6).join(", ") + (i.routes > 6 ? ` … (${i.routes} routes)` : ""))
  )));
  const r = v.reconcile;
  $("#tr-reconcile").replaceChildren(
    r.tun ? el("dl", {},
      el("dt", {}, `Into ${r.tun} (apps → TUN)`), el("dd", {}, fmtBytes(r.tun_up)),
      el("dt", {}, `Out of ${(r.nics || []).join(", ") || "NICs"}`), el("dd", {}, fmtBytes(r.nic_up)),
      el("dt", {}, "Upstream gap"), el("dd", {}, (r.gap_up >= 0 ? "+" : "−") + fmtBytes(Math.abs(r.gap_up))),
      el("dt", {}, "Downstream gap"), el("dd", {}, (r.gap_down >= 0 ? "+" : "−") + fmtBytes(Math.abs(r.gap_down)))) : null,
    el("ul", { class: "events" }, (r.notes || []).map((n) => el("li", {}, n))));
}

// ---- refresh loop ----------------------------------------------------------

function refresh() {
  loadStatus();
  loadProposals();
  if (currentTab === "connections") { loadConnections(); if (selectedConn) loadDetail(); }
  if (currentTab === "rules") { loadRules(); loadTargets(); updateValueHints(); }
  if (currentTab === "network") { loadNetwork(); loadInstances(); }
  if (currentTab === "traffic") loadTraffic();
  if (currentTab === "servers") loadMachines();
}

refresh();
setInterval(() => {
  if (document.hidden) return;
  loadStatus();
  loadProposals();
  if (currentTab === "connections") loadConnections();
  if (currentTab === "traffic" && $("#tr-mode").value === "live") loadTraffic();
  if (currentTab === "servers" && panel().hidden) loadMachines();
}, 2000);
