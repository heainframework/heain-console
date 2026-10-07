// heain-console screens (Step 5b). Plain JS, no build, no inline script:
// every text goes in with textContent, never as HTML.
"use strict";

const CORE = "/api/heain-console/v1/core/";
const REPORT = "/api/heain-report/v1/";
const $ = (id) => document.getElementById(id);
const state = { me: null, whoami: null, node: "", tab: "overview" };

// ---- small DOM helpers ----
function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null && v !== false) e.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) {
    if (k === null || k === undefined || k === false) continue;
    e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return e;
}
function text(v) {
  if (v === null || v === undefined || v === "") return "–";
  if (typeof v === "object") return JSON.stringify(v);
  if (typeof v === "boolean") return v ? "yes" : "no";
  return String(v);
}
function get(o, path) { return path.split(".").reduce((x, k) => (x == null ? undefined : x[k]), o); }
function table(rows, cols, empty) {
  if (!rows || rows.length === 0) return el("p", { class: "muted" }, empty || "None.");
  return el("table", {},
    el("thead", {}, el("tr", {}, cols.map((c) => el("th", {}, c[0])))),
    el("tbody", {}, rows.map((r) => el("tr", {}, cols.map((c) => {
      const v = typeof c[1] === "function" ? c[1](r) : get(r, c[1]);
      return el("td", { class: typeof v === "number" ? "num" : "" }, v instanceof Node ? v : text(v));
    })))));
}
function say(msg, kind) { const s = $("status"); s.textContent = msg || ""; s.className = "msg " + (kind || ""); }
function cookie(name) {
  for (const c of document.cookie.split(";")) { const [k, v] = c.trim().split("="); if (k === name) return decodeURIComponent(v || ""); }
  return "";
}

// ---- requests (same origin: heain-gateway) ----
async function call(method, url, body) {
  const h = { "Accept": "application/json" };
  if (body !== undefined) h["Content-Type"] = "application/json";
  if (method !== "GET") h["X-CSRF-Token"] = cookie("heain_csrf");
  let r;
  try {
    r = await fetch(url, { method, headers: h, credentials: "same-origin", body: body === undefined ? undefined : JSON.stringify(body) });
  } catch (e) { return { ok: false, status: 0, data: { error: { code: "unreachable", message: "the gateway did not answer" } } }; }
  let data = null;
  try { data = await r.json(); } catch (e) { data = null; }
  // the gateway's own "no session" (not core refusing the person, e.g. MFA)
  if (r.status === 401 && data && data.error && data.error.code === "unauthenticated" && url.startsWith("/api/")) { showLogin("Your session has ended. Sign in again."); }
  return { ok: r.ok, status: r.status, data };
}
function errText(res) {
  const e = res.data && res.data.error;
  return e ? `${res.status} ${e.code || ""}: ${e.message || ""}` : `${res.status}`;
}
// core runs on the chosen node (remote admin through the Master)
function core(method, path, body) {
  const p = state.node ? `nodes/${encodeURIComponent(state.node)}/admin/${path}` : path;
  return call(method, CORE + p, body);
}

// ---- sign-in ----
function showLogin(msg) {
  $("top").hidden = true; $("view").hidden = true; $("login").hidden = false;
  $("login-msg").textContent = msg || "";
}
async function login(ev) {
  ev.preventDefault();
  const f = ev.target;
  const body = { username: f.username.value, password: f.password.value, client: "web" };
  if (f.totp.value) body.totp = f.totp.value;
  if (f.new_password.value) body.new_password = f.new_password.value;
  const res = await call("POST", "/auth/login", body);
  if (!res.ok) {
    const code = res.data && res.data.error && res.data.error.code;
    if (code === "password_change_required") $("newpw").hidden = false;
    $("login-msg").textContent = errText(res);
    $("login-msg").className = "msg bad";
    return;
  }
  f.password.value = ""; f.totp.value = ""; f.new_password.value = "";
  start();
}
async function logout() {
  await call("POST", "/auth/logout", {});
  state.me = null;
  showLogin("Signed out.");
}

// ---- the frame ----
const TABS = [
  ["overview", "Overview", overview],
  ["approvals", "Approvals", approvals],
  ["config", "Config", config],
  ["apps", "Apps", appsView],
  ["rollouts", "Rollouts", rollouts],
  ["audit", "Audit", auditView],
  ["reports", "Reports", reports],
];
async function start() {
  const me = await call("GET", "/auth/me");
  if (!me.ok) { showLogin(""); return; }
  state.me = me.data;
  $("login").hidden = true; $("top").hidden = false; $("view").hidden = false;
  const who = await call("GET", CORE + "whoami");
  state.whoami = who.ok ? who.data : null;
  $("who").textContent = `${state.me.name || state.me.user} (user:${state.me.user})` + (state.whoami ? " · " + (state.whoami.roles || []).join(", ") + (state.whoami.approver ? ", approver" : "") : "");
  if (!who.ok) say("Core refused this account: " + errText(who) + ". An admin adds user:" + state.me.user + " to roles.admins (through P5).", "bad");
  await loadNodes();
  tabs();
  show(state.tab);
}
async function loadNodes() {
  const sel = $("node");
  sel.replaceChildren(el("option", { value: "" }, "this node"));
  const res = await call("GET", CORE + "nodes");
  if (res.ok && res.data && res.data.nodes) {
    for (const n of res.data.nodes) if (n.depth > 0) sel.append(el("option", { value: n.node }, n.node + " (depth " + n.depth + ")"));
  }
  sel.value = state.node;
}
function tabs() {
  const nav = $("tabs");
  nav.replaceChildren(...TABS.map(([id, label]) => el("button", { class: id === state.tab ? "on" : "", onclick: () => show(id) }, label)));
}
async function show(id) {
  state.tab = id;
  tabs();
  say("");
  const v = $("view");
  v.replaceChildren(el("p", { class: "muted" }, "Loading…"));
  const t = TABS.find((x) => x[0] === id);
  try { v.replaceChildren(...[].concat(await t[2]())); } catch (e) { v.replaceChildren(el("p", { class: "msg bad" }, "Error: " + e.message)); }
}
function refresh() { show(state.tab); }
function refusal(res) { return el("p", { class: "msg bad" }, "Core refused: " + errText(res)); }

// ---- screens ----
async function overview() {
  const [nodes, alerts, who, lic] = await Promise.all([call("GET", CORE + "nodes"), core("GET", "alerts"), core("GET", "whoami"), core("GET", "license")]);
  const out = [el("h1", {}, "Overview" + (state.node ? " — " + state.node : ""))];
  if (lic.ok) {
    const L = lic.data, t = L.license || {};
    const bad = L.restricted || L.state === "expired", warn = L.state === "warning" || L.state === "grace" || L.state === "unlicensed";
    out.push(el("p", { class: "msg " + (bad ? "bad" : warn ? "" : "good") },
      `License: ${L.state}` + (t.id ? ` — ${t.id}, ${t.licensee}, until ${String(t.expires).slice(0, 10)} (${L.days_left} days)` : "") +
      ` · ceilings ${L.ceilings.max_nodes} nodes, depth ${L.ceilings.max_depth}` + (L.restricted ? ` · RESTRICTED: ${L.reason}` : "") +
      (L.enforced === false ? " · development build (not enforced)" : "")));
  }
  if (who.ok) out.push(el("div", { class: "card kv" },
    el("span", { class: "muted" }, "node"), el("span", {}, text(who.data.node)),
    el("span", { class: "muted" }, "identity"), el("span", {}, text(who.data.identity)),
    el("span", { class: "muted" }, "roles"), el("span", {}, (who.data.roles || []).join(", ") || "–"),
    el("span", { class: "muted" }, "approver"), el("span", {}, text(who.data.approver)),
    el("span", { class: "muted" }, "relayed by"), el("span", {}, text(who.data.via_console) + (who.data.forwarded_by ? " · forwarded by " + who.data.forwarded_by : ""))));
  else out.push(refusal(who));
  out.push(el("h2", {}, "Fleet"));
  out.push(nodes.ok ? table(nodes.data.nodes, [["node", "node"], ["depth", "depth"], ["parent", "parent"], ["core", "core_version"], ["config", "config_version"],
    ["leader", "leader"], ["P5 waiting", "p5_waiting"], ["report age (s)", "age_seconds"]]) : refusal(nodes));
  out.push(el("h2", {}, "Active alerts"));
  out.push(alerts.ok ? table(alerts.data.alerts, [["since", "since"], ["severity", "severity"], ["rule", "rule"], ["node", "node"], ["message", "message"]], "No active alert.") : refusal(alerts));
  return out;
}

async function approvals() {
  const res = await core("GET", "policy/pending");
  const out = [el("h1", {}, "Approvals"), el("p", { class: "muted" }, "Items waiting for an Approver. Core never lets the proposer decide its own item (four-eyes).")];
  if (!res.ok) return out.concat(refusal(res));
  const reason = el("input", { placeholder: "reason (optional)", size: 40 });
  out.push(el("div", { class: "row" }, reason));
  const decide = (id, verb) => async () => {
    const r = await core("POST", `policy/${encodeURIComponent(id)}/${verb}`, reason.value ? { reason: reason.value } : {});
    if (r.ok) { refresh(); say(`${id}: ${r.data.result || verb}`, "good"); } else say(`${id}: ${errText(r)}`, "bad");
  };
  out.push(table(res.data.actions, [["id", "ID"], ["type", "Type"], ["category", "Category"], ["proposed by", "ProposedBy"], ["status", "Status"],
    ["detail", (a) => el("code", {}, text(a.Data || a.Detail || a.Value))],
    ["", (a) => el("span", { class: "row" }, el("button", { onclick: decide(a.ID, "approve") }, "Approve"), el("button", { class: "bad", onclick: decide(a.ID, "reject") }, "Reject"))]],
    "Nothing is waiting."));
  return out;
}

async function config() {
  const [res, hist] = await Promise.all([core("GET", "config"), core("GET", "config/history?limit=20")]);
  const out = [el("h1", {}, "Config" + (state.node ? " — " + state.node : ""))];
  if (!res.ok) return out.concat(refusal(res));
  const fields = res.data.fields || [];
  const filter = el("input", { placeholder: "filter keys", size: 30 });
  const box = el("div");
  const draw = () => {
    const q = filter.value.toLowerCase();
    box.replaceChildren(table(fields.filter((f) => f.key.toLowerCase().includes(q)), [["key", "key"], ["part", (f) => f.part === "system" ? "2a system" : "2b policy"],
      ["value", (f) => el("code", {}, text(f.value))], ["origin", "origin"], ["locked", "locked"], ["by", "updated_by"]]));
  };
  filter.addEventListener("input", draw);
  draw();
  const key = el("input", { list: "keys", placeholder: "key", size: 32, required: true });
  const val = el("textarea", { placeholder: 'value: JSON, e.g. "7s" or {"a":1}' });
  const why = el("input", { placeholder: "reason (2b)", size: 40 });
  const dl = el("datalist", { id: "keys" }, fields.map((f) => el("option", { value: f.key })));
  const submit = async (ev) => {
    ev.preventDefault();
    const f = fields.find((x) => x.key === key.value);
    if (!f) { say("No such key on this node.", "bad"); return; }
    let v;
    try { v = JSON.parse(val.value); } catch (e) { v = val.value; }
    const r = f.part === "system"
      ? await core("PUT", `config/system/${encodeURIComponent(f.key)}`, { value: v })
      : await core("POST", `config/policy/${encodeURIComponent(f.key)}`, { value: v, reason: why.value });
    if (r.ok) { say(f.part === "system" ? `${f.key}: applied` : `${f.key}: proposed to P5 (${r.data.action_id || ""})`, "good"); }
    else say(`${f.key}: ${errText(r)}`, "bad");
  };
  out.push(el("form", { class: "card", onsubmit: submit }, el("strong", {}, "Change a key"),
    el("p", { class: "muted" }, "A system key (2a) is applied at once; a policy key (2b) is proposed to P5 and waits for an Approver."), key, dl, val, why, el("div", { class: "row" }, el("button", { type: "submit" }, "Submit"))));
  out.push(el("div", { class: "row" }, filter), box);
  out.push(el("h2", {}, "History"));
  const hl = hist.ok ? (Array.isArray(hist.data) ? hist.data : (hist.data.history || hist.data.versions || [])) : [];
  out.push(hist.ok ? table(hl, [["version", (h) => h.version ?? h.n], ["at", "at"], ["by", "by"], ["comment", "comment"], ["status", "status"]]) : refusal(hist));
  return out;
}

async function appsView() {
  const [list, inst] = await Promise.all([core("GET", "apps"), core("GET", "apps/instances")]);
  const out = [el("h1", {}, "Apps")];
  out.push(list.ok ? table(list.data.apps, [["app", (a) => a.id || a.app_id], ["versions", (a) => text(a.versions || a.version)],
    ["instances", (a) => (a.instances || []).map((i) => `${i.instance_id} ${i.status}${i.live ? "" : " (not live)"}`).join(", ")]]) : refusal(list));
  out.push(el("h2", {}, "Running here"));
  const rows = inst.ok ? (Array.isArray(inst.data) ? inst.data : (inst.data.instances || [])) : [];
  out.push(inst.ok ? table(rows, [["instance", (i) => i.id || i.instance], ["app", "app"], ["version", "version"], ["state", (i) => i.state || i.status]]) : refusal(inst));
  return out;
}

async function rollouts() {
  const res = await core("GET", "rollouts");
  const out = [el("h1", {}, "Rollouts")];
  if (!res.ok) return out.concat(refusal(res));
  const rows = Array.isArray(res.data) ? res.data : (res.data.rollouts || []);
  const act = (id, verb) => async () => { const r = await core("POST", `rollouts/${encodeURIComponent(id)}/${verb}`, {}); r.ok ? (refresh(), say(`${id}: ${verb}`, "good")) : say(errText(r), "bad"); };
  out.push(table(rows, [["id", "id"], ["kind", "kind"], ["version", "version"], ["state", "state"], ["phase", "phase"],
    ["", (r) => el("span", { class: "row" }, ["pause", "resume", "abort"].map((v) => el("button", { class: "ghost", onclick: act(r.id, v) }, v)))]], "No rollout."));
  return out;
}

async function auditView() {
  const [ver, ev] = await Promise.all([core("GET", "audit/verify"), core("GET", "events?after=0&types=" + encodeURIComponent("config.*,policy.*,alert.*,admin.*"))]);
  const out = [el("h1", {}, "Audit")];
  out.push(ver.ok ? el("p", { class: "msg " + (ver.data.ok ? "good" : "bad") }, ver.data.ok ? `The audit chain verifies (${text(ver.data.count ?? ver.data.records ?? ver.data.head)}).` : "The audit chain does NOT verify: " + text(ver.data)) : refusal(ver));
  const from = el("input", { type: "number", min: 1, value: 1, size: 8 });
  const box = el("div");
  const load = async () => {
    const r = await core("GET", `audit?from=${encodeURIComponent(from.value)}&limit=50`);
    box.replaceChildren(r.ok ? table(r.data.records, [["seq", "seq"], ["time", "event.Timestamp"], ["actor", "event.Actor"], ["action", "event.Action"], ["category", "event.Category"], ["result", "event.Result"]]) : refusal(r));
  };
  out.push(el("h2", {}, "Records"), el("div", { class: "row" }, "from", from, el("button", { class: "ghost", onclick: load }, "Show 50")), box);
  await load();
  out.push(el("h2", {}, "Recent events"));
  const evs = ev.ok ? (ev.data.events || []).slice(-100).reverse() : [];
  out.push(ev.ok ? table(evs, [["seq", "seq"], ["at", "at"], ["node", "node"], ["type", "type"], ["actor", "actor"], ["result", "result"]], "No event.") : refusal(ev));
  return out;
}

async function reports() {
  const res = await call("GET", REPORT + "reports");
  const out = [el("h1", {}, "Reports"), el("p", { class: "muted" }, "From heain-report: the reports you may view, their latest signed snapshot.")];
  if (!res.ok) return out.concat(refusal(res));
  const box = el("div");
  const open = (id) => async () => {
    const d = await call("GET", REPORT + "dashboards/" + encodeURIComponent(id));
    if (!d.ok) { box.replaceChildren(refusal(d)); return; }
    const s = d.data.snapshot || {};
    const parts = [el("h2", {}, s.title || id), el("p", { class: "muted mono" }, `run ${d.data.run.id} · ${s.from} → ${s.to} · sha256 ${d.data.sha256}`),
      el("p", {}, el("a", { href: REPORT + "runs/" + encodeURIComponent(d.data.run.id) + "/csv" }, "Download CSV"))];
    for (const src of s.sources || []) {
      parts.push(el("h2", {}, `${src.name} — ${src.app} / ${src.dataset}`));
      const cols = (src.group_by || []).map((g) => [g, (r) => r.keys[g]]).concat([["count", "count"]]).concat((src.measures || []).map((m) => [m.name + (m.unit ? " (" + m.unit + ")" : ""), (r) => r.values[m.name]]));
      parts.push(table(src.groups, cols, "No group large enough to show."));
      if (src.suppressed_groups) parts.push(el("p", { class: "muted" }, `${src.suppressed_groups} smaller group(s) hidden (min_group ${s.min_group}).`));
    }
    box.replaceChildren(...parts);
  };
  out.push(table(res.data.reports, [["id", "id"], ["title", "title"], ["last run", "last_done"], ["", (r) => el("button", { class: "ghost", onclick: open(r.id), disabled: !r.last_done }, "Open")]], "No report you may view."));
  out.push(box);
  return out;
}

// ---- wiring ----
document.addEventListener("DOMContentLoaded", () => {
  $("login-form").addEventListener("submit", login);
  $("logout").addEventListener("click", logout);
  $("node").addEventListener("change", (e) => { state.node = e.target.value; refresh(); });
  start();
});
