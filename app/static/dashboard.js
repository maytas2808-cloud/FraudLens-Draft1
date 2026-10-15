"use strict";

const $ = (id) => document.getElementById(id);
const el = (tag, className, text) => {
  const n = document.createElement(tag);
  if (className) n.className = className;
  if (text !== undefined) n.textContent = text;
  return n;
};
const ERRORS = {
  not_configured: "Gmail protection isn't configured on this server yet.",
  denied: "Google sign-in was cancelled.",
  state: "Sign-in expired or was interrupted. Please try again.",
  token: "Google didn't accept the sign-in. Please try again.",
  scopes: "FraudLens needs both 'read' and 'send' Gmail permissions. Please sign in again and tick both boxes.",
  profile: "Couldn't read your Gmail profile. Please try again.",
};
let level = "";

function showState(name) {
  for (const s of ["loading", "unconfigured", "signed-out", "signed-in"]) $(`state-${s}`).hidden = s !== name;
}

function when(ts) {
  return ts ? new Date(ts * 1000).toLocaleString() : "never";
}

function notice(text, isError = false) {
  const n = $("notice");
  n.textContent = text;
  n.className = isError ? "small error" : "small muted";
  n.hidden = !text;
}

async function api(path, options = {}) {
  const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Something went wrong.");
  return data;
}

function renderStats(s) {
  const card = (label, value, cls) => {
    const c = el("div", `card ${cls || ""}`);
    c.append(el("div", "small muted", label), el("div", "big", String(value)));
    return c;
  };
  $("stats").replaceChildren(card("Emails checked", s.total), card("High risk", s.high, "high"),
    card("Suspicious", s.medium, "medium"), card("Low risk", s.low, "low"));
}

function renderEmails(list) {
  $("emails-empty").hidden = list.length > 0;
  $("emails").replaceChildren(...list.map((m) => {
    const li = el("li", "mail-item");
    const head = el("div", "mail-head");
    head.append(el("span", `badge ${m.level}`, `${m.level.toUpperCase()} ${m.score}`),
      el("span", "mail-subject", m.subject || "(no subject)"));
    li.append(head, el("div", "small muted", `${m.sender} · ${when(m.received_at)}`));
    if (m.level !== "low" && m.scenarios.length) li.append(el("div", "small", m.scenarios.join(", ")));
    if (m.reasons.length && m.level !== "low") {
      const ul = el("ul", "mail-reasons small");
      for (const r of m.reasons) ul.append(el("li", "", r));
      li.append(ul);
    }
    return li;
  }));
}

async function loadEmails() {
  const q = level ? `?level=${level}` : "";
  const data = await api(`/api/my-emails${q}`);
  renderEmails(data.emails);
}

async function refresh() {
  const me = await api("/api/me");
  if (!me.configured) return showState("unconfigured");
  if (!me.signed_in) return showState("signed-out");
  showState("signed-in");
  $("account").textContent = `${me.email} · last checked ${when(me.last_scan_at)} · new mail checked every ${Math.round(me.poll_seconds / 60 * 10) / 10} min`;
  const err = $("account-error");
  err.textContent = me.error || "";
  err.hidden = !me.error;
  $("pref-digest").checked = me.prefs.digest === "daily";
  $("pref-alerts").checked = me.prefs.alerts;
  renderStats(me.stats);
  await loadEmails();
}

async function action(btn, label, fn) {
  btn.disabled = true;
  const old = btn.textContent;
  btn.textContent = label;
  try { await fn(); } catch (e) { notice(e.message, true); } finally { btn.disabled = false; btn.textContent = old; }
}

async function savePrefs() {
  try {
    await api("/api/prefs", { method: "POST", body: JSON.stringify({ digest: $("pref-digest").checked ? "daily" : "off", alerts: $("pref-alerts").checked }) });
    notice("Preferences saved.");
  } catch (e) { notice(e.message, true); }
}

function init() {
  const params = new URLSearchParams(location.search);
  const code = params.get("error");
  if (code) {
    $("page-error").textContent = ERRORS[code] || "Sign-in failed. Please try again.";
    $("page-error").hidden = false;
    history.replaceState(null, "", "/dashboard");
  }
  $("scan-btn").addEventListener("click", (e) => action(e.target, "Scanning…", async () => {
    const r = await api("/api/my-emails/scan", { method: "POST" });
    notice(r.new ? `${r.new} new email${r.new === 1 ? "" : "s"} checked.` : "No new emails.");
    await refresh();
  }));
  $("report-btn").addEventListener("click", (e) => action(e.target, "Sending…", async () => {
    const r = await api("/api/my-report", { method: "POST" });
    notice(`Report sent to your inbox (${r.emails} email${r.emails === 1 ? "" : "s"} from the last 24 hours).`);
  }));
  $("logout-btn").addEventListener("click", (e) => action(e.target, "Signing out…", async () => {
    await api("/auth/logout", { method: "POST" });
    location.href = "/dashboard";
  }));
  $("disconnect-btn").addEventListener("click", (e) => {
    if (!confirm("Disconnect Gmail? FraudLens will lose access and delete your saved results.")) return;
    action(e.target, "Disconnecting…", async () => {
      await api("/auth/disconnect", { method: "POST" });
      location.href = "/dashboard";
    });
  });
  $("pref-digest").addEventListener("change", savePrefs);
  $("pref-alerts").addEventListener("change", savePrefs);
  for (const b of $("filters").querySelectorAll("button")) {
    b.addEventListener("click", () => {
      level = b.dataset.level;
      for (const o of $("filters").querySelectorAll("button")) o.setAttribute("aria-pressed", String(o === b));
      loadEmails().catch((e) => notice(e.message, true));
    });
  }
  refresh().catch((e) => { showState("signed-out"); $("page-error").textContent = e.message; $("page-error").hidden = false; });
  setInterval(() => { if (!$("state-signed-in").hidden) refresh().catch(() => {}); }, 30000);
}

document.addEventListener("DOMContentLoaded", init);
