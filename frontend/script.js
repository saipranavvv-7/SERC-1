"use strict";
/* SERC front end. Plain JavaScript. All server text is inserted with textContent (never innerHTML),
   so a malicious alert or log line cannot inject code into the page. */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
const show = (el, on = true) => el.classList.toggle("hidden", !on);

const state = {
  health: null, samples: [], file: null, ingest: null, alertSent: null, result: null,
  feedback: {}, approvals: {}, onlyAttention: true, tab: "report",
};

const STATUS_CLASS = {
  "Supported": "st-ok", "Partially Supported": "st-partial", "Conflicting Evidence": "st-bad",
  "Insufficient Evidence": "st-warn", "Requires Review": "st-review",
};
const TYPE_LABEL = { observed_fact: "Alert fact", interpretation: "Interpretation", recommendation: "Recommendation" };

/* ---------------------------------------------------------------- API */
async function api(path, opts = {}) {
  let res;
  try { res = await fetch(path, opts); }
  catch (_) { throw new Error("Cannot reach the SERC server. Is it running?"); }
  let data = null;
  try { data = await res.json(); } catch (_) { /* not JSON */ }
  if (!res.ok) {
    let msg = data && (data.detail || data.message);
    if (Array.isArray(msg)) msg = msg.map((m) => m.msg || JSON.stringify(m)).join("; ");
    throw new Error(msg || `Server error (${res.status})`);
  }
  return data;
}
const postJSON = (path, body) => api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

/* ---------------------------------------------------------------- startup */
async function init() {
  bindUi();
  try {
    state.health = await api("/api/health");
    renderPills();
  } catch (e) {
    const p = $("#pill-backend"); p.textContent = "Backend offline"; p.className = "pill bad";
    banner("The SERC server is not running. Start it with: python backend/main.py");
  }
  try { state.samples = await api("/api/alerts/samples"); fillSamples(); } catch (_) { /* optional */ }
}

function banner(text) { const b = $("#banner"); b.textContent = text; show(b, !!text); }

function renderPills() {
  const hl = state.health;
  const pb = $("#pill-backend"); pb.textContent = "Backend connected"; pb.className = "pill ok";
  const pc = $("#pill-corpus"); show(pc);
  pc.textContent = `Knowledge base: ${hl.vectors.toLocaleString()} passages`;
  pc.className = "pill " + (hl.vectors > 0 ? "info" : "bad");
  const pm = $("#pill-mode"); show(pm);
  pm.textContent = hl.mode === "live" ? "Live model" : "Offline mode (evidence only)";
  pm.className = "pill " + (hl.mode === "live" ? "info" : "warn");
  if (hl.collection_error) banner("Knowledge base problem: " + hl.collection_error);
  else if (hl.vectors === 0) banner("The knowledge base is empty. Run the ingestion step from the README, then restart the server.");
  const vn = $("#vision-note");
  if (!hl.vision_available) { vn.textContent = "Screenshots can only be read in live mode (needs a Pixtral key). In offline mode, paste the alert text or upload a JSON or log file."; show(vn); }
}

function fillSamples() {
  const sel = $("#sample-select");
  sel.replaceChildren(...state.samples.map((s) => h("option", { value: s.id, text: s.label })));
}

/* ---------------------------------------------------------------- input step */
function bindUi() {
  $("#tech-toggle").addEventListener("change", (e) => document.body.classList.toggle("technical", e.target.checked));
  $$("#input-tabs .tab").forEach((b) => b.addEventListener("click", () => switchInputTab(b.dataset.tab)));

  $("#btn-paste").addEventListener("click", () => submitIngest(() => { const fd = new FormData(); fd.append("text", $("#paste-text").value); return fd; }, $("#btn-paste")));
  $("#btn-upload").addEventListener("click", () => submitIngest(() => { const fd = new FormData(); fd.append("file", state.file); return fd; }, $("#btn-upload")));
  $("#btn-sample").addEventListener("click", loadSample);

  const dz = $("#dropzone"), fi = $("#file-input");
  dz.addEventListener("click", () => fi.click());
  dz.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fi.click(); } });
  ["dragenter", "dragover"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("drag"); }));
  ["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("drag"); }));
  dz.addEventListener("drop", (e) => { if (e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]); });
  fi.addEventListener("change", () => { if (fi.files.length) setFile(fi.files[0]); });

  $("#btn-back").addEventListener("click", () => goStep(1));
  $("#btn-analyze").addEventListener("click", analyze);
}

function switchInputTab(name) {
  $$("#input-tabs .tab").forEach((b) => { const on = b.dataset.tab === name; b.classList.toggle("active", on); b.setAttribute("aria-selected", on); });
  ["paste", "upload", "sample"].forEach((n) => show($("#itab-" + n), n === name));
  inputError("");
}

function setFile(f) {
  state.file = f;
  const n = $("#file-name"); n.textContent = `${f.name} (${(f.size / 1024).toFixed(f.size > 102400 ? 0 : 1)} KB)`; show(n);
  $("#btn-upload").disabled = false; inputError("");
}

function inputError(msg) { const e = $("#input-error"); e.textContent = msg; show(e, !!msg); }

async function submitIngest(buildFd, btn) {
  inputError("");
  btn.disabled = true; const old = btn.textContent; btn.textContent = "Reading…";
  try {
    const res = await api("/api/alerts/ingest", { method: "POST", body: buildFd() });
    if (!res.ok) throw new Error(res.message || "That input could not be read.");
    state.ingest = res; showConfirm();
  } catch (e) { inputError(e.message); }
  finally { btn.disabled = false; btn.textContent = old; if (btn.id === "btn-upload" && !state.file) btn.disabled = true; }
}

async function loadSample() {
  inputError("");
  const id = $("#sample-select").value;
  if (!id) return inputError("Choose a sample first.");
  try {
    const alert = await api("/api/alerts/samples/" + encodeURIComponent(id));
    state.ingest = { ok: true, source_type: "sample", alert, warnings: [], needs_confirmation: false };
    showConfirm();
  } catch (e) { inputError(e.message); }
}

/* ---------------------------------------------------------------- confirm step */
function showConfirm() {
  const ing = state.ingest, a = ing.alert, rule = a.rule || {}, data = a.data || {}, editable = !!ing.needs_confirmation;
  const from = { wazuh_json: "Wazuh alert JSON", raw_text: "pasted text", log_file: "a log file", image: "an image", sample: "a built-in sample" }[ing.source_type] || "your input";
  $("#confirm-intro").textContent = editable
    ? `SERC read this from ${from}. Some details were guessed, so please correct anything that looks wrong before analyzing.`
    : `Loaded from ${from}. These details come straight from the alert, so they are shown read-only.`;
  $("#confirm-warnings").replaceChildren(...(ing.warnings || []).map((w) => h("li", { text: w })));
  $("#f-desc").value = rule.description || (a.full_log || "").slice(0, 120);
  $("#f-level").value = rule.level ?? "";
  $("#f-agent").value = (a.agent || {}).name || "";
  $("#f-ip").value = data.srcip || "";
  $("#f-user").value = data.srcuser || data.dstuser || "";
  $("#f-log").value = a.full_log || "";
  ["#f-desc", "#f-level", "#f-agent", "#f-ip", "#f-user", "#f-log"].forEach((s) => { $(s).disabled = !editable; });
  const m = rule.mitre || {}, ids = [].concat(m.id || []);
  const src = (a._serc || {}).mitre_source;
  $("#f-mitre").replaceChildren(...(ids.length
    ? ids.map((i, n) => h("span", { class: "chip", title: src === "heuristic_pattern" ? "Suggested by a text pattern. Please confirm." : "From the alert" }, i + (([].concat(m.technique || [])[n]) ? " " + [].concat(m.technique)[n] : "")))
    : [h("span", { class: "muted", text: "none in the alert" })]));
  if (src === "heuristic_pattern") $("#f-mitre").append(h("span", { class: "muted sm", text: "suggested by a pattern, not confirmed" }));
  $("#f-raw").textContent = JSON.stringify(a, null, 2);
  show($("#confirm-error"), false);
  goStep(2);
}

function collectAlert() {
  const a = structuredClone(state.ingest.alert);
  if (state.ingest.needs_confirmation) {
    a.rule = a.rule || {}; a.agent = a.agent || {}; a.data = a.data || {};
    a.rule.description = $("#f-desc").value.trim();
    const lv = $("#f-level").value.trim();
    if (lv !== "" && !(Number(lv) >= 0 && Number(lv) <= 15)) throw new Error("Severity level must be a number from 0 to 15, or left empty.");
    a.rule.level = lv === "" ? null : Number(lv);
    a.agent.name = $("#f-agent").value.trim();
    for (const [key, sel] of [["srcip", "#f-ip"], ["srcuser", "#f-user"]]) {
      const v = $(sel).value.trim(); if (v) a.data[key] = v; else delete a.data[key];
    }
    a.full_log = $("#f-log").value;
  }
  return a;
}

/* ---------------------------------------------------------------- analysis */
function goStep(n) {
  show($("#panel-input"), n === 1); show($("#panel-confirm"), n === 2);
  show($("#panel-loading"), false); show($("#panel-results"), n === 3);
  $$("#stepper li").forEach((li) => { const s = +li.dataset.step; li.classList.toggle("active", s === n); li.classList.toggle("done", s < n); });
  window.scrollTo({ top: 0, behavior: "smooth" });
}

let loadingTimer = null;
function startLoading() {
  show($("#panel-input"), false); show($("#panel-confirm"), false); show($("#panel-results"), false); show($("#panel-loading"), true);
  const items = $$("#loading-steps li"); let i = 0; show($("#loading-slow"), false);
  const tick = () => items.forEach((li, n) => { li.className = n < i ? "past" : n === i ? "on" : ""; });
  tick(); const t0 = Date.now();
  loadingTimer = setInterval(() => { i = Math.min(i + 1, items.length - 1); tick(); if (Date.now() - t0 > 7000) show($("#loading-slow"), true); }, 2200);
}
function stopLoading() { clearInterval(loadingTimer); show($("#panel-loading"), false); }

async function analyze() {
  const err = $("#confirm-error"); show(err, false);
  let alert;
  try { alert = collectAlert(); } catch (e) { err.textContent = e.message; show(err); return; }
  startLoading();
  try {
    const r = await postJSON("/api/alerts/analyze", { alert });
    stopLoading();
    state.alertSent = alert; state.result = r; state.approvals = {}; state.feedback = {};
    try { (await api("/api/feedback/" + encodeURIComponent(r.alert.alert_id))).forEach((f) => { state.feedback[f.claim_id] = f.decision; }); } catch (_) { /* optional */ }
    renderResults();
    goStep(3);
  } catch (e) {
    stopLoading(); goStep(2); err.textContent = e.message; show(err);
  }
}

/* ---------------------------------------------------------------- results */
function statusChip(s) { return h("span", { class: "status " + (STATUS_CLASS[s] || "") }, s); }
function citeChips(ids) { return (ids || []).map((id) => h("button", { class: "chip-btn", type: "button", title: "Show this source", onclick: () => openEvidence(id) }, id)); }

function renderResults() {
  const r = state.result;
  renderSummary(r);
  const attn = r.validation.needs_attention;
  const tabs = [
    ["report", "Report"], ["mitre", `MITRE ATT&CK`, r.mitre_mapping.length], ["evidence", "Evidence", r.evidence.length],
    ["verify", "Verification", attn || null, true], ["chat", "Ask a question"],
  ];
  $("#result-tabs").replaceChildren(...tabs.map(([key, label, count, warn]) =>
    h("button", { role: "tab", class: "tab" + (key === state.tab ? " active" : ""), "data-tab": key, "aria-selected": key === state.tab, onclick: () => switchResultTab(key) },
      label, count ? h("span", { class: "count" + (warn ? " attn" : "") }, count) : null)));
  renderReport(r); renderMitre(r); renderEvidence(r); renderVerify(r); renderChat();
  switchResultTab("report");
}

function switchResultTab(key) {
  state.tab = key;
  $$("#result-tabs .tab").forEach((b) => { const on = b.dataset.tab === key; b.classList.toggle("active", on); b.setAttribute("aria-selected", on); });
  ["report", "mitre", "evidence", "verify", "chat"].forEach((k) => show($("#tab-" + k), k === key));
}

function openEvidence(eid) {
  switchResultTab("evidence");
  const el = document.getElementById("ev-" + eid);
  if (el) { el.scrollIntoView({ behavior: "smooth", block: "center" }); el.classList.remove("flash"); void el.offsetWidth; el.classList.add("flash"); }
}

function renderSummary(r) {
  const s = r.summary, v = r.validation, a = r.alert;
  const score = v.verification_score;
  const supportedAnalysis = v.analysis_counts["Supported"];
  const box = $("#summary");
  box.replaceChildren(h("div", { class: "card" },
    h("div", { class: "summary" },
      h("div", {},
        h("div", { class: "badges" },
          h("span", { class: "badge sev-" + a.severity.toLowerCase() }, `${a.severity} severity` + (a.level != null ? ` (level ${a.level})` : "")),
          h("span", { class: "badge mode" }, r.mode === "live" ? "Live model" : "Offline: every step comes from a cited source"),
          a.mitre_ids.map((id) => h("span", { class: "badge" }, id))),
        h("h2", {}, s.headline),
        h("p", {}, s.what_happened),
        h("h3", {}, "Suggested first actions"),
        s.top_actions.length
          ? h("ol", {}, s.top_actions.map((t) => h("li", {}, t.text, " ",
              t.approval_required ? h("span", { class: "badge approval" }, "needs analyst approval") : null, " ", citeChips(t.evidence_ids))))
          : h("p", { class: "muted" }, "No evidence-based action could be built for this alert."),
        h("p", { class: "disclaimer" }, s.note)),
      h("div", { class: "gauge-wrap" },
        h("div", { class: "gauge", style: `--pct:${score ?? 0}`, role: "img", "aria-label": `Verification score ${score ?? "not available"} percent` }, h("div", {}, score == null ? "–" : score + "%")),
        h("div", { class: "gauge-label" }, score == null ? "Nothing to verify" : `${supportedAnalysis} of ${v.analysis_total} statements fully supported`),
        v.needs_attention ? h("div", { class: "gauge-label" }, `${v.needs_attention} need a human look`) : null)),
    r.warnings.length ? h("div", { class: "notice" }, r.warnings.map((w) => h("div", {}, w))) : null,
    h("div", { class: "summary-actions" },
      h("button", { class: "btn primary", onclick: downloadReport }, "Download report"),
      h("button", { class: "btn", onclick: newAlert }, "Analyze another alert"),
      h("span", { class: "muted tech" }, `Analysis took ${r.timing_ms} ms`))));
}

function stepItem(s) {
  return h("li", { class: "step" },
    h("span", { class: "phase" }, s.phase || "Step"),
    h("p", {}, s.text),
    h("div", { class: "step-meta" },
      statusChip(s.status), citeChips(s.evidence_ids),
      s.approval_required ? h("span", { class: "badge approval" }, "needs analyst approval") : null,
      h("label", { class: "approve" },
        h("input", { type: "checkbox", checked: !!state.approvals[s.claim_id], onchange: (e) => { state.approvals[s.claim_id] = e.target.checked; } }),
        "Approved by analyst")));
}

function renderReport(r) {
  const root = $("#tab-report");
  const none = (t) => h("p", { class: "muted" }, t);
  root.replaceChildren(
    h("h3", { style: "margin-top:0" }, "What the alert says"),
    h("ul", { class: "facts" }, r.facts.map((f) => h("li", {}, f))),
    h("h3", {}, "What it may mean"),
    r.interpretations.length
      ? h("ul", { class: "facts" }, r.interpretations.map((i) => h("li", {}, i.text, " ", statusChip(i.status), " ", citeChips(i.evidence_ids))))
      : none("No interpretation could be supported by the evidence."),
    h("h3", {}, "What to check"),
    r.investigation_steps.length ? h("ol", { class: "step-list" }, r.investigation_steps.map(stepItem)) : none("No investigation steps found in the retrieved sources."),
    h("h3", {}, "What to do"),
    r.mitigation_steps.length ? h("ol", { class: "step-list" }, r.mitigation_steps.map(stepItem)) : none("No response steps found in the retrieved sources. Check that the knowledge base was ingested."),
    h("p", { class: "disclaimer" }, "Tick “Approved by analyst” only after a person has reviewed the step. Approvals are included in the downloaded report."));
}

function renderMitre(r) {
  const root = $("#tab-mitre");
  if (!r.mitre_mapping.length) { root.replaceChildren(h("p", { class: "muted" }, "No MITRE ATT&CK technique is linked to this alert. Linking one without evidence would be a guess.")); return; }
  root.replaceChildren(h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ["Technique", "Name", "Tactic", "How it was found", "Evidence"].map((t) => h("th", {}, t)))),
    h("tbody", {}, r.mitre_mapping.map((m) => h("tr", {},
      h("td", {}, h("a", { href: m.url, target: "_blank", rel: "noopener noreferrer" }, m.id)),
      h("td", {}, m.name || "–"), h("td", {}, m.tactic || "–"), h("td", {}, m.origin), h("td", {}, citeChips(m.evidence_ids))))))));
}

function renderEvidence(r) {
  const root = $("#tab-evidence");
  if (!r.evidence.length) { root.replaceChildren(h("p", { class: "muted" }, "No evidence was retrieved. Check that the knowledge base is ingested.")); return; }
  root.replaceChildren(
    h("p", { class: "muted" }, "Every suggestion is traced to one of these official passages. The score shows how closely a passage matches this alert. It does not show that the passage is correct."),
    ...r.evidence.map((e) => h("div", { class: "ev-card", id: "ev-" + e.eid },
      h("div", { class: "ev-head" },
        h("span", { class: "eid" }, e.eid),
        h("span", { class: "badge src-" + e.source }, e.source_label),
        e.official ? h("span", { class: "badge sev-low" }, "Official source") : null,
        h("span", { class: "muted" }, e.match === "direct_mitre_id" ? "Exact technique match" : "Closest match by meaning"),
        h("span", { class: "meter tech", title: "Similarity" }, h("span", { style: `width:${Math.round(e.score * 100)}%` })),
        h("span", { class: "tech" }, e.score.toFixed(2)),
        e.low_confidence ? h("span", { class: "status st-partial" }, "Weak match") : null),
      h("div", { class: "ev-ref" }, e.reference || e.source_title, e.url ? [" · ", h("a", { href: e.url, target: "_blank", rel: "noopener noreferrer" }, "open the original")] : null),
      h("details", {}, h("summary", {}, "Show the passage"), h("div", { class: "ev-text" }, e.text)))));
}

/* ---------------------------------------------------------------- verification */
function renderVerify(r) {
  const root = $("#tab-verify"), v = r.validation, c = v.analysis_counts;
  const tile = (label, n, cls) => h("div", { class: "tile " + cls }, h("b", {}, n), h("span", {}, label));
  const analysis = r.claims.filter((x) => x.type !== "observed_fact");
  const facts = r.claims.filter((x) => x.type === "observed_fact");
  const shown = analysis.filter((x) => !state.onlyAttention || x.status !== "Supported");
  const fbBtns = (cl) => {
    const wrap = h("div", { class: "fb" }, h("span", { class: "muted" }, "Your decision:"));
    const saved = h("span", { class: "saved" });
    const mk = (decision, label) => {
      const b = h("button", { class: "btn small" + (state.feedback[cl.id] === decision ? " on" : ""), type: "button" }, label);
      b.addEventListener("click", async () => {
        try {
          await postJSON("/api/feedback", { alert_id: r.alert.alert_id, claim_id: cl.id, decision, claim_text: cl.text });
          state.feedback[cl.id] = decision;
          $$("button", wrap).forEach((x) => x.classList.remove("on")); b.classList.add("on"); saved.textContent = "Saved";
        } catch (e) { saved.textContent = e.message; }
      });
      return b;
    };
    wrap.append(mk("accepted", "Accept"), mk("rejected", "Reject"), mk("review", "Needs review"), saved);
    return wrap;
  };
  root.replaceChildren(
    h("p", { class: "muted" }, "Each statement SERC makes is checked against the alert and the cited source. This shows whether a statement is traceable. It does not prove the advice is right for your environment."),
    h("div", { class: "tiles" },
      tile("Supported", c["Supported"], "st-ok"), tile("Partially supported", c["Partially Supported"], "st-partial"),
      tile("Conflicting", c["Conflicting Evidence"], "st-bad"), tile("Not enough evidence", c["Insufficient Evidence"], "st-warn"),
      tile("Needs review", c["Requires Review"], "st-review")),
    h("p", {}, `Alert facts: ${v.facts_supported} of ${v.facts_total} read directly from the alert.`, " ",
      h("span", { class: "muted" }, "(They are not counted in the score above, because restating the alert proves nothing.)")),
    h("div", { class: "toolbar" },
      h("label", { class: "switch" }, h("input", { type: "checkbox", checked: state.onlyAttention, onchange: (e) => { state.onlyAttention = e.target.checked; renderVerify(r); } }), h("span", {}, "Only show items that need attention")),
      h("button", { class: "btn small", onclick: acceptAllSupported }, "Accept all fully supported")),
    ...(shown.length ? shown.map((cl) => h("div", { class: "claim " + (STATUS_CLASS[cl.status] || "").replace("st-", "c-") },
      h("div", { class: "claim-head" }, statusChip(cl.status), h("span", {}, TYPE_LABEL[cl.type] || cl.type), h("span", { class: "tech" }, cl.id),
        cl.grounding != null ? h("span", { class: "tech" }, `wording match ${Math.round(cl.grounding * 100)}%`) : null),
      h("p", {}, cl.text),
      h("dl", {}, h("dt", {}, "Why"), h("dd", {}, cl.justification), h("dt", {}, "Source"), h("dd", {}, cl.source || "–"), h("dt", {}, "Next step"), h("dd", {}, cl.next_step)),
      fbBtns(cl)))
      : [h("p", { class: "notice", style: "background:var(--ok-bg);color:var(--ok);border-color:#b9e3cc" }, "Nothing needs attention. Untick the box above to see every statement.")]),
    h("details", {}, h("summary", {}, `Show the ${facts.length} alert facts that were checked`), h("ul", { class: "facts" }, facts.map((f) => h("li", {}, f.text, " ", h("span", { class: "muted" }, "(" + f.source + ")"))))));
}

async function acceptAllSupported() {
  const r = state.result;
  const todo = r.claims.filter((c) => c.type !== "observed_fact" && c.status === "Supported" && !state.feedback[c.id]);
  await Promise.allSettled(todo.map((c) => postJSON("/api/feedback", { alert_id: r.alert.alert_id, claim_id: c.id, decision: "accepted", claim_text: c.text })
    .then(() => { state.feedback[c.id] = "accepted"; })));
  renderVerify(r);
}

/* ---------------------------------------------------------------- chat */
function renderChat() {
  const root = $("#tab-chat");
  const log = h("div", { class: "chat-log", "aria-live": "polite" });
  const input = h("input", { type: "text", placeholder: "Ask about this incident, for example: how do I contain it?", "aria-label": "Your question", maxlength: "500" });
  const send = async (q) => {
    q = (q || input.value).trim(); if (!q) return; input.value = "";
    log.append(h("div", { class: "msg user" }, q));
    const wait = h("div", { class: "msg bot muted" }, "Searching the sources…"); log.append(wait); log.scrollTop = log.scrollHeight;
    try {
      const res = await postJSON("/api/alerts/chat", { alert: state.alertSent, question: q });
      if (res.ok === false) throw new Error(res.message);
      const lines = String(res.answer).split("\n");
      const bullets = lines.filter((l) => l.startsWith("• ")), rest = lines.filter((l) => !l.startsWith("• ") && l.trim());
      wait.className = "msg bot";
      wait.replaceChildren(...[...rest.map((l) => h("p", {}, l)), bullets.length ? h("ul", {}, bullets.map((l) => h("li", {}, l.slice(2)))) : null,
        res.citations.length ? h("div", { class: "chips" }, res.citations.map((c) => h("button", { class: "chip-btn", type: "button", title: c.reference, onclick: () => state.result.evidence.some((e) => e.eid === c.eid) && openEvidence(c.eid) }, c.eid + " · " + (c.source_label || "source")))) : null].filter(Boolean));
    } catch (e) { wait.className = "msg bot"; wait.textContent = e.message; }
    log.scrollTop = log.scrollHeight;
  };
  const suggestions = ["What should I check first?", "How do I contain this?", "How can I prevent this from happening again?"];
  root.replaceChildren(
    h("p", { class: "muted" }, "Questions are answered only from the retrieved sources. If they do not cover it, SERC says so instead of guessing."),
    h("div", { class: "suggest" }, suggestions.map((s) => h("button", { class: "btn small", type: "button", onclick: () => send(s) }, s))),
    log, h("form", { class: "chat-form", onsubmit: (e) => { e.preventDefault(); send(); } }, input, h("button", { class: "btn primary", type: "submit" }, "Ask")));
}

/* ---------------------------------------------------------------- report download and reset */
function downloadReport() {
  const r = state.result, a = r.alert, v = r.validation;
  const L = [];
  L.push(`# SERC incident report`, "", `**Alert:** ${a.description}`, `**Severity:** ${a.severity}${a.level != null ? ` (level ${a.level})` : ""}`,
    `**Host:** ${a.agent_name || "n/a"}   **Source IP:** ${a.srcip || "n/a"}   **User:** ${a.srcuser || "n/a"}`,
    `**Time:** ${a.timestamp || "n/a"}`, `**Generated:** ${new Date().toLocaleString()}   **Mode:** ${r.mode}`, "",
    `## Summary`, r.summary.what_happened, "", `_${r.summary.note}_`, "", `## What the alert says`, ...r.facts.map((f) => `- ${f}`), "",
    `## What it may mean`, ...r.interpretations.map((i) => `- ${i.text} [${i.status}] ${i.evidence_ids.join(" ")}`), "");
  const steps = (title, list) => { L.push(`## ${title}`); list.forEach((s) => L.push(`- [${state.approvals[s.claim_id] ? "x" : " "}] ${s.text} (${s.phase}; ${s.status}; ${s.evidence_ids.join(", ")})${s.approval_required ? " **needs analyst approval**" : ""}`)); L.push(""); };
  steps("What to check", r.investigation_steps); steps("What to do", r.mitigation_steps);
  L.push(`## Evidence used`, ...r.evidence.map((e) => `- ${e.eid}: ${e.source_label}, ${e.reference || e.source_title} (similarity ${e.score.toFixed(2)}${e.low_confidence ? ", weak match" : ""})`), "",
    `## Verification`, `Statements fully supported: ${v.analysis_counts["Supported"]} of ${v.analysis_total}` + (v.verification_score != null ? ` (score ${v.verification_score}%)` : ""),
    ...Object.entries(v.analysis_counts).map(([k, n]) => `- ${k}: ${n}`), "");
  const decided = r.claims.filter((c) => state.feedback[c.id]);
  if (decided.length) { L.push(`## Analyst decisions`, ...decided.map((c) => `- ${state.feedback[c.id]}: ${c.text}`), ""); }
  L.push(`---`, `Boxes ticked above were approved by an analyst in SERC. SERC is decision support; people decide and carry out every action.`);
  const blob = new Blob([L.join("\n")], { type: "text/markdown" });
  const link = h("a", { href: URL.createObjectURL(blob), download: `serc-report-${a.alert_id.replace(/[^\w.-]/g, "_")}.md` });
  document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

function newAlert() {
  state.ingest = null; state.result = null; state.file = null; state.tab = "report";
  $("#paste-text").value = ""; $("#file-input").value = ""; show($("#file-name"), false); $("#btn-upload").disabled = true;
  switchInputTab("paste"); goStep(1);
}

document.addEventListener("DOMContentLoaded", init);
