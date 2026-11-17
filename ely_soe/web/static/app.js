/* ELY Security Lab & SOE Command Center — Client Application Controller
 * Strictly uses relative `/api/...` paths (zero localhost/127.0.0.1 references).
 */

const state = {
  overview: null,
  activeRunId: null,
  activeReport: null,
  activeArtifacts: null,
  benchmark: null,
  activeView: "overview",
};

const VIEW_TITLES = {
  overview: "Executive Security Posture & Ely 1.0 Maturity Gate",
  findings: "Discovery vs. Clean-Room Independent Validation Ledger",
  lifecycle: "8-Stage Isolated Evaluation Lifecycle & Snapshot Proof",
  agents: "Zero-Trust Untrusted Internal Agents Arena (UA-01 .. UA-08)",
  benchmark: "GLM 5.3 vs. Frontier Model & Harness Experimental Benchmark",
  attackgraph: "Probabilistic Multi-Agent Exploit Graph & Chokepoints",
  frontier: "Photon Labs Frontier Cybersecurity Research Workbench",
  compliance: "OWASP Agentic / MITRE ATLAS / NIST AI RMF & Scheduled Audits",
  cybersuite: "Generalized Enterprise Cybersecurity Suite (40 Specialized Engines)",
  harness2: "Harness² Second-Order Adaptive Meta-Control Lab (23 Meta-Subsystems)",
};

const DOMAIN_ORDER = [
  "agent_isolation",
  "tool_execution",
  "memory",
  "prompt_injection",
  "api_security",
  "filesystem",
  "process_management",
  "supply_chain",
  "network",
  "rust_core",
];

function esc(val) {
  return String(val ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function showToast(msg, durationMs = 4200) {
  const el = document.getElementById("toastBox");
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => el.classList.remove("show"), durationMs);
}

async function apiGet(url) {
  const resp = await fetch(url, { headers: { Accept: "application/json" } });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
  return data;
}

async function apiPost(url, payload = {}) {
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
  return data;
}

function openModal(id) {
  document.getElementById(id).classList.add("open");
}

function closeModal(id) {
  document.getElementById(id).classList.remove("open");
}

function switchView(viewName) {
  state.activeView = viewName;
  document.querySelectorAll(".view-section").forEach((s) => s.classList.remove("active"));
  document.getElementById(`view-${viewName}`).classList.add("active");
  document.querySelectorAll(".nav-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.view === viewName);
  });
  document.getElementById("viewHeading").textContent = VIEW_TITLES[viewName] || viewName;
}

function sevBadge(sev) {
  const s = (sev || "info").toLowerCase();
  return `<span class="badge sev-${esc(s)}">${esc(s)}</span>`;
}

function statusBadge(st) {
  const s = (st || "").toLowerCase();
  if (s === "confirmed") return `<span class="badge badge-fail">CONFIRMED</span>`;
  if (s === "mitigated") return `<span class="badge badge-approved">MITIGATED</span>`;
  if (s === "false_positive") return `<span class="badge badge-muted">REJECTED FP</span>`;
  return `<span class="badge badge-info">${esc(s)}</span>`;
}

async function loadOverview(preferredRunId = null) {
  try {
    const ov = await apiGet("/api/overview");
    state.overview = ov;
    state.benchmark = ov.latest_benchmark || null;

    // Populate run selector
    const runSel = document.getElementById("runSelect");
    runSel.innerHTML = "";
    (ov.runs || []).forEach((r) => {
      const opt = document.createElement("option");
      opt.value = r.run_id;
      opt.textContent = `${r.target_version} | ${r.modality} | score ${Math.round(r.posture_score)} (${r.confirmed_count} conf)`;
      runSel.appendChild(opt);
    });

    // Populate domain filter dropdown once
    const domSel = document.getElementById("filterDomain");
    if (domSel.options.length <= 1) {
      DOMAIN_ORDER.forEach((d) => {
        const opt = document.createElement("option");
        opt.value = d;
        opt.textContent = d;
        domSel.appendChild(opt);
      });
    }

    const chosenId = preferredRunId || (ov.runs && ov.runs[0] ? ov.runs[0].run_id : null);
    if (chosenId) {
      runSel.value = chosenId;
      await selectRun(chosenId);
    } else {
      renderAll();
    }
  } catch (err) {
    showToast(`Failed loading SOE overview: ${err.message}`, 6000);
  }
}

async function selectRun(runId) {
  try {
    const detail = await apiGet(`/api/runs/${encodeURIComponent(runId)}`);
    state.activeRunId = runId;
    state.activeReport = detail.report;
    state.activeArtifacts = detail.artifacts || {};
    renderAll();
  } catch (err) {
    showToast(`Could not load run ${runId}: ${err.message}`, 5000);
  }
}

function renderAll() {
  renderTopbar();
  renderOverview();
  renderFindings();
  renderLifecycle();
  renderUntrustedAgents();
  renderBenchmark();
  renderAttackGraph();
  renderComplianceAndSchedules();
}

function renderTopbar() {
  const rep = state.activeReport;
  const metaEl = document.getElementById("topbarMeta");
  if (!rep) {
    metaEl.innerHTML = "<span>No runs persisted yet. Launch an isolated evaluation to begin.</span>";
    return;
  }
  const mat = rep.maturity || {};
  const verdict = (mat.verdict || "blocked").toUpperCase();
  metaEl.innerHTML = `
    <span>Target: <strong class="mono">${esc(rep.target_name)}@${esc(rep.target_version)}</strong></span>
    <span>Run: <strong class="mono">${esc(rep.run_id)}</strong></span>
    <span>Model: <strong class="mono">${esc(rep.model_id)}</strong></span>
    <span>Harness: <strong class="mono">${esc(rep.harness_profile)}</strong></span>
    <span>Modality: <strong class="mono">${esc(rep.modality)}</strong></span>
  `;

  const pillGate = document.getElementById("pillGate");
  pillGate.textContent = verdict;
  pillGate.style.color = verdict === "APPROVED" ? "#86efac" : verdict === "CONDITIONAL" ? "#fcd34d" : "#fca5a5";

  const confCount = (rep.findings || []).filter((f) => f.status === "confirmed").length;
  document.getElementById("pillFindings").textContent = String(confCount);

  const isoBadge = document.getElementById("isolationStatusBadge");
  isoBadge.innerHTML = rep.main_instance_untouched_verified
    ? `<span>&#9679;</span> Main Instance Untouched (SHA Verified)`
    : `<span>&#9679;</span> Integrity Check Pending`;
}

function renderOverview() {
  const rep = state.activeReport;
  const kpiStrip = document.getElementById("kpiStrip");
  if (!rep) {
    kpiStrip.innerHTML = `<div class="kpi-card"><div class="kpi-label">Status</div><div class="kpi-value">IDLE</div></div>`;
    return;
  }

  const findings = rep.findings || [];
  const confirmed = findings.filter((f) => f.status === "confirmed");
  const rejected = findings.filter((f) => f.status === "false_positive");
  const critHigh = confirmed.filter((f) => f.severity === "critical" || f.severity === "high").length;
  const mat = rep.maturity || { overall_score: 0, verdict: "blocked", criteria: [] };
  const passedCrit = (mat.criteria || []).filter((c) => c.passed).length;
  const snap = state.activeArtifacts?.snapshot_manifest || {};
  const postureScore = Number((rep.summary && rep.summary.security_posture_score) ?? rep.posture_score ?? 0);

  const scoreColor = mat.overall_score >= 85 ? "var(--emerald)" : mat.overall_score >= 60 ? "var(--amber)" : "var(--crimson)";
  const gateColor = mat.verdict === "approved" ? "var(--emerald)" : mat.verdict === "conditional" ? "var(--amber)" : "var(--crimson)";

  kpiStrip.innerHTML = `
    <div class="kpi-card">
      <div class="kpi-label">Ely 1.0 Maturity Gate</div>
      <div class="kpi-value" style="color:${gateColor}">${esc((mat.verdict || "blocked").toUpperCase())}</div>
      <div class="kpi-sub">${passedCrit}/${(mat.criteria || []).length} verifiable criteria passed (${Number(mat.overall_score || 0).toFixed(1)}/100)</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Security Posture Score</div>
      <div class="kpi-value" style="color:${scoreColor}">${postureScore.toFixed(1)}</div>
      <div class="kpi-sub">Severity-weighted validated posture</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Confirmed Vulnerabilities</div>
      <div class="kpi-value" style="color:${confirmed.length ? "var(--crimson)" : "var(--emerald)"}">${confirmed.length}</div>
      <div class="kpi-sub">${critHigh} Critical/High &middot; ${rejected.length} FPs filtered by Validator</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Snapshot Secret Scrubbing</div>
      <div class="kpi-value" style="color:var(--cyan)">${(snap.sensitive_files_stripped || []).length} / ${snap.inline_secrets_redacted || 0}</div>
      <div class="kpi-sub">Files excluded / inline secrets redacted</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Isolation &amp; Audit Proof</div>
      <div class="kpi-value" style="color:var(--emerald)">${rep.main_instance_untouched_verified && rep.sandbox_destroyed_verified ? "SEALED" : "CHECK"}</div>
      <div class="kpi-sub">Temp instance destroyed &middot; Merkle signed</div>
    </div>
  `;

  // 10-Domain bar chart
  const counts = {};
  DOMAIN_ORDER.forEach((d) => (counts[d] = 0));
  confirmed.forEach((f) => {
    counts[f.domain] = (counts[f.domain] || 0) + 1;
  });
  const maxC = Math.max(1, ...Object.values(counts));
  document.getElementById("domainChart").innerHTML = DOMAIN_ORDER.map((d) => {
    const c = counts[d] || 0;
    const pct = c === 0 ? 0 : Math.max(6, Math.round((c / maxC) * 100));
    const fill = c === 0 ? "var(--emerald)" : c >= 8 ? "var(--crimson)" : c >= 4 ? "var(--orange)" : "var(--amber)";
    return `
      <div class="domain-bar-row">
        <div class="domain-label">${esc(d)}</div>
        <div class="progress-track">
          <div class="progress-fill" style="width:${c === 0 ? 100 : pct}%; background:${fill}; opacity:${c === 0 ? 0.25 : 0.92};"></div>
        </div>
        <div class="mono" style="text-align:right; color:${c === 0 ? "var(--emerald)" : "#fff"}; font-weight:700;">${c}</div>
      </div>
    `;
  }).join("");

  // Version evolution diff card
  const diff = (state.activeArtifacts && state.activeArtifacts.version_comparison) || (state.overview && state.overview.version_diff);
  const vBadge = document.getElementById("versionTrajectoryBadge");
  const vBox = document.getElementById("versionDiffCard");
  if (diff && diff.baseline && diff.candidate) {
    const traj = diff.trajectory || "STABLE";
    vBadge.textContent = traj;
    vBadge.className = `badge ${traj === "IMPROVED" ? "badge-approved" : traj === "REGRESSED" ? "badge-fail" : "badge-info"}`;
    vBox.innerHTML = `
      <div class="grid-kpi" style="margin-bottom:12px;">
        <div class="criterion-card">
          <div class="kpi-label">Baseline (${esc(diff.baseline.version)})</div>
          <div class="mono" style="font-size:20px; font-weight:800; color:var(--crimson);">${diff.baseline.confirmed_count} confirmed</div>
          <div class="kpi-sub">Maturity: ${Number(diff.baseline.maturity_score).toFixed(1)} (${esc(diff.baseline.maturity_verdict)})</div>
        </div>
        <div class="criterion-card">
          <div class="kpi-label">Candidate (${esc(diff.candidate.version)})</div>
          <div class="mono" style="font-size:20px; font-weight:800; color:var(--emerald);">${diff.candidate.confirmed_count} confirmed</div>
          <div class="kpi-sub">Maturity: ${Number(diff.candidate.maturity_score).toFixed(1)} (${esc(diff.candidate.maturity_verdict)})</div>
        </div>
      </div>
      <div style="display:flex; gap:10px; flex-wrap:wrap; margin-bottom:10px;">
        <span class="badge badge-approved">Fixed: ${diff.fixed_count}</span>
        <span class="badge ${diff.newly_introduced_count ? "badge-fail" : "badge-muted"}">New: ${diff.newly_introduced_count}</span>
        <span class="badge badge-muted">Persistent: ${diff.persistent_count}</span>
        <span class="badge badge-info">Maturity &Delta;: ${diff.maturity_delta >= 0 ? "+" : ""}${diff.maturity_delta}</span>
      </div>
      <div class="panel-sub">All longitudinal runs are stored in SQLite for continuous Ely version regression tracking.</div>
    `;
  } else {
    vBadge.textContent = "SINGLE VERSION";
    vBox.innerHTML = `<div class="panel-sub">Run evaluations against two distinct versions (e.g., v0.9 and v1.0-rc1) to visualize security evolution diffs.</div>`;
  }

  // Maturity 9 criteria grid
  const verdictBadge = document.getElementById("maturityVerdictBadge");
  verdictBadge.textContent = `${(mat.verdict || "blocked").toUpperCase()} (${Number(mat.overall_score || 0).toFixed(1)}/100)`;
  verdictBadge.className = `badge ${mat.verdict === "approved" ? "badge-approved" : mat.verdict === "conditional" ? "badge-conditional" : "badge-blocked"}`;

  document.getElementById("maturityCriteriaGrid").innerHTML = (mat.criteria || [])
    .map((c) => {
      const checksHtml = (c.verification_checks || [])
        .map((ck) => `<div style="font-size:11px; color:${ck.passed ? "#86efac" : "#fca5a5"};">${ck.passed ? "&#10003;" : "&#10007;"} ${esc(ck.check)}</div>`)
        .join("");
      return `
        <div class="criterion-card ${c.passed ? "passed" : "failed"}">
          <div style="display:flex; justify-content:space-between; align-items:center; gap:8px;">
            <strong style="font-size:12.5px;">${esc(c.title || c.criterion_id)}</strong>
            <span class="badge ${c.passed ? "badge-pass" : "badge-fail"}">${Number(c.score).toFixed(0)}%</span>
          </div>
          <div class="progress-track">
            <div class="progress-fill" style="width:${Math.min(100, c.score)}%; background:${c.passed ? "var(--emerald)" : "var(--crimson)"};"></div>
          </div>
          <div style="font-size:11.5px; color:var(--text-secondary);">${esc(c.rationale)}</div>
          <div>${checksHtml}</div>
        </div>
      `;
    })
    .join("");
}

function renderFindings() {
  const rep = state.activeReport;
  const tbody = document.getElementById("findingsTableBody");
  if (!rep) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:var(--text-muted);">No findings available.</td></tr>`;
    return;
  }

  const all = rep.findings || [];
  const confirmedN = all.filter((f) => f.status === "confirmed").length;
  const fpN = all.filter((f) => f.status === "false_positive").length;
  const mitN = all.filter((f) => f.status === "mitigated").length;
  document.getElementById("validationRatioBadges").innerHTML = `
    <span class="badge badge-fail">Confirmed: ${confirmedN}</span>
    <span class="badge badge-muted">Rejected FP: ${fpN}</span>
    <span class="badge badge-approved">Mitigated: ${mitN}</span>
  `;

  const q = (document.getElementById("filterSearch").value || "").toLowerCase();
  const dom = document.getElementById("filterDomain").value;
  const sev = document.getElementById("filterSeverity").value;
  const st = document.getElementById("filterStatus").value;

  const filtered = all.filter((f) => {
    if (dom && f.domain !== dom) return false;
    if (sev && f.severity !== sev) return false;
    if (st && f.status !== st) return false;
    if (q) {
      const hay = `${f.title} ${f.rule_id} ${f.domain} ${(f.location || {}).file_path || ""} ${f.cwe_id || ""}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:24px; color:var(--emerald);">Zero findings match current filter criteria.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered
    .slice(0, 200)
    .map((f) => {
      const loc = f.location || {};
      const val = f.validation || {};
      const proof = val.signature ? `${val.signature.slice(0, 14)}...` : "Pending";
      return `
        <tr class="clickable-row" onclick="inspectFinding('${esc(f.finding_id)}')">
          <td>${sevBadge(f.severity)}</td>
          <td>${statusBadge(f.status)}</td>
          <td class="mono">${esc(f.domain)}</td>
          <td>
            <div style="font-weight:600; color:#fff;">${esc(f.title)}</div>
            <div class="mono" style="font-size:11px; color:var(--text-muted);">${esc(f.rule_id)} &middot; ${esc(f.cwe_id || "—")}</div>
          </td>
          <td class="mono" style="font-size:11.5px;">${esc(loc.file_path || "—")}:${loc.line_start || 1}</td>
          <td class="mono" style="font-weight:700;">${Number(f.cvss_score || 0).toFixed(1)}</td>
          <td class="mono" style="font-size:11px; color:var(--cyan);">${esc(proof)}</td>
          <td><button class="btn btn-sm" onclick="event.stopPropagation(); inspectFinding('${esc(f.finding_id)}')">Inspect</button></td>
        </tr>
      `;
    })
    .join("");
}

function inspectFinding(findingId) {
  const rep = state.activeReport;
  if (!rep) return;
  const f = (rep.findings || []).find((x) => x.finding_id === findingId);
  if (!f) return;

  document.getElementById("modalFindingTitle").textContent = f.title;
  document.getElementById("modalFindingMeta").textContent = `${f.finding_id} | ${f.rule_id} | ${f.domain} | CVSS ${f.cvss_score} (${f.cvss_vector || ""})`;

  const val = f.validation || {};
  const rem = f.remediation || {};
  const canPatchVerify = f.status === "confirmed" && !state.activeArtifacts?.restored_from_sqlite;

  document.getElementById("modalFindingBody").innerHTML = `
    <div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:14px;">
      ${sevBadge(f.severity)}
      ${statusBadge(f.status)}
      <span class="badge badge-info">Discovered by: ${esc(f.discovered_by)}</span>
      ${(f.owasp_agentic_ids || []).map((o) => `<span class="badge badge-muted">${esc(o)}</span>`).join("")}
      ${(f.mitre_atlas_ids || []).map((m) => `<span class="badge badge-muted">${esc(m)}</span>`).join("")}
    </div>
    <p style="margin-bottom:12px; color:var(--text-secondary);">${esc(f.description)}</p>
    <div class="grid-2" style="margin-bottom:12px;">
      <div class="criterion-card">
        <div class="kpi-label">Location &amp; Code Snippet</div>
        <div class="mono" style="font-size:12px; color:var(--cyan);">${esc((f.location || {}).file_path)}:${(f.location || {}).line_start || 1}</div>
        <div class="code-box" style="margin-top:6px;">${esc((f.location || {}).snippet || "—")}</div>
      </div>
      <div class="criterion-card">
        <div class="kpi-label">Independent Clean-Room Validator Proof</div>
        <div class="mono" style="font-size:11.5px;">
          Verdict: <strong>${esc((val.verdict || "pending").toUpperCase())}</strong> (${val.trials_reproduced || 0}/${val.trials_run || 0} trials)<br/>
          Validator: ${esc(val.validator_id || "—")}<br/>
          Oracle Proof: ${val.oracle_integrity_verified ? "VERIFIED" : "NONE"}<br/>
          Auditor HMAC: ${esc((val.signature || "—").slice(0, 28))}...
        </div>
        <div style="font-size:11.5px; color:var(--text-secondary); margin-top:6px;">${esc(val.notes || "")}</div>
      </div>
    </div>
    <div class="criterion-card" style="margin-bottom:12px;">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div class="kpi-label">Blue Team Remediation Proposal</div>
        ${
          canPatchVerify
            ? `<button class="btn btn-emerald btn-sm" id="btnPatchVerifyModal" onclick="verifyFindingPatch('${esc(f.finding_id)}')">Run Live Sandbox Patch Verification</button>`
            : ""
        }
      </div>
      <div style="font-size:12.5px; margin-top:4px;">${esc(rem.summary || "Apply defense-in-depth hardening for this domain.")}</div>
      ${rem.diff_preview ? `<div class="code-box" style="margin-top:8px;">${esc(rem.diff_preview)}</div>` : ""}
      <div id="patchVerifyResultSlot" style="margin-top:8px;"></div>
    </div>
  `;
  openModal("findingModal");
}

async function verifyFindingPatch(findingId) {
  const btn = document.getElementById("btnPatchVerifyModal");
  const slot = document.getElementById("patchVerifyResultSlot");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Synthesizing & Replaying PoC in Ephemeral Sandbox...";
  }
  try {
    const res = await apiPost("/api/frontier/patch-verify", {
      run_id: state.activeRunId,
      finding_id: findingId,
    });
    slot.innerHTML = `
      <div class="badge ${res.verified_mitigated ? "badge-approved" : "badge-conditional"}" style="margin-bottom:6px;">
        ${res.verified_mitigated ? "PATCH VERIFIED: POC NEUTRALIZED" : "MANUAL ARCHITECTURAL PATCH NEEDED"} (Quality ${(res.patch_quality_score * 100).toFixed(0)}%)
      </div>
      <div class="code-box">${esc(res.unified_diff || res.notes)}</div>
    `;
    showToast(res.verified_mitigated ? "Differential sandbox replay proved PoC neutralized!" : res.notes);
    if (res.verified_mitigated) {
      await selectRun(state.activeRunId);
    }
  } catch (err) {
    slot.innerHTML = `<span class="badge badge-fail">${esc(err.message)}</span>`;
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Run Live Sandbox Patch Verification";
    }
  }
}

function renderLifecycle() {
  const rep = state.activeReport;
  if (!rep) return;

  const snap = state.activeArtifacts?.snapshot_manifest || {};
  const badge = document.getElementById("lifecycleIntegrityBadge");
  badge.textContent = rep.main_instance_untouched_verified ? "MAIN INSTANCE UNTOUCHED (VERIFIED)" : "UNVERIFIED";
  badge.className = `badge ${rep.main_instance_untouched_verified ? "badge-approved" : "badge-fail"}`;

  document.getElementById("snapshotIsolationSummary").innerHTML = `
    <div class="grid-3" style="margin-bottom:0;">
      <div class="criterion-card passed">
        <div class="kpi-label">Snapshot ID &amp; Secret Scrubbing</div>
        <div class="mono" style="font-size:12px;">${esc(snap.snapshot_id || "—")}</div>
        <div class="kpi-sub">Copied: ${snap.files_copied || 0} files &middot; Scrubbed: ${(snap.sensitive_files_stripped || []).length} (.env/keys) &middot; Redactions: ${snap.inline_secrets_redacted || 0}</div>
      </div>
      <div class="criterion-card passed">
        <div class="kpi-label">Main Instance Pre/Post Tree SHA-256</div>
        <div class="mono" style="font-size:11px; color:var(--emerald); word-break:break-all;">${esc(snap.main_pre_digest || rep.snapshot_digest || "—")}</div>
        <div class="kpi-sub">Zero write permissions from Temporary Adversarial Instance</div>
      </div>
      <div class="criterion-card passed">
        <div class="kpi-label">Ephemeral Instance Disposal</div>
        <div class="mono" style="font-size:12px; color:var(--emerald);">${rep.sandbox_destroyed_verified ? "DESTROYED &amp; VERIFIED" : "PENDING"}</div>
        <div class="kpi-sub">Zero prod creds &middot; No external network &middot; One-way signed report only</div>
      </div>
    </div>
  `;

  document.getElementById("lifecycleTimeline").innerHTML = (rep.lifecycle_steps || [])
    .map(
      (s, i) => `
      <div class="step-card">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
          <span class="step-num">STEP ${i + 1} &middot; ${esc(s.stage)}</span>
          <span class="badge ${s.status === "completed" ? "badge-pass" : "badge-fail"}">${esc(s.status)}</span>
        </div>
        <div style="font-size:12px; color:var(--text-secondary); margin-bottom:6px;">Duration: <span class="mono">${Number(s.duration_ms || 0).toFixed(1)} ms</span></div>
        <div class="code-box" style="max-height:110px; font-size:10.5px;">${esc(JSON.stringify(s.details || {}, null, 2))}</div>
      </div>
    `
    )
    .join("");

  const att = {
    report_id: rep.report_id,
    merkle_root: rep.ledger_merkle_root,
    snapshot_digest: rep.snapshot_digest,
    report_signature: rep.report_signature,
    main_instance_untouched_verified: rep.main_instance_untouched_verified,
    sandbox_destroyed_verified: rep.sandbox_destroyed_verified,
    ledger_verification: state.activeArtifacts?.ledger_verification || {},
    report_verification: state.activeArtifacts?.report_verification || {},
  };
  document.getElementById("cryptoAttestationBox").textContent = JSON.stringify(att, null, 2);
}

function renderUntrustedAgents() {
  const rep = state.activeReport;
  if (!rep) return;

  const list = rep.untrusted_agent_results || [];
  const contained = list.filter((u) => u.contained).length;
  const badge = document.getElementById("agentContainmentBadge");
  badge.textContent = `${contained}/${list.length} ROGUE AGENTS CONTAINED`;
  badge.className = `badge ${contained === list.length && list.length > 0 ? "badge-approved" : "badge-fail"}`;
  document.getElementById("pillAgents").textContent = `${contained}/${list.length}`;

  document.getElementById("untrustedAgentsGrid").innerHTML = list
    .map(
      (u) => `
      <div class="criterion-card ${u.contained ? "passed" : "failed"}">
        <div style="display:flex; justify-content:space-between; gap:8px;">
          <strong class="mono" style="color:var(--cyan);">${esc(u.scenario_id)}</strong>
          <span class="badge ${u.contained ? "badge-pass" : "badge-fail"}">${u.contained ? "CONTAINED" : "BREACHED"}</span>
        </div>
        <div style="font-weight:700; font-size:13px;">${esc(u.title)}</div>
        <div style="font-size:11.5px; color:var(--text-secondary);">Actor: <span class="mono">${esc(u.malicious_actor)}</span> &middot; Domain: <span class="mono">${esc(u.domain)}</span></div>
        <div style="font-size:11.5px; color:${u.contained ? "#86efac" : "#fca5a5"};">${esc(u.outcome_summary || u.attack_attempted || "")}</div>
      </div>
    `
    )
    .join("");

  const drill = rep.blue_team_summary?.compromise_recovery_drill || state.activeArtifacts?.compromise_recovery || { note: "No recovery drill telemetry recorded." };
  document.getElementById("recoveryDrillBox").textContent = JSON.stringify(drill, null, 2);
}

function renderBenchmark() {
  const bench = state.benchmark;
  const kpiEl = document.getElementById("benchKpiStrip");
  const tbody = document.getElementById("benchTableBody");
  const stage = document.getElementById("benchChartStage");

  if (!bench || !bench.runs || !bench.runs.length) {
    kpiEl.innerHTML = `<div class="kpi-card"><div class="kpi-label">Benchmark</div><div class="kpi-value">NOT RUN</div></div>`;
    tbody.innerHTML = `<tr><td colspan="13" style="text-align:center;">Click "Re-Run 16-Cell Matrix" to run ELY-Bench-v1.0.</td></tr>`;
    stage.innerHTML = "";
    return;
  }

  document.getElementById("pillBench").textContent = String(bench.runs.length);
  const lift = bench.harness_lift_summary || {};
  const glmLift = lift.glm_5_3_harness_lift || {};
  const thesis = lift.glm_full_vs_frontier_bare || {};

  kpiEl.innerHTML = `
    <div class="kpi-card">
      <div class="kpi-label">GLM 5.3 F1 Lift (Bare &rarr; SOE)</div>
      <div class="kpi-value" style="color:var(--emerald)">+${Number((glmLift.delta_f1 || 0) * 100).toFixed(1)}%</div>
      <div class="kpi-sub">${Number((glmLift.bare_f1 || 0) * 100).toFixed(1)}% &rarr; ${Number((glmLift.full_harness_f1 || 0) * 100).toFixed(1)}% F1</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">GLM 5.3 + SOE Frontier Index</div>
      <div class="kpi-value" style="color:var(--cyan)">${Number(thesis.glm_full_composite || 0).toFixed(1)}</div>
      <div class="kpi-sub">vs Bare Frontier Cyber: ${Number(thesis.frontier_bare_composite || 0).toFixed(1)}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Harness Thesis Verified</div>
      <div class="kpi-value" style="color:${thesis.glm_with_soe_beats_bare_frontier ? "var(--emerald)" : "var(--amber)"}">${thesis.glm_with_soe_beats_bare_frontier ? "PROVEN" : "MIXED"}</div>
      <div class="kpi-sub">Advantage: +${Number(thesis.delta_composite || 0).toFixed(1)} pts over bare frontier</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Verified Reproducibility</div>
      <div class="kpi-value" style="color:var(--emerald)">${Number((glmLift.full_harness_reproducibility || 0) * 100).toFixed(0)}%</div>
      <div class="kpi-sub">vs 0% bare model (independent sandbox proof)</div>
    </div>
  `;

  // Render SVG Grouped Bar Chart comparing Bare Model vs Full SOE Harness Frontier Index
  const models = [...new Set(bench.runs.map((r) => r.model_id))];
  const barW = 48;
  const groupGap = 90;
  const svgW = Math.max(640, models.length * (barW * 2 + groupGap) + 120);
  const svgH = 230;
  let barsSvg = `<line x1="50" y1="190" x2="${svgW - 20}" y2="190" stroke="#334155" stroke-width="1"/>`;
  [0, 25, 50, 75, 100].forEach((tick) => {
    const y = 190 - tick * 1.55;
    barsSvg += `<line x1="50" y1="${y}" x2="${svgW - 20}" y2="${y}" stroke="rgba(148,163,184,0.12)" stroke-dasharray="3,3"/>`;
    barsSvg += `<text x="42" y="${y + 4}" text-anchor="end" fill="#64748b" font-size="10" font-family="monospace">${tick}</text>`;
  });

  models.forEach((m, idx) => {
    const bare = bench.runs.find((r) => r.model_id === m && r.harness_config === "bare_model");
    const full = bench.runs.find((r) => r.model_id === m && r.harness_config === "full_soe_harness");
    const x0 = 85 + idx * (barW * 2 + groupGap);
    const bareScore = bare ? bare.composite_frontier_index : 0;
    const fullScore = full ? full.composite_frontier_index : 0;
    const hBare = bareScore * 1.55;
    const hFull = fullScore * 1.55;

    barsSvg += `
      <rect x="${x0}" y="${190 - hBare}" width="${barW}" height="${hBare}" rx="5" fill="#475569"/>
      <text x="${x0 + barW / 2}" y="${184 - hBare}" text-anchor="middle" fill="#cbd5e1" font-size="11" font-family="monospace">${bareScore.toFixed(1)}</text>
      <rect x="${x0 + barW + 10}" y="${190 - hFull}" width="${barW}" height="${hFull}" rx="5" fill="url(#gradCyan)"/>
      <text x="${x0 + barW + 10 + barW / 2}" y="${184 - hFull}" text-anchor="middle" fill="#38bdf8" font-size="11" font-weight="700" font-family="monospace">${fullScore.toFixed(1)}</text>
      <text x="${x0 + barW + 5}" y="210" text-anchor="middle" fill="#e2e8f0" font-size="11.5" font-family="monospace">${esc(m)}</text>
    `;
  });

  stage.innerHTML = `
    <svg viewBox="0 0 ${svgW} ${svgH}" width="100%" height="${svgH}">
      <defs>
        <linearGradient id="gradCyan" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#38bdf8"/>
          <stop offset="100%" stop-color="#6366f1"/>
        </linearGradient>
      </defs>
      ${barsSvg}
      <rect x="${svgW - 265}" y="10" width="12" height="12" rx="2" fill="#475569"/>
      <text x="${svgW - 247}" y="20" fill="#94a3b8" font-size="11">bare_model</text>
      <rect x="${svgW - 150}" y="10" width="12" height="12" rx="2" fill="#38bdf8"/>
      <text x="${svgW - 132}" y="20" fill="#e2e8f0" font-size="11">full_soe_harness</text>
    </svg>
  `;

  const sorted = [...bench.runs].sort((a, b) => b.composite_frontier_index - a.composite_frontier_index);
  tbody.innerHTML = sorted
    .map(
      (r) => `
      <tr>
        <td class="mono" style="font-weight:700; color:#fff;">${esc(r.model_id)}</td>
        <td class="mono" style="color:${r.harness_config === "full_soe_harness" ? "var(--cyan)" : "var(--text-secondary)"};">${esc(r.harness_config)}</td>
        <td class="mono">${r.true_positives}</td>
        <td class="mono">${r.false_positives}</td>
        <td class="mono">${r.false_negatives}</td>
        <td class="mono">${(r.precision * 100).toFixed(1)}%</td>
        <td class="mono">${(r.recall * 100).toFixed(1)}%</td>
        <td class="mono" style="font-weight:700;">${(r.f1_score * 100).toFixed(1)}%</td>
        <td class="mono">${(r.false_discovery_rate * 100).toFixed(1)}%</td>
        <td class="mono" style="color:${r.reproducibility_rate > 0.8 ? "var(--emerald)" : "var(--text-muted)"};">${(r.reproducibility_rate * 100).toFixed(0)}%</td>
        <td class="mono">${(r.code_coverage_pct * 100).toFixed(0)}%</td>
        <td class="mono">${(r.patch_quality_score * 100).toFixed(0)}%</td>
        <td class="mono" style="font-weight:800; color:var(--cyan);">${Number(r.composite_frontier_index).toFixed(1)}</td>
      </tr>
    `
    )
    .join("");
}

function renderAttackGraph() {
  const ag = state.activeArtifacts?.attack_graph || {};
  const risk = Number(ag.composite_attack_graph_risk || 0);
  const badge = document.getElementById("graphRiskBadge");
  badge.textContent = `GRAPH RISK: ${risk.toFixed(1)} / 100`;
  badge.className = `badge ${risk >= 60 ? "badge-fail" : risk >= 20 ? "badge-conditional" : "badge-approved"}`;
  document.getElementById("pillGraph").textContent = `${risk.toFixed(0)}`;

  const nodes = ag.nodes || [];
  const edges = ag.edges || [];
  const stage = document.getElementById("attackGraphSvgStage");

  if (!edges.length) {
    stage.innerHTML = `<div style="padding:28px; text-align:center; color:var(--emerald); font-weight:600;">Zero exploitable multi-agent kill chains detected in this build (Attack Surface Contained).</div>`;
  } else {
    const tierX = { entry: 95, agent: 325, asset: 580, crown_jewel: 830 };
    const buckets = { entry: [], agent: [], asset: [], crown_jewel: [] };
    nodes.forEach((n) => (buckets[n.tier] || buckets.agent).push(n));

    const pos = {};
    Object.entries(buckets).forEach(([tier, arr]) => {
      arr.forEach((n, idx) => {
        pos[n.id] = { x: tierX[tier] || 320, y: 52 + idx * 78 };
      });
    });

    const maxY = Math.max(260, ...Object.values(pos).map((p) => p.y + 50));
    let svg = `<svg viewBox="0 0 960 ${maxY}" width="100%" height="${maxY}">
      <defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 1 L 10 5 L 0 9 z" fill="#f97316"/></marker></defs>`;

    edges.forEach((e) => {
      const a = pos[e.source];
      const b = pos[e.target];
      if (!a || !b) return;
      const stroke = e.severity === "critical" ? "#ef4444" : e.severity === "high" ? "#fb923c" : "#eab308";
      svg += `<line x1="${a.x + 68}" y1="${a.y}" x2="${b.x - 68}" y2="${b.y}" stroke="${stroke}" stroke-width="${1.2 + e.probability * 2.2}" stroke-opacity="0.72" marker-end="url(#arrow)"/>`;
    });

    nodes.forEach((n) => {
      const p = pos[n.id];
      const fill = n.tier === "crown_jewel" ? "#2e1065" : n.tier === "entry" ? "#172554" : "#0f172a";
      const stroke = n.tier === "crown_jewel" ? "#c084fc" : n.tier === "entry" ? "#38bdf8" : "#475569";
      svg += `
        <rect x="${p.x - 74}" y="${p.y - 22}" width="148" height="44" rx="9" fill="${fill}" stroke="${stroke}" stroke-width="1.4"/>
        <text x="${p.x}" y="${p.y - 3}" text-anchor="middle" fill="#f8fafc" font-size="10.5" font-weight="700">${esc(n.label.slice(0, 21))}</text>
        <text x="${p.x}" y="${p.y + 12}" text-anchor="middle" fill="#94a3b8" font-size="9" font-family="monospace">${esc(n.tier)}</text>
      `;
    });
    svg += `</svg>`;
    stage.innerHTML = svg;
  }

  document.getElementById("killChainsList").innerHTML = (ag.top_kill_chains || []).length
    ? (ag.top_kill_chains || [])
        .map(
          (kc) => `
          <div class="criterion-card failed" style="margin-bottom:8px;">
            <div style="display:flex; justify-content:space-between;">
              <strong class="mono">${esc((kc.nodes || []).join(" -> "))}</strong>
              <span class="badge badge-fail">P=${(kc.cumulative_probability * 100).toFixed(0)}%</span>
            </div>
            <div style="font-size:11.5px; color:var(--text-secondary);">Hops: ${kc.hop_count} &middot; Impact: ${kc.target_impact_weight} &middot; Expected Risk: ${kc.expected_risk}</div>
          </div>
        `
        )
        .join("")
    : `<div class="panel-sub">No active kill chains.</div>`;

  document.getElementById("chokepointsList").innerHTML = (ag.remediation_chokepoints || []).length
    ? (ag.remediation_chokepoints || [])
        .slice(0, 6)
        .map(
          (cp) => `
          <div class="criterion-card" style="margin-bottom:8px;">
            <div style="display:flex; justify-content:space-between;">
              <strong class="mono">${esc(cp.domain)}</strong>
              <span class="badge badge-info">Breaks ${cp.kill_chains_disrupted} chains</span>
            </div>
            <div style="font-size:11.5px; color:var(--text-secondary);">${esc(cp.recommendation)}</div>
          </div>
        `
        )
        .join("")
    : `<div class="panel-sub">No remediation chokepoints required.</div>`;
}

function renderComplianceAndSchedules() {
  const rep = state.activeReport;
  const runId = state.activeRunId || "";
  document.getElementById("exportRunLabel").textContent = runId || "none";

  const exportBar = document.getElementById("exportButtonsBar");
  if (runId) {
    exportBar.innerHTML = [
      ["json", "Download JSON Report"],
      ["markdown", "Download Markdown Brief"],
      ["sarif", "Download SARIF 2.1.0 (CI/CD)"],
      ["html", "Download Standalone HTML"],
      ["atlas", "Download MITRE ATLAS Layer"],
    ]
      .map(([fmt, label]) => `<a class="btn btn-primary" href="/api/export/${encodeURIComponent(runId)}/${fmt}" target="_blank">${label}</a>`)
      .join("");
  }

  const comp = state.activeArtifacts?.compliance || {};
  const owasp = comp.owasp_agentic_top_10 || [];
  document.getElementById("owaspMatrixBox").innerHTML = owasp.length
    ? owasp
        .map(
          (o) => `
          <div style="display:flex; justify-content:space-between; align-items:center; padding:7px 0; border-bottom:1px solid rgba(148,163,184,0.08);">
            <div><strong class="mono" style="color:var(--cyan);">${esc(o.code)}</strong> <span style="font-size:12px;">${esc(o.title)}</span></div>
            <span class="badge ${o.status === "COMPLIANT" ? "badge-pass" : o.status === "AT_RISK" ? "badge-conditional" : "badge-fail"}">${esc(o.status)} (${o.confirmed_findings})</span>
          </div>
        `
        )
        .join("")
    : `<div class="panel-sub">Run an active evaluation to inspect live OWASP Agentic Top 10 coverage.</div>`;

  const nist = comp.nist_ai_rmf_alignment || [];
  const eu = comp.eu_ai_act_art15_readiness || {};
  document.getElementById("nistEuBox").innerHTML = `
    <div style="margin-bottom:12px;">
      <div class="kpi-label" style="margin-bottom:6px;">EU AI Act Article 15 Readiness: ${Number(eu.readiness_pct || 0).toFixed(0)}%</div>
      ${(eu.checks || [])
        .map(
          (c) => `<div style="display:flex; justify-content:space-between; padding:5px 0; font-size:12px;">
            <span>${esc(c.article)}</span>
            <span class="badge ${c.ready ? "badge-pass" : "badge-fail"}">${c.ready ? "READY" : `${c.blocking_findings} BLOCKERS`}</span>
          </div>`
        )
        .join("")}
    </div>
    <div>
      <div class="kpi-label" style="margin-bottom:6px;">NIST AI RMF Controls</div>
      ${nist
        .map(
          (n) => `<div style="display:flex; justify-content:space-between; padding:5px 0; font-size:12px;">
            <span><strong class="mono">${esc(n.control_id)}</strong> ${esc(n.title)}</span>
            <span class="badge ${n.aligned ? "badge-pass" : "badge-fail"}">${esc(n.status)}</span>
          </div>`
        )
        .join("")}
    </div>
  `;

  const schedules = state.overview?.schedules || [];
  document.getElementById("schedulesTableWrap").innerHTML = schedules.length
    ? `<div class="table-wrap"><table><thead><tr><th>Schedule ID</th><th>Name</th><th>Model / Profile</th><th>Interval (min)</th><th>Last Run</th></tr></thead><tbody>
        ${schedules
          .map(
            (s) => `<tr>
              <td class="mono">${esc(s.schedule_id)}</td>
              <td>${esc(s.name)}</td>
              <td class="mono">${esc(s.model_id)} / ${esc(s.harness_profile)}</td>
              <td class="mono">${s.interval_minutes}</td>
              <td class="mono">${esc(s.last_run_at || "Never")}</td>
            </tr>`
          )
          .join("")}
      </tbody></table></div>`
    : `<div class="panel-sub">No scheduled audit policies registered yet.</div>`;
}

async function runFrontierTool(endpoint, payload) {
  const badge = document.getElementById("frontierStatusBadge");
  const title = document.getElementById("frontierResultTitle");
  const out = document.getElementById("frontierOutputBox");
  badge.textContent = "RUNNING...";
  badge.className = "badge badge-conditional";
  title.textContent = `Running /api/frontier/${endpoint}...`;
  try {
    const res = await apiPost(`/api/frontier/${endpoint}`, payload);
    badge.textContent = "COMPLETED";
    badge.className = "badge badge-approved";
    title.textContent = `Frontier Telemetry: /api/frontier/${endpoint}`;
    out.textContent = JSON.stringify(res, null, 2);
    showToast(`Frontier module '${endpoint}' completed successfully.`);
  } catch (err) {
    badge.textContent = "ERROR";
    badge.className = "badge badge-fail";
    out.textContent = err.message;
    showToast(`Frontier error: ${err.message}`, 5000);
  }
}

async function quickRunAudit(target, version, modality) {
  showToast(`Executing isolated ${modality} audit on ${version}...`);
  try {
    const res = await apiPost("/api/audits/run", {
      target_root: target,
      target_version: version,
      modality,
      model_id: "glm-5.3",
      harness_profile: modality === "pre_release" ? "frontier_deep" : "full_soe_harness",
      compare_with_version: version.startsWith("1.0") ? "0.9.0" : null,
    });
    showToast(`Completed ${version}: run ${res.run_id} (${res.report.maturity?.verdict?.toUpperCase() || "DONE"})`);
    await loadOverview(res.run_id);
  } catch (err) {
    showToast(`Audit failed: ${err.message}`, 6000);
  }
}

// Event Bindings
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.addEventListener("click", () => switchView(btn.dataset.view));
  });

  document.getElementById("runSelect").addEventListener("change", (e) => selectRun(e.target.value));
  ["filterSearch", "filterDomain", "filterSeverity", "filterStatus"].forEach((id) => {
    document.getElementById(id).addEventListener("input", renderFindings);
    document.getElementById(id).addEventListener("change", renderFindings);
  });

  document.getElementById("btnQuickV09").addEventListener("click", () =>
    quickRunAudit("lab_targets/ely_specimen/v0_9", "0.9.0", "pre_release")
  );
  document.getElementById("btnQuickV10").addEventListener("click", () =>
    quickRunAudit("lab_targets/ely_specimen/v1_0_hardened", "1.0.0-rc1", "pre_release")
  );
  document.getElementById("btnRefresh").addEventListener("click", () => loadOverview(state.activeRunId));
  document.getElementById("btnOpenLauncher").addEventListener("click", () => openModal("launcherModal"));

  document.getElementById("btnSubmitLaunch").addEventListener("click", async () => {
    const btn = document.getElementById("btnSubmitLaunch");
    btn.disabled = true;
    btn.textContent = "Running Isolated Lifecycle...";
    try {
      const res = await apiPost("/api/audits/run", {
        target_root: document.getElementById("launchTarget").value,
        modality: document.getElementById("launchModality").value,
        target_version: document.getElementById("launchVersion").value || "dev",
        model_id: document.getElementById("launchModel").value,
        harness_profile: document.getElementById("launchProfile").value,
      });
      closeModal("launcherModal");
      showToast(`Audit ${res.run_id} finished.`);
      await loadOverview(res.run_id);
    } catch (err) {
      showToast(`Audit error: ${err.message}`, 6000);
    } finally {
      btn.disabled = false;
      btn.textContent = "Execute Isolated Evaluation";
    }
  });

  document.getElementById("btnRunBenchmark").addEventListener("click", async () => {
    const btn = document.getElementById("btnRunBenchmark");
    btn.disabled = true;
    btn.textContent = "Running 16-Cell Matrix...";
    showToast("Running ELY-Bench-v1.0 comparative matrix across GLM 5.3 & Frontier models...");
    try {
      const res = await apiPost("/api/benchmarks/run", {});
      state.benchmark = res;
      renderBenchmark();
      showToast("Comparative Benchmark complete!");
    } catch (err) {
      showToast(`Benchmark error: ${err.message}`, 6000);
    } finally {
      btn.disabled = false;
      btn.textContent = "Re-Run 16-Cell Matrix";
    }
  });

  document.getElementById("btnTriggerSchedules").addEventListener("click", async () => {
    showToast("Executing due scheduled SOE audits...");
    try {
      const res = await apiPost("/api/schedules/run-due", { force_all: true });
      showToast(`Executed ${res.executed_count} scheduled audit(s).`);
      await loadOverview();
    } catch (err) {
      showToast(`Schedule trigger failed: ${err.message}`, 5000);
    }
  });

  loadOverview();
});
