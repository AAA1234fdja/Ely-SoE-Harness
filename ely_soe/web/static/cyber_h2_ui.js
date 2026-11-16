/* ELY Generalized Cyber Suite (40 Engines) & Harness² Second-Order Meta-Lab UI Module
 * Strictly uses relative `/api/...` paths for cloud/sandbox preview compatibility.
 */

const cyberH2State = {
  cyberCatalog: null,
  lastCyberScan: null,
  lastEnterpriseSim: null,
  lastSoarExec: null,
  h2Catalog: null,
  lastH2Study: null,
  lastH2AB: null,
  lastH2Bench: null,
  lastH2Stress: null,
  lastH2Fleet: null,
};

function fmtUsd(val) {
  const n = Number(val || 0);
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(1)}K`;
  return `$${n.toFixed(0)}`;
}

function fmtPct(val, digits = 1) {
  return `${Number(val || 0).toFixed(digits)}%`;
}

function renderBarRow(label, value, maxVal, colorClass, rightLabel) {
  const pct = Math.max(2, Math.min(100, (Number(value || 0) / Math.max(1e-6, maxVal)) * 100));
  return `
    <div class="bar-row">
      <div class="bar-row-head">
        <span class="bar-label">${esc(label)}</span>
        <span class="bar-val">${esc(rightLabel ?? value)}</span>
      </div>
      <div class="bar-track">
        <div class="bar-fill ${colorClass || "fill-cyan"}" style="width:${pct.toFixed(1)}%"></div>
      </div>
    </div>
  `;
}

/* ============================================================================
 * VIEW 9: GENERALIZED CYBER SUITE (40 ENGINES)
 * ============================================================================ */

async function initCyberSuiteView() {
  if (!cyberH2State.cyberCatalog) {
    try {
      cyberH2State.cyberCatalog = await apiGet("/api/cyber/catalog");
      renderCyberCatalog();
    } catch (err) {
      showToast(`Cyber catalog load error: ${err.message}`);
    }
  }
}

function renderCyberCatalog() {
  const cat = cyberH2State.cyberCatalog;
  if (!cat) return;
  const pill = document.getElementById("pillCyber");
  if (pill) pill.textContent = `${cat.total_specialized_engines} Eng`;

  const grid = document.getElementById("cyberCatalogGrid");
  if (grid) {
    const catEntries = Object.entries(cat.categories || {});
    grid.innerHTML = catEntries
      .map(
        ([name, count]) => `
        <div class="mini-card">
          <div class="mini-card-k">${esc(name)}</div>
          <div class="mini-card-v">${esc(count)} engines</div>
        </div>`
      )
      .join("");
  }

  const pbSel = document.getElementById("soarPlaybookSelect");
  if (pbSel && cat.soar_playbooks) {
    pbSel.innerHTML = cat.soar_playbooks
      .map(
        (pb) =>
          `<option value="${esc(pb.playbook_id)}">${esc(pb.playbook_id)} — ${esc(pb.name)} (SLA ${pb.severity_sla_minutes}m)</option>`
      )
      .join("");
  }

  const engTbl = document.getElementById("cyberEngineTableBody");
  if (engTbl && cat.engines) {
    engTbl.innerHTML = cat.engines
      .map(
        (e) => `
        <tr>
          <td><span class="badge sev-info">${esc(e.category)}</span></td>
          <td><code>${esc(e.name)}</code></td>
          <td>${esc(e.scope)}</td>
        </tr>`
      )
      .join("");
  }
}

async function runCyberUnifiedScan(targetAlias) {
  const btn = document.getElementById("cyberScanStatus");
  if (btn) btn.textContent = `Scanning ${targetAlias} across 16 core domains + Wave I–III-D analyzers...`;
  try {
    const res = await apiPost("/api/cyber/scan", {
      target: targetAlias,
      run_sandbox_range: false,
      include_extended_analyzers: true,
    });
    cyberH2State.lastCyberScan = res;
    renderCyberScanResult(res);
    showToast(`Cyber Scan complete (${res.target_name}): ${res.gate_verdict} — ${res.total_vulnerabilities} findings in ${res.duration_ms}ms`);
  } catch (err) {
    showToast(`Cyber Scan failed: ${err.message}`);
  } finally {
    if (btn) btn.textContent = "";
  }
}

function renderCyberScanResult(res) {
  const box = document.getElementById("cyberScanOutput");
  if (!box) return;
  const sev = res.severity_counts || {};
  const gateCls = res.gate_verdict === "APPROVED" ? "kpi-good" : "kpi-bad";
  const topVulns = (res.vulnerabilities || []).slice(0, 14);
  const compFrameworks = Object.entries(res.compliance_frameworks || {});

  box.innerHTML = `
    <div class="grid-kpi">
      <div class="kpi-card ${gateCls}">
        <div class="kpi-label">Cyber Gate Verdict</div>
        <div class="kpi-value">${esc(res.gate_verdict)}</div>
        <div class="kpi-sub">${esc(res.target_name)} (${res.duration_ms}ms)</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Total Findings</div>
        <div class="kpi-value">${esc(res.total_vulnerabilities)}</div>
        <div class="kpi-sub">Core ${res.core_vulnerabilities} + Ext ${res.extended_vulnerabilities_added}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Critical / High</div>
        <div class="kpi-value">${esc(sev.critical || 0)} / ${esc(sev.high || 0)}</div>
        <div class="kpi-sub">${esc(res.exploit_chains_count)} Exploit Chains</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Compliance Readiness</div>
        <div class="kpi-value">${fmtPct(res.compliance_readiness_pct)}</div>
        <div class="kpi-sub">WAF Patches: ${esc(res.waf_virtual_patches_synthesized)} · SOAR: ${(res.soar_recommended_playbooks || []).length}</div>
      </div>
    </div>

    <div class="grid-2" style="margin-top:14px">
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">7-Framework Compliance Readiness</div>
        </div>
        <div>
          ${compFrameworks
            .map(([fw, info]) => {
              const pct = typeof info === "object" ? (info.readiness_pct ?? info.score_pct ?? 0) : Number(info || 0);
              return renderBarRow(fw, pct, 100, pct >= 80 ? "fill-emerald" : pct >= 50 ? "fill-amber" : "fill-rose", fmtPct(pct));
            })
            .join("") || '<div class="muted">No framework telemetry</div>'}
        </div>
      </div>
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">Recommended SOAR Containment Playbooks</div>
        </div>
        <div class="stack-list">
          ${(res.soar_recommended_playbooks || [])
            .map(
              (pb) => `
              <div class="list-item">
                <div>
                  <strong>${esc(pb.playbook_id)}</strong> — ${esc(pb.name)}
                  <div class="muted">Matched CWEs: ${esc((pb.matched_cwes || []).join(", ") || "—")} · SLA ${pb.severity_sla_minutes}m</div>
                </div>
                <button class="btn btn-sm btn-primary" onclick="triggerSoarFromCard('${esc(pb.playbook_id)}')">Simulate</button>
              </div>`
            )
            .join("") || '<div class="muted">No emergency playbooks triggered.</div>'}
        </div>
      </div>
    </div>

    <div class="panel" style="margin-top:14px">
      <div class="panel-header">
        <div class="panel-title">Top Discovered Generalized Cyber Findings (${topVulns.length} of ${res.total_vulnerabilities})</div>
      </div>
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr><th>Severity</th><th>Rule ID</th><th>Title</th><th>CWE</th><th>Location</th></tr>
          </thead>
          <tbody>
            ${topVulns
              .map(
                (v) => `
                <tr>
                  <td>${sevBadge(v.severity)}</td>
                  <td><code>${esc(v.rule_id)}</code></td>
                  <td>${esc(v.title)}</td>
                  <td>${esc((v.cwe_ids || []).join(", "))}</td>
                  <td><code>${esc(v.file_path || v.endpoint_or_asset || "—")}</code></td>
                </tr>`
              )
              .join("")}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

async function runCyberEnterpriseSim(hardened) {
  const box = document.getElementById("cyberEnterpriseSimOutput");
  if (box) box.innerHTML = `<div class="muted">Running EASM + Ransomware BFS Contagion + 3-2-1-1-0 Backup + SaaS SSPM + OIDC + FAIR Monte-Carlo (1,200 trials) + Sigma F1...</div>`;
  try {
    const res = await apiPost("/api/cyber/enterprise-sim", { hardened });
    cyberH2State.lastEnterpriseSim = res;
    const fair = res.fair_financial_risk || {};
    const rans = res.ransomware_contagion || {};
    const easm = res.easm || {};
    const sspm = res.saas_sspm || {};
    const sig = res.sigma_detection_quality || {};
    const topCut = (rans.top_segmentation_chokepoints || [])[0];

    box.innerHTML = `
      <div class="grid-kpi">
        <div class="kpi-card ${hardened ? "kpi-good" : "kpi-bad"}">
          <div class="kpi-label">FAIR Mean Annual Loss (ALE)</div>
          <div class="kpi-value">${fmtUsd(fair.mean_ale_usd)}</div>
          <div class="kpi-sub">P95 VaR: ${fmtUsd((fair.percentiles_usd || {}).p95_var)}</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Ransomware Blast Radius</div>
          <div class="kpi-value">${fmtPct(rans.blast_radius_pct)}</div>
          <div class="kpi-sub">Tier-0 DC Hit: ${(rans.tier0_dc_compromised || []).length ? "YES" : "NO"} · Backup 3-2-1-1-0: ${fmtPct((res.backup_32110 || {}).resilience_score_pct)}</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">EASM &amp; SaaS SSPM</div>
          <div class="kpi-value">${esc(easm.exposure_grade || "—")} / ${fmtPct(sspm.overall_sspm_score_pct)}</div>
          <div class="kpi-sub">Shadow-IT: ${(easm.shadow_it_assets || []).length} · Total Findings: ${esc(res.total_enterprise_findings)}</div>
        </div>
        <div class="kpi-card kpi-good">
          <div class="kpi-label">Sigma Detection F1</div>
          <div class="kpi-value">${Number(sig.f1_score || 0).toFixed(3)}</div>
          <div class="kpi-sub">Precision ${Number(sig.precision || 0).toFixed(2)} · FPR ${Number(sig.false_positive_rate || 0).toFixed(2)}</div>
        </div>
      </div>
      ${
        topCut
          ? `<div class="callout-bar" style="margin-top:10px">
               <strong>#1 Ransomware Segmentation Chokepoint:</strong> Block edge <code>${esc(topCut.edge)}</code> (${esc(topCut.vector)}) to save <strong>${esc(topCut.hosts_saved_if_blocked)} hosts</strong> (<strong>-${fmtPct(topCut.blast_radius_reduction_pct)}</strong> blast radius).
             </div>`
          : ""
      }
    `;
    showToast(`Enterprise Posture Simulation (${res.mode}) finished in ${res.duration_ms}ms`);
  } catch (err) {
    if (box) box.innerHTML = `<div class="muted">Error: ${esc(err.message)}</div>`;
    showToast(`Enterprise Sim error: ${err.message}`);
  }
}

async function triggerSoarFromCard(playbookId) {
  const sel = document.getElementById("soarPlaybookSelect");
  if (sel) sel.value = playbookId;
  await runSoarExecution();
}

async function runSoarExecution() {
  const pbId = document.getElementById("soarPlaybookSelect")?.value || "PB-RANSOMWARE-ISOLATION";
  const asset = document.getElementById("soarTargetAsset")?.value || "corp-dc-01";
  const autoHitl = Boolean(document.getElementById("soarAutoHitl")?.checked);
  const out = document.getElementById("soarExecOutput");
  try {
    const res = await apiPost("/api/cyber/soar-execute", {
      playbook_id: pbId,
      target_asset: asset,
      dry_run: true,
      auto_approve_hitl: autoHitl,
    });
    cyberH2State.lastSoarExec = res;
    if (out) {
      out.innerHTML = `
        <div class="callout-bar">
          <strong>${esc(res.playbook_id)}</strong> on <code>${esc(res.target_asset)}</code> ·
          MTTR: <strong>${res.estimated_mttr_seconds}s</strong> (SLA ${res.sla_minutes}m ${res.sla_met ? "MET" : "BREACHED"}) ·
          HITL Paused: <strong>${res.steps_awaiting_hitl}</strong> ·
          Merkle Ledger: <code>${esc((res.ledger_merkle_root || "").slice(0, 16))}...</code> (${res.ledger_verified ? "VERIFIED" : "INVALID"})
        </div>
        <div class="table-wrap" style="margin-top:8px">
          <table class="data-table">
            <thead><tr><th>Step</th><th>Action</th><th>Title</th><th>Status</th><th>Rollback Plan</th></tr></thead>
            <tbody>
              ${(res.step_results || [])
                .map(
                  (s) => `
                  <tr>
                    <td><code>${esc(s.step_id)}</code></td>
                    <td><code>${esc(s.action_type)}</code></td>
                    <td>${esc(s.title)}</td>
                    <td><span class="badge ${s.status.includes("AWAITING") ? "sev-medium" : "sev-low"}">${esc(s.status)}</span></td>
                    <td class="muted">${esc(s.rollback_command)}</td>
                  </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>
      `;
    }
    showToast(`SOAR ${res.playbook_id} sealed to Merkle Ledger (${res.estimated_mttr_seconds}s MTTR)`);
  } catch (err) {
    showToast(`SOAR execution error: ${err.message}`);
  }
}

async function runCicdPpeDemo() {
  const out = document.getElementById("cicdSigmaOutput");
  try {
    const [cicd, hunt] = await Promise.all([
      apiPost("/api/cyber/cicd-audit", {}),
      apiPost("/api/cyber/sigma-hunt", {}),
    ]);
    if (out) {
      out.innerHTML = `
        <div class="grid-2">
          <div class="mini-panel">
            <div class="panel-title">CI/CD PPE Execution-Graph Audit</div>
            <div class="muted">Score: <strong>${cicd.pipeline_security_score}/100</strong> · Findings: <strong>${cicd.total_findings}</strong> · PPE Paths: <strong>${(cicd.ppe_attack_paths || []).length}</strong></div>
            <ul class="compact-list">
              ${(cicd.vulnerabilities || []).slice(0, 5).map((v) => `<li>${sevBadge(v.severity)} <code>${esc(v.rule_id)}</code> — ${esc(v.title)}</li>`).join("")}
            </ul>
          </div>
          <div class="mini-panel">
            <div class="panel-title">Live Sigma Log Hunt &amp; YARA Scanner</div>
            <div class="muted">Sigma Alerts: <strong>${hunt.sigma_hunt.alerts_triggered}</strong> across ${hunt.sigma_hunt.events_scanned} events · YARA Hits: <strong>${(hunt.yara_scan.yara_matches || []).length}</strong></div>
            <ul class="compact-list">
              ${(hunt.sigma_hunt.alerts || []).map((a) => `<li><span class="badge sev-${esc(a.level)}">${esc(a.mitre_technique)}</span> ${esc(a.title)}</li>`).join("")}
              ${(hunt.yara_scan.yara_matches || []).map((y) => `<li><span class="badge sev-critical">YARA</span> <code>${esc(y.rule)}</code> (${esc((y.matched_indicators || []).join(", "))})</li>`).join("")}
            </ul>
          </div>
        </div>
      `;
    }
    showToast(`CI/CD PPE (${cicd.total_findings} findings) & Sigma/YARA Hunt (${hunt.sigma_hunt.alerts_triggered} alerts) complete`);
  } catch (err) {
    showToast(`CI/CD & Sigma error: ${err.message}`);
  }
}

/* ============================================================================
 * VIEW 10: HARNESS² SECOND-ORDER META-CONTROL LAB (23 SUBSYSTEMS, 30 STAGES)
 * ============================================================================ */

async function initHarness2View() {
  if (!cyberH2State.h2Catalog) {
    try {
      cyberH2State.h2Catalog = await apiGet("/api/h2/catalog");
      renderH2Catalog();
    } catch (err) {
      showToast(`Harness² catalog error: ${err.message}`);
    }
  }
}

function renderH2Catalog() {
  const cat = cyberH2State.h2Catalog;
  if (!cat) return;
  const pill = document.getElementById("pillH2");
  if (pill) pill.textContent = `${cat.total_meta_subsystems} Meta`;

  const grid = document.getElementById("h2SubsystemsGrid");
  if (grid && cat.subsystems) {
    grid.innerHTML = cat.subsystems
      .map(
        (s) => `
        <div class="mini-card">
          <div class="mini-card-k">${esc(s.layer)}</div>
          <div class="mini-card-v" style="font-size:0.86rem">${esc(s.name)}</div>
          <div class="muted" style="font-size:0.75rem;margin-top:3px">${esc(s.role)}</div>
        </div>`
      )
      .join("");
  }
}

async function runH2CompleteStudy(targetAlias) {
  const status = document.getElementById("h2StatusLine");
  const budget = Number(document.getElementById("h2BudgetInput")?.value || 35000);
  if (status) status.textContent = `Executing Harness² Closed-Loop Meta-Study on ${targetAlias} (LinUCB + MAPE-K + Formal M1–M8 + Shapley + ADTree + Root-Cause + SARIF)...`;
  try {
    const res = await apiPost("/api/h2/study", {
      target: targetAlias,
      preferred_profile: "fast_ci",
      evolve_pareto: true,
      defense_budget_usd: budget,
      breach_impact_usd: 6000000,
    });
    cyberH2State.lastH2Study = res;
    renderH2Study(res);
    showToast(`Harness² Meta-Study complete in ${res.total_study_duration_ms}ms — Formal M1–M8: ${res.formal_meta_verification.overall_verdict}`);
  } catch (err) {
    showToast(`Harness² Study failed: ${err.message}`);
  } finally {
    if (status) status.textContent = "";
  }
}

function renderH2Study(study) {
  const box = document.getElementById("h2StudyOutput");
  if (!box) return;
  const run = study.harness2_run || {};
  const fv = study.formal_meta_verification || {};
  const causal = study.causal_shapley_attribution || {};
  const replay = study.replay_debugger || {};
  const playbook = study.autonomous_remediation_playbook || {};
  const adtree = study.attack_defense_tree_optimization || {};
  const rc = study.architectural_root_causes || {};
  const gov = study.policy_governance_gate || {};
  const mapek = run.mapek_adaptation || {};

  const shapStages = (causal.stage_attributions || []).slice(0, 8);
  const maxShap = Math.max(1, ...shapStages.map((s) => Number(s.shapley_yield || s.risk_weighted_yield || 0)));

  box.innerHTML = `
    <div class="grid-kpi">
      <div class="kpi-card ${fv.overall_verdict === "PROVEN_SAFE" ? "kpi-good" : "kpi-bad"}">
        <div class="kpi-label">Formal Meta-Verifier (M1–M8)</div>
        <div class="kpi-value">${esc(fv.overall_verdict)} (${fv.theorems_passed}/${fv.theorems_total})</div>
        <div class="kpi-sub">HMAC Signed: ${fv.signature_verified ? "VERIFIED" : "FAIL"} · ${esc(fv.certificate_id || "")}</div>
      </div>
      <div class="kpi-card ${run.gate_verdict === "APPROVED" ? "kpi-good" : "kpi-bad"}">
        <div class="kpi-label">Harness² Gate &amp; Governance</div>
        <div class="kpi-value">${esc(run.gate_verdict)} / ${esc(gov.governance_verdict)}</div>
        <div class="kpi-sub">${run.total_vulnerabilities} Vulns · ${mapek.total_adaptations_applied || 0} Live MAPE-K Adaptations</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">ADTree Optimal Defense</div>
        <div class="kpi-value">-${fmtPct(adtree.relative_risk_reduction_pct, 2)} Risk</div>
        <div class="kpi-sub">Spend ${fmtUsd(adtree.optimal_defense_spend_usd)} / ${fmtUsd(adtree.budget_usd)} · Avoided ${fmtUsd(adtree.expected_loss_avoided_usd)}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Root-Cause Compression</div>
        <div class="kpi-value">${esc(rc.whack_a_mole_compression_ratio)}x</div>
        <div class="kpi-sub">${rc.total_findings_analyzed} raw &rarr; ${rc.systemic_root_causes_identified} blueprints · SARIF: ${(study.sarif_v2_1_summary || {}).results_count}</div>
      </div>
    </div>

    <div class="grid-2" style="margin-top:14px">
      <div class="panel">
        <div class="panel-header">
          <div>
            <div class="panel-title">Exact Shapley Stage Causal Attribution</div>
            <div class="panel-sub">Total Yield: ${Number(causal.total_coalition_risk_yield || 0).toFixed(1)} · Adaptive Lift: +${Number(causal.adaptive_counterfactual_lift || 0).toFixed(1)} · Efficiency Err: ${Number(causal.efficiency_check_error || 0).toFixed(6)}</div>
          </div>
        </div>
        <div>
          ${shapStages
            .map((s) =>
              renderBarRow(
                `${s.stage_id} (${Number(s.elapsed_ms || 0).toFixed(0)}ms)`,
                s.shapley_yield ?? s.risk_weighted_yield ?? 0,
                maxShap,
                "fill-cyan",
                `${Number(s.shapley_yield ?? s.risk_weighted_yield ?? 0).toFixed(1)} yield`
              )
            )
            .join("")}
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <div>
            <div class="panel-title">Formal M1–M8 Theorems &amp; Replay Counterfactual</div>
            <div class="panel-sub">Replay Tape: ${replay.total_ticks || 0} ticks · Top-stage ablation impact: ${esc((replay.counterfactual_top_stage_ablation || {}).findings_lost ?? 0)} findings lost</div>
          </div>
          <a class="btn btn-sm btn-emerald" href="/api/h2/latest-sarif" download="ely-harness2-report.sarif.json">Export SARIF 2.1</a>
        </div>
        <div class="stack-list">
          ${(fv.theorem_results || [])
            .map(
              (t) => `
              <div class="list-item">
                <span><code>${esc(t.theorem_id)}</code> ${esc(t.name)}</span>
                <span class="badge ${t.passed ? "sev-low" : "sev-critical"}">${t.passed ? "PROVEN" : "VIOLATED"}</span>
              </div>`
            )
            .join("")}
        </div>
      </div>
    </div>

    <div class="grid-2" style="margin-top:14px">
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">Cognitive Architectural Root-Cause Blueprints (${rc.systemic_root_causes_identified})</div>
        </div>
        <div class="stack-list">
          ${(rc.architectural_blueprints || [])
            .map(
              (b) => `
              <div class="list-item" style="flex-direction:column;align-items:flex-start;gap:4px">
                <div><strong>${esc(b.archetype_id)}</strong> — ${esc(b.title)} <span class="badge sev-high">-${esc(b.findings_eliminated)} findings (${fmtPct(b.risk_mass_eliminated_pct)})</span></div>
                <div class="muted">${esc(b.secure_by_construction_blueprint)}</div>
              </div>`
            )
            .join("")}
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">Autonomous Weighted Set-Cover Remediation Playbook (Top 6)</div>
        </div>
        <div class="table-wrap">
          <table class="data-table">
            <thead><tr><th>Ticket</th><th>Risk Cut</th><th>Effort</th><th>Title</th></tr></thead>
            <tbody>
              ${(playbook.ordered_playbook || playbook.tickets || [])
                .slice(0, 6)
                .map(
                  (t) => `
                  <tr>
                    <td><code>${esc(t.ticket_id || t.rule_id)}</code></td>
                    <td>${fmtPct(t.risk_reduction_pct || t.cumulative_risk_eliminated_pct || 0)}</td>
                    <td>${esc(t.effort_hours || t.estimated_hours || "—")}h</td>
                    <td>${esc((t.title || "").slice(0, 70))}</td>
                  </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

async function runH2Experiment(kind) {
  const out = document.getElementById("h2ExperimentsOutput");
  if (out) out.innerHTML = `<div class="muted">Running Harness² ${esc(kind)} experiment...</div>`;
  try {
    if (kind === "ab-lift") {
      const r = await apiPost("/api/h2/ab-lift", { target: "v0_9", preferred_profile: "fast_ci" });
      cyberH2State.lastH2AB = r;
      const st = r.static_baseline || {};
      const ad = r.adaptive_harness_squared || {};
      const lift = r.lift_metrics || {};
      out.innerHTML = `
        <div class="panel-title" style="margin-bottom:8px">Controlled Static vs. Adaptive Harness² A/B Lift Benchmark (v0_9)</div>
        <div class="table-wrap">
          <table class="data-table">
            <thead><tr><th>Metric</th><th>Static First-Order Baseline</th><th>Adaptive Harness²</th><th>Delta / Lift</th></tr></thead>
            <tbody>
              <tr><td>Total Vulnerabilities</td><td>${st.total_vulnerabilities}</td><td><strong>${ad.total_vulnerabilities}</strong></td><td><span class="badge sev-low">+${lift.vuln_discovery_lift_pct}%</span></td></tr>
              <tr><td>Critical Findings</td><td>${st.critical_count}</td><td><strong>${ad.critical_count}</strong></td><td>+${(ad.critical_count || 0) - (st.critical_count || 0)}</td></tr>
              <tr><td>Risk-Weighted Yield</td><td>${st.risk_weighted_yield}</td><td><strong>${ad.risk_weighted_yield}</strong></td><td><span class="badge sev-low">+${lift.risk_yield_lift_pct}%</span></td></tr>
              <tr><td>Exploit Chains</td><td>${st.exploit_chains}</td><td><strong>${ad.exploit_chains}</strong></td><td>+${(ad.exploit_chains || 0) - (st.exploit_chains || 0)}</td></tr>
              <tr><td>Live MAPE-K Adaptations</td><td>0</td><td><strong>${ad.adaptations_applied}</strong></td><td>Safety Invariants Preserved: ${r.safety_invariants_preserved ? "TRUE" : "FALSE"}</td></tr>
            </tbody>
          </table>
        </div>
      `;
    } else if (kind === "curriculum") {
      const r = await apiPost("/api/h2/curriculum-bench", { preferred_profile: "fast_ci" });
      cyberH2State.lastH2Bench = r;
      const agg = r.aggregate_metrics || r;
      out.innerHTML = `
        <div class="panel-title" style="margin-bottom:8px">5-Tier Multi-Objective Synthetic Curriculum &amp; Pareto Hypervolume Benchmark</div>
        <div class="grid-kpi">
          <div class="kpi-card kpi-good"><div class="kpi-label">Adaptive CWE Recall</div><div class="kpi-value">${fmtPct(agg.adaptive_avg_cwe_recall_pct)}</div><div class="kpi-sub">vs Static ${fmtPct(agg.static_avg_cwe_recall_pct)}</div></div>
          <div class="kpi-card kpi-good"><div class="kpi-label">Adaptive Yield Lift</div><div class="kpi-value">+${fmtPct(agg.avg_yield_lift_pct)}</div><div class="kpi-sub">Gate Acc: ${fmtPct(agg.gate_accuracy_pct)}</div></div>
          <div class="kpi-card kpi-good"><div class="kpi-label">M1–M8 Formal Proof Rate</div><div class="kpi-value">${fmtPct(agg.meta_safety_proof_rate_pct)}</div><div class="kpi-sub">2D Pareto Hypervolume: ${Number(agg.pareto_hypervolume_2d || 0).toFixed(4)}</div></div>
        </div>
      `;
    } else if (kind === "stress") {
      const r = await apiPost("/api/h2/adversarial-stress", {});
      cyberH2State.lastH2Stress = r;
      out.innerHTML = `
        <div class="panel-title" style="margin-bottom:8px">Self-Adversarial Evasion Stress-Test ("Red-Teaming the Harness")</div>
        <div class="callout-bar" style="margin-bottom:10px">
          Baseline Detection: <strong>${fmtPct(r.baseline_detection_rate_pct)}</strong> &rarr;
          Evasive Mutant Resilience: <strong>${fmtPct(r.evasion_resilience_rate_pct)}</strong> ·
          Blind Spots Auto-Discovered: <strong>${r.blind_spot_count}</strong> (${r.duration_ms}ms)
        </div>
        <div class="table-wrap">
          <table class="data-table">
            <thead><tr><th>Case</th><th>Evasion Transform</th><th>Baseline</th><th>Mutant</th><th>Status</th></tr></thead>
            <tbody>
              ${(r.case_results || [])
                .map(
                  (c) => `
                  <tr>
                    <td><code>${esc(c.case_id)}</code></td>
                    <td>${esc(c.evasion_family)}</td>
                    <td>${c.baseline_caught ? "CAUGHT" : "MISS"}</td>
                    <td>${c.mutant_caught ? "CAUGHT" : "EVADED"}</td>
                    <td><span class="badge ${c.status === "RESILIENT" ? "sev-low" : "sev-critical"}">${esc(c.status)}</span></td>
                  </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>
      `;
    } else if (kind === "fleet") {
      const r = await apiPost("/api/h2/fleet-sweep", { force_profile: "fast_ci" });
      cyberH2State.lastH2Fleet = r;
      out.innerHTML = `
        <div class="panel-title" style="margin-bottom:8px">Distributed Multi-Repo Fleet Sweep &amp; Shared-Dependency Blast Radius</div>
        <div class="callout-bar" style="margin-bottom:10px">
          Repos Assessed: <strong>${r.fleet_repos_assessed}</strong> · Fleet Avg Posture: <strong>${r.fleet_avg_posture}/100</strong> ·
          Blocked Repos: <strong>${r.fleet_blocked_repos}</strong> · Systemic Shared-Dep Hotspots: <strong>${(r.systemic_dependency_hotspots || []).length}</strong>
        </div>
        <div class="table-wrap">
          <table class="data-table">
            <thead><tr><th>Repository</th><th>Team</th><th>Tier</th><th>Gate</th><th>Posture</th><th>Findings</th></tr></thead>
            <tbody>
              ${(r.repo_outcomes || [])
                .map(
                  (o) => `
                  <tr>
                    <td><code>${esc(o.repo_id)}</code></td>
                    <td>${esc(o.owner_team)}</td>
                    <td>${esc(o.tier)}</td>
                    <td><span class="badge ${o.gate_verdict === "APPROVED" ? "sev-low" : "sev-critical"}">${esc(o.gate_verdict)}</span></td>
                    <td>${o.overall_cyber_posture}</td>
                    <td>${o.total_vulnerabilities} (${o.critical_count} crit)</td>
                  </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>
      `;
    }
    showToast(`Harness² ${kind} experiment completed`);
  } catch (err) {
    if (out) out.innerHTML = `<div class="muted">Error: ${esc(err.message)}</div>`;
    showToast(`Harness² ${kind} error: ${err.message}`);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  // Hook View 9 & View 10 navigation triggers & action buttons
  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (btn.dataset.view === "cybersuite") initCyberSuiteView();
      if (btn.dataset.view === "harness2") initHarness2View();
    });
  });

  document.getElementById("btnCyberScanV09")?.addEventListener("click", () => runCyberUnifiedScan("v0_9"));
  document.getElementById("btnCyberScanV10")?.addEventListener("click", () => runCyberUnifiedScan("v1_0_hardened"));
  document.getElementById("btnCyberSimVuln")?.addEventListener("click", () => runCyberEnterpriseSim(false));
  document.getElementById("btnCyberSimHard")?.addEventListener("click", () => runCyberEnterpriseSim(true));
  document.getElementById("btnSoarRun")?.addEventListener("click", () => runSoarExecution());
  document.getElementById("btnCicdSigmaRun")?.addEventListener("click", () => runCicdPpeDemo());

  document.getElementById("btnH2StudyV09")?.addEventListener("click", () => runH2CompleteStudy("v0_9"));
  document.getElementById("btnH2StudyV10")?.addEventListener("click", () => runH2CompleteStudy("v1_0_hardened"));
  document.getElementById("btnH2ExpAB")?.addEventListener("click", () => runH2Experiment("ab-lift"));
  document.getElementById("btnH2ExpCurr")?.addEventListener("click", () => runH2Experiment("curriculum"));
  document.getElementById("btnH2ExpStress")?.addEventListener("click", () => runH2Experiment("stress"));
  document.getElementById("btnH2ExpFleet")?.addEventListener("click", () => runH2Experiment("fleet"));
});
