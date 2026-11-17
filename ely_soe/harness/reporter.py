"""
Component 6 of the 6-Stage Security Harness: Multi-Format Security Reporter.

Produces comprehensive, tamper-evidenced Security Evaluation Reports delivered
one-way from the Temporary Adversarial Instance back to the Ely Main Instance:
  1. JSON Report (`report.json`) — complete machine-readable bundle with signatures & Merkle root
  2. Markdown Briefing (`report.md`) — executive summary, 10-domain posture table, Ely 1.0
     Maturity Gate scorecard, confirmed findings with CVSS/OWASP/MITRE/repro steps & diffs
  3. SARIF 2.1.0 (`report.sarif`) — industry-standard static/dynamic security interchange
     ready for GitHub Advanced Security / IDE / CI ingestion
  4. Standalone Interactive HTML (`report.html`) — self-contained dark-mode executive &
     engineering report requiring zero external CDN assets
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ely_soe.core.models import (
    Finding,
    FindingStatus,
    SecurityDomain,
    SecurityEvaluationReport,
    Severity,
)
from ely_soe.core.scoring import RiskScoringEngine


class SecurityReporter:
    """Renders signed `SecurityEvaluationReport` objects to JSON, Markdown, SARIF 2.1.0 & HTML."""

    def __init__(self) -> None:
        self.scorer = RiskScoringEngine()

    def write_all_formats(
        self,
        report: SecurityEvaluationReport,
        output_dir: Path,
    ) -> Dict[str, str]:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        paths: Dict[str, str] = {}

        json_path = out / f"{report.report_id}.json"
        md_path = out / f"{report.report_id}.md"
        sarif_path = out / f"{report.report_id}.sarif"
        html_path = out / f"{report.report_id}.html"

        json_path.write_text(self.to_json(report), encoding="utf-8")
        md_path.write_text(self.to_markdown(report), encoding="utf-8")
        sarif_path.write_text(self.to_sarif(report), encoding="utf-8")
        html_path.write_text(self.to_html(report), encoding="utf-8")

        paths["json"] = str(json_path)
        paths["markdown"] = str(md_path)
        paths["sarif"] = str(sarif_path)
        paths["html"] = str(html_path)
        return paths

    def to_json(self, report: SecurityEvaluationReport) -> str:
        return json.dumps(report.to_dict(), indent=2, sort_keys=False)

    def to_markdown(self, report: SecurityEvaluationReport) -> str:
        stats = report.summary_stats()
        domain_risk = self.scorer.aggregate_domain_risk(report.confirmed_findings)
        lines: List[str] = [
            f"# ELY Security Lab — Security Evaluation Report (`{report.report_id}`)",
            "",
            f"- **Target**: `{report.target_name}` (version `{report.target_version}`)",
            f"- **Modality**: `{report.modality.value}` | **Model**: `{report.model_id}` | **Harness**: `{report.harness_profile}`",
            f"- **Posture Score**: **{stats['security_posture_score']} / 100**",
            f"- **Ely 1.0 Maturity Gate**: **{stats['maturity_verdict'].upper()}** ({stats['maturity_score']} / 100)",
            f"- **Isolation Guarantees**: Sandbox Destroyed=`{report.sandbox_destroyed_verified}` | Main Instance Untouched=`{report.main_instance_untouched_verified}`",
            f"- **Cryptographic Attestation**: Merkle Root `{report.ledger_merkle_root[:24]}...` | Auditor Signature `{report.report_signature[:24]}...`",
            "",
            "## 1. Executive Summary",
            "",
            "| Metric | Count |",
            "| --- | ---: |",
            f"| Total Discovery Candidates (`HYPOTHESIS`) | {stats['total_candidates']} |",
            f"| Independently Confirmed (`CONFIRMED`) | **{stats['confirmed_count']}** |",
            f"| False Positives Filtered by Validator | {stats['false_positive_count']} |",
            f"| Mitigated & Verified (`MITIGATED`) | {stats['mitigated_count']} |",
            f"| Critical Confirmed | {stats['confirmed_by_severity']['critical']} |",
            f"| High Confirmed | {stats['confirmed_by_severity']['high']} |",
            f"| Medium Confirmed | {stats['confirmed_by_severity']['medium']} |",
            f"| Low Confirmed | {stats['confirmed_by_severity']['low']} |",
            "",
            "## 2. 10-Domain Security Posture Matrix",
            "",
            "| Domain | Confirmed Findings | Max CVSS | Avg Agentic Risk | Posture Score | Status |",
            "| --- | ---: | ---: | ---: | ---: | --- |",
        ]

        for d in SecurityDomain:
            info = domain_risk[d.value]
            lines.append(
                f"| {info['display_name']} | {info['finding_count']} | {info['max_cvss']} | "
                f"{info['avg_agentic_risk']} | {info['posture_score']}/100 | `{info['status'].upper()}` |"
            )

        if report.maturity is not None:
            lines.extend(
                [
                    "",
                    "## 3. Ely 1.0 Security Maturity Criteria (Verifiable Release Gate)",
                    "",
                    f"**Verdict**: `{report.maturity.verdict.value.upper()}` — Maturity Level **L{report.maturity.maturity_level}** "
                    f"({report.maturity.passed_count}/{len(report.maturity.criteria)} criteria passed)",
                    "",
                    "| Criterion | Status | Score | Level | Rationale |",
                    "| --- | --- | ---: | ---: | --- |",
                ]
            )
            for c in report.maturity.criteria:
                badge = "PASS" if c.passed else "FAIL"
                lines.append(f"| {c.title} | **{badge}** | {c.score:.1f} | L{c.level} | {c.rationale} |")

        if report.untrusted_agent_results:
            lines.extend(
                [
                    "",
                    "## 4. Zero-Trust Untrusted Internal Agent Simulations",
                    "",
                    "| Scenario | Title | Rogue Actor | Domain | Result |",
                    "| --- | --- | --- | --- | --- |",
                ]
            )
            for ua in report.untrusted_agent_results:
                status = "CONTAINED" if ua.get("contained") else "BREACHED"
                lines.append(
                    f"| `{ua.get('scenario_id')}` | {ua.get('title')} | `{ua.get('rogue_actor')}` | "
                    f"`{ua.get('domain')}` | **{status}** |"
                )

        lines.extend(["", "## 5. Independently Confirmed Findings & Verified Remediations", ""])
        confirmed = report.confirmed_findings
        if not confirmed:
            lines.append("_Zero confirmed vulnerabilities detected in this evaluation run._")
        else:
            for idx, f in enumerate(confirmed, start=1):
                lines.extend(self._finding_markdown_block(idx, f))

        if report.lifecycle_steps:
            lines.extend(
                [
                    "",
                    "## 6. 8-Stage Isolated Evaluation Lifecycle Audit Trail",
                    "",
                    "| Step | Stage | Status | Duration (ms) |",
                    "| ---: | --- | --- | ---: |",
                ]
            )
            for i, step in enumerate(report.lifecycle_steps, start=1):
                lines.append(f"| {i} | `{step.stage.value}` | `{step.status}` | {step.duration_ms:.2f} |")

        return "\n".join(lines) + "\n"

    def _finding_markdown_block(self, idx: int, f: Finding) -> List[str]:
        repro_str = (
            f"{f.validation.trials_reproduced}/{f.validation.trials_run} trials (cert `{f.validation.certificate_id}`)"
            if f.validation
            else "unvalidated"
        )
        block = [
            f"### {idx}. [{f.severity.value.upper()}] {f.title} (`{f.rule_id}`)",
            f"- **ID**: `{f.finding_id}` | **Domain**: `{f.domain.display_name}` | **Location**: `{f.location.file_path}:{f.location.line_start}`",
            f"- **CVSS v3.1**: `{f.cvss_score}` (`{f.cvss_vector}`) | **Agentic Risk**: `{f.agentic_risk_score}/10`",
            f"- **Taxonomies**: CWE={', '.join(f.cwe_ids)} | OWASP-Agentic={', '.join(f.owasp_agentic_ids)} | MITRE-ATLAS={', '.join(f.mitre_atlas_ids)}",
            f"- **Independent Validation**: {repro_str}",
            f"- **Description**: {f.description}",
            f"- **Impact**: {f.impact}",
        ]
        if f.location.snippet:
            block.append(f"- **Code Snippet**: `{f.location.snippet}`")
        if f.validation and f.validation.reproduction_steps:
            block.append("- **Controlled Reproduction Steps**:")
            for s in f.validation.reproduction_steps:
                block.append(f"  1. {s}")
        if f.remediation:
            block.append(f"- **Blue Team Remediation**: {f.remediation.summary}")
            block.append("```diff")
            block.append(f.remediation.diff_preview.strip())
            block.append("```")
        block.append("")
        return block

    def to_sarif(self, report: SecurityEvaluationReport) -> str:
        """Render confirmed (and high-confidence) findings into valid SARIF 2.1.0."""
        level_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        rules_by_id: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for f in report.findings:
            if f.status == FindingStatus.FALSE_POSITIVE:
                continue
            if f.rule_id not in rules_by_id:
                rules_by_id[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.title[:100],
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "properties": {
                        "domain": f.domain.value,
                        "cwe": f.cwe_ids,
                        "owasp_agentic": f.owasp_agentic_ids,
                        "mitre_atlas": f.mitre_atlas_ids,
                        "security-severity": str(f.cvss_score),
                    },
                }

            results.append(
                {
                    "ruleId": f.rule_id,
                    "level": level_map[f.severity],
                    "message": {
                        "text": f"[{f.status.value.upper()}] {f.title}: {f.description} (CVSS {f.cvss_score}, AgenticRisk {f.agentic_risk_score})"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.location.file_path},
                                "region": {
                                    "startLine": max(1, f.location.line_start),
                                    "snippet": {"text": f.location.snippet},
                                },
                            }
                        }
                    ],
                    "partialFingerprints": {"elySoeFingerprint/v1": f.fingerprint},
                    "properties": {
                        "finding_id": f.finding_id,
                        "status": f.status.value,
                        "domain": f.domain.value,
                        "cvss_score": f.cvss_score,
                        "agentic_risk_score": f.agentic_risk_score,
                        "validation_certificate_id": f.validation.certificate_id if f.validation else None,
                    },
                }
            )

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ELY Security Lab — SOE Harness",
                            "organization": "Photon Labs",
                            "version": "1.0.0",
                            "rules": list(rules_by_id.values()),
                        }
                    },
                    "results": results,
                    "properties": {
                        "report_id": report.report_id,
                        "target_version": report.target_version,
                        "model_id": report.model_id,
                        "harness_profile": report.harness_profile,
                        "ledger_merkle_root": report.ledger_merkle_root,
                        "report_signature": report.report_signature,
                    },
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    def to_html(self, report: SecurityEvaluationReport) -> str:
        """Render a standalone, zero-dependency interactive HTML security report."""
        stats = report.summary_stats()
        domain_risk = self.scorer.aggregate_domain_risk(report.confirmed_findings)

        domain_rows = []
        for d in SecurityDomain:
            info = domain_risk[d.value]
            color = "#22c55e" if info["status"] == "secure" else ("#f59e0b" if info["status"] == "warning" else "#ef4444")
            domain_rows.append(
                f"<tr><td>{html.escape(info['display_name'])}</td>"
                f"<td>{info['finding_count']}</td><td>{info['max_cvss']}</td>"
                f"<td>{info['avg_agentic_risk']}</td>"
                f"<td><span class='pill' style='background:{color}22;color:{color};border:1px solid {color}55'>"
                f"{info['posture_score']}/100 ({info['status'].upper()})</span></td></tr>"
            )

        finding_cards = []
        for f in report.confirmed_findings:
            sev_color = {
                Severity.CRITICAL: "#ef4444",
                Severity.HIGH: "#f97316",
                Severity.MEDIUM: "#eab308",
                Severity.LOW: "#38bdf8",
                Severity.INFO: "#94a3b8",
            }[f.severity]
            diff_html = ""
            if f.remediation:
                diff_html = f"<pre class='diff'>{html.escape(f.remediation.diff_preview)}</pre>"
            finding_cards.append(
                f"<div class='card'>"
                f"<div class='card-hd'><span class='pill' style='background:{sev_color}22;color:{sev_color}'>{f.severity.value.upper()}</span> "
                f"<strong>{html.escape(f.title)}</strong> <code>{html.escape(f.rule_id)}</code></div>"
                f"<p class='meta'>{html.escape(f.location.file_path)}:{f.location.line_start} &middot; "
                f"Domain: {html.escape(f.domain.display_name)} &middot; CVSS {f.cvss_score} &middot; "
                f"Agentic Risk {f.agentic_risk_score}/10</p>"
                f"<p>{html.escape(f.description)}</p>"
                f"{diff_html}</div>"
            )

        maturity_rows = []
        if report.maturity:
            for c in report.maturity.criteria:
                badge_col = "#22c55e" if c.passed else "#ef4444"
                maturity_rows.append(
                    f"<tr><td>{html.escape(c.title)}</td>"
                    f"<td><span class='pill' style='background:{badge_col}22;color:{badge_col}'>{'PASS' if c.passed else 'FAIL'}</span></td>"
                    f"<td>{c.score:.1f}</td><td>L{c.level}</td><td>{html.escape(c.rationale)}</td></tr>"
                )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>ELY Security Lab Report — {html.escape(report.report_id)}</title>
<style>
  body {{ font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; background:#0b1120; color:#e2e8f0; margin:0; padding:32px; line-height:1.5; }}
  .wrap {{ max-width:1180px; margin:0 auto; }}
  h1,h2 {{ color:#f8fafc; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:14px; margin:20px 0; }}
  .kpi {{ background:#111827; border:1px solid #1e293b; border-radius:10px; padding:16px; }}
  .kpi .lbl {{ font-size:12px; color:#94a3b8; text-transform:uppercase; letter-spacing:.05em; }}
  .kpi .val {{ font-size:26px; font-weight:700; margin-top:4px; color:#38bdf8; }}
  table {{ width:100%; border-collapse:collapse; margin:16px 0; background:#111827; border-radius:10px; overflow:hidden; }}
  th,td {{ padding:10px 12px; border-bottom:1px solid #1e293b; text-align:left; font-size:14px; }}
  th {{ background:#0f172a; color:#94a3b8; font-weight:600; }}
  .pill {{ display:inline-block; padding:2px 8px; border-radius:999px; font-size:12px; font-weight:600; }}
  .card {{ background:#111827; border:1px solid #1e293b; border-radius:10px; padding:16px; margin-bottom:14px; }}
  .meta {{ color:#94a3b8; font-size:13px; }}
  pre.diff {{ background:#020617; color:#cbd5e1; padding:12px; border-radius:8px; overflow-x:auto; font-size:12px; }}
  code {{ background:#1e293b; padding:2px 6px; border-radius:4px; font-size:12px; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>ELY Security Lab — Security Evaluation Report</h1>
  <p class="meta">Report <code>{html.escape(report.report_id)}</code> &middot; Target <code>{html.escape(report.target_name)}@{html.escape(report.target_version)}</code>
     &middot; Model <code>{html.escape(report.model_id)}</code> &middot; Harness <code>{html.escape(report.harness_profile)}</code></p>
  <div class="grid">
    <div class="kpi"><div class="lbl">Security Posture</div><div class="val">{stats['security_posture_score']}/100</div></div>
    <div class="kpi"><div class="lbl">Confirmed Vulns</div><div class="val" style="color:#ef4444">{stats['confirmed_count']}</div></div>
    <div class="kpi"><div class="lbl">FP Filtered</div><div class="val" style="color:#22c55e">{stats['false_positive_count']}</div></div>
    <div class="kpi"><div class="lbl">Ely 1.0 Maturity</div><div class="val">{html.escape(stats['maturity_verdict'].upper())}</div></div>
  </div>
  <h2>10-Domain Security Posture</h2>
  <table><thead><tr><th>Domain</th><th>Confirmed</th><th>Max CVSS</th><th>Agentic Risk</th><th>Posture</th></tr></thead>
  <tbody>{"".join(domain_rows)}</tbody></table>
  <h2>Ely 1.0 Security Maturity Criteria</h2>
  <table><thead><tr><th>Criterion</th><th>Status</th><th>Score</th><th>Level</th><th>Rationale</th></tr></thead>
  <tbody>{"".join(maturity_rows) or "<tr><td colspan='5'>Maturity gate not evaluated</td></tr>"}</tbody></table>
  <h2>Independently Confirmed Findings</h2>
  {"".join(finding_cards) or "<p>No confirmed vulnerabilities detected.</p>"}
  <p class="meta">Merkle Root: <code>{html.escape(report.ledger_merkle_root)}</code> &middot; Auditor Signature: <code>{html.escape(report.report_signature[:32])}...</code></p>
</div>
</body>
</html>"""
