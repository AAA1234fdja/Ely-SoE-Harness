"""
REST API Extension Controller for:
  1. Generalized Cybersecurity Suite (`ely_soe.cyber` — 40 specialized engines)
  2. Harness² Second-Order Adaptive Meta-Lab (`ely_soe.harness_squared` — 23 meta-subsystems, 30 stages)

Enforces strict authorized-path confinement (`repo_root`) before scanning any local target
and caches recent study/SARIF results thread-safely for interactive UI inspection & download.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ely_soe.core.models import utc_now_iso
from ely_soe.cyber.cicd_pipeline_graph_auditor import CICDPipelineGraphAuditor
from ely_soe.cyber.extended_suite_facade import EnterpriseCyberSuiteFacade
from ely_soe.cyber.models import AssetCriticality
from ely_soe.cyber.soar_incident_playbooks import CANONICAL_SOAR_PLAYBOOKS
from ely_soe.cyber.threat_hunting_sigma_yara_engine import ThreatHuntingSigmaYaraEngine
from ely_soe.harness_squared.distributed_fleet_scheduler import FleetRepositorySpec
from ely_soe.harness_squared.research_lab_facade import HarnessSquaredResearchLabFacade
from ely_soe.harness_squared.stage_registry import STAGE_CATALOG
from ely_soe.web.cyber_h2_store import CyberAndHarness2Store


TARGET_ALIASES: Dict[str, str] = {
    "v0_9": "lab_targets/ely_specimen/v0_9",
    "v0.9": "lab_targets/ely_specimen/v0_9",
    "v0.9.0": "lab_targets/ely_specimen/v0_9",
    "vulnerable": "lab_targets/ely_specimen/v0_9",
    "v1_0": "lab_targets/ely_specimen/v1_0_hardened",
    "v1.0": "lab_targets/ely_specimen/v1_0_hardened",
    "v1_0_hardened": "lab_targets/ely_specimen/v1_0_hardened",
    "hardened": "lab_targets/ely_specimen/v1_0_hardened",
}


class CyberAndHarness2ApiController:
    """Thread-safe service controller backing `/api/cyber/*` and `/api/h2/*` REST routes."""

    def __init__(self, repo_root: Path, data_dir: Optional[Path] = None) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.data_dir = Path(data_dir).resolve() if data_dir else (self.repo_root / ".ely_soe_data")
        self._lock = threading.RLock()
        self.cyber = EnterpriseCyberSuiteFacade()
        h2_db = self.data_dir / "harness2_meta_memory.sqlite"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.store = CyberAndHarness2Store(self.data_dir / "cyber_h2_history.sqlite")
        self.h2_lab = HarnessSquaredResearchLabFacade(memory_db_path=h2_db)
        self.cicd_auditor = CICDPipelineGraphAuditor()
        self.sigma_yara = ThreatHuntingSigmaYaraEngine()

        self._latest_cyber_scan: Optional[Dict[str, Any]] = None
        self._latest_enterprise_sim: Optional[Dict[str, Any]] = None
        self._latest_h2_study: Optional[Dict[str, Any]] = None
        self._latest_h2_sarif: Optional[Dict[str, Any]] = None
        self._soar_history: List[Dict[str, Any]] = []

    def _resolve_authorized_target(self, raw_target: Optional[str], default_alias: str = "v0_9") -> Path:
        key = (raw_target or default_alias).strip()
        mapped = TARGET_ALIASES.get(key.lower(), key)
        cand = Path(mapped)
        if not cand.is_absolute():
            cand = (self.repo_root / cand).resolve()
        else:
            cand = cand.resolve()
        if not cand.is_relative_to(self.repo_root):
            raise PermissionError(
                f"ScopeGuard violation: target `{raw_target}` escapes authorized repository sandbox `{self.repo_root}`."
            )
        if not cand.exists():
            raise FileNotFoundError(f"Authorized target path not found: `{mapped}`")
        return cand

    # ------------------------------------------------------------------
    # GENERALIZED CYBER SUITE ENDPOINTS (`/api/cyber/*`)
    # ------------------------------------------------------------------
    def get_cyber_catalog(self) -> Dict[str, Any]:
        cat = self.cyber.catalog_engines()
        cat["soar_playbooks"] = [
            {
                "playbook_id": pb.playbook_id,
                "name": pb.name,
                "severity_sla_minutes": pb.severity_sla_minutes,
                "step_count": len(pb.steps),
                "trigger_cwes": list(pb.trigger_cwes),
                "trigger_mitre_ids": list(pb.trigger_mitre_ids),
            }
            for pb in CANONICAL_SOAR_PLAYBOOKS.values()
        ]
        cat["has_cached_scan"] = self._latest_cyber_scan is not None
        cat["has_cached_enterprise_sim"] = self._latest_enterprise_sim is not None
        return cat

    def run_cyber_scan(self, body: Dict[str, Any]) -> Dict[str, Any]:
        target_path = self._resolve_authorized_target(body.get("target") or body.get("target_path") or "v0_9")
        run_range = bool(body.get("run_sandbox_range", False))
        hardened = bool(body.get("hardened_simulation", "hardened" in target_path.name.lower()))
        include_ext = bool(body.get("include_extended_analyzers", True))
        crit_raw = str(body.get("asset_criticality", "tier_1_production")).lower()
        crit_map = {c.value: c for c in AssetCriticality}
        crit = crit_map.get(crit_raw, AssetCriticality.TIER_1_PRODUCTION)

        with self._lock:
            res = self.cyber.run_unified_cyber_scan(
                str(target_path),
                target_name=str(body.get("target_name") or target_path.name),
                run_sandbox_range=run_range,
                hardened_simulation=hardened,
                include_extended_analyzers=include_ext,
                asset_criticality=crit,
            )
            scan_id = self.store.save_cyber_scan(res)
            res["scan_id"] = scan_id
            self._latest_cyber_scan = res
            return res

    def run_enterprise_sim(self, body: Dict[str, Any]) -> Dict[str, Any]:
        hardened = bool(body.get("hardened", False))
        with self._lock:
            res = self.cyber.run_enterprise_posture_simulation(hardened=hardened)
            self._latest_enterprise_sim = res
            return res

    def run_soar_playbook(self, body: Dict[str, Any]) -> Dict[str, Any]:
        pb_id = str(body.get("playbook_id", "PB-RANSOMWARE-ISOLATION"))
        incident_id = str(body.get("incident_id", f"INC-ELY-{len(self._soar_history) + 1:04d}"))
        target_asset = str(body.get("target_asset", "corp-dc-01"))
        dry_run = bool(body.get("dry_run", True))
        auto_approve = bool(body.get("auto_approve_hitl", False))
        with self._lock:
            res = self.cyber.execute_soar_playbook(
                playbook_id=pb_id,
                incident_id=incident_id,
                target_asset=target_asset,
                dry_run=dry_run,
                auto_approve_hitl=auto_approve,
            )
            self.store.save_soar_execution(res)
            self._soar_history.insert(0, res)
            self._soar_history = self._soar_history[:25]
            return res

    def run_sigma_yara_hunt(self, body: Dict[str, Any]) -> Dict[str, Any]:
        events = body.get("events")
        if not isinstance(events, list) or not events:
            events = [
                {"Image": "C:\\Windows\\powershell.exe", "CommandLine": "powershell -enc SQBFAFgA...", "User": "CORP\\alice"},
                {"CommandLine": "vssadmin delete shadows /all /quiet"},
                {"uri": "/fetch?url=http://169.254.169.254/latest/meta-data/iam/"},
                {"eventName": "AttachUserPolicy", "userAgent": "aws-cli/2.1"},
                {"verb": "create", "subresource": "exec", "namespace": "prod"},
                {"uri": "/healthz", "query": "ok=1"},
            ]
        sample_payload = str(body.get("yara_sample", '<?php eval($_POST["cmd"]); system($_GET["x"]); ?>')).encode("utf-8", errors="ignore")
        hunt_res = self.sigma_yara.hunt_log_stream(events)
        yara_res = self.sigma_yara.scan_bytes_yara(sample_payload, artifact_name=str(body.get("artifact_name", "uploaded_sample.php")))
        return {
            "executed_at": utc_now_iso(),
            "sigma_hunt": hunt_res,
            "yara_scan": yara_res,
        }

    def run_cicd_ppe_audit(self, body: Dict[str, Any]) -> Dict[str, Any]:
        yaml_text = body.get("workflow_yaml")
        if not isinstance(yaml_text, str) or not yaml_text.strip():
            yaml_text = (
                "on:\n"
                "  pull_request_target:\n"
                "permissions: write-all\n"
                "jobs:\n"
                "  build_pr:\n"
                "    runs-on: self-hosted\n"
                "    steps:\n"
                "      - uses: actions/checkout@v3\n"
                "        with:\n"
                "          ref: ${{ github.event.pull_request.head.sha }}\n"
                "      - uses: tj-actions/changed-files@v40\n"
                "      - run: echo \"PR: ${{ github.event.pull_request.title }}\"\n"
                "      - uses: actions/upload-artifact@v3\n"
                "  deploy_prod:\n"
                "    needs: [build_pr]\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/download-artifact@v3\n"
                "      - run: echo \"${{ secrets.AWS_SECRET_ACCESS_KEY }}\"\n"
            )
        rep = self.cicd_auditor.audit_github_workflow(yaml_text, file_path=str(body.get("file_path", ".github/workflows/ci.yml")))
        return {
            **{k: v for k, v in rep.items() if k != "vulnerabilities"},
            "total_findings": len(rep["vulnerabilities"]),
            "vulnerabilities": [v.to_dict() for v in rep["vulnerabilities"]],
        }

    # ------------------------------------------------------------------
    # HARNESS² SECOND-ORDER META-LAB ENDPOINTS (`/api/h2/*`)
    # ------------------------------------------------------------------
    def get_h2_catalog(self) -> Dict[str, Any]:
        cat = self.h2_lab.catalog_subsystems()
        cat["registered_first_order_stages_count"] = len(STAGE_CATALOG)
        cat["registered_first_order_stages"] = [
            {
                "adapter_name": s.adapter_name,
                "label": s.label,
                "category": s.category.value,
                "default_budget_ms": s.default_budget_ms,
                "description": s.description,
            }
            for s in STAGE_CATALOG.values()
        ]
        cat["has_cached_study"] = self._latest_h2_study is not None
        cat["has_cached_sarif"] = self._latest_h2_sarif is not None
        return cat

    def run_h2_complete_study(self, body: Dict[str, Any]) -> Dict[str, Any]:
        target_path = self._resolve_authorized_target(body.get("target") or body.get("target_path") or "v0_9")
        profile = str(body.get("preferred_profile") or body.get("profile") or "fast_ci")
        evolve = bool(body.get("evolve_pareto", True))
        budget_usd = float(body.get("defense_budget_usd") or body.get("budget_usd") or 35_000.0)
        impact_usd = float(body.get("breach_impact_usd", 6_000_000.0))

        with self._lock:
            study = self.h2_lab.run_complete_meta_study(
                str(target_path),
                target_name=str(body.get("target_name") or target_path.name),
                preferred_profile=profile,
                evolve_pareto=evolve,
                defense_budget_usd=budget_usd,
                breach_impact_usd=impact_usd,
            )
            self._latest_h2_sarif = study.get("sarif_v2_1")
            compact = {k: v for k, v in study.items() if k != "sarif_v2_1"}
            study_id = self.store.save_h2_study(compact, sarif_doc=self._latest_h2_sarif)
            compact["study_id"] = study_id
            self._latest_h2_study = compact
            return compact

    def run_h2_ab_lift(self, body: Dict[str, Any]) -> Dict[str, Any]:
        target_path = self._resolve_authorized_target(body.get("target") or body.get("target_path") or "v0_9")
        profile = str(body.get("preferred_profile") or body.get("profile") or "fast_ci")
        with self._lock:
            return self.h2_lab.run_ab_lift_benchmark(str(target_path), preferred_profile=profile)

    def run_h2_curriculum_bench(self, body: Dict[str, Any]) -> Dict[str, Any]:
        profile = str(body.get("preferred_profile", "fast_ci"))
        with self._lock:
            return self.h2_lab.run_multi_tier_curriculum_bench(preferred_profile=profile)

    def run_h2_adversarial_stress(self, body: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            return self.h2_lab.run_adversarial_evasion_stress()

    def run_h2_fleet_sweep(self, body: Dict[str, Any]) -> Dict[str, Any]:
        profile = str(body.get("force_profile", "fast_ci"))
        v09 = self._resolve_authorized_target("v0_9")
        v10 = self._resolve_authorized_target("v1_0_hardened")
        specs = [
            FleetRepositorySpec("ely-core-v0_9-vulnerable", str(v09), "core-platform", "tier0_crown_jewel", True, 350.0, ["ely-auth-sdk", "ely-py311-base"]),
            FleetRepositorySpec("ely-core-v1_0-hardened", str(v10), "security-eng", "tier1_prod", True, 300.0, ["ely-auth-sdk", "ely-py311-base"]),
        ]
        with self._lock:
            return self.h2_lab.run_fleet_sweep(specs, force_profile=profile)

    def run_h2_adtree_solve(self, body: Dict[str, Any]) -> Dict[str, Any]:
        budget_usd = float(body.get("defense_budget_usd") or body.get("budget_usd") or 35_000.0)
        impact_usd = float(body.get("breach_impact_usd", 6_000_000.0))
        with self._lock:
            if self._latest_h2_study and "harness2_run" in self._latest_h2_study:
                h2_run = self._latest_h2_study["harness2_run"]
            else:
                v09 = self._resolve_authorized_target(body.get("target", "v0_9"))
                h2_run = self.h2_lab.engine.run_adaptive_assessment(v09, target_name=v09.name, preferred_profile="fast_ci")
            return self.h2_lab.adtree_solver.build_and_solve_from_h2_run(
                h2_run,
                budget_usd=budget_usd,
                breach_impact_usd=impact_usd,
            )

    def export_latest_h2_sarif(self) -> Tuple[str, str, str]:
        with self._lock:
            if self._latest_h2_sarif is None:
                stored = self.store.get_latest_h2_sarif()
                if stored is not None:
                    self._latest_h2_sarif = stored
            if self._latest_h2_sarif is None:
                v09 = self._resolve_authorized_target("v0_9")
                h2_run = self.h2_lab.engine.run_adaptive_assessment(v09, target_name=v09.name, preferred_profile="fast_ci")
                self._latest_h2_sarif = self.h2_lab.governance.export_sarif_2_1(h2_run)
            return (
                json.dumps(self._latest_h2_sarif, indent=2),
                "application/sarif+json; charset=utf-8",
                "ely-harness2-report.sarif.json",
            )

    # ------------------------------------------------------------------
    # WAVE V CRITICAL ENDPOINTS (PERSISTENCE, AUTOPATCH, DAST, AI FIREWALL,
    # SYSTEMIC PORTFOLIO, COUNTERFACTUAL PLAN, DIAGNOSTICS, MONOTONICITY)
    # ------------------------------------------------------------------
    def get_history_summary(self) -> Dict[str, Any]:
        return self.store.get_history_summary()

    def diff_cyber_scans(self, body: Dict[str, Any]) -> Dict[str, Any]:
        b_id = str(body.get("baseline_scan_id", "")).strip()
        c_id = str(body.get("candidate_scan_id", "")).strip()
        if not b_id or not c_id:
            scans = self.store.list_cyber_scans(limit=2)
            if len(scans) < 2:
                raise ValueError("Provide `baseline_scan_id` and `candidate_scan_id` (or run at least 2 scans first).")
            c_id, b_id = scans[0]["scan_id"], scans[1]["scan_id"]
        return self.store.diff_cyber_scans(b_id, c_id)

    def run_verified_autopatch(self, body: Dict[str, Any]) -> Dict[str, Any]:
        target_path = self._resolve_authorized_target(body.get("target") or body.get("target_path") or "v0_9")
        with self._lock:
            res = self.cyber.run_verified_autopatch(str(target_path))
            self.store.save_autopatch_run(res)
            return res

    def run_dast_selfcheck(self, body: Dict[str, Any], *, default_base_url: str = "http://127.0.0.1:8080") -> Dict[str, Any]:
        base_url = str(body.get("target_url") or default_base_url).strip()
        return self.cyber.run_live_dast_scan(base_url)

    def run_llm_firewall(self, body: Dict[str, Any]) -> Dict[str, Any]:
        return self.cyber.run_llm_firewall_eval(
            prompt_text=body.get("prompt_text"),
            source_channel=str(body.get("source_channel", "user_prompt")),
            tool_name=body.get("tool_name"),
            tool_arguments=body.get("tool_arguments") if isinstance(body.get("tool_arguments"), dict) else None,
            caller_trust_level=str(body.get("caller_trust_level", "UNTRUSTED_DATA")),
        )

    def run_forensic_bundle(self, body: Dict[str, Any]) -> Dict[str, Any]:
        target_path = self._resolve_authorized_target(body.get("target") or body.get("target_path") or "v0_9")
        with self._lock:
            summary = self._latest_cyber_scan if (
                self._latest_cyber_scan and Path(str(self._latest_cyber_scan.get("target_path", ""))).resolve() == target_path
            ) else None
            bundle = self.cyber.build_signed_forensic_bundle(str(target_path), scan_summary=summary)
            return {k: v for k, v in bundle.items() if k != "executive_html_full"}

    def run_h2_systemic_portfolio(self, body: Dict[str, Any]) -> Dict[str, Any]:
        target_path = self._resolve_authorized_target(body.get("target") or body.get("target_path") or "v0_9")
        budget_usd = float(body.get("budget_usd") or body.get("defense_budget_usd") or 50_000.0)
        impact_usd = float(body.get("breach_impact_usd", 6_000_000.0))
        with self._lock:
            return self.h2_lab.run_systemic_defense_portfolio(
                str(target_path), budget_usd=budget_usd, breach_impact_usd=impact_usd
            )

    def run_h2_counterfactual_plan(self, body: Dict[str, Any]) -> Dict[str, Any]:
        target_path = self._resolve_authorized_target(body.get("target") or body.get("target_path") or "v0_9")
        target_posture = float(body.get("target_posture", 80.0))
        with self._lock:
            return self.h2_lab.run_counterfactual_remediation_plan(str(target_path), target_posture=target_posture)

    def run_h2_self_diagnostics(self) -> Dict[str, Any]:
        with self._lock:
            return self.h2_lab.run_self_diagnostics()

    def run_h2_synthesize_guardrails(self, body: Dict[str, Any]) -> Dict[str, Any]:
        target_path = self._resolve_authorized_target(body.get("target") or body.get("target_path") or "v0_9")
        max_rules = int(body.get("max_rules", 8))
        with self._lock:
            return self.h2_lab.synthesize_permanent_guardrails(str(target_path), max_rules=max_rules)

    def run_h2_monotonicity_proof(self, body: Dict[str, Any]) -> Dict[str, Any]:
        base_p = self._resolve_authorized_target(body.get("baseline") or "v0_9")
        cand_p = self._resolve_authorized_target(body.get("candidate") or "v1_0_hardened")
        with self._lock:
            return self.h2_lab.prove_version_monotonicity(str(base_p), str(cand_p))

    def run_h2_parallel_pareto(self, body: Dict[str, Any]) -> Dict[str, Any]:
        target_path = self._resolve_authorized_target(body.get("target") or body.get("target_path") or "v0_9")
        sla_ms = int(body.get("sla_budget_ms", 5000))
        max_stages = int(body.get("max_stages", 10))
        with self._lock:
            return self.h2_lab.run_pareto_parallel_schedule(
                str(target_path), sla_budget_ms=sla_ms, max_stages=max_stages
            )

    def run_cyber_dfir_timeline(self, body: Dict[str, Any]) -> Dict[str, Any]:
        events = body.get("events") if isinstance(body.get("events"), list) else None
        inc_id = str(body.get("incident_id", "INC-ELY-DFIR-001"))
        return self.cyber.correlate_dfir_timeline(events, incident_id=inc_id)
