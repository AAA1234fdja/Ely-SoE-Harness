"""
Harness² Declarative Security Workflow Policy Compiler & Custom Genome DSL.

Compiles structured organization security-testing policies (e.g., CI-Fast Gate,
PCI-DSS Pre-Release Audit, Cloud-Native Red-Team Sprint, AI Agent Launch Gate)
into formally validated `HarnessGenome` + `MAPEKRule` execution bundles, rejecting
any policy directive that attempts to weaken first-order ELY safety invariants.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import new_id
from ely_soe.harness_squared.mapek_controller import BUILTIN_MAPEK_RULES, MAPEKRule
from ely_soe.harness_squared.models import AdaptationActionType, HarnessGenome
from ely_soe.harness_squared.safety_invariant_guard import MetaSafetyInvariantGuard
from ely_soe.harness_squared.stage_registry import STAGE_CATALOG


BUILT_IN_POLICY_PRESETS: Dict[str, Dict[str, Any]] = {
    "pci_dss_release_gate": {
        "name": "PCI-DSS v4.0 Mandatory Pre-Release Security Gate",
        "profile_family": "compliance_audit",
        "stages": [
            "web_injection", "web_client_protocol", "web_ssrf_deser", "auth_access",
            "secrets_dlp", "tls_crypto", "supply_chain_sbom", "network_zero_trust",
            "live_sandbox_dast",
        ],
        "total_budget_ms": 35_000,
        "drilldown_aggressiveness": 0.78,
        "prune_threshold_yield": 0.04,
        "max_adaptation_rounds": 10,
    },
    "ai_agent_launch_gate": {
        "name": "AI / MCP Autonomous Agent Launch Safety Gate",
        "profile_family": "ai_supply_chain_specialist",
        "stages": [
            "ai_llm_redteam", "secrets_dlp", "supply_chain_sbom", "web_injection",
            "web_ssrf_deser", "auth_access", "iac_cicd", "live_sandbox_dast",
        ],
        "total_budget_ms": 32_000,
        "drilldown_aggressiveness": 0.85,
        "prune_threshold_yield": 0.05,
        "max_adaptation_rounds": 10,
    },
    "cloud_native_zero_trust": {
        "name": "Cloud-Native Kubernetes & IAM Zero-Trust Verification",
        "profile_family": "cloud_k8s_specialist",
        "stages": [
            "cloud_iam_graph", "kubernetes_container", "container_runtime_ebpf",
            "iac_cicd", "network_zero_trust", "secrets_dlp", "supply_chain_sbom",
            "mitre_sigma_purple", "bas_campaigns",
        ],
        "total_budget_ms": 40_000,
        "drilldown_aggressiveness": 0.75,
        "prune_threshold_yield": 0.05,
        "max_adaptation_rounds": 10,
    },
    "enterprise_purple_team": {
        "name": "Full Enterprise Purple-Team Adversary Emulation & Detection Verification",
        "profile_family": "deep_adversarial",
        "stages": list(STAGE_CATALOG.keys()),
        "total_budget_ms": 75_000,
        "drilldown_aggressiveness": 0.90,
        "prune_threshold_yield": 0.02,
        "max_adaptation_rounds": 14,
    },
}


class HarnessWorkflowPolicyCompiler:
    """Validates and compiles declarative workflow policies into invariant-proven Harness² genomes."""

    def __init__(self, invariant_guard: Optional[MetaSafetyInvariantGuard] = None) -> None:
        self.invariant_guard = invariant_guard or MetaSafetyInvariantGuard()

    def compile_policy(self, policy_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Compile a user/enterprise policy dict into a verified `HarnessGenome` and `MAPEKRule` list."""
        errors: List[str] = []
        warnings: List[str] = []

        raw_stages = policy_spec.get("stages", [])
        if not isinstance(raw_stages, list) or not raw_stages:
            errors.append("Policy must specify a non-empty list of `stages`.")
            raw_stages = []

        valid_stages: List[str] = []
        for s in raw_stages:
            if s in STAGE_CATALOG:
                if s not in valid_stages:
                    valid_stages.append(s)
            else:
                warnings.append(f"Unknown stage '{s}' ignored during compilation.")

        if not valid_stages:
            errors.append("No recognized stages remained after validation.")

        total_budget = int(policy_spec.get("total_budget_ms", 30_000))
        per_stage = max(800, total_budget // max(1, len(valid_stages)))

        genome = HarnessGenome(
            genome_id=new_id("polgen"),
            name=str(policy_spec.get("name", "Compiled Enterprise Security Policy")),
            profile_family=str(policy_spec.get("profile_family", "compiled_policy")),
            enabled_stages=valid_stages,
            stage_priorities={s: float(policy_spec.get("stage_priorities", {}).get(s, 0.70)) for s in valid_stages},
            stage_budgets_ms={s: int(policy_spec.get("stage_budgets_ms", {}).get(s, per_stage)) for s in valid_stages},
            total_budget_ms=total_budget,
            enable_live_sandbox_dast="live_sandbox_dast" in valid_stages,
            enable_enterprise_graph_sim=bool({"cloud_iam_graph", "active_directory_graph", "network_zero_trust"} & set(valid_stages)),
            enable_mitre_emulation="mitre_sigma_purple" in valid_stages,
            enable_ai_redteam="ai_llm_redteam" in valid_stages,
            enable_grammar_fuzzing="grammar_fuzzer" in valid_stages,
            drilldown_aggressiveness=float(policy_spec.get("drilldown_aggressiveness", 0.70)),
            prune_threshold_yield=float(policy_spec.get("prune_threshold_yield", 0.05)),
            max_adaptation_rounds=int(policy_spec.get("max_adaptation_rounds", 8)),
            # Allow explicit policy fields to be tested by invariant guard (never silently override violations)
            enforce_scope_guard=bool(policy_spec.get("enforce_scope_guard", True)),
            enforce_secret_scrubbing=bool(policy_spec.get("enforce_secret_scrubbing", True)),
            enforce_separation_of_duties=bool(policy_spec.get("enforce_separation_of_duties", True)),
            require_independent_validation=bool(policy_spec.get("require_independent_validation", True)),
            loopback_only_dast=bool(policy_spec.get("loopback_only_dast", True)),
            validator_id=str(policy_spec.get("validator_id", "ely_h2_independent_validator")),
            planner_id=str(policy_spec.get("planner_id", "ely_h2_meta_planner")),
        )

        # Compile optional custom MAPE-K rules
        compiled_rules = list(BUILTIN_MAPEK_RULES)
        for idx, cr in enumerate(policy_spec.get("custom_adaptation_rules", [])):
            try:
                act = AdaptationActionType(str(cr["action_type"]))
                adapter = cr.get("inject_adapter")
                if adapter and adapter not in STAGE_CATALOG:
                    warnings.append(f"Custom rule #{idx} references unknown adapter '{adapter}'; skipped.")
                    continue
                compiled_rules.append(
                    MAPEKRule(
                        rule_id=str(cr.get("rule_id", f"CUSTOM-MAPEK-{idx+1:02d}")),
                        trigger_signal=str(cr["trigger_signal"]),
                        action_type=act,
                        inject_adapter=adapter,
                        base_evi=float(cr.get("base_evi", 0.82)),
                        rationale=str(cr.get("rationale", "Custom enterprise adaptation rule.")),
                    )
                )
            except Exception as exc:
                warnings.append(f"Custom rule #{idx} invalid ({exc}); skipped.")

        inv_results = self.invariant_guard.verify_genome(genome, raise_on_violation=False)
        failed_invs = [r for r in inv_results if not r.passed]
        for fi in failed_invs:
            errors.append(f"[{fi.invariant_id}] {fi.message}")

        return {
            "compiled_ok": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "genome": genome if len(errors) == 0 else None,
            "genome_dict": genome.to_dict(),
            "rules_count": len(compiled_rules),
            "compiled_rules": compiled_rules,
            "invariant_checks": [r.to_dict() for r in inv_results],
        }

    def compile_preset(self, preset_name: str) -> Dict[str, Any]:
        if preset_name not in BUILT_IN_POLICY_PRESETS:
            raise KeyError(f"Unknown Harness² policy preset '{preset_name}'. Available: {sorted(BUILT_IN_POLICY_PRESETS)}")
        return self.compile_policy(BUILT_IN_POLICY_PRESETS[preset_name])
