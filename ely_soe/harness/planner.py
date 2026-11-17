"""
Component 1 of the 6-Stage Security Harness: Audit Planner.

Decomposes a security evaluation into an explicit, risk-prioritized Directed Acyclic
Graph (DAG) of `AuditTask` work units spanning:
  - Stage 1: Planning & Scope Binding
  - Stage 2: Repository & Attack Surface Analysis
  - Stage 3: Multi-Domain Vulnerability Discovery (Static, Taint, Rust Core, Supply Chain, LLM Semantic)
  - Stage 4: Controlled PoC Test Generation, Fuzzing & Untrusted-Agent Simulation
  - Stage 5: Strictly Separated Independent Validation & Auditor Certification
  - Stage 6: Multi-Format Reporting, Maturity Gate & Remediation Verification

Adjusts priorities dynamically based on:
  - AttackSurfaceGraph node exposure (higher exposure domains scheduled first)
  - Historical regressions from prior Ely versions (if supplied)
  - AuditModality (`pre_release` elevates all 10 domains + untrusted-agent scenarios to P1)
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set

from ely_soe.core.config import HarnessProfileConfig
from ely_soe.core.models import (
    AttackSurfaceGraph,
    AuditModality,
    AuditPlan,
    AuditTask,
    HarnessStage,
    SecurityDomain,
    new_id,
)


DOMAIN_TECHNIQUES: Dict[SecurityDomain, List[str]] = {
    SecurityDomain.AGENT_ISOLATION: ["static_isolation_audit", "capability_lattice_check", "rogue_agent_sim_ua04_ua06"],
    SecurityDomain.TOOL_EXECUTION: ["ast_taint_cmd_code", "wildcard_capability_audit", "tool_rpc_fuzzer", "red_team_rt03"],
    SecurityDomain.MEMORY: ["memory_provenance_audit", "ast_taint_memory_sink", "rogue_memory_poison_sim"],
    SecurityDomain.PROMPT_INJECTION: ["ast_prompt_mixing", "camel_separation_audit", "adaptive_tap_redteam", "prompt_fuzzer"],
    SecurityDomain.API_SECURITY: ["jwt_auth_audit", "ast_bfla_bola_check", "api_auth_fuzzer", "sqli_taint_check"],
    SecurityDomain.FILESYSTEM: ["path_traversal_audit", "symlink_toctou_check", "archive_slip_audit", "path_fuzzer"],
    SecurityDomain.PROCESS_MANAGEMENT: ["rlimit_sandbox_audit", "env_scrub_check", "child_escape_sandbox_sim"],
    SecurityDomain.SUPPLY_CHAIN: ["cve_advisory_scan", "typosquat_detector", "skill_manifest_verifier", "cyclonedx_sbom"],
    SecurityDomain.NETWORK: ["ssrf_metadata_audit", "tls_verify_check", "egress_allowlist_audit", "sleeper_exfil_sim"],
    SecurityDomain.RUST_CORE: ["rust_unsafe_ffi_audit", "rust_concurrency_deadlock", "rust_build_rs_audit", "ffi_boundary_fuzzer"],
}


class AuditPlanner:
    """Produces a structured, dependency-ordered `AuditPlan` DAG."""

    def build_plan(
        self,
        target_name: str,
        target_version: str,
        modality: AuditModality,
        domains: List[SecurityDomain],
        profile: HarnessProfileConfig,
        model_id: str = "glm-5.3",
        attack_surface: Optional[AttackSurfaceGraph] = None,
        historical_hotspot_domains: Optional[Set[SecurityDomain]] = None,
    ) -> AuditPlan:
        hotspots = historical_hotspot_domains or set()
        tasks: List[AuditTask] = []

        # Task 0: Repository & Attack Surface comprehension
        repo_task_id = new_id("tsk")
        if profile.use_repo_analyzer:
            tasks.append(
                AuditTask(
                    task_id=repo_task_id,
                    name="Repository Architecture, Trust Boundary & Permission Matrix Mapping",
                    domain=SecurityDomain.AGENT_ISOLATION,
                    stage=HarnessStage.REPOSITORY_ANALYZER,
                    priority=1,
                    techniques=["ast_inventory", "rust_ffi_map", "trust_boundary_extraction", "permission_matrix"],
                    estimated_budget_seconds=4.0,
                )
            )

        discovery_task_ids: List[str] = []
        exposure_by_domain = attack_surface.domain_exposure_summary() if attack_surface else {}

        for domain in domains:
            exp_count = exposure_by_domain.get(domain.value, 1)
            prio = self._compute_priority(domain, modality, exp_count, domain in hotspots)
            node_ids = (
                [n.node_id for n in attack_surface.nodes if domain in n.domains][:12]
                if attack_surface
                else []
            )

            disc_id = new_id("tsk")
            discovery_task_ids.append(disc_id)
            tasks.append(
                AuditTask(
                    task_id=disc_id,
                    name=f"Discover Candidate Vulnerabilities — {domain.display_name}",
                    domain=domain,
                    stage=HarnessStage.VULNERABILITY_ANALYZER,
                    priority=prio,
                    depends_on=[repo_task_id] if profile.use_repo_analyzer else [],
                    target_nodes=node_ids,
                    techniques=list(DOMAIN_TECHNIQUES.get(domain, ["static_audit"])),
                    estimated_budget_seconds=6.0 if modality == AuditModality.PRE_RELEASE else 4.0,
                )
            )

        # Stage 4: Controlled PoC Test Generation
        testgen_id = new_id("tsk")
        if profile.use_test_generator:
            tasks.append(
                AuditTask(
                    task_id=testgen_id,
                    name="Synthesize Controlled Sandbox-Safe PoCs & Adversarial Probes",
                    domain=SecurityDomain.TOOL_EXECUTION,
                    stage=HarnessStage.TEST_GENERATOR,
                    priority=2,
                    depends_on=list(discovery_task_ids),
                    techniques=["poc_synthesis", "fuzz_seed_generation", "untrusted_agent_probes"],
                    estimated_budget_seconds=5.0,
                )
            )

        # Stage 5: Strictly Separated Independent Validation Plane
        validator_id = new_id("tsk")
        if profile.use_independent_validator:
            tasks.append(
                AuditTask(
                    task_id=validator_id,
                    name="Independent Clean-Room Sandbox Reproduction & Auditor Certification",
                    domain=SecurityDomain.AGENT_ISOLATION,
                    stage=HarnessStage.VALIDATOR,
                    priority=1,
                    depends_on=[testgen_id] if profile.use_test_generator else list(discovery_task_ids),
                    techniques=[
                        "differential_baseline_vs_exploit",
                        "multi_trial_determinism",
                        "oracle_nonce_verification",
                        "auditor_hmac_certification",
                    ],
                    estimated_budget_seconds=12.0,
                )
            )

        # Stage 6: Multi-Format Reporting & Maturity Attestation
        report_deps = (
            [validator_id]
            if profile.use_independent_validator
            else ([testgen_id] if profile.use_test_generator else list(discovery_task_ids))
        )
        tasks.append(
            AuditTask(
                task_id=new_id("tsk"),
                name="Compile Signed Security Evaluation Report, SARIF & Ely 1.0 Maturity Gate",
                domain=SecurityDomain.AGENT_ISOLATION,
                stage=HarnessStage.REPORTER,
                priority=1,
                depends_on=report_deps,
                techniques=["json_report", "markdown_briefing", "sarif_2_1_0", "html_dashboard", "maturity_attestation"],
                estimated_budget_seconds=3.0,
            )
        )

        return AuditPlan(
            plan_id=new_id("plan"),
            target_name=target_name,
            target_version=target_version,
            modality=modality,
            domains=list(domains),
            tasks=tasks,
            harness_profile=profile.name,
            model_id=model_id,
            max_duration_seconds=900 if modality == AuditModality.PRE_RELEASE else 450,
        )

    @staticmethod
    def _compute_priority(
        domain: SecurityDomain,
        modality: AuditModality,
        exposure_count: int,
        is_historical_hotspot: bool,
    ) -> int:
        if modality == AuditModality.PRE_RELEASE or is_historical_hotspot:
            return 1
        critical_domains = {
            SecurityDomain.AGENT_ISOLATION,
            SecurityDomain.PROMPT_INJECTION,
            SecurityDomain.TOOL_EXECUTION,
            SecurityDomain.RUST_CORE,
        }
        if domain in critical_domains or exposure_count >= 4:
            return 1
        if exposure_count >= 2:
            return 2
        return 3
