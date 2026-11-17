"""
Harness² (`ely_soe.harness_squared`) Core Data Models & Immutable Meta-Governance Schemas.

Defines the complete second-order meta-harness domain vocabulary:
  - `TargetFingerprint` & `TargetArchetype` — multi-dimensional surface characterization
  - `HarnessGenome` — evolvable first-order workflow configuration genome
  - `WorkflowDAG`, `WorkflowStageNode`, `WorkflowEdge` — live-mutable execution graph models
  - `StageTelemetryRecord`, `TelemetrySignal`, `LiveTelemetryFrame` — real-time observability
  - `AdaptationDirective`, `AdaptationActionType`, `AdaptationTransaction` — MAPE-K mutations
  - `SecurityHypothesis` — Bayesian adversarial hypothesis tracking
  - `InvariantCheckResult`, `MetaInvariantViolationError` — formal safety preservation
  - `ParetoFrontierPoint`, `MetaRunReport` — multi-objective optimization & signed provenance.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ely_soe.core.models import Severity, new_id, utc_now_iso


class TargetArchetype(str, Enum):
    CLOUD_NATIVE_K8S = "cloud_native_k8s"
    WEB_API_MONOLITH = "web_api_monolith"
    AI_AGENT_PLATFORM = "ai_agent_platform"
    ENTERPRISE_HYBRID_AD = "enterprise_hybrid_ad"
    EMBEDDED_OT_FIRMWARE = "embedded_ot_firmware"
    NATIVE_SYSTEMS_BINARY = "native_systems_binary"
    CI_SUPPLY_CHAIN_HEAVY = "ci_supply_chain_heavy"
    POLYGLOT_FULLSTACK = "polyglot_fullstack"


class StageStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PRUNED = "pruned"
    SKIPPED = "skipped"
    ESCALATED = "escalated"
    FAILED = "failed"


class StageCategory(str, Enum):
    RECON_STATIC = "recon_static"
    WEB_APPSEC = "web_appsec"
    AUTH_IDENTITY = "auth_identity"
    API_MICROSERVICES = "api_microservices"
    INFRA_CLOUD_K8S = "infra_cloud_k8s"
    SUPPLY_CHAIN_SECRETS = "supply_chain_secrets"
    NETWORK_CRYPTO = "network_crypto"
    BINARY_OT = "binary_ot"
    DYNAMIC_SANDBOX = "dynamic_sandbox"
    ADVERSARY_EMULATION = "adversary_emulation"
    AI_REDTEAM = "ai_redteam"
    SYNTHESIS_COMPLIANCE = "synthesis_compliance"
    HYPOTHESIS_DRILLDOWN = "hypothesis_drilldown"


class AdaptationActionType(str, Enum):
    EXPAND_DRILLDOWN = "expand_drilldown"
    PRUNE_LOW_YIELD_BRANCH = "prune_low_yield_branch"
    REALLOCATE_BUDGET = "reallocate_budget"
    ESCALATE_VALIDATION = "escalate_validation"
    INJECT_HYPOTHESIS_PROBE = "inject_hypothesis_probe"
    REPRIORITIZE_QUEUE = "reprioritize_queue"
    TIGHTEN_SAFETY_GATE = "tighten_safety_gate"
    ROLLBACK_MUTATION = "rollback_mutation"


class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    TESTING = "testing"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class MetaInvariantViolationError(RuntimeError):
    """Raised whenever a proposed Harness² adaptation attempts to violate a non-relaxable safety invariant."""

    def __init__(self, invariant_id: str, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(f"[{invariant_id}] {message}")
        self.invariant_id = invariant_id
        self.details = details or {}


# ---------------------------------------------------------------------------
# Target Surface Fingerprint
# ---------------------------------------------------------------------------

@dataclass
class TargetFingerprint:
    """Rich multi-modal characterization of a security assessment target."""

    fingerprint_id: str
    target_name: str
    target_root: str
    archetype: TargetArchetype
    created_at: str = field(default_factory=utc_now_iso)
    total_files: int = 0
    total_loc: int = 0
    language_distribution: Dict[str, int] = field(default_factory=dict)
    detected_frameworks: List[str] = field(default_factory=list)
    detected_cloud_providers: List[str] = field(default_factory=list)
    has_kubernetes: bool = False
    has_dockerfile: bool = False
    has_terraform_or_iac: bool = False
    has_cicd_workflows: bool = False
    has_openapi_or_graphql: bool = False
    has_ai_llm_components: bool = False
    has_native_c_cpp_binaries: bool = False
    has_iot_ot_artifacts: bool = False
    has_lockfiles_or_sbom: bool = False
    has_env_or_secret_files: bool = False
    sink_density_per_kloc: float = 0.0
    domain_affinities: Dict[str, float] = field(default_factory=dict)
    feature_vector: List[float] = field(default_factory=list)  # fixed 16-dim vector for LinUCB + Cosine memory
    estimated_risk_prior: float = 0.5
    fingerprint_hash: str = ""

    def __post_init__(self) -> None:
        if not self.fingerprint_hash:
            canonical = json.dumps(
                {
                    "archetype": self.archetype.value,
                    "langs": sorted(self.language_distribution.items()),
                    "frameworks": sorted(self.detected_frameworks),
                    "vec": [round(x, 4) for x in self.feature_vector],
                },
                sort_keys=True,
            )
            self.fingerprint_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint_id": self.fingerprint_id,
            "target_name": self.target_name,
            "target_root": self.target_root,
            "archetype": self.archetype.value,
            "created_at": self.created_at,
            "total_files": self.total_files,
            "total_loc": self.total_loc,
            "language_distribution": dict(self.language_distribution),
            "detected_frameworks": list(self.detected_frameworks),
            "detected_cloud_providers": list(self.detected_cloud_providers),
            "surface_flags": {
                "kubernetes": self.has_kubernetes,
                "dockerfile": self.has_dockerfile,
                "iac": self.has_terraform_or_iac,
                "cicd": self.has_cicd_workflows,
                "api_specs": self.has_openapi_or_graphql,
                "ai_llm": self.has_ai_llm_components,
                "native_binary": self.has_native_c_cpp_binaries,
                "iot_ot": self.has_iot_ot_artifacts,
                "supply_chain_manifests": self.has_lockfiles_or_sbom,
                "secret_bearing_configs": self.has_env_or_secret_files,
            },
            "sink_density_per_kloc": round(self.sink_density_per_kloc, 3),
            "domain_affinities": {k: round(v, 3) for k, v in self.domain_affinities.items()},
            "feature_vector": [round(x, 4) for x in self.feature_vector],
            "estimated_risk_prior": round(self.estimated_risk_prior, 3),
            "fingerprint_hash": self.fingerprint_hash,
        }


# ---------------------------------------------------------------------------
# Evolvable Harness Genome (Second-Order Configuration Vector)
# ---------------------------------------------------------------------------

@dataclass
class HarnessGenome:
    """
    Complete evolvable specification of a first-order security testing workflow.

    Harness² optimizes, mutates, crosses over, and selects `HarnessGenome` instances
    via Contextual Bandits (LinUCB) and NSGA-II Pareto Evolution while enforcing
    immutable safety bounds (`enforce_scope_guard`, `enforce_secret_scrubbing`,
    `enforce_separation_of_duties`, `max_total_budget_ms`).
    """

    genome_id: str
    name: str
    profile_family: str  # fast_ci | balanced_enterprise | deep_adversarial | compliance_audit | evolved
    enabled_stages: List[str] = field(default_factory=list)
    stage_priorities: Dict[str, float] = field(default_factory=dict)
    stage_budgets_ms: Dict[str, int] = field(default_factory=dict)
    total_budget_ms: int = 30_000
    enable_live_sandbox_dast: bool = True
    enable_enterprise_graph_sim: bool = True
    enable_mitre_emulation: bool = True
    enable_ai_redteam: bool = False
    enable_grammar_fuzzing: bool = True
    fuzz_iterations_per_grammar: int = 12
    drilldown_aggressiveness: float = 0.65      # [0.0, 1.0] controls MAPE-K expansion sensitivity
    prune_threshold_yield: float = 0.05         # prune low-yield downstream branches below this yield/sec
    max_adaptation_rounds: int = 8              # finite termination bound (INV-08)
    exploration_alpha: float = 0.35             # LinUCB exploration parameter
    # Non-relaxable safety invariants (ALWAYS True — guarded by MetaSafetyInvariantGuard)
    enforce_scope_guard: bool = True
    enforce_secret_scrubbing: bool = True
    enforce_separation_of_duties: bool = True
    require_independent_validation: bool = True
    loopback_only_dast: bool = True
    validator_id: str = "ely_h2_independent_validator"
    planner_id: str = "ely_h2_meta_planner"
    generation: int = 0
    parent_ids: List[str] = field(default_factory=list)

    def clone(self, new_name: Optional[str] = None) -> "HarnessGenome":
        cp = copy.deepcopy(self)
        cp.genome_id = new_id("gen")
        if new_name:
            cp.name = new_name
        cp.parent_ids = [self.genome_id]
        cp.generation = self.generation + 1
        return cp

    def genome_signature(self) -> str:
        payload = json.dumps(
            {
                "stages": sorted(self.enabled_stages),
                "dast": self.enable_live_sandbox_dast,
                "ent": self.enable_enterprise_graph_sim,
                "mitre": self.enable_mitre_emulation,
                "ai": self.enable_ai_redteam,
                "fuzz": self.fuzz_iterations_per_grammar,
                "agg": round(self.drilldown_aggressiveness, 2),
                "prune": round(self.prune_threshold_yield, 2),
                "budget": self.total_budget_ms,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "genome_id": self.genome_id,
            "name": self.name,
            "profile_family": self.profile_family,
            "genome_signature": self.genome_signature(),
            "enabled_stages": list(self.enabled_stages),
            "stage_priorities": {k: round(v, 3) for k, v in self.stage_priorities.items()},
            "stage_budgets_ms": dict(self.stage_budgets_ms),
            "total_budget_ms": self.total_budget_ms,
            "enable_live_sandbox_dast": self.enable_live_sandbox_dast,
            "enable_enterprise_graph_sim": self.enable_enterprise_graph_sim,
            "enable_mitre_emulation": self.enable_mitre_emulation,
            "enable_ai_redteam": self.enable_ai_redteam,
            "enable_grammar_fuzzing": self.enable_grammar_fuzzing,
            "fuzz_iterations_per_grammar": self.fuzz_iterations_per_grammar,
            "drilldown_aggressiveness": round(self.drilldown_aggressiveness, 3),
            "prune_threshold_yield": round(self.prune_threshold_yield, 3),
            "max_adaptation_rounds": self.max_adaptation_rounds,
            "exploration_alpha": round(self.exploration_alpha, 3),
            "safety_invariants": {
                "enforce_scope_guard": self.enforce_scope_guard,
                "enforce_secret_scrubbing": self.enforce_secret_scrubbing,
                "enforce_separation_of_duties": self.enforce_separation_of_duties,
                "require_independent_validation": self.require_independent_validation,
                "loopback_only_dast": self.loopback_only_dast,
            },
            "validator_id": self.validator_id,
            "planner_id": self.planner_id,
            "generation": self.generation,
            "parent_ids": list(self.parent_ids),
        }


# ---------------------------------------------------------------------------
# Live-Mutable Workflow Execution DAG Models
# ---------------------------------------------------------------------------

@dataclass
class WorkflowStageNode:
    stage_id: str
    adapter_name: str
    label: str
    category: StageCategory
    priority: float = 0.5
    budget_ms: int = 3000
    params: Dict[str, Any] = field(default_factory=dict)
    status: StageStatus = StageStatus.PENDING
    injected_by_adaptation: bool = False
    injection_reason: str = ""
    prune_reason: str = ""
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    elapsed_ms: float = 0.0
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_id": self.stage_id,
            "adapter_name": self.adapter_name,
            "label": self.label,
            "category": self.category.value,
            "priority": round(self.priority, 3),
            "budget_ms": self.budget_ms,
            "status": self.status.value,
            "injected_by_adaptation": self.injected_by_adaptation,
            "injection_reason": self.injection_reason,
            "prune_reason": self.prune_reason,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "findings_count": self.findings_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "error_message": self.error_message,
        }


@dataclass(frozen=True)
class WorkflowEdge:
    src_stage_id: str
    dst_stage_id: str
    edge_kind: str = "depends_on"  # depends_on | drilldown_trigger | validation_gate

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.src_stage_id,
            "target": self.dst_stage_id,
            "edge_kind": self.edge_kind,
        }


# ---------------------------------------------------------------------------
# Real-Time Telemetry & MAPE-K Adaptation Directives
# ---------------------------------------------------------------------------

@dataclass
class StageTelemetryRecord:
    stage_id: str
    adapter_name: str
    category: str
    elapsed_ms: float
    budget_ms: int
    findings_total: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    reproduced_count: int
    max_cvss4: float
    distinct_cwes: List[str] = field(default_factory=list)
    distinct_domains: List[str] = field(default_factory=list)
    risk_weighted_yield: float = 0.0
    yield_per_second: float = 0.0
    budget_utilization_pct: float = 0.0
    recorded_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_id": self.stage_id,
            "adapter_name": self.adapter_name,
            "category": self.category,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "budget_ms": self.budget_ms,
            "findings_total": self.findings_total,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "reproduced_count": self.reproduced_count,
            "max_cvss4": round(self.max_cvss4, 2),
            "distinct_cwes": list(self.distinct_cwes),
            "distinct_domains": list(self.distinct_domains),
            "risk_weighted_yield": round(self.risk_weighted_yield, 2),
            "yield_per_second": round(self.yield_per_second, 2),
            "budget_utilization_pct": round(self.budget_utilization_pct, 2),
            "recorded_at": self.recorded_at,
        }


@dataclass
class TelemetrySignal:
    signal_id: str
    signal_type: str  # high_severity_cluster | cross_domain_pivot | low_yield_saturation | budget_pressure | unverified_criticals | ai_surface_hit
    source_stage_id: str
    strength: float  # [0.0, 1.0]
    evidence: Dict[str, Any] = field(default_factory=dict)
    emitted_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "signal_type": self.signal_type,
            "source_stage_id": self.source_stage_id,
            "strength": round(self.strength, 3),
            "evidence": dict(self.evidence),
            "emitted_at": self.emitted_at,
        }


@dataclass
class AdaptationDirective:
    directive_id: str
    rule_id: str
    action_type: AdaptationActionType
    target_stage_id: str
    rationale: str
    expected_value_of_info: float
    payload: Dict[str, Any] = field(default_factory=dict)
    approved_by_invariant_guard: bool = False
    applied: bool = False
    rejection_reason: str = ""
    decided_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "directive_id": self.directive_id,
            "rule_id": self.rule_id,
            "action_type": self.action_type.value,
            "target_stage_id": self.target_stage_id,
            "rationale": self.rationale,
            "expected_value_of_info": round(self.expected_value_of_info, 3),
            "payload": dict(self.payload),
            "approved_by_invariant_guard": self.approved_by_invariant_guard,
            "applied": self.applied,
            "rejection_reason": self.rejection_reason,
            "decided_at": self.decided_at,
        }


# ---------------------------------------------------------------------------
# Security Hypothesis & Invariant Verification
# ---------------------------------------------------------------------------

@dataclass
class SecurityHypothesis:
    hypothesis_id: str
    title: str
    statement: str
    source_stage_id: str
    triggering_cwes: List[str]
    target_verification_adapter: str
    prior_probability: float
    posterior_probability: float
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    evidence_notes: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now_iso)
    resolved_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "title": self.title,
            "statement": self.statement,
            "source_stage_id": self.source_stage_id,
            "triggering_cwes": list(self.triggering_cwes),
            "target_verification_adapter": self.target_verification_adapter,
            "prior_probability": round(self.prior_probability, 3),
            "posterior_probability": round(self.posterior_probability, 3),
            "status": self.status.value,
            "evidence_notes": list(self.evidence_notes),
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
        }


@dataclass
class InvariantCheckResult:
    check_id: str
    invariant_id: str
    invariant_name: str
    passed: bool
    message: str
    checked_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "invariant_id": self.invariant_id,
            "invariant_name": self.invariant_name,
            "passed": self.passed,
            "message": self.message,
            "checked_at": self.checked_at,
        }


@dataclass
class ParetoFrontierPoint:
    genome_id: str
    genome_name: str
    generation: int
    recall_yield_score: float       # Obj 1: maximize [0..100]
    chain_coverage_score: float     # Obj 2: maximize [0..100]
    efficiency_speed_score: float   # Obj 3: maximize [0..100] (inverse latency/budget)
    precision_signal_score: float   # Obj 4: maximize [0..100]
    pareto_rank: int = 0
    crowding_distance: float = 0.0
    genome_dict: Dict[str, Any] = field(default_factory=dict)

    def objective_vector(self) -> Tuple[float, float, float, float]:
        return (
            self.recall_yield_score,
            self.chain_coverage_score,
            self.efficiency_speed_score,
            self.precision_signal_score,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "genome_id": self.genome_id,
            "genome_name": self.genome_name,
            "generation": self.generation,
            "objectives": {
                "recall_yield": round(self.recall_yield_score, 2),
                "chain_coverage": round(self.chain_coverage_score, 2),
                "efficiency_speed": round(self.efficiency_speed_score, 2),
                "precision_signal": round(self.precision_signal_score, 2),
            },
            "pareto_rank": self.pareto_rank,
            "crowding_distance": round(self.crowding_distance, 4) if self.crowding_distance != float("inf") else 9999.0,
        }
