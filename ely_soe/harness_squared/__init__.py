"""
Harness² (`ely_soe.harness_squared`) — Second-Order Adaptive Security Meta-Harness.

Wraps the first-order ELY Security Harness and the Generalized Cybersecurity Suite
(`ely_soe.cyber`) in a closed-loop, self-adapting, formally invariant-preserving
meta-orchestration layer:
  - `TargetSurfaceFingerprinter`: 16-dim polyglot surface profiling & risk priors
  - `MetaSafetyInvariantGuard`: 8 non-relaxable cryptographic/structural safety invariants
  - `WorkflowDAG`: live-mutable Kahn-scheduled DAG with drilldown injection, pruning & rollback
  - `TelemetryObserver`: real-time discovery velocity, saturation & CWE cross-domain signals
  - `AdversarialHypothesisEngine`: Bayesian falsifiable security hypothesis synthesis
  - `MAPEKController`: autonomic Monitor–Analyze–Plan–Execute–Knowledge live adaptation loop
  - `LinUCBGenomeBandit` & `DomainThompsonScheduler`: pure-Python online contextual bandits
  - `NSGA2GenomeOptimizer`: 4-objective Pareto evolutionary genome optimization
  - `MetaMemoryStore`: SQLite cross-run episodic transfer recall & adaptation-rule efficacy
  - `HarnessWorkflowPolicyCompiler`: declarative enterprise security policy DSL compiler
  - `HarnessSquaredABEvaluator`: controlled static-vs-adaptive lift benchmarking
  - `HarnessSquaredMetaAnalytics`: longitudinal regret, ROI & posture-drift analytics
  - `HarnessSquaredEngine`: unified closed-loop Harness² orchestrator.
"""

from ely_soe.harness_squared.ab_evaluator import HarnessSquaredABEvaluator
from ely_soe.harness_squared.bandit_optimizer import (
    GENOME_ARM_TEMPLATES,
    DomainThompsonScheduler,
    LinUCBGenomeBandit,
)
from ely_soe.harness_squared.evolutionary_optimizer import NSGA2GenomeOptimizer
from ely_soe.harness_squared.hypothesis_engine import AdversarialHypothesisEngine
from ely_soe.harness_squared.mapek_controller import BUILTIN_MAPEK_RULES, MAPEKController, MAPEKRule
from ely_soe.harness_squared.meta_analytics import HarnessSquaredMetaAnalytics
from ely_soe.harness_squared.meta_memory import MetaMemoryStore
from ely_soe.harness_squared.meta_orchestrator import HarnessSquaredEngine
from ely_soe.harness_squared.models import (
    AdaptationActionType,
    AdaptationDirective,
    HarnessGenome,
    HypothesisStatus,
    InvariantCheckResult,
    MetaInvariantViolationError,
    ParetoFrontierPoint,
    SecurityHypothesis,
    StageCategory,
    StageStatus,
    StageTelemetryRecord,
    TargetArchetype,
    TargetFingerprint,
    TelemetrySignal,
    WorkflowEdge,
    WorkflowStageNode,
)
from ely_soe.harness_squared.policy_compiler import (
    BUILT_IN_POLICY_PRESETS,
    HarnessWorkflowPolicyCompiler,
)
from ely_soe.harness_squared.safety_invariant_guard import MetaSafetyInvariantGuard
from ely_soe.harness_squared.stage_registry import (
    STAGE_CATALOG,
    FirstOrderStageRegistry,
    StageExecutionContext,
    StageExecutionResult,
)
from ely_soe.harness_squared.target_fingerprinter import TargetSurfaceFingerprinter
from ely_soe.harness_squared.telemetry_observer import TelemetryObserver
from ely_soe.harness_squared.workflow_dag import WorkflowDAG
# Wave II, III-B, III-C, III-D Second-Order Meta-Control Subsystems & Facade
from ely_soe.harness_squared.adversarial_harness_stress_tester import AdversarialHarnessStressTester
from ely_soe.harness_squared.autonomous_playbook_synthesizer import AutonomousPlaybookSynthesizer
from ely_soe.harness_squared.bayesian_experiment_designer import (
    BayesianExperimentDesigner,
    StageInformationProfile,
)
from ely_soe.harness_squared.budget_allocator import AnytimeBudgetAllocator
from ely_soe.harness_squared.causal_attribution import CausalAttributionEngine
from ely_soe.harness_squared.cognitive_root_cause_synthesizer import CognitiveRootCauseSynthesizer
from ely_soe.harness_squared.conformal_risk_calibrator import (
    CalibrationEpisode,
    ConformalRiskCalibrator,
)
from ely_soe.harness_squared.curriculum_generator import AdversarialCurriculumGenerator
from ely_soe.harness_squared.distributed_fleet_scheduler import DistributedFleetScheduler, FleetRepositorySpec
from ely_soe.harness_squared.drift_and_regression import HarnessDriftAndRegressionDetector
from ely_soe.harness_squared.ensemble_coordinator import HarnessEnsembleCoordinator
from ely_soe.harness_squared.formal_attack_tree_solver import (
    ADTreeNode,
    DefensiveCountermeasure,
    FormalAttackDefenseTreeSolver,
)
from ely_soe.harness_squared.hyperparameter_tuner import TPEHyperparameterTuner
from ely_soe.harness_squared.meta_verifier import HarnessSquaredMetaVerifier
from ely_soe.harness_squared.multi_agent_debate_adjudicator import (
    AdjudicationTranscript,
    MultiAgentDebateAdjudicator,
)
from ely_soe.harness_squared.multi_objective_bench_suite import HarnessSquaredMultiTierBenchmark
from ely_soe.harness_squared.policy_governance_engine import (
    EnterpriseReleasePolicy,
    HarnessPolicyGovernanceEngine,
)
from ely_soe.harness_squared.replay_debugger import HarnessReplayDebugger
from ely_soe.harness_squared.research_lab_facade import (
    HARNESS2_SUBSYSTEM_CATALOG,
    HarnessSquaredResearchLabFacade,
)
from ely_soe.harness_squared.security_chaos_bandit_curriculum import (
    CandidateGenomeConfig,
    ContextualLinUCBBandit,
    PureLinearAlgebra,
    SuccessiveHalvingPruner,
)
from ely_soe.harness_squared.self_healing_supervisor import SelfHealingMetaSupervisor
from ely_soe.harness_squared.transfer_learning import CrossTargetTransferEngine

__all__ = [
    "AdaptationActionType",
    "AdaptationDirective",
    "AdversarialHypothesisEngine",
    "BUILTIN_MAPEK_RULES",
    "BUILT_IN_POLICY_PRESETS",
    "DomainThompsonScheduler",
    "FirstOrderStageRegistry",
    "GENOME_ARM_TEMPLATES",
    "HarnessGenome",
    "HarnessSquaredABEvaluator",
    "HarnessSquaredEngine",
    "HarnessSquaredMetaAnalytics",
    "HarnessWorkflowPolicyCompiler",
    "HypothesisStatus",
    "InvariantCheckResult",
    "LinUCBGenomeBandit",
    "MAPEKController",
    "MAPEKRule",
    "MetaInvariantViolationError",
    "MetaMemoryStore",
    "MetaSafetyInvariantGuard",
    "NSGA2GenomeOptimizer",
    "ParetoFrontierPoint",
    "STAGE_CATALOG",
    "SecurityHypothesis",
    "StageCategory",
    "StageExecutionContext",
    "StageExecutionResult",
    "StageStatus",
    "StageTelemetryRecord",
    "TargetArchetype",
    "TargetFingerprint",
    "TargetSurfaceFingerprinter",
    "TelemetryObserver",
    "TelemetrySignal",
    "WorkflowDAG",
    "WorkflowEdge",
    "WorkflowStageNode",
    "ADTreeNode",
    "AdjudicationTranscript",
    "AdversarialCurriculumGenerator",
    "AdversarialHarnessStressTester",
    "AnytimeBudgetAllocator",
    "AutonomousPlaybookSynthesizer",
    "BayesianExperimentDesigner",
    "CalibrationEpisode",
    "CandidateGenomeConfig",
    "CausalAttributionEngine",
    "CognitiveRootCauseSynthesizer",
    "ConformalRiskCalibrator",
    "ContextualLinUCBBandit",
    "CrossTargetTransferEngine",
    "PureLinearAlgebra",
    "StageInformationProfile",
    "SuccessiveHalvingPruner",
    "DefensiveCountermeasure",
    "DistributedFleetScheduler",
    "EnterpriseReleasePolicy",
    "FleetRepositorySpec",
    "FormalAttackDefenseTreeSolver",
    "HARNESS2_SUBSYSTEM_CATALOG",
    "HarnessDriftAndRegressionDetector",
    "HarnessEnsembleCoordinator",
    "HarnessPolicyGovernanceEngine",
    "HarnessReplayDebugger",
    "HarnessSquaredMetaVerifier",
    "HarnessSquaredMultiTierBenchmark",
    "HarnessSquaredResearchLabFacade",
    "MultiAgentDebateAdjudicator",
    "SelfHealingMetaSupervisor",
    "TPEHyperparameterTuner",
]
