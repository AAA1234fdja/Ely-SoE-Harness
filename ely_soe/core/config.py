"""
Hierarchical Configuration, Harness Presets & SOE Modality Profiles.

Supports side-by-side comparison of harness configurations (e.g., `bare_model` vs
`static_only` vs `harness_no_validator` vs `full_soe_harness` vs `frontier_deep`)
as well as configuring the 3 permanent SOE modalities (`scheduled`, `on_demand`,
`pre_release`).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ely_soe.core.models import AuditModality, SecurityDomain


@dataclass
class SandboxConfig:
    """Resource and isolation limits enforced on every Temporary Adversarial Instance."""

    max_cpu_seconds: int = 30
    max_memory_mb: int = 512
    max_open_files: int = 256
    max_processes: int = 32
    execution_timeout_seconds: float = 15.0
    allow_external_network: bool = False
    verify_destruction: bool = True
    scrub_secrets: bool = True
    base_temp_dir: Optional[str] = None


@dataclass
class FuzzerConfig:
    """Controls for the coverage/grammar/mutation fuzzer."""

    enabled: bool = True
    max_iterations_per_target: int = 120
    max_payload_bytes: int = 4096
    seed: int = 1337
    enable_grammar_fuzzing: bool = True
    enable_mutation_fuzzing: bool = True
    enable_differential_fuzzing: bool = True


@dataclass
class RedTeamConfig:
    """Controls for static & adaptive multi-turn Red Team simulations."""

    enabled: bool = True
    enable_adaptive_tree_search: bool = True
    max_tree_depth: int = 3
    branching_factor: int = 3
    run_untrusted_agent_suite: bool = True
    canary_token_count: int = 6


@dataclass
class ValidatorConfig:
    """Controls for the strictly separated Independent Validation plane."""

    enabled: bool = True
    require_independent_signature: bool = True
    reproducibility_trials: int = 3
    min_reproducibility_ratio: float = 0.66
    enforce_clean_sandbox_per_trial: bool = True
    detect_oracle_tampering: bool = True


@dataclass
class HarnessProfileConfig:
    """Defines which harness stages & frontier tools are active for an audit or benchmark."""

    name: str
    description: str
    use_planner: bool = True
    use_repo_analyzer: bool = True
    use_static_analyzers: bool = True
    use_taint_engine: bool = True
    use_rust_analyzer: bool = True
    use_supply_chain_scanner: bool = True
    use_llm_reasoning: bool = True
    use_test_generator: bool = True
    use_independent_validator: bool = True
    use_fuzzer: bool = True
    use_red_team: bool = True
    use_blue_team_remediation: bool = True
    use_untrusted_agent_sim: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


HARNESS_PRESETS: Dict[str, HarnessProfileConfig] = {
    "bare_model": HarnessProfileConfig(
        name="bare_model",
        description="Unassisted model scanning source files directly without structured harness, taint engine, fuzzer, or independent validator",
        use_planner=False,
        use_repo_analyzer=False,
        use_static_analyzers=False,
        use_taint_engine=False,
        use_rust_analyzer=False,
        use_supply_chain_scanner=False,
        use_llm_reasoning=True,
        use_test_generator=False,
        use_independent_validator=False,
        use_fuzzer=False,
        use_red_team=False,
        use_blue_team_remediation=False,
        use_untrusted_agent_sim=False,
    ),
    "static_only": HarnessProfileConfig(
        name="static_only",
        description="Deterministic static analyzers + Rust + supply chain without LLM reasoning, fuzzing, or dynamic validation",
        use_planner=True,
        use_repo_analyzer=True,
        use_static_analyzers=True,
        use_taint_engine=True,
        use_rust_analyzer=True,
        use_supply_chain_scanner=True,
        use_llm_reasoning=False,
        use_test_generator=False,
        use_independent_validator=False,
        use_fuzzer=False,
        use_red_team=False,
        use_blue_team_remediation=False,
        use_untrusted_agent_sim=False,
    ),
    "harness_no_validator": HarnessProfileConfig(
        name="harness_no_validator",
        description="Full discovery harness (Planner + Repo + Static + Taint + LLM + TestGen) WITHOUT independent validation plane",
        use_planner=True,
        use_repo_analyzer=True,
        use_static_analyzers=True,
        use_taint_engine=True,
        use_rust_analyzer=True,
        use_supply_chain_scanner=True,
        use_llm_reasoning=True,
        use_test_generator=True,
        use_independent_validator=False,
        use_fuzzer=True,
        use_red_team=True,
        use_blue_team_remediation=True,
        use_untrusted_agent_sim=True,
    ),
    "full_soe_harness": HarnessProfileConfig(
        name="full_soe_harness",
        description="Complete 6-stage ELY Security Lab & SOE Harness with strict Discovery/Validation separation, Fuzzer, Red/Blue Teams & Rogue Agent Suite",
        use_planner=True,
        use_repo_analyzer=True,
        use_static_analyzers=True,
        use_taint_engine=True,
        use_rust_analyzer=True,
        use_supply_chain_scanner=True,
        use_llm_reasoning=True,
        use_test_generator=True,
        use_independent_validator=True,
        use_fuzzer=True,
        use_red_team=True,
        use_blue_team_remediation=True,
        use_untrusted_agent_sim=True,
    ),
    "frontier_deep": HarnessProfileConfig(
        name="frontier_deep",
        description="Maximum-depth frontier adversarial campaign: full SOE harness + deep adaptive red-team search + extended fuzzing + patch re-verification",
        use_planner=True,
        use_repo_analyzer=True,
        use_static_analyzers=True,
        use_taint_engine=True,
        use_rust_analyzer=True,
        use_supply_chain_scanner=True,
        use_llm_reasoning=True,
        use_test_generator=True,
        use_independent_validator=True,
        use_fuzzer=True,
        use_red_team=True,
        use_blue_team_remediation=True,
        use_untrusted_agent_sim=True,
    ),
}


@dataclass
class SOEConfig:
    """Top-level configuration for the Ely Security Orchestration Engine."""

    data_dir: str = ".ely_soe_data"
    db_filename: str = "ely_soe_history.sqlite3"
    default_model_id: str = "glm-5.3"
    default_harness_profile: str = "full_soe_harness"
    auditor_passphrase: str = "photon-labs-ely-auditor-isolated-key"
    domains: List[SecurityDomain] = field(default_factory=lambda: list(SecurityDomain))
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    fuzzer: FuzzerConfig = field(default_factory=FuzzerConfig)
    red_team: RedTeamConfig = field(default_factory=RedTeamConfig)
    validator: ValidatorConfig = field(default_factory=ValidatorConfig)
    llm_api_base_url: Optional[str] = None
    llm_api_key_env: str = "ELY_LLM_API_KEY"
    pre_release_min_maturity_score: float = 82.0
    pre_release_allow_high_findings: int = 0
    pre_release_allow_critical_findings: int = 0

    @property
    def db_path(self) -> Path:
        return Path(self.data_dir) / self.db_filename

    def get_harness_profile(self, name: Optional[str] = None) -> HarnessProfileConfig:
        key = name or self.default_harness_profile
        if key not in HARNESS_PRESETS:
            raise ValueError(f"Unknown harness profile '{key}'. Available: {sorted(HARNESS_PRESETS)}")
        return HARNESS_PRESETS[key]

    @classmethod
    def for_modality(cls, modality: AuditModality, base: Optional["SOEConfig"] = None) -> "SOEConfig":
        cfg = base if base is not None else cls()
        if modality == AuditModality.PRE_RELEASE:
            cfg.default_harness_profile = "frontier_deep"
            cfg.fuzzer.max_iterations_per_target = max(cfg.fuzzer.max_iterations_per_target, 160)
            cfg.validator.reproducibility_trials = max(cfg.validator.reproducibility_trials, 3)
            cfg.red_team.run_untrusted_agent_suite = True
        elif modality == AuditModality.SCHEDULED:
            cfg.default_harness_profile = "full_soe_harness"
            cfg.fuzzer.max_iterations_per_target = 100
        elif modality == AuditModality.ON_DEMAND:
            cfg.default_harness_profile = "full_soe_harness"
        return cfg

    @classmethod
    def from_json_file(cls, path: Path) -> "SOEConfig":
        raw = json.loads(path.read_text(encoding="utf-8"))
        cfg = cls()
        for key in (
            "data_dir",
            "db_filename",
            "default_model_id",
            "default_harness_profile",
            "auditor_passphrase",
            "llm_api_base_url",
            "llm_api_key_env",
            "pre_release_min_maturity_score",
            "pre_release_allow_high_findings",
            "pre_release_allow_critical_findings",
        ):
            if key in raw:
                setattr(cfg, key, raw[key])
        if "domains" in raw:
            cfg.domains = [SecurityDomain(d) for d in raw["domains"]]
        if "sandbox" in raw:
            cfg.sandbox = SandboxConfig(**raw["sandbox"])
        if "fuzzer" in raw:
            cfg.fuzzer = FuzzerConfig(**raw["fuzzer"])
        if "red_team" in raw:
            cfg.red_team = RedTeamConfig(**raw["red_team"])
        if "validator" in raw:
            cfg.validator = ValidatorConfig(**raw["validator"])
        return cfg

    def resolve_llm_api_key(self) -> Optional[str]:
        return os.environ.get(self.llm_api_key_env)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "data_dir": self.data_dir,
            "db_filename": self.db_filename,
            "default_model_id": self.default_model_id,
            "default_harness_profile": self.default_harness_profile,
            "domains": [d.value for d in self.domains],
            "sandbox": asdict(self.sandbox),
            "fuzzer": asdict(self.fuzzer),
            "red_team": asdict(self.red_team),
            "validator": asdict(self.validator),
            "pre_release_min_maturity_score": self.pre_release_min_maturity_score,
            "pre_release_allow_high_findings": self.pre_release_allow_high_findings,
            "pre_release_allow_critical_findings": self.pre_release_allow_critical_findings,
        }
