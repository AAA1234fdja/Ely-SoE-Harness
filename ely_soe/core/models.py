"""
Core domain models and architectural invariants for the ELY Security Lab & SOE Harness.

Key architectural invariant enforced at the data-model level:
    Discovery components (RepositoryAnalyzer, VulnerabilityAnalyzer, LLM adapters,
    Fuzzer, RedTeam) can ONLY create findings in `HYPOTHESIS` status. Promoting a
    finding to `CONFIRMED` requires a signed `ValidationCertificate` issued by the
    strictly separated independent `Validator` / `Auditor` plane.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


def utc_now_iso() -> str:
    """Return an ISO-8601 UTC timestamp with millisecond precision."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def new_id(prefix: str) -> str:
    """Generate a deterministic-format collision-resistant identifier."""
    return f"{prefix}-{secrets.token_hex(8)}"


class SecurityDomain(str, Enum):
    """The 10 mandatory cybersecurity evaluation domains for Ely."""

    AGENT_ISOLATION = "agent_isolation"
    TOOL_EXECUTION = "tool_execution"
    MEMORY = "memory"
    PROMPT_INJECTION = "prompt_injection"
    API_SECURITY = "api_security"
    FILESYSTEM = "filesystem"
    PROCESS_MANAGEMENT = "process_management"
    SUPPLY_CHAIN = "supply_chain"
    NETWORK = "network"
    RUST_CORE = "rust_core"

    @property
    def display_name(self) -> str:
        names = {
            SecurityDomain.AGENT_ISOLATION: "Agent Isolation",
            SecurityDomain.TOOL_EXECUTION: "Tool Execution",
            SecurityDomain.MEMORY: "Memory Security",
            SecurityDomain.PROMPT_INJECTION: "Prompt Injection",
            SecurityDomain.API_SECURITY: "API Security",
            SecurityDomain.FILESYSTEM: "Filesystem Security",
            SecurityDomain.PROCESS_MANAGEMENT: "Process Management",
            SecurityDomain.SUPPLY_CHAIN: "Supply Chain",
            SecurityDomain.NETWORK: "Network Security",
            SecurityDomain.RUST_CORE: "Rust Core",
        }
        return names[self]

    @property
    def primary_risk(self) -> str:
        risks = {
            SecurityDomain.AGENT_ISOLATION: "One agent accesses resources, state, or tokens belonging to another agent",
            SecurityDomain.TOOL_EXECUTION: "Tools possess excessive capabilities, unsafe shell execution, or argument smuggling",
            SecurityDomain.MEMORY: "Injection, poisoning, tampering, or cross-session contamination of agent memory",
            SecurityDomain.PROMPT_INJECTION: "Malicious instructions embedded in external content hijack agent control flow",
            SecurityDomain.API_SECURITY: "Weak authentication, missing authorization (BOLA/BFLA), replay, or DoS exposure",
            SecurityDomain.FILESYSTEM: "Unauthorized file reads/writes, path traversal, symlink races, or archive slip",
            SecurityDomain.PROCESS_MANAGEMENT: "Subprocess escape, privilege escalation, resource exhaustion, or env poisoning",
            SecurityDomain.SUPPLY_CHAIN: "Compromised dependencies, typosquatted packages, build hooks, or rogue skills",
            SecurityDomain.NETWORK: "Unauthorized egress, SSRF/metadata access, cleartext exfiltration, or covert channels",
            SecurityDomain.RUST_CORE: "Memory unsafety, FFI boundary errors, data races, panic DoS, or cryptographic flaws",
        }
        return risks[self]


class Severity(str, Enum):
    """Standardized vulnerability severity levels aligned with CVSS v4.0 / v3.1."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> float:
        weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 4.5,
            Severity.LOW: 2.0,
            Severity.INFO: 0.5,
        }
        return weights[self]

    @property
    def rank(self) -> int:
        ranks = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return ranks[self]

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


class FindingStatus(str, Enum):
    """
    Lifecycle status of a security finding.

    Strict Discovery-vs-Validation separation rule:
    - Discovery stages emit `HYPOTHESIS` only.
    - Only the independent Validator/Auditor can transition to `CONFIRMED`,
      `FALSE_POSITIVE`, or `INCONCLUSIVE`.
    - Blue Team remediation verification can transition `CONFIRMED` -> `MITIGATED`
      or `REGRESSED`.
    """

    HYPOTHESIS = "hypothesis"
    VALIDATING = "validating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    INCONCLUSIVE = "inconclusive"
    MITIGATED = "mitigated"
    REGRESSED = "regressed"


class ValidationVerdict(str, Enum):
    """Authoritative outcome produced by the Independent Validator / Auditor."""

    REPRODUCED = "reproduced"
    NOT_REPRODUCED = "not_reproduced"
    INCONCLUSIVE = "inconclusive"
    TAMPER_DETECTED = "tamper_detected"
    OUT_OF_SCOPE = "out_of_scope"


class AuditModality(str, Enum):
    """The three permanent execution modalities of the Security Orchestration Engine."""

    SCHEDULED = "scheduled"
    ON_DEMAND = "on_demand"
    PRE_RELEASE = "pre_release"


class HarnessStage(str, Enum):
    """The 6-component modular security harness pipeline."""

    PLANNER = "planner"
    REPOSITORY_ANALYZER = "repository_analyzer"
    VULNERABILITY_ANALYZER = "vulnerability_analyzer"
    TEST_GENERATOR = "test_generator"
    VALIDATOR = "validator"
    REPORTER = "reporter"


class LifecycleStage(str, Enum):
    """The 8-step isolated adversarial evaluation lifecycle."""

    SNAPSHOT_CREATE = "snapshot_create"
    SANDBOX_PROVISION = "sandbox_provision"
    SURFACE_ANALYZE = "surface_analyze"
    ADVERSARIAL_EXECUTE = "adversarial_execute"
    EVIDENCE_SEAL = "evidence_seal"
    SANDBOX_DESTROY = "sandbox_destroy"
    REPORT_DELIVER = "report_deliver"
    REMEDIATE_REVERIFY = "remediate_reverify"


class MaturityGateVerdict(str, Enum):
    """Release-gate decision for Ely 1.0 Security Maturity."""

    APPROVED = "approved"
    CONDITIONAL = "conditional"
    BLOCKED = "blocked"


class MaturityCriterionId(str, Enum):
    """The 9 mandatory Ely 1.0 Security Maturity approval criteria."""

    AGENT_ISOLATION = "agent_isolation"
    GRANULAR_PERMISSIONS = "granular_permissions"
    PROMPT_INJECTION_DEFENSE = "prompt_injection_defense"
    IO_VALIDATION = "io_validation"
    MEMORY_SECURITY = "memory_security"
    DEPENDENCY_AUDIT = "dependency_audit"
    AUTOMATED_ADVERSARIAL_TESTING = "automated_adversarial_testing"
    COMPROMISE_RECOVERY = "compromise_recovery"
    INDEPENDENT_AUDIT = "independent_audit"

    @property
    def title(self) -> str:
        titles = {
            MaturityCriterionId.AGENT_ISOLATION: "Aislamiento entre agentes",
            MaturityCriterionId.GRANULAR_PERMISSIONS: "Control granular de permisos",
            MaturityCriterionId.PROMPT_INJECTION_DEFENSE: "Protección frente a prompt injection",
            MaturityCriterionId.IO_VALIDATION: "Validación de entradas y salidas",
            MaturityCriterionId.MEMORY_SECURITY: "Seguridad del sistema de memoria",
            MaturityCriterionId.DEPENDENCY_AUDIT: "Auditoría de dependencias",
            MaturityCriterionId.AUTOMATED_ADVERSARIAL_TESTING: "Pruebas adversariales automatizadas",
            MaturityCriterionId.COMPROMISE_RECOVERY: "Recuperación ante compromisos",
            MaturityCriterionId.INDEPENDENT_AUDIT: "Auditoría independiente",
        }
        return titles[self]


class SeparationOfDutiesViolation(RuntimeError):
    """Raised when a discovery component attempts to bypass independent validation."""


@dataclass(frozen=True)
class CodeLocation:
    """Exact source code pointer for a finding or attack surface element."""

    file_path: str
    line_start: int
    line_end: Optional[int] = None
    symbol: Optional[str] = None
    snippet: str = ""
    language: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end if self.line_end is not None else self.line_start,
            "symbol": self.symbol,
            "snippet": self.snippet,
            "language": self.language,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CodeLocation":
        return cls(
            file_path=str(data.get("file_path", "")),
            line_start=int(data.get("line_start", 1)),
            line_end=data.get("line_end"),
            symbol=data.get("symbol"),
            snippet=str(data.get("snippet", "")),
            language=str(data.get("language", "unknown")),
        )


@dataclass
class EvidenceArtifact:
    """Immutable evidence item captured during analysis, fuzzing, or validation."""

    artifact_id: str
    kind: str  # poc_script, stdout_log, telemetry_trace, taint_path, sbom, diff, canary_alert
    description: str
    content: str
    sha256: str = ""
    created_at: str = field(default_factory=utc_now_iso)
    producer: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.sha256:
            self.sha256 = hashlib.sha256(self.content.encode("utf-8", errors="replace")).hexdigest()

    def verify_integrity(self) -> bool:
        expected = hashlib.sha256(self.content.encode("utf-8", errors="replace")).hexdigest()
        return expected == self.sha256

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "description": self.description,
            "content": self.content,
            "sha256": self.sha256,
            "created_at": self.created_at,
            "producer": self.producer,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceArtifact":
        return cls(
            artifact_id=data["artifact_id"],
            kind=data["kind"],
            description=data.get("description", ""),
            content=data.get("content", ""),
            sha256=data.get("sha256", ""),
            created_at=data.get("created_at", utc_now_iso()),
            producer=data.get("producer", "unknown"),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class ValidationCertificate:
    """
    Cryptographically signed certificate emitted EXCLUSIVELY by the Independent
    Validator / Auditor plane after clean-room PoC reproduction.
    """

    certificate_id: str
    finding_id: str
    verdict: ValidationVerdict
    validator_id: str
    sandbox_id: str
    trials_run: int
    trials_reproduced: int
    baseline_passed: bool
    exploit_triggered: bool
    oracle_integrity_verified: bool
    reproduction_steps: List[str]
    evidence_hashes: List[str]
    issued_at: str
    signature: str  # HMAC-SHA256 generated by independent Auditor key
    notes: str = ""

    @property
    def reproducibility_ratio(self) -> float:
        if self.trials_run <= 0:
            return 0.0
        return self.trials_reproduced / float(self.trials_run)

    def canonical_payload(self) -> str:
        payload = {
            "certificate_id": self.certificate_id,
            "finding_id": self.finding_id,
            "verdict": self.verdict.value,
            "validator_id": self.validator_id,
            "sandbox_id": self.sandbox_id,
            "trials_run": self.trials_run,
            "trials_reproduced": self.trials_reproduced,
            "baseline_passed": self.baseline_passed,
            "exploit_triggered": self.exploit_triggered,
            "oracle_integrity_verified": self.oracle_integrity_verified,
            "evidence_hashes": sorted(self.evidence_hashes),
            "issued_at": self.issued_at,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "finding_id": self.finding_id,
            "verdict": self.verdict.value,
            "validator_id": self.validator_id,
            "sandbox_id": self.sandbox_id,
            "trials_run": self.trials_run,
            "trials_reproduced": self.trials_reproduced,
            "reproducibility_ratio": round(self.reproducibility_ratio, 4),
            "baseline_passed": self.baseline_passed,
            "exploit_triggered": self.exploit_triggered,
            "oracle_integrity_verified": self.oracle_integrity_verified,
            "reproduction_steps": list(self.reproduction_steps),
            "evidence_hashes": list(self.evidence_hashes),
            "issued_at": self.issued_at,
            "signature": self.signature,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ValidationCertificate":
        return cls(
            certificate_id=data["certificate_id"],
            finding_id=data["finding_id"],
            verdict=ValidationVerdict(data["verdict"]),
            validator_id=data["validator_id"],
            sandbox_id=data["sandbox_id"],
            trials_run=int(data["trials_run"]),
            trials_reproduced=int(data["trials_reproduced"]),
            baseline_passed=bool(data["baseline_passed"]),
            exploit_triggered=bool(data["exploit_triggered"]),
            oracle_integrity_verified=bool(data["oracle_integrity_verified"]),
            reproduction_steps=list(data.get("reproduction_steps", [])),
            evidence_hashes=list(data.get("evidence_hashes", [])),
            issued_at=data["issued_at"],
            signature=data["signature"],
            notes=str(data.get("notes", "")),
        )


@dataclass
class RemediationProposal:
    """Structured Blue Team fix proposal and sandbox verification state."""

    proposal_id: str
    finding_id: str
    summary: str
    strategy: str  # code_patch, capability_policy, sandbox_rule, dependency_upgrade, config_hardening
    diff_preview: str
    target_files: List[str] = field(default_factory=list)
    regression_tests: List[str] = field(default_factory=list)
    verified_neutralizes_poc: bool = False
    verified_no_regression: bool = False
    verification_notes: str = ""
    estimated_effort: str = "medium"
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RemediationProposal":
        return cls(**data)


@dataclass
class Finding:
    """
    A security vulnerability record with strict discovery/validation separation.

    Discovery engines instantiate `Finding` with status=HYPOTHESIS.
    To transition into `CONFIRMED`, `apply_validation_certificate()` MUST be called
    with a valid, auditor-signed `ValidationCertificate`.
    """

    finding_id: str
    title: str
    description: str
    domain: SecurityDomain
    severity: Severity
    rule_id: str
    discovered_by: str
    location: CodeLocation
    status: FindingStatus = FindingStatus.HYPOTHESIS
    cvss_score: float = 0.0
    cvss_vector: str = ""
    agentic_risk_score: float = 0.0
    confidence: float = 0.5
    cwe_ids: List[str] = field(default_factory=list)
    owasp_agentic_ids: List[str] = field(default_factory=list)
    mitre_atlas_ids: List[str] = field(default_factory=list)
    attack_vector: str = ""
    impact: str = ""
    poc_spec: Dict[str, Any] = field(default_factory=dict)
    evidence: List[EvidenceArtifact] = field(default_factory=list)
    validation: Optional[ValidationCertificate] = None
    remediation: Optional[RemediationProposal] = None
    fingerprint: str = ""
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    def __post_init__(self) -> None:
        # Enforce architectural separation of duties on creation:
        if self.status == FindingStatus.CONFIRMED and self.validation is None:
            raise SeparationOfDutiesViolation(
                f"Finding {self.finding_id} cannot be initialized as CONFIRMED without "
                "an independent ValidationCertificate from the Auditor/Validator plane."
            )
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()

    def compute_fingerprint(self) -> str:
        """Stable cross-version deduplication fingerprint."""
        raw = "|".join(
            [
                self.domain.value,
                self.rule_id,
                self.location.file_path.replace("\\", "/"),
                str(self.location.symbol or ""),
                str(self.location.line_start // 5),  # resilient to minor line shifts
            ]
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]

    def mark_validating(self) -> None:
        if self.status == FindingStatus.HYPOTHESIS:
            self.status = FindingStatus.VALIDATING
            self.updated_at = utc_now_iso()

    def apply_validation_certificate(
        self,
        cert: ValidationCertificate,
        verify_signature_fn: Any = None,
    ) -> None:
        """
        Authoritative state transition driven exclusively by an independent
        ValidationCertificate. Rejects unverified or mismatched certificates.
        """
        if cert.finding_id != self.finding_id:
            raise SeparationOfDutiesViolation(
                f"Certificate {cert.certificate_id} targets {cert.finding_id}, not {self.finding_id}"
            )
        if cert.validator_id == self.discovered_by:
            raise SeparationOfDutiesViolation(
                f"Discovery actor '{self.discovered_by}' cannot act as its own Independent Validator!"
            )
        if not cert.signature:
            raise SeparationOfDutiesViolation("ValidationCertificate is missing cryptographic signature")
        if verify_signature_fn is not None and not verify_signature_fn(cert):
            raise SeparationOfDutiesViolation(
                f"ValidationCertificate {cert.certificate_id} failed Auditor signature verification!"
            )

        self.validation = cert
        if cert.verdict == ValidationVerdict.REPRODUCED and cert.oracle_integrity_verified:
            self.status = FindingStatus.CONFIRMED
            self.confidence = max(self.confidence, min(0.99, 0.75 + 0.24 * cert.reproducibility_ratio))
        elif cert.verdict == ValidationVerdict.NOT_REPRODUCED:
            self.status = FindingStatus.FALSE_POSITIVE
            self.confidence = min(self.confidence, 0.15)
        elif cert.verdict == ValidationVerdict.TAMPER_DETECTED:
            # Tampering during validation is itself a severe security incident!
            self.status = FindingStatus.INCONCLUSIVE
            if "oracle_tamper_attempt" not in self.tags:
                self.tags.append("oracle_tamper_attempt")
        else:
            self.status = FindingStatus.INCONCLUSIVE
        self.updated_at = utc_now_iso()

    def mark_mitigated(self, remediation: RemediationProposal) -> None:
        if not remediation.verified_neutralizes_poc:
            raise SeparationOfDutiesViolation(
                "Cannot mark finding MITIGATED without verified sandbox neutralization of PoC."
            )
        self.remediation = remediation
        self.status = FindingStatus.MITIGATED
        self.updated_at = utc_now_iso()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "domain": self.domain.value,
            "severity": self.severity.value,
            "status": self.status.value,
            "rule_id": self.rule_id,
            "discovered_by": self.discovered_by,
            "location": self.location.to_dict(),
            "cvss_score": round(self.cvss_score, 2),
            "cvss_vector": self.cvss_vector,
            "agentic_risk_score": round(self.agentic_risk_score, 2),
            "confidence": round(self.confidence, 3),
            "cwe_ids": list(self.cwe_ids),
            "owasp_agentic_ids": list(self.owasp_agentic_ids),
            "mitre_atlas_ids": list(self.mitre_atlas_ids),
            "attack_vector": self.attack_vector,
            "impact": self.impact,
            "poc_spec": dict(self.poc_spec),
            "evidence": [e.to_dict() for e in self.evidence],
            "validation": self.validation.to_dict() if self.validation else None,
            "remediation": self.remediation.to_dict() if self.remediation else None,
            "fingerprint": self.fingerprint,
            "tags": list(self.tags),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        cert_raw = data.get("validation")
        cert = ValidationCertificate.from_dict(cert_raw) if cert_raw else None
        rem_raw = data.get("remediation")
        rem = RemediationProposal.from_dict(rem_raw) if rem_raw else None
        return cls(
            finding_id=data["finding_id"],
            title=data["title"],
            description=data.get("description", ""),
            domain=SecurityDomain(data["domain"]),
            severity=Severity(data["severity"]),
            rule_id=data.get("rule_id", "unknown"),
            discovered_by=data.get("discovered_by", "unknown"),
            location=CodeLocation.from_dict(data["location"]),
            status=FindingStatus(data.get("status", "hypothesis")),
            cvss_score=float(data.get("cvss_score", 0.0)),
            cvss_vector=str(data.get("cvss_vector", "")),
            agentic_risk_score=float(data.get("agentic_risk_score", 0.0)),
            confidence=float(data.get("confidence", 0.5)),
            cwe_ids=list(data.get("cwe_ids", [])),
            owasp_agentic_ids=list(data.get("owasp_agentic_ids", [])),
            mitre_atlas_ids=list(data.get("mitre_atlas_ids", [])),
            attack_vector=str(data.get("attack_vector", "")),
            impact=str(data.get("impact", "")),
            poc_spec=dict(data.get("poc_spec", {})),
            evidence=[EvidenceArtifact.from_dict(e) for e in data.get("evidence", [])],
            validation=cert,
            remediation=rem,
            fingerprint=str(data.get("fingerprint", "")),
            tags=list(data.get("tags", [])),
            created_at=data.get("created_at", utc_now_iso()),
            updated_at=data.get("updated_at", utc_now_iso()),
        )


@dataclass
class AttackSurfaceNode:
    """An architectural entity discovered by the Repository Analyzer."""

    node_id: str
    kind: str  # agent, tool, skill, api_endpoint, memory_store, rust_ffi, subprocess_exec, dependency, secret_sink
    name: str
    location: CodeLocation
    domains: List[SecurityDomain] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    exposed_externally: bool = False
    trust_zone: str = "internal"
    risk_exposure: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "kind": self.kind,
            "name": self.name,
            "location": self.location.to_dict(),
            "domains": [d.value for d in self.domains],
            "capabilities": list(self.capabilities),
            "exposed_externally": self.exposed_externally,
            "trust_zone": self.trust_zone,
            "risk_exposure": round(self.risk_exposure, 2),
            "metadata": dict(self.metadata),
        }


@dataclass
class TrustBoundary:
    """Explicit security boundary between two trust zones in Ely."""

    boundary_id: str
    name: str
    source_zone: str
    target_zone: str
    crossing_nodes: List[str] = field(default_factory=list)
    controls_detected: List[str] = field(default_factory=list)
    missing_controls: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackSurfaceGraph:
    """Complete architectural security model built by RepositoryAnalyzer."""

    target_name: str
    target_version: str
    root_path: str
    languages: Dict[str, int] = field(default_factory=dict)
    total_files: int = 0
    total_lines: int = 0
    nodes: List[AttackSurfaceNode] = field(default_factory=list)
    edges: List[Tuple[str, str, str]] = field(default_factory=list)  # (src_id, dst_id, relation)
    trust_boundaries: List[TrustBoundary] = field(default_factory=list)
    permission_matrix: Dict[str, List[str]] = field(default_factory=dict)
    dependencies_count: int = 0
    analyzed_at: str = field(default_factory=utc_now_iso)

    def nodes_by_kind(self, kind: str) -> List[AttackSurfaceNode]:
        return [n for n in self.nodes if n.kind == kind]

    def domain_exposure_summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {d.value: 0 for d in SecurityDomain}
        for node in self.nodes:
            for d in node.domains:
                counts[d.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_name": self.target_name,
            "target_version": self.target_version,
            "root_path": self.root_path,
            "languages": dict(self.languages),
            "total_files": self.total_files,
            "total_lines": self.total_lines,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [list(e) for e in self.edges],
            "trust_boundaries": [b.to_dict() for b in self.trust_boundaries],
            "permission_matrix": {k: list(v) for k, v in self.permission_matrix.items()},
            "dependencies_count": self.dependencies_count,
            "domain_exposure": self.domain_exposure_summary(),
            "analyzed_at": self.analyzed_at,
        }


@dataclass
class AuditTask:
    """A single work unit in the Planner's audit DAG."""

    task_id: str
    name: str
    domain: SecurityDomain
    stage: HarnessStage
    priority: int  # 1 (highest) to 5 (lowest)
    depends_on: List[str] = field(default_factory=list)
    target_nodes: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    estimated_budget_seconds: float = 5.0
    status: str = "pending"
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "name": self.name,
            "domain": self.domain.value,
            "stage": self.stage.value,
            "priority": self.priority,
            "depends_on": list(self.depends_on),
            "target_nodes": list(self.target_nodes),
            "techniques": list(self.techniques),
            "estimated_budget_seconds": self.estimated_budget_seconds,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


@dataclass
class AuditPlan:
    """Structured multi-stage security audit plan produced by the Planner."""

    plan_id: str
    target_name: str
    target_version: str
    modality: AuditModality
    domains: List[SecurityDomain]
    tasks: List[AuditTask] = field(default_factory=list)
    harness_profile: str = "full_soe_harness"
    model_id: str = "glm-5.3"
    max_duration_seconds: int = 600
    created_at: str = field(default_factory=utc_now_iso)

    def ordered_tasks(self) -> List[AuditTask]:
        """Return tasks topologically sorted respecting dependencies and priority."""
        by_id = {t.task_id: t for t in self.tasks}
        visited: Set[str] = set()
        result: List[AuditTask] = []

        def visit(tid: str) -> None:
            if tid in visited:
                return
            visited.add(tid)
            task = by_id[tid]
            for dep in task.depends_on:
                if dep in by_id:
                    visit(dep)
            result.append(task)

        for t in sorted(self.tasks, key=lambda x: (x.priority, x.task_id)):
            visit(t.task_id)
        return result

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "target_name": self.target_name,
            "target_version": self.target_version,
            "modality": self.modality.value,
            "domains": [d.value for d in self.domains],
            "tasks": [t.to_dict() for t in self.tasks],
            "harness_profile": self.harness_profile,
            "model_id": self.model_id,
            "max_duration_seconds": self.max_duration_seconds,
            "created_at": self.created_at,
        }


@dataclass
class MaturityCriterionResult:
    """Verifiable evidence-backed evaluation of one Ely 1.0 Security Maturity criterion."""

    criterion_id: MaturityCriterionId
    title: str
    passed: bool
    score: float  # 0.0 to 100.0
    level: int  # 0 to 5
    required_for_release: bool
    verifiable_checks: List[Dict[str, Any]] = field(default_factory=list)
    blocking_finding_ids: List[str] = field(default_factory=list)
    evidence_hashes: List[str] = field(default_factory=list)
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "criterion_id": self.criterion_id.value,
            "title": self.title,
            "passed": self.passed,
            "score": round(self.score, 2),
            "level": self.level,
            "required_for_release": self.required_for_release,
            "verifiable_checks": list(self.verifiable_checks),
            "blocking_finding_ids": list(self.blocking_finding_ids),
            "evidence_hashes": list(self.evidence_hashes),
            "rationale": self.rationale,
        }


@dataclass
class MaturityAssessment:
    """Complete Ely 1.0 Security Maturity evaluation and release-gate verdict."""

    assessment_id: str
    target_version: str
    verdict: MaturityGateVerdict
    overall_score: float
    maturity_level: int  # 0..5
    criteria: List[MaturityCriterionResult] = field(default_factory=list)
    blocking_reasons: List[str] = field(default_factory=list)
    attestation_merkle_root: str = ""
    attestation_signature: str = ""
    evaluated_at: str = field(default_factory=utc_now_iso)

    @property
    def passed_count(self) -> int:
        return sum(1 for c in self.criteria if c.passed)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "target_version": self.target_version,
            "verdict": self.verdict.value,
            "overall_score": round(self.overall_score, 2),
            "maturity_level": self.maturity_level,
            "passed_criteria": self.passed_count,
            "total_criteria": len(self.criteria),
            "criteria": [c.to_dict() for c in self.criteria],
            "blocking_reasons": list(self.blocking_reasons),
            "attestation_merkle_root": self.attestation_merkle_root,
            "attestation_signature": self.attestation_signature,
            "evaluated_at": self.evaluated_at,
        }


@dataclass
class LifecycleStepRecord:
    """Telemetry record for one step of the 8-stage evaluation lifecycle."""

    stage: LifecycleStage
    status: str  # completed, failed, skipped
    started_at: str
    completed_at: str
    duration_ms: float
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage": self.stage.value,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": round(self.duration_ms, 2),
            "details": dict(self.details),
        }


@dataclass
class SecurityEvaluationReport:
    """
    Immutable, auditor-sealed report delivered one-way from the Temporary
    Adversarial Instance back to the Ely Main Instance.
    """

    report_id: str
    run_id: str
    target_name: str
    target_version: str
    modality: AuditModality
    model_id: str
    harness_profile: str
    snapshot_digest: str
    sandbox_destroyed_verified: bool
    main_instance_untouched_verified: bool
    findings: List[Finding] = field(default_factory=list)
    attack_surface: Optional[AttackSurfaceGraph] = None
    maturity: Optional[MaturityAssessment] = None
    lifecycle_steps: List[LifecycleStepRecord] = field(default_factory=list)
    untrusted_agent_results: List[Dict[str, Any]] = field(default_factory=list)
    fuzzer_summary: Dict[str, Any] = field(default_factory=dict)
    red_team_summary: Dict[str, Any] = field(default_factory=dict)
    blue_team_summary: Dict[str, Any] = field(default_factory=dict)
    monitor_summary: Dict[str, Any] = field(default_factory=dict)
    ledger_merkle_root: str = ""
    report_signature: str = ""
    created_at: str = field(default_factory=utc_now_iso)

    @property
    def confirmed_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.status == FindingStatus.CONFIRMED]

    @property
    def hypothesis_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.status == FindingStatus.HYPOTHESIS]

    @property
    def false_positives(self) -> List[Finding]:
        return [f for f in self.findings if f.status == FindingStatus.FALSE_POSITIVE]

    @property
    def mitigated_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.status == FindingStatus.MITIGATED]

    @property
    def posture_score(self) -> float:
        return float(self.summary_stats()["security_posture_score"])

    def summary_stats(self) -> Dict[str, Any]:
        by_severity: Dict[str, int] = {s.value: 0 for s in Severity}
        by_domain: Dict[str, int] = {d.value: 0 for d in SecurityDomain}
        by_status: Dict[str, int] = {s.value: 0 for s in FindingStatus}

        for f in self.findings:
            by_status[f.status.value] += 1
            if f.status in (FindingStatus.CONFIRMED, FindingStatus.REGRESSED):
                by_severity[f.severity.value] += 1
                by_domain[f.domain.value] += 1

        total_risk = sum(
            (f.cvss_score * 0.6 + f.agentic_risk_score * 0.4)
            for f in self.confirmed_findings
        )
        posture_score = max(0.0, round(100.0 - min(100.0, total_risk * 1.35), 2))

        return {
            "total_candidates": len(self.findings),
            "confirmed_count": len(self.confirmed_findings),
            "false_positive_count": len(self.false_positives),
            "mitigated_count": len(self.mitigated_findings),
            "unvalidated_hypotheses": len(self.hypothesis_findings),
            "confirmed_by_severity": by_severity,
            "confirmed_by_domain": by_domain,
            "by_status": by_status,
            "security_posture_score": posture_score,
            "maturity_verdict": self.maturity.verdict.value if self.maturity else "not_evaluated",
            "maturity_score": self.maturity.overall_score if self.maturity else 0.0,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "run_id": self.run_id,
            "target_name": self.target_name,
            "target_version": self.target_version,
            "modality": self.modality.value,
            "model_id": self.model_id,
            "harness_profile": self.harness_profile,
            "snapshot_digest": self.snapshot_digest,
            "sandbox_destroyed_verified": self.sandbox_destroyed_verified,
            "main_instance_untouched_verified": self.main_instance_untouched_verified,
            "summary": self.summary_stats(),
            "findings": [f.to_dict() for f in self.findings],
            "attack_surface": self.attack_surface.to_dict() if self.attack_surface else None,
            "maturity": self.maturity.to_dict() if self.maturity else None,
            "lifecycle_steps": [s.to_dict() for s in self.lifecycle_steps],
            "untrusted_agent_results": list(self.untrusted_agent_results),
            "fuzzer_summary": dict(self.fuzzer_summary),
            "red_team_summary": dict(self.red_team_summary),
            "blue_team_summary": dict(self.blue_team_summary),
            "monitor_summary": dict(self.monitor_summary),
            "ledger_merkle_root": self.ledger_merkle_root,
            "report_signature": self.report_signature,
            "created_at": self.created_at,
        }


@dataclass
class BenchmarkRunMetrics:
    """Quantitative metrics for one (Model x HarnessConfig) experimental run."""

    model_id: str
    harness_config: str
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    false_discovery_rate: float
    reproducibility_rate: float
    code_coverage_ratio: float
    patch_quality_score: float
    severity_calibration_mae: float
    per_domain_recall: Dict[str, float] = field(default_factory=dict)
    per_domain_f1: Dict[str, float] = field(default_factory=dict)
    duration_seconds: float = 0.0
    estimated_tokens: int = 0
    composite_frontier_index: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "harness_config": self.harness_config,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "false_discovery_rate": round(self.false_discovery_rate, 4),
            "reproducibility_rate": round(self.reproducibility_rate, 4),
            "code_coverage_ratio": round(self.code_coverage_ratio, 4),
            "patch_quality_score": round(self.patch_quality_score, 4),
            "severity_calibration_mae": round(self.severity_calibration_mae, 4),
            "per_domain_recall": {k: round(v, 4) for k, v in self.per_domain_recall.items()},
            "per_domain_f1": {k: round(v, 4) for k, v in self.per_domain_f1.items()},
            "duration_seconds": round(self.duration_seconds, 3),
            "estimated_tokens": self.estimated_tokens,
            "composite_frontier_index": round(self.composite_frontier_index, 4),
        }


@dataclass
class BenchmarkExperimentResult:
    """Full comparative benchmark study across models and harness configurations."""

    experiment_id: str
    corpus_version: str
    total_ground_truth_vulns: int
    runs: List[BenchmarkRunMetrics] = field(default_factory=list)
    harness_lift_summary: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "corpus_version": self.corpus_version,
            "total_ground_truth_vulns": self.total_ground_truth_vulns,
            "runs": [r.to_dict() for r in self.runs],
            "harness_lift_summary": dict(self.harness_lift_summary),
            "created_at": self.created_at,
        }
