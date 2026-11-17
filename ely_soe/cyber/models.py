"""
Generalized Cybersecurity Vulnerability Testing & Adversary Emulation Domain Models.

Extends the ELY-SOE core domain model with structured types for full-spectrum
authorized cybersecurity testing:
  - 16 generalized cybersecurity domains (Web/OWASP, API/Microservices, Network,
    TLS/Crypto, Cloud IAM, Kubernetes/Containers, IaC/CI-CD, Active Directory/Identity,
    Binary/Memory Safety, Firmware/IoT/OT, Supply Chain, MITRE ATT&CK Emulation,
    Detection Engineering, Threat Modeling, Grammar Fuzzing, Exploit Chaining)
  - Full CVSS v4.0 vector & score metadata alongside EPSS/KEV prioritization
  - Bidirectional conversion to `ely_soe.core.models.Finding` (strictly respecting
    `FindingStatus.HYPOTHESIS` until independently validated)
  - Structured graph models for Cloud IAM, Kubernetes RBAC, Active Directory,
    Data-Flow Diagrams (STRIDE), and Multi-Stage Exploit Chains
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from ely_soe.core.models import (
    CodeLocation,
    Finding,
    FindingStatus,
    SecurityDomain,
    Severity,
    new_id,
    utc_now_iso,
)


class CyberDomain(str, Enum):
    """16 generalized cybersecurity assessment & adversary emulation domains."""

    WEB_INJECTION = "web_injection"
    WEB_CLIENT_PROTOCOL = "web_client_protocol"
    WEB_SSRF_XXE_SSTI_DESER = "web_ssrf_xxe_ssti_deser"
    AUTH_ACCESS_CONTROL = "auth_access_control"
    API_MICROSERVICES = "api_microservices"
    NETWORK_PROTOCOL = "network_protocol"
    TLS_CRYPTOGRAPHY = "tls_cryptography"
    CLOUD_IAM = "cloud_iam"
    KUBERNETES_CONTAINER = "kubernetes_container"
    IAC_CICD = "iac_cicd"
    IDENTITY_ACTIVE_DIRECTORY = "identity_active_directory"
    BINARY_MEMORY_SAFETY = "binary_memory_safety"
    FIRMWARE_IOT_OT = "firmware_iot_ot"
    ADVERSARY_EMULATION = "adversary_emulation"
    DETECTION_ENGINEERING = "detection_engineering"
    THREAT_MODELING = "threat_modeling"

    def to_soe_domain(self) -> SecurityDomain:
        """Map generalized cybersecurity domain onto the core 10-domain SOE taxonomy."""
        mapping = {
            CyberDomain.WEB_INJECTION: SecurityDomain.API_SECURITY,
            CyberDomain.WEB_CLIENT_PROTOCOL: SecurityDomain.API_SECURITY,
            CyberDomain.WEB_SSRF_XXE_SSTI_DESER: SecurityDomain.NETWORK,
            CyberDomain.AUTH_ACCESS_CONTROL: SecurityDomain.API_SECURITY,
            CyberDomain.API_MICROSERVICES: SecurityDomain.API_SECURITY,
            CyberDomain.NETWORK_PROTOCOL: SecurityDomain.NETWORK,
            CyberDomain.TLS_CRYPTOGRAPHY: SecurityDomain.NETWORK,
            CyberDomain.CLOUD_IAM: SecurityDomain.AGENT_ISOLATION,
            CyberDomain.KUBERNETES_CONTAINER: SecurityDomain.AGENT_ISOLATION,
            CyberDomain.IAC_CICD: SecurityDomain.SUPPLY_CHAIN,
            CyberDomain.IDENTITY_ACTIVE_DIRECTORY: SecurityDomain.AGENT_ISOLATION,
            CyberDomain.BINARY_MEMORY_SAFETY: SecurityDomain.RUST_CORE,
            CyberDomain.FIRMWARE_IOT_OT: SecurityDomain.PROCESS_MANAGEMENT,
            CyberDomain.ADVERSARY_EMULATION: SecurityDomain.TOOL_EXECUTION,
            CyberDomain.DETECTION_ENGINEERING: SecurityDomain.PROCESS_MANAGEMENT,
            CyberDomain.THREAT_MODELING: SecurityDomain.AGENT_ISOLATION,
        }
        return mapping.get(self, SecurityDomain.API_SECURITY)


class MitreTactic(str, Enum):
    """14 MITRE ATT&CK Enterprise Tactics."""

    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


class ExploitMaturity(str, Enum):
    """Exploit maturity classification aligned with CVSS v4.0 Threat Metrics."""

    UNREPORTED = "U"
    PROOF_OF_CONCEPT = "P"
    ATTACKED = "A"
    NOT_DEFINED = "X"


class VerificationMethod(str, Enum):
    """How a generalized vulnerability finding was discovered or probed."""

    STATIC_AST = "static_ast"
    STATIC_PATTERN = "static_pattern"
    PROTOCOL_STATE_MACHINE = "protocol_state_machine"
    SANDBOX_DIFFERENTIAL_PROBE = "sandbox_differential_probe"
    GRAMMAR_FUZZER = "grammar_fuzzer"
    GRAPH_REACHABILITY = "graph_reachability"
    BINARY_HEADER_INSPECTION = "binary_header_inspection"
    CRYPTO_ORACLE_CHECK = "crypto_oracle_check"
    EMULATION_PLAYBOOK = "emulation_playbook"
    SIGMA_YARA_MATCH = "sigma_yara_match"


class AssetCriticality(str, Enum):
    """Business criticality tier of the target asset."""

    TIER_0_CROWN_JEWEL = "tier_0_crown_jewel"
    TIER_1_PRODUCTION = "tier_1_production"
    TIER_2_INTERNAL = "tier_2_internal"
    TIER_3_DEV_LAB = "tier_3_dev_lab"


@dataclass
class MitreTechniqueRef:
    """Reference to a specific MITRE ATT&CK technique / sub-technique."""

    technique_id: str
    name: str
    tactic: MitreTactic
    subtechnique: Optional[str] = None
    platforms: List[str] = field(default_factory=lambda: ["Linux", "Windows", "Cloud"])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic.value,
            "tactic_name": self.tactic.name.lower(),
            "subtechnique": self.subtechnique,
            "platforms": list(self.platforms),
        }


@dataclass
class CVSSv4Metrics:
    """
    CVSS v4.0 Base + Threat + Environmental metric vector.

    Base Metrics:
      - AV: Attack Vector (N, A, L, P)
      - AC: Attack Complexity (L, H)
      - AT: Attack Requirements (N, P)
      - PR: Privileges Required (N, L, H)
      - UI: User Interaction (N, P, A)
      - VC/VI/VA: Vulnerable System Impact (H, L, N)
      - SC/SI/SA: Subsequent System Impact (H, L, N)
    Threat Metric:
      - E: Exploit Maturity (X, A, P, U)
    """

    av: str = "N"
    ac: str = "L"
    at: str = "N"
    pr: str = "N"
    ui: str = "N"
    vc: str = "H"
    vi: str = "H"
    va: str = "H"
    sc: str = "N"
    si: str = "N"
    sa: str = "N"
    e: str = "X"
    cr: str = "X"
    ir: str = "X"
    ar: str = "X"

    def vector_string(self) -> str:
        parts = [
            "CVSS:4.0",
            f"AV:{self.av}",
            f"AC:{self.ac}",
            f"AT:{self.at}",
            f"PR:{self.pr}",
            f"UI:{self.ui}",
            f"VC:{self.vc}",
            f"VI:{self.vi}",
            f"VA:{self.va}",
            f"SC:{self.sc}",
            f"SI:{self.si}",
            f"SA:{self.sa}",
        ]
        if self.e != "X":
            parts.append(f"E:{self.e}")
        if self.cr != "X":
            parts.append(f"CR:{self.cr}")
        if self.ir != "X":
            parts.append(f"IR:{self.ir}")
        if self.ar != "X":
            parts.append(f"AR:{self.ar}")
        return "/".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vector": self.vector_string(),
            "AV": self.av,
            "AC": self.ac,
            "AT": self.at,
            "PR": self.pr,
            "UI": self.ui,
            "VC": self.vc,
            "VI": self.vi,
            "VA": self.va,
            "SC": self.sc,
            "SI": self.si,
            "SA": self.sa,
            "E": self.e,
        }


@dataclass
class EvidenceArtifact:
    """Structured forensic evidence attached to a generalized vulnerability finding."""

    artifact_id: str
    kind: str  # code_snippet, http_exchange, payload_diff, graph_path, binary_header, log_match
    summary: str
    content: str
    sha256: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.sha256:
            self.sha256 = hashlib.sha256(self.content.encode("utf-8", errors="replace")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "summary": self.summary,
            "content": self.content[:1500],
            "sha256": self.sha256,
            "metadata": dict(self.metadata),
        }


@dataclass
class CyberVulnerability:
    """
    Rich generalized cybersecurity vulnerability record produced by `ely_soe/cyber/*`.

    Preserves full Separation of Duties when converted to a core SOE `Finding`:
    it ALWAYS enters the core pipeline as `FindingStatus.HYPOTHESIS`.
    """

    vuln_id: str
    rule_id: str
    title: str
    description: str
    cyber_domain: CyberDomain
    severity: Severity
    confidence: float
    cwe_ids: List[str]
    owasp_categories: List[str] = field(default_factory=list)
    mitre_techniques: List[MitreTechniqueRef] = field(default_factory=list)
    cvss4: Optional[CVSSv4Metrics] = None
    cvss4_score: float = 0.0
    epss_probability: float = 0.0
    kev_listed: bool = False
    verification_method: VerificationMethod = VerificationMethod.STATIC_PATTERN
    sandbox_reproduced: bool = False
    file_path: str = ""
    line_start: int = 1
    line_end: int = 1
    endpoint_or_asset: str = ""
    code_snippet: str = ""
    attack_vector_detail: str = ""
    remediation_guidance: str = ""
    secure_code_example: str = ""
    evidence: List[EvidenceArtifact] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    discovered_by: str = "ely_cyber_engine"
    discovered_at: str = field(default_factory=utc_now_iso)

    def fingerprint(self) -> str:
        raw = json.dumps(
            [
                self.rule_id,
                self.cyber_domain.value,
                self.file_path,
                self.endpoint_or_asset,
                self.line_start,
            ],
            sort_keys=True,
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]

    def to_soe_finding(self) -> Finding:
        """Convert to core SOE Finding strictly as HYPOTHESIS (Separation of Duties)."""
        loc = CodeLocation(
            file_path=self.file_path or self.endpoint_or_asset or "unknown",
            line_start=max(1, int(self.line_start)),
            line_end=max(1, int(self.line_end)),
            snippet=self.code_snippet[:400],
        )
        merged_tags = sorted(
            set(
                list(self.tags)
                + [f"cyber:{self.cyber_domain.value}", f"method:{self.verification_method.value}"]
                + [f"owasp:{c}" for c in self.owasp_categories]
                + [f"attack:{m.technique_id}" for m in self.mitre_techniques]
            )
        )
        return Finding(
            finding_id=self.vuln_id if self.vuln_id.startswith("fnd-") else new_id("fnd"),
            rule_id=self.rule_id,
            title=self.title,
            description=self.description,
            domain=self.cyber_domain.to_soe_domain(),
            severity=self.severity,
            status=FindingStatus.HYPOTHESIS,
            confidence=max(0.05, min(0.99, float(self.confidence))),
            discovered_by=self.discovered_by,
            location=loc,
            cwe_ids=list(self.cwe_ids),
            tags=merged_tags,
            remediation_hint=self.remediation_guidance,
            evidence_summary=self.attack_vector_detail or self.description[:240],
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_id": self.vuln_id,
            "fingerprint": self.fingerprint(),
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "cyber_domain": self.cyber_domain.value,
            "soe_domain": self.cyber_domain.to_soe_domain().value,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 3),
            "cwe_ids": list(self.cwe_ids),
            "owasp_categories": list(self.owasp_categories),
            "mitre_techniques": [m.to_dict() for m in self.mitre_techniques],
            "cvss4": self.cvss4.to_dict() if self.cvss4 else None,
            "cvss4_score": round(self.cvss4_score, 1),
            "epss_probability": round(self.epss_probability, 4),
            "kev_listed": self.kev_listed,
            "verification_method": self.verification_method.value,
            "sandbox_reproduced": self.sandbox_reproduced,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "endpoint_or_asset": self.endpoint_or_asset,
            "code_snippet": self.code_snippet[:400],
            "attack_vector_detail": self.attack_vector_detail,
            "remediation_guidance": self.remediation_guidance,
            "secure_code_example": self.secure_code_example[:600],
            "evidence": [e.to_dict() for e in self.evidence],
            "tags": list(self.tags),
            "discovered_by": self.discovered_by,
            "discovered_at": self.discovered_at,
        }


@dataclass
class HttpProbeRequest:
    """Normalized HTTP request structure used in local sandboxed web security probes."""

    method: str
    path: str
    headers: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    content_type: str = "application/json"
    protocol_version: str = "HTTP/1.1"
    raw_wire: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "headers": dict(self.headers),
            "query_params": dict(self.query_params),
            "body": self.body[:800],
            "cookies": dict(self.cookies),
            "protocol_version": self.protocol_version,
        }


@dataclass
class HttpProbeResponse:
    """Normalized HTTP response structure returned by sandboxed local web handlers."""

    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0
    side_effects: List[str] = field(default_factory=list)
    db_queries_executed: List[str] = field(default_factory=list)
    outbound_requests: List[str] = field(default_factory=list)
    shell_commands: List[str] = field(default_factory=list)
    files_accessed: List[str] = field(default_factory=list)

    def header_lower(self, name: str, default: str = "") -> str:
        target = name.lower()
        for k, v in self.headers.items():
            if k.lower() == target:
                return v
        return default

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status_code": self.status_code,
            "headers": dict(self.headers),
            "body": self.body[:800],
            "elapsed_ms": round(self.elapsed_ms, 2),
            "side_effects": list(self.side_effects),
            "db_queries_executed": list(self.db_queries_executed[:5]),
            "outbound_requests": list(self.outbound_requests[:5]),
            "shell_commands": list(self.shell_commands[:5]),
            "files_accessed": list(self.files_accessed[:5]),
        }


@dataclass
class NetworkServiceDescriptor:
    """Authorized snapshot descriptor for an internal or lab network service."""

    host: str
    port: int
    protocol: str  # tcp, udp
    service_name: str  # http, https, ssh, smb, dns, smtp, ldap, redis, postgres, etc.
    banner: str = ""
    tls_enabled: bool = False
    tls_version: str = ""
    cipher_suites: List[str] = field(default_factory=list)
    certificate_info: Dict[str, Any] = field(default_factory=dict)
    auth_required: bool = True
    exposed_zone: str = "internal"  # internet, dmz, internal, restricted_mgmt
    config_flags: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "service_name": self.service_name,
            "banner": self.banner,
            "tls_enabled": self.tls_enabled,
            "tls_version": self.tls_version,
            "cipher_suites": list(self.cipher_suites),
            "auth_required": self.auth_required,
            "exposed_zone": self.exposed_zone,
            "config_flags": dict(self.config_flags),
        }


@dataclass
class FirewallRuleDescriptor:
    """Firewall / Security Group / Network ACL rule for segmentation auditing."""

    rule_id: str
    direction: str  # ingress, egress
    action: str  # allow, deny
    source_cidr: str
    dest_cidr: str
    protocol: str
    port_start: int
    port_end: int
    zone_src: str = "unknown"
    zone_dst: str = "unknown"
    description: str = ""

    def matches_port(self, port: int) -> bool:
        return self.port_start <= port <= self.port_end

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "direction": self.direction,
            "action": self.action,
            "source_cidr": self.source_cidr,
            "dest_cidr": self.dest_cidr,
            "protocol": self.protocol,
            "port_range": f"{self.port_start}-{self.port_end}",
            "zone_src": self.zone_src,
            "zone_dst": self.zone_dst,
            "description": self.description,
        }


@dataclass
class CloudIAMPolicyStatement:
    """Normalized multi-cloud IAM statement (AWS/GCP/Azure)."""

    sid: str
    effect: str  # Allow, Deny
    actions: List[str]
    resources: List[str]
    conditions: Dict[str, Any] = field(default_factory=dict)
    principals: List[str] = field(default_factory=list)

    def allows_action(self, action: str) -> bool:
        if self.effect.lower() != "allow":
            return False
        act_l = action.lower()
        for pat in self.actions:
            p = pat.lower()
            if p == "*" or p == act_l:
                return True
            if p.endswith("*") and act_l.startswith(p[:-1]):
                return True
        return False

    def covers_all_resources(self) -> bool:
        return any(r.strip() in ("*", "arn:aws:*:*:*:*", "projects/*/roles/*", "/*") for r in self.resources)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sid": self.sid,
            "effect": self.effect,
            "actions": list(self.actions),
            "resources": list(self.resources),
            "conditions": dict(self.conditions),
            "principals": list(self.principals),
        }


@dataclass
class CloudPrincipalNode:
    """Cloud identity principal (IAM User, Role, Service Account, Managed Identity)."""

    principal_id: str
    provider: str  # aws, gcp, azure
    principal_type: str  # user, role, service_account, workload_identity, group
    account_id: str = "000000000000"
    is_admin: bool = False
    is_external_facing: bool = False
    mfa_enforced: bool = True
    statements: List[CloudIAMPolicyStatement] = field(default_factory=list)
    trust_principals: List[str] = field(default_factory=list)
    attached_managed_policies: List[str] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)

    def effective_allows(self, action: str) -> bool:
        denied = any(
            s.effect.lower() == "deny" and any(
                p.lower() == "*" or p.lower() == action.lower() or (p.endswith("*") and action.lower().startswith(p[:-1].lower()))
                for p in s.actions
            )
            for s in self.statements
        )
        if denied:
            return False
        return any(s.allows_action(action) for s in self.statements)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "provider": self.provider,
            "principal_type": self.principal_type,
            "account_id": self.account_id,
            "is_admin": self.is_admin,
            "is_external_facing": self.is_external_facing,
            "mfa_enforced": self.mfa_enforced,
            "statements_count": len(self.statements),
            "trust_principals": list(self.trust_principals),
        }


@dataclass
class IdentityDirectoryObject:
    """Enterprise Active Directory / IdP principal or object node."""

    object_id: str
    name: str
    object_type: str  # user, computer, group, gpo, cert_template, ca, domain, service_principal
    domain: str = "corp.local"
    tier: int = 2  # 0 = Domain Admin / DC / CA, 1 = Servers, 2 = Workstations/Users
    enabled: bool = True
    spns: List[str] = field(default_factory=list)
    dont_req_preauth: bool = False
    unconstrained_delegation: bool = False
    constrained_delegation_targets: List[str] = field(default_factory=list)
    rbcd_allowed_principals: List[str] = field(default_factory=list)
    password_never_expires: bool = False
    admin_count: int = 0
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "object_id": self.object_id,
            "name": self.name,
            "object_type": self.object_type,
            "domain": self.domain,
            "tier": self.tier,
            "enabled": self.enabled,
            "spns": list(self.spns),
            "dont_req_preauth": self.dont_req_preauth,
            "unconstrained_delegation": self.unconstrained_delegation,
            "constrained_delegation_targets": list(self.constrained_delegation_targets),
        }


@dataclass
class IdentityDirectoryEdge:
    """Directed privilege, membership, delegation, or ACL edge in an identity graph."""

    src_id: str
    dst_id: str
    relation: str  # MemberOf, GenericAll, WriteDacl, WriteOwner, ForceChangePassword, DCSync, CanRDP, HasSession, AllowedToDelegate, Enroll, WriteProperty
    exploit_probability: float = 0.85
    mitre_id: str = "T1078"
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src_id": self.src_id,
            "dst_id": self.dst_id,
            "relation": self.relation,
            "exploit_probability": round(self.exploit_probability, 3),
            "mitre_id": self.mitre_id,
            "notes": self.notes,
        }


@dataclass
class BinarySecurityProfile:
    """Extracted security hardening & import profile for an ELF or PE binary."""

    file_path: str
    binary_format: str  # ELF64, ELF32, PE32, PE32+, Mach-O, UNKNOWN
    architecture: str
    endianness: str
    has_pie: bool = False
    has_nx: bool = False
    has_relro: str = "none"  # none, partial, full
    has_stack_canary: bool = False
    has_aslr: bool = False
    has_dep: bool = False
    has_cfg: bool = False
    has_fortify: bool = False
    has_rpath: bool = False
    stripped: bool = False
    dangerous_imports: List[str] = field(default_factory=list)
    sections: List[Dict[str, Any]] = field(default_factory=list)
    hardening_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "binary_format": self.binary_format,
            "architecture": self.architecture,
            "endianness": self.endianness,
            "has_pie": self.has_pie,
            "has_nx": self.has_nx,
            "has_relro": self.has_relro,
            "has_stack_canary": self.has_stack_canary,
            "has_aslr": self.has_aslr,
            "has_dep": self.has_dep,
            "has_cfg": self.has_cfg,
            "has_fortify": self.has_fortify,
            "has_rpath": self.has_rpath,
            "stripped": self.stripped,
            "dangerous_imports": list(self.dangerous_imports),
            "sections_count": len(self.sections),
            "hardening_score": round(self.hardening_score, 2),
        }


@dataclass
class GeneralizedExploitStep:
    """Single atomic step inside a multi-stage generalized exploit chain."""

    step_index: int
    src_state: str
    dst_state: str
    cyber_domain: CyberDomain
    technique_id: str
    technique_name: str
    vuln_id: str
    rule_id: str
    success_probability: float
    stealth_score: float
    prerequisites: List[str] = field(default_factory=list)
    gained_capabilities: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_index": self.step_index,
            "src_state": self.src_state,
            "dst_state": self.dst_state,
            "cyber_domain": self.cyber_domain.value,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "vuln_id": self.vuln_id,
            "rule_id": self.rule_id,
            "success_probability": round(self.success_probability, 3),
            "stealth_score": round(self.stealth_score, 3),
            "prerequisites": list(self.prerequisites),
            "gained_capabilities": list(self.gained_capabilities),
        }


@dataclass
class GeneralizedExploitChain:
    """End-to-end attack chain linking initial foothold to a crown-jewel impact state."""

    chain_id: str
    entry_state: str
    objective_state: str
    steps: List[GeneralizedExploitStep]
    cumulative_probability: float
    mean_stealth: float
    impact_score: float
    composite_chain_risk: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "entry_state": self.entry_state,
            "objective_state": self.objective_state,
            "hop_count": len(self.steps),
            "cumulative_probability": round(self.cumulative_probability, 4),
            "mean_stealth": round(self.mean_stealth, 3),
            "impact_score": round(self.impact_score, 2),
            "composite_chain_risk": round(self.composite_chain_risk, 2),
            "steps": [s.to_dict() for s in self.steps],
        }


@dataclass
class TelemetryEvent:
    """Normalized security event log consumed by the Sigma detection engine."""

    event_id: str
    timestamp: str
    log_source: str  # process_creation, network_connection, cloudtrail, k8s_audit, auth, dns, web_access, windows_security
    host: str
    actor: str
    fields: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "log_source": self.log_source,
            "host": self.host,
            "actor": self.actor,
            "fields": dict(self.fields),
        }


@dataclass
class DetectionMatch:
    """Result emitted when a Sigma or YARA detection rule matches telemetry or bytes."""

    match_id: str
    engine: str  # sigma, yara
    rule_id: str
    rule_title: str
    severity: Severity
    mitre_techniques: List[str]
    target_ref: str
    matched_evidence: str
    matched_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "match_id": self.match_id,
            "engine": self.engine,
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "severity": self.severity.value,
            "mitre_techniques": list(self.mitre_techniques),
            "target_ref": self.target_ref,
            "matched_evidence": self.matched_evidence[:300],
            "matched_at": self.matched_at,
        }


@dataclass
class CyberAssessmentSummary:
    """Aggregate report emitted by the Generalized Cybersecurity Assessment Orchestrator."""

    assessment_id: str
    target_name: str
    target_root: str
    started_at: str
    completed_at: str
    domains_executed: List[str]
    vulnerabilities: List[CyberVulnerability]
    exploit_chains: List[GeneralizedExploitChain] = field(default_factory=list)
    detection_matches: List[DetectionMatch] = field(default_factory=list)
    emulation_summary: Dict[str, Any] = field(default_factory=dict)
    threat_model: Dict[str, Any] = field(default_factory=dict)
    binary_profiles: List[BinarySecurityProfile] = field(default_factory=list)
    risk_summary: Dict[str, Any] = field(default_factory=dict)
    domain_scores: Dict[str, float] = field(default_factory=dict)
    overall_cyber_posture: float = 100.0
    ledger_merkle_root: str = ""
    auditor_signature: str = ""

    def severity_counts(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in self.vulnerabilities:
            counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
        return counts

    def domain_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for v in self.vulnerabilities:
            counts[v.cyber_domain.value] = counts.get(v.cyber_domain.value, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "target_name": self.target_name,
            "target_root": self.target_root,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "domains_executed": list(self.domains_executed),
            "total_vulnerabilities": len(self.vulnerabilities),
            "severity_counts": self.severity_counts(),
            "domain_counts": self.domain_counts(),
            "overall_cyber_posture": round(self.overall_cyber_posture, 2),
            "domain_scores": {k: round(v, 2) for k, v in self.domain_scores.items()},
            "risk_summary": dict(self.risk_summary),
            "exploit_chains": [c.to_dict() for c in self.exploit_chains[:15]],
            "detection_matches_count": len(self.detection_matches),
            "detection_matches": [m.to_dict() for m in self.detection_matches[:40]],
            "emulation_summary": dict(self.emulation_summary),
            "threat_model": dict(self.threat_model),
            "binary_profiles": [b.to_dict() for b in self.binary_profiles[:20]],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "ledger_merkle_root": self.ledger_merkle_root,
            "auditor_signature": self.auditor_signature,
        }


def make_cyber_vuln(
    *,
    rule_id: str,
    title: str,
    description: str,
    cyber_domain: CyberDomain,
    severity: Severity,
    cwe_ids: List[str],
    confidence: float = 0.86,
    owasp_categories: Optional[List[str]] = None,
    mitre_techniques: Optional[List[MitreTechniqueRef]] = None,
    cvss4: Optional[CVSSv4Metrics] = None,
    epss_probability: float = 0.0,
    kev_listed: bool = False,
    verification_method: VerificationMethod = VerificationMethod.STATIC_PATTERN,
    sandbox_reproduced: bool = False,
    file_path: str = "",
    line_start: int = 1,
    line_end: int = 1,
    endpoint_or_asset: str = "",
    code_snippet: str = "",
    attack_vector_detail: str = "",
    remediation_guidance: str = "",
    secure_code_example: str = "",
    evidence: Optional[List[EvidenceArtifact]] = None,
    tags: Optional[List[str]] = None,
    discovered_by: str = "ely_cyber_engine",
) -> CyberVulnerability:
    """Factory helper constructing a well-formed `CyberVulnerability`."""
    return CyberVulnerability(
        vuln_id=new_id("cvuln"),
        rule_id=rule_id,
        title=title,
        description=description,
        cyber_domain=cyber_domain,
        severity=severity,
        confidence=confidence,
        cwe_ids=list(cwe_ids),
        owasp_categories=list(owasp_categories or []),
        mitre_techniques=list(mitre_techniques or []),
        cvss4=cvss4,
        epss_probability=epss_probability,
        kev_listed=kev_listed,
        verification_method=verification_method,
        sandbox_reproduced=sandbox_reproduced,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        endpoint_or_asset=endpoint_or_asset,
        code_snippet=code_snippet,
        attack_vector_detail=attack_vector_detail,
        remediation_guidance=remediation_guidance,
        secure_code_example=secure_code_example,
        evidence=list(evidence or []),
        tags=list(tags or []),
        discovered_by=discovered_by,
    )
