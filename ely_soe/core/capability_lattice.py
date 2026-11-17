"""
CaMeL-Inspired Information Flow Control (IFC) & Capability Security Lattice.

Grounded in frontier AI security research (CaMeL: Defeating Prompt Injections by
Design — Control/Data Plane Separation, capability-based security, and zero-trust
multi-agent delegation).

Enforces:
  1. Provenance & Taint Lattice: Every datum carries an immutable trust label
     (`SYSTEM_TRUSTED` > `USER_VERIFIED` > `AGENT_INTERNAL` > `EXTERNAL_UNTRUSTED`
     > `ADVERSARIAL_TAINTED`). Combining data takes the least-trusted join (`lub`).
  2. Capability Grants: Agents and skills only execute operations explicitly authorized
     by scoped, non-forgeable capability tokens (path prefixes, domains, tool names,
     IPC targets, memory namespaces, max spawn counts).
  3. Delegation Attenuation: When Agent A delegates to Agent B, delegated capabilities
     MUST be a strict subset (attenuation) of A's capabilities; privilege amplification
     and confused-deputy calls are rejected and flagged.
  4. Control-Flow Integrity (CFI) for Prompts: Untrusted/external data can NEVER
     enter the privileged instruction/control plane or trigger privileged side-effect
     tools without an explicit policy sanitizer + human/policy approval gate.
"""

from __future__ import annotations

import fnmatch
import posixpath
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from ely_soe.core.models import utc_now_iso


class TrustLevel(IntEnum):
    """
    Security provenance lattice ordered from highest trust (0) to lowest trust (4).
    The lattice join (combining two values) is `max(a, b)` — taint is sticky!
    """

    SYSTEM_TRUSTED = 0       # Signed Ely core policies, auditor plane
    USER_VERIFIED = 1        # Direct authenticated operator instructions
    AGENT_INTERNAL = 2       # Derived internal state of a single isolated agent
    EXTERNAL_UNTRUSTED = 3   # Web pages, emails, external APIs, third-party tool outputs
    ADVERSARIAL_TAINTED = 4  # Confirmed or suspected prompt-injection / untrusted input

    @classmethod
    def join(cls, *levels: "TrustLevel") -> "TrustLevel":
        if not levels:
            return cls.SYSTEM_TRUSTED
        return cls(max(int(lv) for lv in levels))


@dataclass(frozen=True)
class ProvenanceTag:
    """Tracks origin, taint level, and transformation lineage of any value in Ely."""

    trust_level: TrustLevel
    source_id: str
    origin_agent: Optional[str] = None
    namespace: str = "default"
    sanitizers_applied: FrozenSet[str] = field(default_factory=frozenset)
    lineage: Tuple[str, ...] = field(default_factory=tuple)

    def combine(self, other: "ProvenanceTag", op: str = "merge") -> "ProvenanceTag":
        joined_trust = TrustLevel.join(self.trust_level, other.trust_level)
        # Sanitizers only survive if applied to BOTH inputs
        common_sanitizers = self.sanitizers_applied.intersection(other.sanitizers_applied)
        new_lineage = (self.lineage + other.lineage + (f"{op}:{self.source_id}+{other.source_id}",))[-12:]
        return ProvenanceTag(
            trust_level=joined_trust,
            source_id=f"{self.source_id}+{other.source_id}",
            origin_agent=self.origin_agent or other.origin_agent,
            namespace=self.namespace if self.namespace == other.namespace else "cross_namespace",
            sanitizers_applied=common_sanitizers,
            lineage=new_lineage,
        )

    def with_sanitizer(self, sanitizer_name: str, downgraded_trust: Optional[TrustLevel] = None) -> "ProvenanceTag":
        new_trust = self.trust_level
        # A sanitizer can at most lift EXTERNAL_UNTRUSTED -> AGENT_INTERNAL, never SYSTEM_TRUSTED
        if downgraded_trust is not None and downgraded_trust >= TrustLevel.AGENT_INTERNAL:
            new_trust = min(self.trust_level, downgraded_trust)
        return ProvenanceTag(
            trust_level=new_trust,
            source_id=self.source_id,
            origin_agent=self.origin_agent,
            namespace=self.namespace,
            sanitizers_applied=self.sanitizers_applied | {sanitizer_name},
            lineage=(self.lineage + (f"sanitized:{sanitizer_name}",))[-12:],
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trust_level": self.trust_level.name,
            "source_id": self.source_id,
            "origin_agent": self.origin_agent,
            "namespace": self.namespace,
            "sanitizers_applied": sorted(self.sanitizers_applied),
            "lineage": list(self.lineage),
        }


@dataclass(frozen=True)
class CapabilityGrant:
    """
    Fine-grained least-privilege capability token assigned to an agent or skill.

    Examples:
        CapabilityGrant(resource_type="fs_read", pattern="/workspace/proj_a/**")
        CapabilityGrant(resource_type="tool_invoke", pattern="search_docs")
        CapabilityGrant(resource_type="net_egress", pattern="api.github.com:443")
        CapabilityGrant(resource_type="memory_write", pattern="agent:researcher:*")
    """

    resource_type: str  # fs_read, fs_write, tool_invoke, net_egress, memory_read, memory_write, proc_spawn, ipc_send, audit_read
    pattern: str
    max_trust_required: TrustLevel = TrustLevel.USER_VERIFIED
    delegatable: bool = False
    requires_human_approval: bool = False
    rate_limit_per_min: int = 60

    def is_wildcard_overreach(self) -> bool:
        """Detect overly permissive wildcard grants that violate least privilege."""
        dangerous_patterns = {"*", "**", "/**", "/", "0.0.0.0/0", "*:*", "/*"}
        return self.pattern.strip() in dangerous_patterns

    def matches(self, resource_type: str, target: str) -> bool:
        if self.resource_type != resource_type:
            return False
        if self.resource_type in ("fs_read", "fs_write"):
            norm_target = posixpath.normpath(target)
            norm_pat = self.pattern
            if norm_pat.endswith("/**"):
                prefix = posixpath.normpath(norm_pat[:-3])
                return norm_target == prefix or norm_target.startswith(prefix.rstrip("/") + "/")
            return fnmatch.fnmatch(norm_target, norm_pat)
        return fnmatch.fnmatch(target, self.pattern)

    def subsumes(self, child: "CapabilityGrant") -> bool:
        """Check whether `self` strictly encompasses `child` (valid delegation attenuation)."""
        if self.resource_type != child.resource_type:
            return False
        if not self.delegatable:
            return False
        if child.max_trust_required > self.max_trust_required:
            # Child would accept less-trusted inputs than parent allows -> escalation!
            return False
        if self.pattern == child.pattern:
            return True
        if self.pattern.endswith("/**") and child.pattern.startswith(self.pattern[:-3]):
            return True
        if self.pattern.endswith("*") and child.pattern.startswith(self.pattern[:-1]):
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_type": self.resource_type,
            "pattern": self.pattern,
            "max_trust_required": self.max_trust_required.name,
            "delegatable": self.delegatable,
            "requires_human_approval": self.requires_human_approval,
            "rate_limit_per_min": self.rate_limit_per_min,
        }


@dataclass
class AgentSecurityPrincipal:
    """Identity, isolation namespace, and capability set of a single Ely agent or skill."""

    principal_id: str
    role: str  # researcher, executor, skill, orchestrator, auditor
    namespace: str
    workspace_root: str
    capabilities: List[CapabilityGrant] = field(default_factory=list)
    allowed_ipc_peers: Set[str] = field(default_factory=set)
    can_modify_validation: bool = False  # MUST ALWAYS be False for non-auditors!
    max_child_processes: int = 0
    isolated_memory_prefix: str = ""

    def __post_init__(self) -> None:
        if not self.isolated_memory_prefix:
            self.isolated_memory_prefix = f"ns:{self.namespace}:agent:{self.principal_id}:"

    def overreach_findings(self) -> List[str]:
        issues: List[str] = []
        if self.role != "auditor" and self.can_modify_validation:
            issues.append(f"Principal '{self.principal_id}' ({self.role}) has can_modify_validation=True!")
        for cap in self.capabilities:
            if cap.is_wildcard_overreach():
                issues.append(
                    f"Principal '{self.principal_id}' holds wildcard overreach capability {cap.resource_type}:{cap.pattern}"
                )
            if cap.resource_type in ("proc_spawn", "fs_write") and cap.max_trust_required >= TrustLevel.EXTERNAL_UNTRUSTED:
                issues.append(
                    f"Principal '{self.principal_id}' permits {cap.resource_type} driven by EXTERNAL_UNTRUSTED taint!"
                )
        return issues

    def to_dict(self) -> Dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "role": self.role,
            "namespace": self.namespace,
            "workspace_root": self.workspace_root,
            "capabilities": [c.to_dict() for c in self.capabilities],
            "allowed_ipc_peers": sorted(self.allowed_ipc_peers),
            "can_modify_validation": self.can_modify_validation,
            "max_child_processes": self.max_child_processes,
            "isolated_memory_prefix": self.isolated_memory_prefix,
        }


@dataclass
class PolicyDecision:
    """Decision record emitted by the CapabilityPolicyEngine."""

    allowed: bool
    principal_id: str
    action: str
    target: str
    reason: str
    violation_code: Optional[str] = None
    provenance_trust: str = "SYSTEM_TRUSTED"
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "principal_id": self.principal_id,
            "action": self.action,
            "target": self.target,
            "reason": self.reason,
            "violation_code": self.violation_code,
            "provenance_trust": self.provenance_trust,
            "timestamp": self.timestamp,
        }


class CapabilityPolicyEngine:
    """
    Zero-Trust runtime and static policy verifier enforcing:
      - Agent-to-agent namespace isolation
      - CaMeL control/data plane taint barriers
      - Least-privilege capability checking
      - Delegation attenuation (anti-confused-deputy)
      - Auditor plane immutability
    """

    PRIVILEGED_ACTIONS = frozenset({"fs_write", "proc_spawn", "net_egress", "tool_invoke", "audit_write", "skill_install"})

    def __init__(self) -> None:
        self.principals: Dict[str, AgentSecurityPrincipal] = {}
        self.decision_log: List[PolicyDecision] = []

    def register_principal(self, principal: AgentSecurityPrincipal) -> None:
        self.principals[principal.principal_id] = principal

    def _record(self, decision: PolicyDecision) -> PolicyDecision:
        self.decision_log.append(decision)
        return decision

    def evaluate_action(
        self,
        principal_id: str,
        action: str,
        target: str,
        input_provenance: Optional[ProvenanceTag] = None,
        human_approved: bool = False,
    ) -> PolicyDecision:
        prov = input_provenance or ProvenanceTag(TrustLevel.AGENT_INTERNAL, source_id=principal_id)

        if principal_id not in self.principals:
            return self._record(
                PolicyDecision(
                    allowed=False,
                    principal_id=principal_id,
                    action=action,
                    target=target,
                    reason="Unknown/unregistered principal denied by default zero-trust policy",
                    violation_code="ZT_UNKNOWN_PRINCIPAL",
                    provenance_trust=prov.trust_level.name,
                )
            )

        principal = self.principals[principal_id]

        # Hard Invariant 1: No non-auditor may EVER touch validation or audit results
        if action in ("audit_write", "validation_modify", "ledger_tamper"):
            if principal.role != "auditor" or not principal.can_modify_validation:
                return self._record(
                    PolicyDecision(
                        allowed=False,
                        principal_id=principal_id,
                        action=action,
                        target=target,
                        reason="Auditor plane isolation: non-auditor principals cannot alter validation results",
                        violation_code="SOD_VALIDATION_TAMPER",
                        provenance_trust=prov.trust_level.name,
                    )
                )

        # Hard Invariant 2: Path traversal & workspace boundary enforcement
        if action in ("fs_read", "fs_write"):
            if ".." in target.split("/") or "\x00" in target:
                return self._record(
                    PolicyDecision(
                        allowed=False,
                        principal_id=principal_id,
                        action=action,
                        target=target,
                        reason="Path traversal or null-byte smuggling detected in filesystem request",
                        violation_code="FS_TRAVERSAL_BLOCKED",
                        provenance_trust=prov.trust_level.name,
                    )
                )
            norm_target = posixpath.normpath(target)
            norm_root = posixpath.normpath(principal.workspace_root)
            if not (norm_target == norm_root or norm_target.startswith(norm_root.rstrip("/") + "/")):
                return self._record(
                    PolicyDecision(
                        allowed=False,
                        principal_id=principal_id,
                        action=action,
                        target=target,
                        reason=f"Target '{norm_target}' escapes principal workspace '{norm_root}'",
                        violation_code="FS_WORKSPACE_ESCAPE",
                        provenance_trust=prov.trust_level.name,
                    )
                )

        # Hard Invariant 3: Cross-agent memory namespace isolation
        if action in ("memory_read", "memory_write"):
            if not target.startswith(principal.isolated_memory_prefix):
                return self._record(
                    PolicyDecision(
                        allowed=False,
                        principal_id=principal_id,
                        action=action,
                        target=target,
                        reason=(
                            f"Cross-agent memory boundary violation: '{principal_id}' attempted "
                            f"{action} on '{target}' outside '{principal.isolated_memory_prefix}'"
                        ),
                        violation_code="AGENT_MEMORY_CROSS_NAMESPACE",
                        provenance_trust=prov.trust_level.name,
                    )
                )

        # Hard Invariant 4: CaMeL Control/Data Plane Separation
        if action in self.PRIVILEGED_ACTIONS and prov.trust_level >= TrustLevel.EXTERNAL_UNTRUSTED:
            if not human_approved:
                return self._record(
                    PolicyDecision(
                        allowed=False,
                        principal_id=principal_id,
                        action=action,
                        target=target,
                        reason=(
                            f"CaMeL IFC violation: {prov.trust_level.name} data from '{prov.source_id}' "
                            f"cannot directly drive privileged action '{action}' without explicit approval"
                        ),
                        violation_code="CAMEL_UNTRUSTED_CONTROL_FLOW",
                        provenance_trust=prov.trust_level.name,
                    )
                )

        # Hard Invariant 5: Explicit capability matching
        matching = [c for c in principal.capabilities if c.matches(action, target)]
        if not matching:
            return self._record(
                PolicyDecision(
                    allowed=False,
                    principal_id=principal_id,
                    action=action,
                    target=target,
                    reason=f"Least-privilege deny: principal '{principal_id}' lacks capability for {action}:{target}",
                    violation_code="CAP_MISSING_GRANT",
                    provenance_trust=prov.trust_level.name,
                )
            )

        best_grant = min(matching, key=lambda c: int(c.max_trust_required))
        if prov.trust_level > best_grant.max_trust_required and not human_approved:
            return self._record(
                PolicyDecision(
                    allowed=False,
                    principal_id=principal_id,
                    action=action,
                    target=target,
                    reason=(
                        f"Trust threshold exceeded: input trust {prov.trust_level.name} is weaker than "
                        f"required {best_grant.max_trust_required.name}"
                    ),
                    violation_code="IFC_TRUST_DEGRADATION",
                    provenance_trust=prov.trust_level.name,
                )
            )

        if best_grant.requires_human_approval and not human_approved:
            return self._record(
                PolicyDecision(
                    allowed=False,
                    principal_id=principal_id,
                    action=action,
                    target=target,
                    reason="Action requires explicit out-of-band human approval",
                    violation_code="APPROVAL_REQUIRED",
                    provenance_trust=prov.trust_level.name,
                )
            )

        return self._record(
            PolicyDecision(
                allowed=True,
                principal_id=principal_id,
                action=action,
                target=target,
                reason=f"Authorized by capability {best_grant.resource_type}:{best_grant.pattern}",
                provenance_trust=prov.trust_level.name,
            )
        )

    def evaluate_delegation(
        self,
        delegator_id: str,
        delegatee_id: str,
        requested_grant: CapabilityGrant,
        context_provenance: ProvenanceTag,
    ) -> PolicyDecision:
        """
        Verify multi-agent delegation: prevents confused-deputy attacks and
        capability amplification by a compromised skill or sub-agent.
        """
        if delegator_id not in self.principals or delegatee_id not in self.principals:
            return self._record(
                PolicyDecision(
                    allowed=False,
                    principal_id=delegator_id,
                    action="delegate_capability",
                    target=f"{delegatee_id}:{requested_grant.resource_type}:{requested_grant.pattern}",
                    reason="Unknown delegator or delegatee principal",
                    violation_code="DELEGATION_UNKNOWN_PRINCIPAL",
                    provenance_trust=context_provenance.trust_level.name,
                )
            )

        delegator = self.principals[delegator_id]
        if delegatee_id not in delegator.allowed_ipc_peers:
            return self._record(
                PolicyDecision(
                    allowed=False,
                    principal_id=delegator_id,
                    action="delegate_capability",
                    target=delegatee_id,
                    reason=f"IPC isolation violation: '{delegator_id}' is not authorized to communicate with '{delegatee_id}'",
                    violation_code="AGENT_IPC_ISOLATION_VIOLATION",
                    provenance_trust=context_provenance.trust_level.name,
                )
            )

        if context_provenance.trust_level >= TrustLevel.EXTERNAL_UNTRUSTED:
            return self._record(
                PolicyDecision(
                    allowed=False,
                    principal_id=delegator_id,
                    action="delegate_capability",
                    target=f"{delegatee_id}:{requested_grant.resource_type}",
                    reason="Confused-deputy defense: untrusted external content cannot trigger capability delegation",
                    violation_code="CONFUSED_DEPUTY_DELEGATION",
                    provenance_trust=context_provenance.trust_level.name,
                )
            )

        if not any(cap.subsumes(requested_grant) for cap in delegator.capabilities):
            return self._record(
                PolicyDecision(
                    allowed=False,
                    principal_id=delegator_id,
                    action="delegate_capability",
                    target=f"{delegatee_id}:{requested_grant.resource_type}:{requested_grant.pattern}",
                    reason="Privilege amplification blocked: delegator cannot grant capabilities it does not delegatably hold",
                    violation_code="DELEGATION_ESCALATION_BLOCKED",
                    provenance_trust=context_provenance.trust_level.name,
                )
            )

        return self._record(
            PolicyDecision(
                allowed=True,
                principal_id=delegator_id,
                action="delegate_capability",
                target=f"{delegatee_id}:{requested_grant.resource_type}:{requested_grant.pattern}",
                reason="Attenuated delegation verified within allowed IPC peers",
                provenance_trust=context_provenance.trust_level.name,
            )
        )

    def audit_all_principals(self) -> Dict[str, List[str]]:
        """Static verification of all registered principals for policy overreach."""
        report: Dict[str, List[str]] = {}
        for pid, principal in self.principals.items():
            issues = principal.overreach_findings()
            if issues:
                report[pid] = issues
        return report

    @classmethod
    def build_default_ely_policy(cls) -> "CapabilityPolicyEngine":
        """
        Constructs the canonical hardened zero-trust Ely 1.0 capability policy:
          - Strictly disjoint per-agent workspaces & memory namespaces
          - CaMeL trust boundaries blocking EXTERNAL_UNTRUSTED privileged side effects
          - Isolated Auditor plane unreachable via IPC from any evaluated agent
          - Zero wildcards and zero transitive delegation paths to `proc_spawn`
        """
        engine = cls()
        engine.register_principal(
            AgentSecurityPrincipal(
                principal_id="ely-researcher",
                role="researcher",
                namespace="ns-research",
                workspace_root="/workspace/research",
                isolated_memory_prefix="mem:research:",
                can_modify_validation=False,
                allowed_ipc_peers={"ely-planner"},
                capabilities=[
                    CapabilityGrant("fs_read", "/workspace/research/**", max_trust_required=TrustLevel.AGENT_INTERNAL),
                    CapabilityGrant("net_egress", "https://api.github.com/**", max_trust_required=TrustLevel.USER_VERIFIED, requires_human_approval=False),
                    CapabilityGrant("memory_read", "mem:research:*", max_trust_required=TrustLevel.AGENT_INTERNAL),
                    CapabilityGrant("memory_write", "mem:research:*", max_trust_required=TrustLevel.AGENT_INTERNAL),
                ],
            )
        )
        engine.register_principal(
            AgentSecurityPrincipal(
                principal_id="ely-planner",
                role="planner",
                namespace="ns-planner",
                workspace_root="/workspace/plans",
                isolated_memory_prefix="mem:planner:",
                can_modify_validation=False,
                allowed_ipc_peers={"ely-researcher", "ely-executor"},
                capabilities=[
                    CapabilityGrant("fs_read", "/workspace/plans/**", max_trust_required=TrustLevel.AGENT_INTERNAL),
                    CapabilityGrant("memory_read", "mem:planner:*", max_trust_required=TrustLevel.AGENT_INTERNAL),
                    CapabilityGrant("memory_write", "mem:planner:*", max_trust_required=TrustLevel.AGENT_INTERNAL),
                ],
            )
        )
        engine.register_principal(
            AgentSecurityPrincipal(
                principal_id="ely-executor",
                role="executor",
                namespace="ns-executor",
                workspace_root="/workspace/proj_alpha",
                isolated_memory_prefix="mem:executor:",
                can_modify_validation=False,
                allowed_ipc_peers={"ely-planner"},
                capabilities=[
                    CapabilityGrant("fs_read", "/workspace/proj_alpha/**", max_trust_required=TrustLevel.AGENT_INTERNAL),
                    CapabilityGrant("fs_write", "/workspace/proj_alpha/**", max_trust_required=TrustLevel.AGENT_INTERNAL),
                    CapabilityGrant("proc_spawn", "pytest", max_trust_required=TrustLevel.USER_VERIFIED, delegatable=False),
                    CapabilityGrant("memory_read", "mem:executor:*", max_trust_required=TrustLevel.AGENT_INTERNAL),
                    CapabilityGrant("memory_write", "mem:executor:*", max_trust_required=TrustLevel.AGENT_INTERNAL),
                ],
            )
        )
        engine.register_principal(
            AgentSecurityPrincipal(
                principal_id="ely-skill-sandboxed",
                role="skill",
                namespace="ns-skill-doc",
                workspace_root="/workspace/skills/doc_fmt",
                isolated_memory_prefix="mem:skill_doc:",
                can_modify_validation=False,
                allowed_ipc_peers=set(),
                capabilities=[
                    CapabilityGrant("fs_read", "/workspace/skills/doc_fmt/*.md", max_trust_required=TrustLevel.AGENT_INTERNAL),
                ],
            )
        )
        engine.register_principal(
            AgentSecurityPrincipal(
                principal_id="ely-independent-auditor",
                role="auditor",
                namespace="ns-auditor-isolated",
                workspace_root="/var/ely/audit_vault",
                isolated_memory_prefix="mem:auditor:",
                can_modify_validation=True,
                allowed_ipc_peers=set(),
                capabilities=[
                    CapabilityGrant("audit_write", "validation/verdicts/*", max_trust_required=TrustLevel.SYSTEM_TRUSTED),
                    CapabilityGrant("memory_read", "mem:auditor:*", max_trust_required=TrustLevel.SYSTEM_TRUSTED),
                ],
            )
        )
        return engine
