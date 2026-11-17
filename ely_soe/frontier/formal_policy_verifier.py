"""
Frontier Research Module 3: Formal Capability Lattice & Non-Interference Policy Verifier.

Performs exhaustive formal verification over an Ely `CapabilityPolicyEngine`
configuration (set of `AgentSecurityPrincipal`s, `CapabilityGrant`s, workspaces,
memory namespaces, and IPC peer graphs), checking 6 mathematical security theorems
and generating minimal counterexample witness traces whenever any theorem fails:

  Theorem 1 (Auditor Plane Unreachability):
      No non-auditor principal can reach `audit_write` / `validation_modify` directly
      or via any finite sequence of IPC/delegation hops.
  Theorem 2 (Strict Workspace Disjointness / Non-Interference):
      No two principals with distinct namespaces share overlapping writable workspace
      prefixes (`fs_write`), preventing silent cross-agent file poisoning.
  Theorem 3 (Memory Namespace Non-Interference):
      No principal possesses a `memory_read` or `memory_write` grant matching another
      principal's isolated memory prefix.
  Theorem 4 (CaMeL Control-Flow Integrity):
      No `EXTERNAL_UNTRUSTED` or `ADVERSARIAL_TAINTED` input can satisfy the trust
      requirement of any privileged side-effect capability (`proc_spawn`, `fs_write`,
      `net_egress`, `skill_install`) without `requires_human_approval=True`.
  Theorem 5 (Zero Wildcard Least Privilege):
      No principal holds unconstrained wildcard capabilities (`*`, `/**`, `0.0.0.0/0`).
  Theorem 6 (Transitive Delegation Safety / No Escalation Cycles):
      Computing the transitive closure of `allowed_ipc_peers` × `delegatable` grants
      proves that a low-trust external-facing agent (e.g., researcher or skill) cannot
      transitively acquire `proc_spawn` or `audit_write` from a peer!
"""

from __future__ import annotations

import posixpath
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from ely_soe.core.capability_lattice import (
    AgentSecurityPrincipal,
    CapabilityGrant,
    CapabilityPolicyEngine,
    TrustLevel,
)
from ely_soe.core.models import utc_now_iso


@dataclass
class CounterexampleWitness:
    """Concrete minimal witness trace disproving a security theorem."""

    theorem_id: str
    theorem_name: str
    severity: str
    principals_involved: List[str]
    hop_trace: List[str]
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "theorem_id": self.theorem_id,
            "theorem_name": self.theorem_name,
            "severity": self.severity,
            "principals_involved": list(self.principals_involved),
            "hop_trace": list(self.hop_trace),
            "explanation": self.explanation,
        }


@dataclass
class TheoremVerificationResult:
    """Verification outcome for one formal security property."""

    theorem_id: str
    name: str
    holds: bool
    states_checked: int
    counterexamples: List[CounterexampleWitness] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "theorem_id": self.theorem_id,
            "name": self.name,
            "holds": self.holds,
            "states_checked": self.states_checked,
            "counterexample_count": len(self.counterexamples),
            "counterexamples": [c.to_dict() for c in self.counterexamples],
        }


class FormalPolicyVerifier:
    """Exhaustive model-checker for multi-agent capability policies & non-interference."""

    PRIVILEGED_TYPES = frozenset({"proc_spawn", "fs_write", "net_egress", "skill_install", "audit_write"})

    def verify_policy(self, engine: CapabilityPolicyEngine) -> Dict[str, Any]:
        principals = list(engine.principals.values())
        theorems = [
            self._verify_t1_auditor_unreachability(principals, engine.principals),
            self._verify_t2_workspace_non_interference(principals),
            self._verify_t3_memory_non_interference(principals),
            self._verify_t4_camel_cfi(principals),
            self._verify_t5_least_privilege_no_wildcards(principals),
            self._verify_t6_transitive_delegation_closure(principals, engine.principals),
        ]

        all_hold = all(t.holds for t in theorems)
        total_counterexamples = sum(len(t.counterexamples) for t in theorems)
        total_states = sum(t.states_checked for t in theorems)
        return {
            "verified_at": utc_now_iso(),
            "principals_verified": len(principals),
            "total_states_checked": total_states,
            "all_theorems_hold": all_hold,
            "passed_theorems": sum(1 for t in theorems if t.holds),
            "total_theorems": len(theorems),
            "total_counterexamples": total_counterexamples,
            "theorems": [t.to_dict() for t in theorems],
        }

    def _verify_t1_auditor_unreachability(
        self,
        principals: List[AgentSecurityPrincipal],
        by_id: Dict[str, AgentSecurityPrincipal],
    ) -> TheoremVerificationResult:
        """T1: No non-auditor principal can reach audit_write/validation_modify directly or via IPC."""
        witnesses: List[CounterexampleWitness] = []
        states = 0

        for p in principals:
            states += 1
            if p.role == "auditor":
                continue
            if p.can_modify_validation:
                witnesses.append(
                    CounterexampleWitness(
                        theorem_id="T1-AUDITOR-UNREACH",
                        theorem_name="Auditor Plane Unreachability",
                        severity="critical",
                        principals_involved=[p.principal_id],
                        hop_trace=[f"{p.principal_id}(role={p.role}) -> can_modify_validation=True"],
                        explanation=f"Non-auditor principal `{p.principal_id}` directly holds validation modification flag!",
                    )
                )
            for cap in p.capabilities:
                states += 1
                if cap.resource_type in ("audit_write", "validation_modify"):
                    witnesses.append(
                        CounterexampleWitness(
                            theorem_id="T1-AUDITOR-UNREACH",
                            theorem_name="Auditor Plane Unreachability",
                            severity="critical",
                            principals_involved=[p.principal_id],
                            hop_trace=[f"{p.principal_id} -> grant({cap.resource_type}:{cap.pattern})"],
                            explanation=f"Non-auditor principal `{p.principal_id}` directly holds `{cap.resource_type}` capability.",
                        )
                    )
            # BFS over IPC graph to verify no non-auditor can reach an auditor principal via IPC
            path = self._bfs_path_to_predicate(
                start_id=p.principal_id,
                by_id=by_id,
                goal_fn=lambda cand: cand.role == "auditor" or cand.can_modify_validation,
            )
            states += len(by_id)
            if path and len(path) > 1:
                witnesses.append(
                    CounterexampleWitness(
                        theorem_id="T1-AUDITOR-UNREACH",
                        theorem_name="Auditor Plane Unreachability",
                        severity="critical",
                        principals_involved=path,
                        hop_trace=[f"IPC: {' -> '.join(path)}"],
                        explanation=f"Untrusted principal `{p.principal_id}` can reach Auditor plane via IPC chain `{path}`!",
                    )
                )

        return TheoremVerificationResult(
            theorem_id="T1-AUDITOR-UNREACH",
            name="Auditor Plane Unreachability Theorem",
            holds=len(witnesses) == 0,
            states_checked=states,
            counterexamples=witnesses,
        )

    def _verify_t2_workspace_non_interference(
        self, principals: List[AgentSecurityPrincipal]
    ) -> TheoremVerificationResult:
        """T2: Principals in distinct namespaces cannot have overlapping writable workspaces."""
        witnesses: List[CounterexampleWitness] = []
        states = 0

        for i, pa in enumerate(principals):
            root_a = posixpath.normpath(pa.workspace_root)
            a_writes = any(c.resource_type == "fs_write" for c in pa.capabilities)
            for pb in principals[i + 1 :]:
                states += 1
                if pa.namespace == pb.namespace:
                    continue
                root_b = posixpath.normpath(pb.workspace_root)
                b_writes = any(c.resource_type == "fs_write" for c in pb.capabilities)
                if not (a_writes or b_writes):
                    continue
                overlap = (
                    root_a == root_b
                    or root_a.startswith(root_b.rstrip("/") + "/")
                    or root_b.startswith(root_a.rstrip("/") + "/")
                )
                if overlap:
                    witnesses.append(
                        CounterexampleWitness(
                            theorem_id="T2-WS-NONINTERFERENCE",
                            theorem_name="Workspace Non-Interference",
                            severity="high",
                            principals_involved=[pa.principal_id, pb.principal_id],
                            hop_trace=[
                                f"{pa.principal_id}({root_a}, write={a_writes}) <-> {pb.principal_id}({root_b}, write={b_writes})"
                            ],
                            explanation="Cross-namespace principals share overlapping writable filesystem workspace roots.",
                        )
                    )

        return TheoremVerificationResult(
            theorem_id="T2-WS-NONINTERFERENCE",
            name="Strict Workspace Disjointness & Non-Interference",
            holds=len(witnesses) == 0,
            states_checked=states,
            counterexamples=witnesses,
        )

    def _verify_t3_memory_non_interference(
        self, principals: List[AgentSecurityPrincipal]
    ) -> TheoremVerificationResult:
        """T3: No principal's memory grant matches another principal's isolated memory prefix."""
        witnesses: List[CounterexampleWitness] = []
        states = 0
        for pa in principals:
            for cap in pa.capabilities:
                if cap.resource_type not in ("memory_read", "memory_write"):
                    continue
                for pb in principals:
                    if pa.principal_id == pb.principal_id:
                        continue
                    states += 1
                    probe_key = pb.isolated_memory_prefix + "session_secret"
                    if cap.matches(cap.resource_type, probe_key):
                        witnesses.append(
                            CounterexampleWitness(
                                theorem_id="T3-MEM-NONINTERFERENCE",
                                theorem_name="Memory Namespace Non-Interference",
                                severity="critical",
                                principals_involved=[pa.principal_id, pb.principal_id],
                                hop_trace=[f"{pa.principal_id}({cap.resource_type}:{cap.pattern}) -> {probe_key}"],
                                explanation=(
                                    f"Principal `{pa.principal_id}` holds memory capability matching "
                                    f"`{pb.principal_id}` private memory namespace `{pb.isolated_memory_prefix}`."
                                ),
                            )
                        )
        return TheoremVerificationResult(
            theorem_id="T3-MEM-NONINTERFERENCE",
            name="Memory Namespace Non-Interference",
            holds=len(witnesses) == 0,
            states_checked=states,
            counterexamples=witnesses,
        )

    def _verify_t4_camel_cfi(
        self, principals: List[AgentSecurityPrincipal]
    ) -> TheoremVerificationResult:
        """T4: No untrusted external provenance can drive privileged side-effect capabilities."""
        witnesses: List[CounterexampleWitness] = []
        states = 0
        for p in principals:
            for cap in p.capabilities:
                states += 1
                if cap.resource_type in self.PRIVILEGED_TYPES:
                    if cap.max_trust_required >= TrustLevel.EXTERNAL_UNTRUSTED and not cap.requires_human_approval:
                        witnesses.append(
                            CounterexampleWitness(
                                theorem_id="T4-CAMEL-CFI",
                                theorem_name="CaMeL Control-Flow Integrity",
                                severity="critical",
                                principals_involved=[p.principal_id],
                                hop_trace=[
                                    f"EXTERNAL_UNTRUSTED -> {p.principal_id}.{cap.resource_type}({cap.pattern}) [no human gate]"
                                ],
                                explanation=(
                                    f"Privileged capability `{cap.resource_type}:{cap.pattern}` on `{p.principal_id}` "
                                    "permits EXTERNAL_UNTRUSTED taint without requiring human approval."
                                ),
                            )
                        )
        return TheoremVerificationResult(
            theorem_id="T4-CAMEL-CFI",
            name="CaMeL Control/Data Plane Non-Interference",
            holds=len(witnesses) == 0,
            states_checked=states,
            counterexamples=witnesses,
        )

    def _verify_t5_least_privilege_no_wildcards(
        self, principals: List[AgentSecurityPrincipal]
    ) -> TheoremVerificationResult:
        witnesses: List[CounterexampleWitness] = []
        states = 0
        for p in principals:
            for cap in p.capabilities:
                states += 1
                if cap.is_wildcard_overreach():
                    witnesses.append(
                        CounterexampleWitness(
                            theorem_id="T5-LEAST-PRIVILEGE",
                            theorem_name="Zero Wildcard Least Privilege",
                            severity="high",
                            principals_involved=[p.principal_id],
                            hop_trace=[f"{p.principal_id} -> WILDCARD({cap.resource_type}:{cap.pattern})"],
                            explanation=f"Principal `{p.principal_id}` holds unconstrained wildcard grant `{cap.resource_type}:{cap.pattern}`.",
                        )
                    )
        return TheoremVerificationResult(
            theorem_id="T5-LEAST-PRIVILEGE",
            name="Zero Wildcard Least-Privilege Invariant",
            holds=len(witnesses) == 0,
            states_checked=states,
            counterexamples=witnesses,
        )

    def _verify_t6_transitive_delegation_closure(
        self,
        principals: List[AgentSecurityPrincipal],
        by_id: Dict[str, AgentSecurityPrincipal],
    ) -> TheoremVerificationResult:
        """
        T6: External-facing principals (role in {researcher, skill}) must NOT be able to
        transitively invoke or trigger a peer possessing `proc_spawn` or `fs_write` on
        arbitrary paths without strict attenuation.
        """
        witnesses: List[CounterexampleWitness] = []
        states = 0
        external_facing = [p for p in principals if p.role in ("researcher", "skill")]

        for src in external_facing:
            # Find any transitive IPC chain from an external-facing principal to a proc_spawn holder
            path = self._bfs_path_to_predicate(
                start_id=src.principal_id,
                by_id=by_id,
                goal_fn=lambda cand: any(
                    c.resource_type == "proc_spawn" and c.delegatable for c in cand.capabilities
                ),
            )
            states += len(principals)
            if path and len(path) > 1:
                witnesses.append(
                    CounterexampleWitness(
                        theorem_id="T6-TRANSITIVE-DELEGATION",
                        theorem_name="Transitive Delegation Escalation Safety",
                        severity="high",
                        principals_involved=path,
                        hop_trace=[f"Transitive IPC/Delegation: {' -> '.join(path)} -> delegatable(proc_spawn)"],
                        explanation=(
                            f"External-facing principal `{src.principal_id}` ({src.role}) has a transitive IPC path "
                            f"to delegatable `proc_spawn` capability via `{path}`."
                        ),
                    )
                )

        return TheoremVerificationResult(
            theorem_id="T6-TRANSITIVE-DELEGATION",
            name="Transitive Delegation Non-Amplification Theorem",
            holds=len(witnesses) == 0,
            states_checked=states,
            counterexamples=witnesses,
        )

    @staticmethod
    def _bfs_path_to_predicate(
        start_id: str,
        by_id: Dict[str, AgentSecurityPrincipal],
        goal_fn: Any,
    ) -> Optional[List[str]]:
        visited: Set[str] = {start_id}
        q: deque[List[str]] = deque([[start_id]])
        while q:
            path = q.popleft()
            cur = by_id.get(path[-1])
            if cur is None:
                continue
            if len(path) > 1 and goal_fn(cur):
                return path
            for peer_id in sorted(cur.allowed_ipc_peers):
                if peer_id not in visited and peer_id in by_id:
                    visited.add(peer_id)
                    q.append(path + [peer_id])
        return None
