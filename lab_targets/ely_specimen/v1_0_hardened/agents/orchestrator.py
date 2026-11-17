"""
Ely-Cowork v1.0-rc1 (Hardened Specimen) — Zero-Trust Multi-Agent Orchestrator.
Enforces strict per-agent namespace isolation, delegation attenuation, and
isolated Auditor plane immutability.
"""

from __future__ import annotations

import hmac
from typing import Any, Dict, FrozenSet, List, Set


AGENT_ISOLATION = True
AUDITOR_PLANE_ISOLATED = True
DELEGATION_ESCALATION_BLOCKED = True


class AgentOrchestrator:
    """Hardened zero-trust orchestrator enforcing agent isolation and capability attenuation."""

    def __init__(self) -> None:
        self.isolated_memory_prefix = "ns:prod:agent:"
        self.allowed_ipc_peers: Dict[str, Set[str]] = {
            "orchestrator": {"researcher", "executor"},
            "researcher": {"orchestrator"},
            "executor": {"orchestrator"},
        }
        self._isolated_state: Dict[str, Dict[str, Any]] = {}
        self._principal_caps: Dict[str, FrozenSet[str]] = {
            "researcher": frozenset({"fs:read:/workspace/research/**", "tool:web_summarize"}),
            "executor": frozenset({"fs:read:/workspace/proj_alpha/**", "fs:write:/workspace/proj_alpha/**", "tool:run_tests"}),
            "orchestrator": frozenset({"fs:read:/workspace/research/**"}),
        }

    def verify_agent_namespace(self, caller_id: str, target_agent_id: str) -> None:
        if not hmac.compare_digest(caller_id, target_agent_id):
            raise PermissionError("AGENT_ISOLATION: Cross-agent state access denied")

    def get_agent_state(self, caller_id: str, target_agent_id: str) -> Dict[str, Any]:
        self.verify_agent_namespace(caller_id, target_agent_id)
        key = f"{self.isolated_memory_prefix}{caller_id}"
        return dict(self._isolated_state.get(key, {}))

    def evaluate_delegation(self, from_agent: str, to_agent: str, requested_caps: Set[str]) -> Dict[str, Any]:
        """Enforces strict capability attenuation and IPC peer allowlists."""
        if to_agent not in self.allowed_ipc_peers.get(from_agent, set()):
            raise PermissionError("AGENT_IPC_ISOLATION_VIOLATION")
        caller_caps = self._principal_caps.get(from_agent, frozenset())
        if not requested_caps.issubset(caller_caps):
            raise PermissionError("DELEGATION_ESCALATION_BLOCKED")
        return {"delegated": True, "from": from_agent, "to": to_agent, "caps": sorted(requested_caps)}

    def verify_certificate(self, caller_role: str, cert_sig: str, expected_sig: str) -> bool:
        if caller_role != "auditor":
            raise PermissionError("AUDITOR_PLANE_ISOLATED: non-auditor cannot modify validation state")
        return hmac.compare_digest(cert_sig, expected_sig)
