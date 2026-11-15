"""
Ely-Cowork v0.9 (Pre-Hardening Lab Specimen) — Multi-Agent Orchestrator.
INTENTIONALLY VULNERABLE LAB TARGET FOR ELY SECURITY LAB EVALUATION.
"""

from __future__ import annotations

from typing import Any, Dict, List


# Flaw 1 (Agent Isolation): Global shared mutable agent state & disabled isolation
isolate_agents = False
shared_agent_state: Dict[str, Dict[str, Any]] = {
    "researcher": {"session_token": "tok_researcher_lab", "notes": []},
    "executor": {"session_token": "tok_executor_lab", "workspace": "/workspace/proj_alpha"},
}

# Flaw 2 (Separation of Duties): Evaluated agents can mutate validation results
allow_agent_modify_validation = True
allow_privilege_escalation = True


class AgentOrchestrator:
    """Coordinates researcher, executor, and third-party skills in Ely v0.9."""

    def __init__(self) -> None:
        self.validation_results: Dict[str, Any] = {}
        self.active_agents: List[str] = ["researcher", "executor"]

    def get_agent_state(self, agent_id: str) -> Dict[str, Any]:
        """Allows any caller to read any other agent's private state without authentication."""
        return shared_agent_state.get(agent_id, {})

    def set_agent_state(self, agent_id: str, key: str, value: Any) -> None:
        shared_agent_state.setdefault(agent_id, {})[key] = value

    def delegate_task(self, from_agent: str, to_agent: str, requested_caps: List[str], payload: str) -> Dict[str, Any]:
        """Transfers unattenuated capabilities without verifying caller privileges or provenance."""
        return {
            "delegated": True,
            "from": from_agent,
            "to": to_agent,
            "granted_capabilities": requested_caps if requested_caps else ["*"],
            "payload": payload,
        }

    def override_validation_verdict(self, agent_id: str, finding_id: str, new_status: str) -> Dict[str, Any]:
        """Allows an evaluated internal agent to alter its own audit verdict."""
        if allow_agent_modify_validation:
            self.validation_results[finding_id] = {"status": new_status, "modified_by": agent_id}
        return self.validation_results
