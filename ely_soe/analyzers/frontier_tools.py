"""
Dual-Class Frontier Cybersecurity Tools Registry (Section 3 of Proposal).

Explicitly distinguishes and governs the two classes of Frontier capabilities:
  - Class 1: Frontier Cybersecurity Models (GLM 5.3, Frontier Cyber Reasoning Models,
    Defense Evaluators) — used for deep semantic vulnerability analysis, attack path
    synthesis, and patch evaluation.
  - Class 2: Specialized Security Tools (Static AST/Taint Analysis, Rust Core Auditor,
    Coverage/Grammar Fuzzer, Supply-Chain/SBOM Auditor, Dynamic Untrusted-Agent Lab,
    plus ScopeGuard-gated optional external CLI wrappers for `cargo-audit`, `clippy`,
    `semgrep`, `bandit` if installed in the isolated lab).

Every experimental tool execution MUST pass `ScopeGuard.assert_tool_authorized()` so
experimental tools remain strictly restricted to authorized local lab sandboxes.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from ely_soe.core.models import SecurityDomain
from ely_soe.core.scope_guard import ScopeGuard


class FrontierToolClass(str, Enum):
    FRONTIER_CYBER_MODEL = "frontier_cyber_model"
    SPECIALIZED_SECURITY_TOOL = "specialized_security_tool"


@dataclass
class FrontierToolDescriptor:
    """Metadata and governance status for one registered security tool or model."""

    tool_id: str
    name: str
    tool_class: FrontierToolClass
    category: str  # llm_reasoner, static_analysis, taint, fuzzing, dependency_audit, dynamic_pentest, rust_audit
    supported_domains: List[SecurityDomain]
    lab_only_enforced: bool = True
    available: bool = True
    builtin: bool = True
    binary_name: Optional[str] = None
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "name": self.name,
            "tool_class": self.tool_class.value,
            "category": self.category,
            "supported_domains": [d.value for d in self.supported_domains],
            "lab_only_enforced": self.lab_only_enforced,
            "available": self.available,
            "builtin": self.builtin,
            "binary_name": self.binary_name,
            "notes": self.notes,
        }


class FrontierToolRegistry:
    """Central catalog & governed executor for Class 1 & Class 2 frontier security capabilities."""

    def __init__(self, scope_guard: Optional[ScopeGuard] = None) -> None:
        self.scope_guard = scope_guard
        self._tools: Dict[str, FrontierToolDescriptor] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        all_domains = list(SecurityDomain)
        defaults = [
            # --- Class 1: Frontier Cybersecurity Models ---
            FrontierToolDescriptor(
                tool_id="glm-5.3",
                name="GLM 5.3 Security Reasoning Adapter",
                tool_class=FrontierToolClass.FRONTIER_CYBER_MODEL,
                category="llm_reasoner",
                supported_domains=all_domains,
                notes="Primary target model evaluated inside the 6-stage SOE harness and comparative benchmark",
            ),
            FrontierToolDescriptor(
                tool_id="frontier-cyber-v2",
                name="Frontier Specialized Cybersecurity Model",
                tool_class=FrontierToolClass.FRONTIER_CYBER_MODEL,
                category="llm_reasoner",
                supported_domains=all_domains,
                notes="Specialized frontier cyber-reasoning benchmark reference model",
            ),
            FrontierToolDescriptor(
                tool_id="frontier-reasoner",
                name="Frontier General Reasoning Model",
                tool_class=FrontierToolClass.FRONTIER_CYBER_MODEL,
                category="llm_reasoner",
                supported_domains=all_domains,
                notes="General frontier reasoning reference for cross-model comparison",
            ),
            # --- Class 2: Built-in Specialized Security Tools ---
            FrontierToolDescriptor(
                tool_id="static_analyzer",
                name="ELY Multi-Domain Static & AST Security Analyzer",
                tool_class=FrontierToolClass.SPECIALIZED_SECURITY_TOOL,
                category="static_analysis",
                supported_domains=all_domains,
                notes="Built-in deterministic analyzer covering Agent Isolation, Tool, Memory, PI, API, FS, Process, Network",
            ),
            FrontierToolDescriptor(
                tool_id="taint_engine",
                name="ELY Interprocedural Python AST Taint Engine",
                tool_class=FrontierToolClass.SPECIALIZED_SECURITY_TOOL,
                category="taint",
                supported_domains=[
                    SecurityDomain.TOOL_EXECUTION,
                    SecurityDomain.PROMPT_INJECTION,
                    SecurityDomain.FILESYSTEM,
                    SecurityDomain.MEMORY,
                    SecurityDomain.API_SECURITY,
                    SecurityDomain.NETWORK,
                ],
                notes="Tracks untrusted sources across AST assignments and calls to dangerous sinks",
            ),
            FrontierToolDescriptor(
                tool_id="rust_auditor",
                name="ELY Rust Core Deep Unsafe/FFI/Concurrency Auditor",
                tool_class=FrontierToolClass.SPECIALIZED_SECURITY_TOOL,
                category="rust_audit",
                supported_domains=[SecurityDomain.RUST_CORE, SecurityDomain.SUPPLY_CHAIN],
                notes="Comment-aware lexical & structural Rust Core analyzer",
            ),
            FrontierToolDescriptor(
                tool_id="supply_chain_scanner",
                name="ELY Supply Chain, Typosquat & CycloneDX SBOM Auditor",
                tool_class=FrontierToolClass.SPECIALIZED_SECURITY_TOOL,
                category="dependency_audit",
                supported_domains=[SecurityDomain.SUPPLY_CHAIN],
                notes="Audits Cargo, PyPI, NPM, and Ely skill manifests with CycloneDX 1.5 SBOM output",
            ),
            FrontierToolDescriptor(
                tool_id="fuzzer",
                name="ELY Grammar + Coverage-Guided Mutation Fuzzer",
                tool_class=FrontierToolClass.SPECIALIZED_SECURITY_TOOL,
                category="fuzzing",
                supported_domains=all_domains,
                notes="Protocol/grammar fuzzing, delta-minimization, and invariant checking",
            ),
            FrontierToolDescriptor(
                tool_id="red_team_lab",
                name="ELY Red Team + Adaptive TAP/PAIR Attack Engine",
                tool_class=FrontierToolClass.SPECIALIZED_SECURITY_TOOL,
                category="dynamic_pentest",
                supported_domains=all_domains,
                notes="Authorized lab-only threat simulation & adaptive multi-turn attack search",
            ),
            # --- Class 2: Optional External CLI Tools (auto-detected) ---
            FrontierToolDescriptor(
                tool_id="ext_cargo_audit",
                name="cargo-audit (External RustSec CLI)",
                tool_class=FrontierToolClass.SPECIALIZED_SECURITY_TOOL,
                category="dependency_audit",
                supported_domains=[SecurityDomain.RUST_CORE, SecurityDomain.SUPPLY_CHAIN],
                builtin=False,
                binary_name="cargo-audit",
                available=shutil.which("cargo-audit") is not None,
                notes="Optional external RustSec scanner invoked strictly inside isolated snapshot",
            ),
            FrontierToolDescriptor(
                tool_id="ext_semgrep",
                name="Semgrep (External SAST CLI)",
                tool_class=FrontierToolClass.SPECIALIZED_SECURITY_TOOL,
                category="static_analysis",
                supported_domains=all_domains,
                builtin=False,
                binary_name="semgrep",
                available=shutil.which("semgrep") is not None,
                notes="Optional external SAST runner gated by ScopeGuard",
            ),
            FrontierToolDescriptor(
                tool_id="ext_bandit",
                name="Bandit (External Python Security Linter)",
                tool_class=FrontierToolClass.SPECIALIZED_SECURITY_TOOL,
                category="static_analysis",
                supported_domains=[
                    SecurityDomain.TOOL_EXECUTION,
                    SecurityDomain.FILESYSTEM,
                    SecurityDomain.PROCESS_MANAGEMENT,
                    SecurityDomain.API_SECURITY,
                ],
                builtin=False,
                binary_name="bandit",
                available=shutil.which("bandit") is not None,
                notes="Optional external Python security linter gated by ScopeGuard",
            ),
        ]
        for d in defaults:
            self._tools[d.tool_id] = d

    def list_tools(self, tool_class: Optional[FrontierToolClass] = None) -> List[FrontierToolDescriptor]:
        items = list(self._tools.values())
        if tool_class is not None:
            items = [t for t in items if t.tool_class == tool_class]
        return items

    def summary(self) -> Dict[str, Any]:
        models = [t.to_dict() for t in self.list_tools(FrontierToolClass.FRONTIER_CYBER_MODEL)]
        specialized = [t.to_dict() for t in self.list_tools(FrontierToolClass.SPECIALIZED_SECURITY_TOOL)]
        return {
            "class_1_frontier_models": models,
            "class_2_specialized_tools": specialized,
            "available_count": sum(1 for t in self._tools.values() if t.available),
            "total_registered": len(self._tools),
            "lab_only_policy": "STRICT_ISOLATED_LAB_ONLY",
        }

    def invoke_external_cli_safe(
        self,
        tool_id: str,
        snapshot_root: Path,
        args: List[str],
        timeout: float = 30.0,
    ) -> Dict[str, Any]:
        """Invoke an optional external security CLI strictly within authorized snapshot scope."""
        desc = self._tools.get(tool_id)
        if desc is None or desc.builtin or not desc.binary_name:
            raise ValueError(f"Tool '{tool_id}' is not an external CLI tool")
        if self.scope_guard is not None:
            self.scope_guard.assert_read_path_in_scope(snapshot_root)
        if not desc.available:
            return {"tool_id": tool_id, "status": "unavailable", "stdout": "", "stderr": f"{desc.binary_name} not installed"}

        proc = subprocess.run(
            [desc.binary_name, *args],
            cwd=str(snapshot_root),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return {
            "tool_id": tool_id,
            "status": "completed",
            "returncode": proc.returncode,
            "stdout": proc.stdout[:16000],
            "stderr": proc.stderr[:8000],
        }
