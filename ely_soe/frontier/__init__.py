"""
Photon Labs Frontier Cybersecurity Research Modules for Multi-Agent AI Platforms.

Extends the core SOE Harness with state-of-the-art research capabilities:
  - MCP (Model Context Protocol) & Tool-Schema Poisoning / Rug-Pull Auditor
  - Automated Multi-Agent Attack Graph, Blast-Radius & Min-Cut Chokepoint Analyzer
  - Formal Capability Lattice & Non-Interference Policy Verifier (Counterexample Engine)
  - RAG & Episodic Memory Forensics, Semantic Outlier & Poisoning Quarantine Engine
  - AST Constraint / Parser-Differential & Boundary Counterexample Explorer
  - SWE-Cyber Automated Patch Synthesis & Differential Sandbox Verifier
  - MITRE ATLAS / OWASP Agentic / NIST AI RMF Compliance & Navigator Layer Mapper
"""

from ely_soe.frontier.mcp_protocol_auditor import MCPProtocolAuditor
from ely_soe.frontier.attack_graph import AttackGraphAnalyzer
from ely_soe.frontier.formal_policy_verifier import FormalPolicyVerifier
from ely_soe.frontier.memory_forensics import MemoryForensicsEngine
from ely_soe.frontier.symbolic_path_fuzzer import GuardrailDifferentialExplorer
from ely_soe.frontier.differential_patch_verifier import DifferentialPatchVerifier
from ely_soe.frontier.threat_intel_mapper import ThreatIntelComplianceMapper
from ely_soe.frontier.policy_synthesizer import LeastPrivilegePolicySynthesizer, SynthesizedDefenseBundle
from ely_soe.frontier.purple_team_replay import PURPLE_TEAM_PLAYBOOKS, PurpleTeamReplayEngine

__all__ = [
    "MCPProtocolAuditor",
    "AttackGraphAnalyzer",
    "FormalPolicyVerifier",
    "MemoryForensicsEngine",
    "GuardrailDifferentialExplorer",
    "DifferentialPatchVerifier",
    "ThreatIntelComplianceMapper",
    "LeastPrivilegePolicySynthesizer",
    "SynthesizedDefenseBundle",
    "PURPLE_TEAM_PLAYBOOKS",
    "PurpleTeamReplayEngine",
]
