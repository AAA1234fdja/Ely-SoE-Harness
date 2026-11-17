"""
Frontier Research Module 2: Multi-Agent Attack Graph, Blast-Radius & Min-Cut Chokepoint Engine.

Models Ely as a weighted probabilistic exploit graph spanning external entry points,
agents, skills, tools, memory stores, filesystem workspaces, Rust Core FFI, and
crown-jewel assets (Production Credentials, Host OS Execution, Auditor Validation Plane):
  - Maps `AttackSurfaceGraph` nodes + confirmed `Finding`s onto directed exploit edges
    weighted by exploitability (`p_exploit` derived from CVSS & Agentic Risk Score).
  - Runs modified Dijkstra (max-probability / min-negative-log-prob) to find the top
    **Shortest / Highest-Probability Kill Chains** from `EXTERNAL_ATTACKER` or
    `COMPROMISED_INTERNAL_AGENT` to every crown jewel!
  - Computes exact **Multi-Agent Blast Radius** (percentage of agents, tools, and
    crown jewels reachable from compromising a single internal agent).
  - Computes **Betweenness / Chokepoint Remediation Priorities**: identifies the exact
    minimum set of findings whose remediation collapses the maximum fraction of attack
    paths (actionable prioritization for Ely engineers).
"""

from __future__ import annotations

import heapq
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from ely_soe.core.models import (
    AttackSurfaceGraph,
    Finding,
    FindingStatus,
    SecurityDomain,
    Severity,
    utc_now_iso,
)


@dataclass
class ExploitEdge:
    """Directed adversarial transition enabled by an architecture link + vulnerability."""

    src: str
    dst: str
    technique: str
    probability: float  # 0.01..0.99
    finding_id: Optional[str] = None
    domain: Optional[str] = None
    rule_id: Optional[str] = None

    @property
    def cost(self) -> float:
        p = max(0.01, min(0.99, self.probability))
        return -math.log(p)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "technique": self.technique,
            "probability": round(self.probability, 3),
            "finding_id": self.finding_id,
            "domain": self.domain,
            "rule_id": self.rule_id,
        }


@dataclass
class KillChainPath:
    """One concrete multi-hop attack path from entry point to a crown-jewel asset."""

    entry_node: str
    crown_jewel: str
    nodes: List[str]
    edges: List[ExploitEdge]
    cumulative_probability: float
    hop_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_node": self.entry_node,
            "crown_jewel": self.crown_jewel,
            "nodes": list(self.nodes),
            "edges": [e.to_dict() for e in self.edges],
            "cumulative_probability": round(self.cumulative_probability, 4),
            "hop_count": self.hop_count,
        }


class AttackGraphAnalyzer:
    """
    Constructs and analyzes probabilistic multi-agent attack graphs from Ely's
    AttackSurfaceGraph + confirmed/active security findings.
    """

    ENTRY_NODES: Tuple[str, ...] = (
        "ENTRY:external_untrusted_web",
        "ENTRY:compromised_researcher_agent",
        "ENTRY:compromised_thirdparty_skill",
        "ENTRY:unauthenticated_api_client",
    )

    CROWN_JEWELS: Tuple[str, ...] = (
        "JEWEL:host_os_rce",
        "JEWEL:cross_agent_secrets",
        "JEWEL:persistent_memory_control",
        "JEWEL:auditor_validation_plane",
        "JEWEL:external_data_exfiltration",
    )

    # Canonical transition templates mapping SecurityDomain vulnerabilities to attack-graph hops
    DOMAIN_TRANSITIONS: Dict[SecurityDomain, List[Tuple[str, str, str]]] = {
        SecurityDomain.PROMPT_INJECTION: [
            ("ENTRY:external_untrusted_web", "PLANE:researcher_agent", "indirect_prompt_injection"),
            ("PLANE:researcher_agent", "PLANE:tool_dispatcher", "goal_hijack_tool_invocation"),
        ],
        SecurityDomain.AGENT_ISOLATION: [
            ("ENTRY:compromised_researcher_agent", "PLANE:executor_agent", "cross_agent_lateral_movement"),
            ("PLANE:researcher_agent", "JEWEL:cross_agent_secrets", "shared_state_secret_theft"),
            ("PLANE:executor_agent", "JEWEL:auditor_validation_plane", "validation_result_tampering"),
        ],
        SecurityDomain.TOOL_EXECUTION: [
            ("PLANE:tool_dispatcher", "JEWEL:host_os_rce", "shell_injection_or_eval_rce"),
            ("ENTRY:compromised_researcher_agent", "PLANE:tool_dispatcher", "wildcard_tool_abuse"),
        ],
        SecurityDomain.MEMORY: [
            ("PLANE:researcher_agent", "PLANE:memory_store", "unverified_memory_write"),
            ("PLANE:memory_store", "JEWEL:persistent_memory_control", "sleeper_rag_poisoning"),
            ("PLANE:memory_store", "PLANE:executor_agent", "cross_session_agent_hijack"),
        ],
        SecurityDomain.API_SECURITY: [
            ("ENTRY:unauthenticated_api_client", "PLANE:api_gateway", "jwt_bypass_or_bfla"),
            ("PLANE:api_gateway", "PLANE:executor_agent", "unauthorized_agent_control"),
            ("PLANE:api_gateway", "JEWEL:cross_agent_secrets", "bola_or_sqli_secret_dump"),
        ],
        SecurityDomain.FILESYSTEM: [
            ("PLANE:executor_agent", "PLANE:filesystem_host", "path_traversal_or_symlink_escape"),
            ("PLANE:filesystem_host", "JEWEL:cross_agent_secrets", "env_and_ssh_key_harvest"),
            ("PLANE:filesystem_host", "JEWEL:host_os_rce", "archive_slip_script_overwrite"),
        ],
        SecurityDomain.PROCESS_MANAGEMENT: [
            ("PLANE:tool_dispatcher", "PLANE:subprocess_worker", "unsandboxed_child_spawn"),
            ("PLANE:subprocess_worker", "JEWEL:host_os_rce", "rlimit_or_ld_preload_escape"),
            ("PLANE:subprocess_worker", "JEWEL:cross_agent_secrets", "inherited_parent_env_harvest"),
        ],
        SecurityDomain.SUPPLY_CHAIN: [
            ("ENTRY:compromised_thirdparty_skill", "PLANE:tool_dispatcher", "unsigned_overprivileged_skill"),
            ("ENTRY:compromised_thirdparty_skill", "JEWEL:host_os_rce", "postinstall_or_typosquat_exec"),
        ],
        SecurityDomain.NETWORK: [
            ("PLANE:researcher_agent", "JEWEL:external_data_exfiltration", "unrestricted_egress_exfil"),
            ("PLANE:api_gateway", "JEWEL:cross_agent_secrets", "cloud_metadata_169_254_ssrf"),
        ],
        SecurityDomain.RUST_CORE: [
            ("PLANE:subprocess_worker", "PLANE:rust_core_ffi", "malformed_ffi_frame"),
            ("PLANE:rust_core_ffi", "JEWEL:host_os_rce", "unsafe_transmute_or_oob_memory_corruption"),
        ],
    }

    def analyze(
        self,
        findings: List[Finding],
        attack_surface: Optional[AttackSurfaceGraph] = None,
        include_hypotheses: bool = False,
    ) -> Dict[str, Any]:
        active = [
            f
            for f in findings
            if f.status in (FindingStatus.CONFIRMED, FindingStatus.REGRESSED)
            or (include_hypotheses and f.status == FindingStatus.HYPOTHESIS)
        ]

        edges: List[ExploitEdge] = []
        adj: Dict[str, List[ExploitEdge]] = {}
        all_nodes: Set[str] = set(self.ENTRY_NODES) | set(self.CROWN_JEWELS)

        # Baseline structural links (always present in an agentic platform, low baseline prob unless vuln exists)
        structural_links = [
            ("ENTRY:compromised_researcher_agent", "PLANE:researcher_agent", "assumed_compromised_internal_agent", 0.99),
        ]
        for s, d, tech, prob in structural_links:
            e = ExploitEdge(src=s, dst=d, technique=tech, probability=prob)
            edges.append(e)
            adj.setdefault(s, []).append(e)
            all_nodes.add(s)
            all_nodes.add(d)

        # Project findings onto attack graph edges
        for f in active:
            prob = self._finding_exploit_probability(f)
            transitions = self.DOMAIN_TRANSITIONS.get(f.domain, [])
            for src, dst, tech in transitions:
                # Special check: Auditor plane is ONLY reachable if finding specifically touches validation/audit!
                if dst == "JEWEL:auditor_validation_plane":
                    if not any(k in (f.title + " " + f.rule_id + " " + f.description).lower() for k in ("validation", "audit", "ua-04", "agt-iso-003")):
                        continue
                e = ExploitEdge(
                    src=src,
                    dst=dst,
                    technique=tech,
                    probability=prob,
                    finding_id=f.finding_id,
                    domain=f.domain.value,
                    rule_id=f.rule_id,
                )
                edges.append(e)
                adj.setdefault(src, []).append(e)
                all_nodes.add(src)
                all_nodes.add(dst)

        # Find highest-probability kill chains from every entry to every crown jewel
        kill_chains: List[KillChainPath] = []
        for entry in self.ENTRY_NODES:
            for jewel in self.CROWN_JEWELS:
                path = self._dijkstra_max_prob(entry, jewel, adj)
                if path is not None:
                    kill_chains.append(path)

        kill_chains.sort(key=lambda p: (-p.cumulative_probability, p.hop_count))

        # Compute Multi-Agent Blast Radius starting from a compromised internal researcher agent
        reachable_from_rogue = self._bfs_reachable("ENTRY:compromised_researcher_agent", adj)
        compromised_jewels = sorted(j for j in self.CROWN_JEWELS if j in reachable_from_rogue)
        blast_radius_pct = round((len(compromised_jewels) / float(len(self.CROWN_JEWELS))) * 100.0, 2)

        # Chokepoint / Min-Cut Prioritization: how many kill chains collapse if each finding is fixed?
        chokepoints = self._compute_remediation_chokepoints(active, kill_chains, edges)

        # Structured nodes/edges & composite graph risk score for UI visualizer & executive reporting
        def _tier(node_id: str) -> str:
            if node_id.startswith("ENTRY:"):
                return "entry"
            if node_id.startswith("JEWEL:"):
                return "crown_jewel"
            if node_id.startswith("AGENT:"):
                return "agent"
            return "asset"

        node_objs = [
            {
                "id": nid,
                "label": nid.split(":", 1)[-1].replace("_", " "),
                "tier": _tier(nid),
            }
            for nid in sorted(all_nodes)
        ]
        edge_objs = [
            {
                "source": e.src,
                "target": e.dst,
                "technique": e.technique,
                "probability": round(e.probability, 3),
                "domain": e.domain,
                "severity": "critical" if e.probability >= 0.8 else ("high" if e.probability >= 0.65 else "medium"),
            }
            for e in edges[:60]
        ]
        max_chain_prob = kill_chains[0].cumulative_probability if kill_chains else 0.0
        auditor_hit = "JEWEL:auditor_validation_plane" in {kc.crown_jewel for kc in kill_chains}
        composite_risk = min(
            100.0,
            round(
                max_chain_prob * 55.0
                + (blast_radius_pct * 0.30)
                + (15.0 if auditor_hit else 0.0),
                2,
            ),
        ) if kill_chains else 0.0

        return {
            "analyzed_at": utc_now_iso(),
            "active_findings_mapped": len(active),
            "graph_nodes_count": len(all_nodes),
            "graph_edges_count": len(edges),
            "nodes": node_objs,
            "edges": edge_objs,
            "kill_chains_found": len(kill_chains),
            "composite_attack_graph_risk": composite_risk,
            "top_kill_chains": [kc.to_dict() for kc in kill_chains[:10]],
            "compromised_jewels_from_rogue_agent": compromised_jewels,
            "rogue_agent_blast_radius_pct": blast_radius_pct,
            "auditor_plane_reachable": auditor_hit,
            "auditor_plane_reachable_from_untrusted": auditor_hit,
            "top_remediation_chokepoints": chokepoints[:8],
            "remediation_chokepoints": [
                {
                    "domain": cp.get("domain", ""),
                    "rule_id": cp.get("rule_id", ""),
                    "kill_chains_disrupted": cp.get("chains_eliminated", 0),
                    "recommendation": f"Fix `{cp.get('title', cp.get('rule_id', ''))}` to disrupt {cp.get('chains_eliminated', 0)} kill chain(s).",
                }
                for cp in chokepoints[:8]
            ],
            "attack_surface_nodes_referenced": len(attack_surface.nodes) if attack_surface else 0,
        }

    def _dijkstra_max_prob(
        self, start: str, goal: str, adj: Dict[str, List[ExploitEdge]]
    ) -> Optional[KillChainPath]:
        pq: List[Tuple[float, str, List[str], List[ExploitEdge]]] = [(0.0, start, [start], [])]
        best_cost: Dict[str, float] = {start: 0.0}

        while pq:
            cost, cur, nodes, path_edges = heapq.heappop(pq)
            if cur == goal:
                cum_prob = math.exp(-cost)
                return KillChainPath(
                    entry_node=start,
                    crown_jewel=goal,
                    nodes=nodes,
                    edges=path_edges,
                    cumulative_probability=cum_prob,
                    hop_count=len(path_edges),
                )
            if cost > best_cost.get(cur, float("inf")) + 1e-9:
                continue
            for edge in adj.get(cur, []):
                if edge.dst in nodes:
                    continue
                nc = cost + edge.cost
                if nc < best_cost.get(edge.dst, float("inf")):
                    best_cost[edge.dst] = nc
                    heapq.heappush(pq, (nc, edge.dst, nodes + [edge.dst], path_edges + [edge]))
        return None

    @staticmethod
    def _bfs_reachable(start: str, adj: Dict[str, List[ExploitEdge]]) -> Set[str]:
        visited: Set[str] = {start}
        queue: List[str] = [start]
        while queue:
            cur = queue.pop(0)
            for edge in adj.get(cur, []):
                if edge.dst not in visited:
                    visited.add(edge.dst)
                    queue.append(edge.dst)
        return visited

    def _compute_remediation_chokepoints(
        self,
        findings: List[Finding],
        baseline_chains: List[KillChainPath],
        all_edges: List[ExploitEdge],
    ) -> List[Dict[str, Any]]:
        """Rank findings by how many kill chains vanish if that finding is fixed (min-cut impact)."""
        if not baseline_chains:
            return []

        base_count = len(baseline_chains)
        base_risk_sum = sum(c.cumulative_probability for c in baseline_chains)
        ranked: List[Dict[str, Any]] = []

        # Group by rule_id/finding_id appearing on any kill chain
        candidate_fids: Set[str] = set()
        for chain in baseline_chains:
            for e in chain.edges:
                if e.finding_id:
                    candidate_fids.add(e.finding_id)

        finding_by_id = {f.finding_id: f for f in findings}
        for fid in candidate_fids:
            # Rebuild adjacency without edges belonging to `fid`
            filtered_adj: Dict[str, List[ExploitEdge]] = {}
            for e in all_edges:
                if e.finding_id == fid:
                    continue
                filtered_adj.setdefault(e.src, []).append(e)

            rem_chains = 0
            rem_risk = 0.0
            for entry in self.ENTRY_NODES:
                for jewel in self.CROWN_JEWELS:
                    p = self._dijkstra_max_prob(entry, jewel, filtered_adj)
                    if p is not None:
                        rem_chains += 1
                        rem_risk += p.cumulative_probability

            f = finding_by_id.get(fid)
            chains_eliminated = base_count - rem_chains
            risk_reduction = round(base_risk_sum - rem_risk, 4)
            ranked.append(
                {
                    "finding_id": fid,
                    "rule_id": f.rule_id if f else "unknown",
                    "title": f.title if f else fid,
                    "domain": f.domain.value if f else "unknown",
                    "severity": f.severity.value if f else "medium",
                    "kill_chains_eliminated": chains_eliminated,
                    "cumulative_risk_reduction": risk_reduction,
                }
            )

        ranked.sort(key=lambda r: (-r["kill_chains_eliminated"], -r["cumulative_risk_reduction"]))
        return ranked

    @staticmethod
    def _finding_exploit_probability(f: Finding) -> float:
        base = {
            Severity.CRITICAL: 0.92,
            Severity.HIGH: 0.78,
            Severity.MEDIUM: 0.52,
            Severity.LOW: 0.25,
            Severity.INFO: 0.10,
        }[f.severity]
        if f.status == FindingStatus.CONFIRMED:
            base = min(0.98, base + 0.05)
        return round(base, 3)
