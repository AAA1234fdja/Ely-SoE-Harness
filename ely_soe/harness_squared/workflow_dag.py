"""
Harness² Live-Mutable Workflow Execution DAG Engine.

Manages the first-order security testing workflow as an explicitly inspectable,
transactionally mutable Directed Acyclic Graph (`WorkflowDAG`):
  - **Priority-Aware Kahn Topological Scheduling**: selects the highest-priority
    ready `PENDING` stage whose predecessor dependencies are all `COMPLETED`/`SKIPPED`/`PRUNED`.
  - **Live Runtime Mutations**:
      * `inject_stage_after(parent_id, new_node)` — inserts drilldown/verification stage
        with automatic dependency rewiring before terminal synthesis nodes.
      * `prune_branch(stage_id, reason)` — safely marks low-yield pending stages `PRUNED`
        and reclaims their unused millisecond budgets.
      * `reprioritize_stage(stage_id, new_priority)` — promotes high-value pending work.
      * `reallocate_budget(from_id, to_id, delta_ms)` — shifts compute budget dynamically.
      * `checkpoint()` / `rollback(checkpoint_id)` — atomic transactional rollback.
  - **Formal 3-Color DFS Acyclicity Verification** (`has_cycle()` / `would_create_cycle()`).
  - **Critical Path Estimator** & **Mermaid Adapted-Workflow Diagram Exporter** highlighting
    completed, adapted/injected, escalated, and pruned nodes!
"""

from __future__ import annotations

import copy
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ely_soe.core.models import new_id
from ely_soe.harness_squared.models import (
    StageCategory,
    StageStatus,
    WorkflowEdge,
    WorkflowStageNode,
)


class WorkflowDAG:
    """Transactional, live-mutable Directed Acyclic Graph for Harness² security workflows."""

    def __init__(self, dag_id: Optional[str] = None, total_budget_ms: int = 30_000) -> None:
        self.dag_id = dag_id or new_id("dag")
        self.total_budget_ms = total_budget_ms
        self.nodes: Dict[str, WorkflowStageNode] = {}
        self.edges: List[WorkflowEdge] = []
        self._checkpoints: Dict[str, Tuple[Dict[str, WorkflowStageNode], List[WorkflowEdge]]] = {}
        self.mutation_log: List[Dict[str, Any]] = []

    def add_node(self, node: WorkflowStageNode) -> None:
        if node.stage_id in self.nodes:
            raise ValueError(f"Duplicate stage_id '{node.stage_id}' in DAG '{self.dag_id}'.")
        self.nodes[node.stage_id] = node

    def add_edge(self, src_id: str, dst_id: str, edge_kind: str = "depends_on") -> None:
        if src_id not in self.nodes or dst_id not in self.nodes:
            raise KeyError(f"Both endpoints must exist before adding edge ({src_id} -> {dst_id}).")
        if self.would_create_cycle(src_id, dst_id):
            raise ValueError(f"Adding edge ({src_id} -> {dst_id}) would introduce a DAG cycle.")
        edge = WorkflowEdge(src_id, dst_id, edge_kind)
        if edge not in self.edges:
            self.edges.append(edge)

    def predecessors(self, stage_id: str) -> List[str]:
        return [e.src_stage_id for e in self.edges if e.dst_stage_id == stage_id]

    def successors(self, stage_id: str) -> List[str]:
        return [e.dst_stage_id for e in self.edges if e.src_stage_id == stage_id]

    def has_cycle(self) -> bool:
        """3-color DFS cycle detector (0=unvisited, 1=visiting, 2=visited)."""
        color: Dict[str, int] = {nid: 0 for nid in self.nodes}
        adj: Dict[str, List[str]] = {nid: [] for nid in self.nodes}
        for e in self.edges:
            adj.setdefault(e.src_stage_id, []).append(e.dst_stage_id)

        def _dfs(u: str) -> bool:
            color[u] = 1
            for v in adj.get(u, []):
                if color.get(v, 0) == 1:
                    return True
                if color.get(v, 0) == 0 and _dfs(v):
                    return True
            color[u] = 2
            return False

        return any(color[n] == 0 and _dfs(n) for n in self.nodes)

    def would_create_cycle(self, src_id: str, dst_id: str) -> bool:
        """Check whether adding `src_id -> dst_id` creates a directed cycle (is `src_id` reachable from `dst_id`?)."""
        if src_id == dst_id:
            return True
        adj: Dict[str, List[str]] = {}
        for e in self.edges:
            adj.setdefault(e.src_stage_id, []).append(e.dst_stage_id)
        visited: Set[str] = {dst_id}
        q: deque[str] = deque([dst_id])
        while q:
            cur = q.popleft()
            if cur == src_id:
                return True
            for nxt in adj.get(cur, []):
                if nxt not in visited:
                    visited.add(nxt)
                    q.append(nxt)
        return False

    def next_ready_stage(self) -> Optional[WorkflowStageNode]:
        """Return highest-priority PENDING stage whose dependencies are all terminal."""
        terminal = {StageStatus.COMPLETED, StageStatus.PRUNED, StageStatus.SKIPPED, StageStatus.FAILED}
        ready: List[WorkflowStageNode] = []
        for nid, node in self.nodes.items():
            if node.status != StageStatus.PENDING:
                continue
            preds = self.predecessors(nid)
            if all(self.nodes[p].status in terminal for p in preds):
                ready.append(node)
        if not ready:
            return None
        ready.sort(key=lambda n: (-n.priority, n.category == StageCategory.SYNTHESIS_COMPLIANCE, n.stage_id))
        return ready[0]

    def inject_drilldown_after(
        self,
        parent_stage_id: str,
        new_node: WorkflowStageNode,
        connect_before_synthesis: bool = True,
    ) -> None:
        """Live-mutate DAG to insert a drilldown or hypothesis verification node after `parent_stage_id`."""
        if parent_stage_id not in self.nodes:
            raise KeyError(f"Parent stage '{parent_stage_id}' not found in DAG.")
        new_node.injected_by_adaptation = True
        self.add_node(new_node)
        self.add_edge(parent_stage_id, new_node.stage_id, edge_kind="drilldown_trigger")

        if connect_before_synthesis:
            for nid, node in self.nodes.items():
                if nid != new_node.stage_id and node.category == StageCategory.SYNTHESIS_COMPLIANCE and node.status == StageStatus.PENDING:
                    if not self.would_create_cycle(new_node.stage_id, nid):
                        self.add_edge(new_node.stage_id, nid, edge_kind="depends_on")

        self.mutation_log.append(
            {
                "action": "inject_drilldown_after",
                "parent_stage_id": parent_stage_id,
                "new_stage_id": new_node.stage_id,
                "adapter_name": new_node.adapter_name,
                "reason": new_node.injection_reason,
            }
        )

    def prune_stage(self, stage_id: str, reason: str) -> int:
        """Prune a PENDING stage and return its reclaimed budget in milliseconds."""
        node = self.nodes.get(stage_id)
        if node is None or node.status != StageStatus.PENDING:
            return 0
        if node.category == StageCategory.SYNTHESIS_COMPLIANCE:
            return 0  # Never prune mandatory synthesis / compliance gate
        node.status = StageStatus.PRUNED
        node.prune_reason = reason
        reclaimed = node.budget_ms
        self.mutation_log.append(
            {
                "action": "prune_stage",
                "stage_id": stage_id,
                "reason": reason,
                "reclaimed_budget_ms": reclaimed,
            }
        )
        return reclaimed

    def reallocate_budget(self, from_stage_id: str, to_stage_id: str, delta_ms: int) -> bool:
        src = self.nodes.get(from_stage_id)
        dst = self.nodes.get(to_stage_id)
        if src is None or dst is None or delta_ms <= 0:
            return False
        if src.status != StageStatus.PENDING or src.budget_ms - delta_ms < 250:
            return False
        src.budget_ms -= delta_ms
        dst.budget_ms += delta_ms
        self.mutation_log.append(
            {
                "action": "reallocate_budget",
                "from_stage_id": from_stage_id,
                "to_stage_id": to_stage_id,
                "delta_ms": delta_ms,
            }
        )
        return True

    def reprioritize_stage(self, stage_id: str, new_priority: float) -> bool:
        node = self.nodes.get(stage_id)
        if node is None or node.status != StageStatus.PENDING:
            return False
        old_p = node.priority
        node.priority = max(0.05, min(1.0, new_priority))
        self.mutation_log.append(
            {
                "action": "reprioritize_stage",
                "stage_id": stage_id,
                "old_priority": round(old_p, 3),
                "new_priority": round(node.priority, 3),
            }
        )
        return True

    def checkpoint(self) -> str:
        cp_id = new_id("cp")
        self._checkpoints[cp_id] = (copy.deepcopy(self.nodes), copy.deepcopy(self.edges))
        return cp_id

    def rollback(self, checkpoint_id: str) -> bool:
        snap = self._checkpoints.get(checkpoint_id)
        if snap is None:
            return False
        self.nodes, self.edges = copy.deepcopy(snap[0]), copy.deepcopy(snap[1])
        self.mutation_log.append({"action": "rollback", "checkpoint_id": checkpoint_id})
        return True

    def topological_order(self) -> List[str]:
        in_deg: Dict[str, int] = {nid: 0 for nid in self.nodes}
        adj: Dict[str, List[str]] = {nid: [] for nid in self.nodes}
        for e in self.edges:
            adj[e.src_stage_id].append(e.dst_stage_id)
            in_deg[e.dst_stage_id] += 1
        q = deque(sorted([nid for nid, d in in_deg.items() if d == 0], key=lambda x: -self.nodes[x].priority))
        order: List[str] = []
        while q:
            u = q.popleft()
            order.append(u)
            for v in adj[u]:
                in_deg[v] -= 1
                if in_deg[v] == 0:
                    q.append(v)
        return order

    def remaining_budget_ms(self) -> int:
        spent = sum(int(n.elapsed_ms) for n in self.nodes.values() if n.status in (StageStatus.COMPLETED, StageStatus.FAILED))
        return max(0, self.total_budget_ms - spent)

    def to_mermaid(self) -> str:
        """Render the live-adapted DAG into a Mermaid flowchart highlighting injected & pruned branches."""
        lines = ["flowchart TD"]
        for nid, node in self.nodes.items():
            safe_lbl = node.label.replace('"', "'")
            tag = ""
            if node.injected_by_adaptation:
                tag = " [H2-ADAPTED]"
            elif node.status == StageStatus.PRUNED:
                tag = " [PRUNED]"
            lines.append(f'  {nid}["{safe_lbl}{tag}\\n{node.status.value} | {node.findings_count} findings | {node.elapsed_ms:.0f}ms"]')
            if node.injected_by_adaptation:
                lines.append(f"  style {nid} fill:#1e3a8a,stroke:#60a5fa,color:#f8fafc")
            elif node.status == StageStatus.PRUNED:
                lines.append(f"  style {nid} fill:#334155,stroke:#94a3b8,stroke-dasharray: 5 5,color:#cbd5e1")
            elif node.critical_count > 0:
                lines.append(f"  style {nid} fill:#7f1d1d,stroke:#ef4444,color:#fef2f2")
            elif node.status == StageStatus.COMPLETED:
                lines.append(f"  style {nid} fill:#14532d,stroke:#22c55e,color:#f0fdf4")
        for e in self.edges:
            arrow = "==>" if e.edge_kind == "drilldown_trigger" else "-->"
            lines.append(f"  {e.src_stage_id} {arrow} {e.dst_stage_id}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dag_id": self.dag_id,
            "total_budget_ms": self.total_budget_ms,
            "remaining_budget_ms": self.remaining_budget_ms(),
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "acyclic": not self.has_cycle(),
            "status_counts": {
                st.value: sum(1 for n in self.nodes.values() if n.status == st)
                for st in StageStatus
            },
            "injected_stage_count": sum(1 for n in self.nodes.values() if n.injected_by_adaptation),
            "pruned_stage_count": sum(1 for n in self.nodes.values() if n.status == StageStatus.PRUNED),
            "nodes": [self.nodes[nid].to_dict() for nid in self.topological_order()],
            "edges": [e.to_dict() for e in self.edges],
            "mutation_log": list(self.mutation_log),
            "mermaid_dag": self.to_mermaid(),
        }
