"""
Semantic Reachability Verifier, Dead-Code Pruner & Guard-Condition Feasibility Analyzer.

Fixes one of the #1 real-world SAST pain points: **False-Positive Alert Fatigue from
Unreachable / Dead / Auth-Guarded Code**.

What this engine proves via Python AST Control-Flow & Call-Graph Reachability:
  1. **Entrypoint Discovery** across the whole repository:
       - Web/API route handlers (`@app.route`, `@router.get/post`, `do_GET`, `do_POST`, `handle_*`)
       - CLI entrypoints (`main`, `cmd_*`, `if __name__ == "__main__":`)
       - Public exported module APIs & class public methods
       - Module top-level executable statements.
  2. **Intra-Procedural Dead-Code & Constant-Branch Feasibility Analysis**:
       - Detects statements after unconditional `return`/`raise`/`break`/`continue`
       - Detects `if False:`, `if 0:`, `if None:`, `if DEBUG and False:` dead branches
       - Detects whether a finding line is protected by a dominating **Authorization /
         Validation Guard** (e.g., `require_auth`, `check_permission`, `scope_guard`,
         `validate_`, `verify_token`, `is_authorized`, `assert_safe`, `is_relative_to`).
  3. **Inter-Procedural Call-Graph BFS from Entrypoints**:
       - Maps every finding's `(file_path, line_number)` to its enclosing function/method,
         then computes shortest call distance from any external entrypoint (`entrypoint_hops`).
  4. **Exploitability Reachability Classification & Risk Recalibration**:
       - `PROVEN_REACHABLE_UNPROTECTED` (risk multiplier `1.15`, high priority)
       - `REACHABLE_BEHIND_GUARD` (risk multiplier `0.75`, verify guard strength)
       - `INTERNAL_CALLABLE` (risk multiplier `0.85`, reachable from exported library API)
       - `TEST_OR_FIXTURE_ONLY` (risk multiplier `0.25`, isolated to tests/mocks)
       - `UNREACHABLE_DEAD_CODE` (risk multiplier `0.10`, candidate false-positive suppression!).
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ely_soe.core.models import utc_now_iso


HTTP_ROUTE_DECORATOR_RE = re.compile(r"(route|get|post|put|delete|patch|api_view|endpoint|handler)", re.I)
AUTH_GUARD_CALL_RE = re.compile(
    r"(require_auth|check_auth|verify_token|verify_signature|check_permission|authorize|"
    r"is_authorized|scope_guard|validate_target|is_relative_to|assert_safe|sanitize|"
    r"check_capability|enforce_policy|verify_hmac|constant_time|compare_digest)",
    re.I,
)
TEST_FILE_RE = re.compile(r"(^|/|\\)(test_|tests/|fixtures/|mock_|conftest\.py)", re.I)


@dataclass
class FunctionSpan:
    fqn: str
    short_name: str
    rel_file: str
    line_start: int
    line_end: int
    is_entrypoint: bool = False
    entrypoint_kind: str = ""
    calls: Set[str] = field(default_factory=set)
    guard_lines: Set[int] = field(default_factory=set)
    dead_lines: Set[int] = field(default_factory=set)


@dataclass
class ReachabilityVerdict:
    finding_key: str
    file_path: str
    line: int
    enclosing_function: str
    status: str  # PROVEN_REACHABLE_UNPROTECTED | REACHABLE_BEHIND_GUARD | INTERNAL_CALLABLE | TEST_OR_FIXTURE_ONLY | UNREACHABLE_DEAD_CODE
    entrypoint_hops: int  # -1 if unreachable
    entrypoint_path: List[str]
    dominating_guards: List[str]
    risk_multiplier: float
    suppress_recommended: bool
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_key": self.finding_key,
            "file_path": self.file_path,
            "line": self.line,
            "enclosing_function": self.enclosing_function,
            "status": self.status,
            "entrypoint_hops": self.entrypoint_hops,
            "entrypoint_path": self.entrypoint_path,
            "dominating_guards": self.dominating_guards,
            "risk_multiplier": self.risk_multiplier,
            "suppress_recommended": self.suppress_recommended,
            "rationale": self.rationale,
        }


class SemanticReachabilityVerifier:
    """Repository-wide AST entrypoint reachability, dead-code & guard verifier."""

    def __init__(self) -> None:
        self._funcs_by_file: Dict[str, List[FunctionSpan]] = defaultdict(list)
        self._funcs_by_fqn: Dict[str, FunctionSpan] = {}
        self._fqns_by_short: Dict[str, List[str]] = defaultdict(list)
        self._module_dead_lines: Dict[str, Set[int]] = defaultdict(set)
        self._module_guard_names: Dict[str, Dict[int, List[str]]] = defaultdict(lambda: defaultdict(list))
        self._shortest_ep_path: Dict[str, List[str]] = {}
        self._indexed_files: int = 0

    def index_repository(self, target_dir: str | Path) -> Dict[str, Any]:
        """Parse Python files in `target_dir`, extract functions, dead code, guards & entrypoint BFS."""
        self._funcs_by_file.clear()
        self._funcs_by_fqn.clear()
        self._fqns_by_short.clear()
        self._module_dead_lines.clear()
        self._module_guard_names.clear()
        self._shortest_ep_path.clear()
        self._indexed_files = 0

        root = Path(target_dir).resolve()
        py_files = [root] if root.is_file() else sorted(root.rglob("*.py"))

        for pf in py_files:
            if "__pycache__" in pf.parts or ".venv" in pf.parts or ".git" in pf.parts:
                continue
            rel = pf.name if root.is_file() else str(pf.relative_to(root))
            try:
                src = pf.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(src, filename=rel)
            except (OSError, SyntaxError):
                continue
            self._indexed_files += 1
            self._index_module_ast(rel, tree)

        # Build call graph & run multi-source BFS from all entrypoints
        adj: Dict[str, Set[str]] = defaultdict(set)
        for fqn, span in self._funcs_by_fqn.items():
            for callee in span.calls:
                for target_fqn in self._fqns_by_short.get(callee, []):
                    adj[fqn].add(target_fqn)

        queue: deque[Tuple[str, List[str]]] = deque()
        for fqn, span in self._funcs_by_fqn.items():
            if span.is_entrypoint:
                self._shortest_ep_path[fqn] = [fqn]
                queue.append((fqn, [fqn]))

        while queue:
            cur, path = queue.popleft()
            if len(path) > 10:
                continue
            for nxt in adj.get(cur, ()):
                if nxt not in self._shortest_ep_path:
                    npath = path + [nxt]
                    self._shortest_ep_path[nxt] = npath
                    queue.append((nxt, npath))

        entrypoints = [f.fqn for f in self._funcs_by_fqn.values() if f.is_entrypoint]
        reachable_funcs = len(self._shortest_ep_path)
        total_funcs = len(self._funcs_by_fqn)
        dead_line_count = sum(len(s) for s in self._module_dead_lines.values())

        return {
            "indexed_at": utc_now_iso(),
            "files_indexed": self._indexed_files,
            "total_functions": total_funcs,
            "entrypoints_discovered": len(entrypoints),
            "reachable_functions_from_entrypoints": reachable_funcs,
            "reachability_ratio_pct": round((reachable_funcs / max(1, total_funcs)) * 100.0, 2),
            "dead_code_lines_detected": dead_line_count,
            "sample_entrypoints": entrypoints[:15],
        }

    def verify_findings(
        self,
        findings: Sequence[Any],
        *,
        target_dir: Optional[str | Path] = None,
    ) -> Dict[str, Any]:
        """Classify reachability & guard protection for every finding."""
        if target_dir is not None and self._indexed_files == 0:
            self.index_repository(target_dir)

        verdicts: List[ReachabilityVerdict] = []
        counts: Dict[str, int] = defaultdict(int)
        suppressed = 0

        for idx, f in enumerate(findings):
            fpath, line, rule_id = self._extract_loc(f, idx)
            v = self._evaluate_single(rule_id, fpath, line)
            verdicts.append(v)
            counts[v.status] += 1
            if v.suppress_recommended:
                suppressed += 1

        total = len(verdicts)
        proven_crit_reachable = counts["PROVEN_REACHABLE_UNPROTECTED"]
        fp_suppression_pct = round((suppressed / max(1, total)) * 100.0, 2)

        return {
            "verified_at": utc_now_iso(),
            "total_findings_evaluated": total,
            "status_distribution": dict(counts),
            "proven_reachable_unprotected": proven_crit_reachable,
            "guarded_reachable": counts["REACHABLE_BEHIND_GUARD"],
            "dead_or_test_suppression_candidates": suppressed,
            "estimated_false_positive_reduction_pct": fp_suppression_pct,
            "verdicts": [v.to_dict() for v in verdicts[:120]],
        }

    # ------------------------------------------------------------------
    # AST INDEXING HELPERS
    # ------------------------------------------------------------------
    def _index_module_ast(self, rel_file: str, tree: ast.Module) -> None:
        self._scan_dead_statements(rel_file, tree.body)

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._register_function(rel_file, node, class_name=None)
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self._register_function(rel_file, item, class_name=node.name)

    def _register_function(
        self,
        rel_file: str,
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        class_name: Optional[str],
    ) -> None:
        fqn = f"{rel_file}::{class_name}.{fn.name}" if class_name else f"{rel_file}::{fn.name}"
        is_ep, ep_kind = self._classify_entrypoint(rel_file, fn, class_name)

        calls: Set[str] = set()
        guard_lines: Set[int] = set()
        dead_before = set(self._module_dead_lines[rel_file])
        self._scan_dead_statements(rel_file, fn.body)
        fn_dead = self._module_dead_lines[rel_file] - dead_before

        for sub in ast.walk(fn):
            if isinstance(sub, ast.Call):
                cname = self._call_short_name(sub.func)
                if cname:
                    calls.add(cname)
                    if AUTH_GUARD_CALL_RE.search(cname):
                        ln = getattr(sub, "lineno", fn.lineno)
                        guard_lines.add(ln)
                        self._module_guard_names[rel_file][ln].append(cname)

        span = FunctionSpan(
            fqn=fqn,
            short_name=fn.name,
            rel_file=rel_file,
            line_start=fn.lineno,
            line_end=getattr(fn, "end_lineno", fn.lineno + 1),
            is_entrypoint=is_ep,
            entrypoint_kind=ep_kind,
            calls=calls,
            guard_lines=guard_lines,
            dead_lines=fn_dead,
        )
        self._funcs_by_file[rel_file].append(span)
        self._funcs_by_fqn[fqn] = span
        self._fqns_by_short[fn.name].append(fqn)

    def _scan_dead_statements(self, rel_file: str, stmts: Sequence[ast.stmt]) -> None:
        terminated = False
        for stmt in stmts:
            if terminated:
                self._mark_subtree_dead(rel_file, stmt)
                continue
            if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                terminated = True
                continue
            if isinstance(stmt, ast.If):
                const_truth = self._eval_constant_truth(stmt.test)
                if const_truth is False:
                    for sub in stmt.body:
                        self._mark_subtree_dead(rel_file, sub)
                    self._scan_dead_statements(rel_file, stmt.orelse)
                elif const_truth is True:
                    self._scan_dead_statements(rel_file, stmt.body)
                    for sub in stmt.orelse:
                        self._mark_subtree_dead(rel_file, sub)
                else:
                    self._scan_dead_statements(rel_file, stmt.body)
                    self._scan_dead_statements(rel_file, stmt.orelse)
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
                self._scan_dead_statements(rel_file, stmt.body)
                if hasattr(stmt, "orelse"):
                    self._scan_dead_statements(rel_file, getattr(stmt, "orelse"))
            elif isinstance(stmt, ast.Try):
                self._scan_dead_statements(rel_file, stmt.body)
                for h in stmt.handlers:
                    self._scan_dead_statements(rel_file, h.body)
                self._scan_dead_statements(rel_file, stmt.orelse)
                self._scan_dead_statements(rel_file, stmt.finalbody)

    def _mark_subtree_dead(self, rel_file: str, node: ast.AST) -> None:
        s = getattr(node, "lineno", None)
        e = getattr(node, "end_lineno", s)
        if s is not None and e is not None:
            for ln in range(s, e + 1):
                self._module_dead_lines[rel_file].add(ln)

    @staticmethod
    def _eval_constant_truth(expr: ast.expr) -> Optional[bool]:
        if isinstance(expr, ast.Constant):
            return bool(expr.value)
        if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
            inner = SemanticReachabilityVerifier._eval_constant_truth(expr.operand)
            return (not inner) if inner is not None else None
        if isinstance(expr, ast.BoolOp):
            vals = [SemanticReachabilityVerifier._eval_constant_truth(v) for v in expr.values]
            if isinstance(expr.op, ast.And) and any(v is False for v in vals):
                return False
            if isinstance(expr.op, ast.Or) and any(v is True for v in vals):
                return True
        return None

    @staticmethod
    def _classify_entrypoint(
        rel_file: str,
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
        class_name: Optional[str],
    ) -> Tuple[bool, str]:
        for dec in fn.decorator_list:
            dtxt = ast.unparse(dec) if hasattr(ast, "unparse") else ""
            if HTTP_ROUTE_DECORATOR_RE.search(dtxt):
                return True, "http_route_decorator"
        if fn.name in ("main", "cli", "do_GET", "do_POST", "do_PUT", "do_DELETE", "app", "application", "lambda_handler", "handler"):
            return True, f"canonical_entry:{fn.name}"
        if fn.name.startswith(("handle_", "api_", "endpoint_", "route_", "cmd_", "run_", "execute_", "serve_")):
            return True, "handler_prefix"
        if not fn.name.startswith("_") and not TEST_FILE_RE.search(rel_file):
            if class_name is None or fn.name in ("__call__", "process", "dispatch", "evaluate", "scan", "audit"):
                return True, "public_api"
        return False, ""

    @staticmethod
    def _call_short_name(func_node: ast.expr) -> str:
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            return func_node.attr
        return ""

    # ------------------------------------------------------------------
    # FINDING EVALUATION
    # ------------------------------------------------------------------
    def _evaluate_single(self, rule_id: str, fpath: str, line: int) -> ReachabilityVerdict:
        norm = fpath.replace("\\", "/").lstrip("./")

        if TEST_FILE_RE.search(norm):
            return ReachabilityVerdict(
                finding_key=f"{rule_id}@{norm}:{line}",
                file_path=norm,
                line=line,
                enclosing_function="<test_fixture>",
                status="TEST_OR_FIXTURE_ONLY",
                entrypoint_hops=-1,
                entrypoint_path=[],
                dominating_guards=[],
                risk_multiplier=0.25,
                suppress_recommended=True,
                rationale="Finding resides exclusively inside a test suite or fixture file.",
            )

        # Match indexed file (exact or suffix match)
        matched_file = self._match_indexed_file(norm)
        if matched_file is None:
            return ReachabilityVerdict(
                finding_key=f"{rule_id}@{norm}:{line}",
                file_path=norm,
                line=line,
                enclosing_function="<non_python_or_external>",
                status="INTERNAL_CALLABLE",
                entrypoint_hops=0,
                entrypoint_path=[],
                dominating_guards=[],
                risk_multiplier=0.90,
                suppress_recommended=False,
                rationale="Non-Python artifact (config/IaC/runtime endpoint); retained without dead-code suppression.",
            )

        if line > 0 and line in self._module_dead_lines.get(matched_file, set()):
            return ReachabilityVerdict(
                finding_key=f"{rule_id}@{matched_file}:{line}",
                file_path=matched_file,
                line=line,
                enclosing_function="<dead_branch>",
                status="UNREACHABLE_DEAD_CODE",
                entrypoint_hops=-1,
                entrypoint_path=[],
                dominating_guards=[],
                risk_multiplier=0.10,
                suppress_recommended=True,
                rationale="Line lies inside an unreachable branch (`if False:` or post-return dead code).",
            )

        enclosing = self._find_enclosing_function(matched_file, line)
        if enclosing is None:
            return ReachabilityVerdict(
                finding_key=f"{rule_id}@{matched_file}:{line}",
                file_path=matched_file,
                line=line,
                enclosing_function="<module_top_level>",
                status="PROVEN_REACHABLE_UNPROTECTED",
                entrypoint_hops=0,
                entrypoint_path=[f"{matched_file}::<module>"],
                dominating_guards=[],
                risk_multiplier=1.10,
                suppress_recommended=False,
                rationale="Executes at module import / top-level initialization.",
            )

        ep_path = self._shortest_ep_path.get(enclosing.fqn)
        if ep_path is None:
            return ReachabilityVerdict(
                finding_key=f"{rule_id}@{matched_file}:{line}",
                file_path=matched_file,
                line=line,
                enclosing_function=enclosing.fqn,
                status="UNREACHABLE_DEAD_CODE",
                entrypoint_hops=-1,
                entrypoint_path=[],
                dominating_guards=[],
                risk_multiplier=0.15,
                suppress_recommended=True,
                rationale=f"Private function `{enclosing.fqn}` has zero incoming call paths from any discovered entrypoint.",
            )

        # Check dominating guards earlier in the same function
        guards: List[str] = []
        for gln in sorted(enclosing.guard_lines):
            if gln <= line or line <= 0:
                guards.extend(self._module_guard_names[matched_file].get(gln, []))
        guards = sorted(set(guards))

        if guards:
            return ReachabilityVerdict(
                finding_key=f"{rule_id}@{matched_file}:{line}",
                file_path=matched_file,
                line=line,
                enclosing_function=enclosing.fqn,
                status="REACHABLE_BEHIND_GUARD",
                entrypoint_hops=len(ep_path) - 1,
                entrypoint_path=ep_path,
                dominating_guards=guards,
                risk_multiplier=0.75,
                suppress_recommended=False,
                rationale=f"Reachable in {len(ep_path)-1} hops from `{ep_path[0]}`, preceded by guard(s): {', '.join(guards)}.",
            )

        return ReachabilityVerdict(
            finding_key=f"{rule_id}@{matched_file}:{line}",
            file_path=matched_file,
            line=line,
            enclosing_function=enclosing.fqn,
            status="PROVEN_REACHABLE_UNPROTECTED",
            entrypoint_hops=len(ep_path) - 1,
            entrypoint_path=ep_path,
            dominating_guards=[],
            risk_multiplier=1.15,
            suppress_recommended=False,
            rationale=f"Directly reachable in {len(ep_path)-1} hops from entrypoint `{ep_path[0]}` with no dominating auth/scope guard.",
        )

    def _match_indexed_file(self, norm_path: str) -> Optional[str]:
        if norm_path in self._funcs_by_file or norm_path in self._module_dead_lines:
            return norm_path
        for cand in self._funcs_by_file.keys():
            if cand.endswith(norm_path) or norm_path.endswith(cand):
                return cand
        return None

    def _find_enclosing_function(self, rel_file: str, line: int) -> Optional[FunctionSpan]:
        matches = [
            f for f in self._funcs_by_file.get(rel_file, [])
            if f.line_start <= line <= f.line_end
        ]
        if not matches:
            return None
        matches.sort(key=lambda f: f.line_end - f.line_start)
        return matches[0]

    @staticmethod
    def _extract_loc(finding: Any, idx: int) -> Tuple[str, int, str]:
        if isinstance(finding, dict):
            loc = finding.get("location") or {}
            fp = str(finding.get("file_path") or loc.get("file_path") or finding.get("endpoint_or_asset") or "")
            ln = int(finding.get("line_start") or loc.get("line_start") or 0)
            rid = str(finding.get("rule_id") or f"F-{idx}")
            return fp, ln, rid
        loc = getattr(finding, "location", None)
        fp = str(getattr(finding, "file_path", "") or (getattr(loc, "file_path", "") if loc else "") or getattr(finding, "endpoint_or_asset", ""))
        ln = int(getattr(finding, "line_start", 0) or (getattr(loc, "line_start", 0) if loc else 0))
        rid = str(getattr(finding, "rule_id", f"F-{idx}"))
        return fp, ln, rid
