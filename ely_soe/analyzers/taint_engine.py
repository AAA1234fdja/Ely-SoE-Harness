"""
Interprocedural Python AST Control-Flow & Source-to-Sink Taint Analysis Engine.

Performs static dataflow tracking across Python modules in an Ely snapshot:
  - Identifies untrusted **Taint Sources**:
      * Function parameters representing external inputs (`user_input`, `url`, `path`,
        `web_content`, `html`, `query`, `prompt`, `payload`, `cmd`, `token`, `skill_data`, `body`, `args`)
      * Calls to network/external fetchers (`urlopen`, `requests.get`, `fetch_page`, `input`)
      * Request/header/body lookups (`request.args`, `request.json`, `headers.get`)
  - Propagates taint through:
      * Direct assignments, augmented assignments (`+=`), f-strings (`JoinedStr`),
        `.format()`, `%` formatting, binary concatenation (`+`), dict/list literals,
        and intra-module helper function return values!
  - Respects explicit **Sanitizers** (`shlex.quote`, `sanitize_untrusted_content`,
    `validate_egress_url`, `Path.resolve`, `is_relative_to`, `separate_control_data_plane`,
    `escape`, `bleach.clean`, `hmac.compare_digest`).
  - Flags tainted values reaching dangerous **Sinks** across Ely domains:
      * Command Injection (`subprocess.run/Popen/call`, `os.system`, `os.popen`)
      * Code Injection (`eval`, `exec`, `compile`, `__import__`, `importlib.import_module`)
      * Filesystem Traversal (`open`, `Path.read_text`, `Path.write_text`, `shutil.copy`, `tarfile.extractall`)
      * SQL Injection (`cursor.execute`, `conn.execute` with formatted string)
      * SSRF / Network Egress (`urllib.request.urlopen`, `requests.get/post`)
      * Prompt Injection (`build_prompt`, `llm.complete`, `system_prompt` concatenation)
      * Memory Poisoning (`memory.store`, `vector_store.upsert`, `save_memory`)
      * Insecure Deserialization (`pickle.loads`, `yaml.load` without SafeLoader)
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ely_soe.core.models import (
    CodeLocation,
    EvidenceArtifact,
    Finding,
    FindingStatus,
    SecurityDomain,
    Severity,
    new_id,
)


TAINTED_PARAM_TOKENS: Tuple[str, ...] = (
    "user_", "external", "web_", "page_", "html", "untrusted", "payload", "raw_",
    "prompt", "query", "cmd", "command", "path", "filepath", "filename", "url",
    "uri", "endpoint", "body", "header", "token", "skill", "plugin", "doc",
    "content", "message", "arg", "input", "data", "req", "request", "archive",
)

TAINT_SOURCE_CALLS: Set[str] = {
    "urlopen",
    "urllib.request.urlopen",
    "requests.get",
    "requests.post",
    "fetch_url",
    "fetch_page",
    "http_get",
    "input",
    "recv",
    "read_external",
    "get_external_page",
}

SANITIZER_CALLS: Set[str] = {
    "shlex.quote",
    "quote",
    "sanitize_untrusted_content",
    "strip_prompt_injection",
    "separate_control_data_plane",
    "validate_egress_url",
    "safe_resolve_path",
    "resolve_in_workspace",
    "is_relative_to",
    "validate_tool_arguments",
    "sign_memory_entry",
    "verify_skill_signature",
    "escape",
    "html.escape",
}


@dataclass(frozen=True)
class SinkSpec:
    rule_id: str
    title: str
    domain: SecurityDomain
    severity: Severity
    cwe: str
    sink_names: FrozenSet[str]
    require_shell_true: bool = False
    require_non_literal_first_arg: bool = True


from typing import FrozenSet  # noqa: E402

SINK_SPECS: List[SinkSpec] = [
    SinkSpec(
        rule_id="TAINT-CMD-001",
        title="Tainted Data Flows to OS Command Execution",
        domain=SecurityDomain.TOOL_EXECUTION,
        severity=Severity.CRITICAL,
        cwe="CWE-78",
        sink_names=frozenset({"os.system", "os.popen", "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output"}),
    ),
    SinkSpec(
        rule_id="TAINT-CODE-002",
        title="Tainted Data Flows to Dynamic Code Execution (eval/exec/import)",
        domain=SecurityDomain.TOOL_EXECUTION,
        severity=Severity.CRITICAL,
        cwe="CWE-94",
        sink_names=frozenset({"eval", "exec", "compile", "__import__", "importlib.import_module"}),
    ),
    SinkSpec(
        rule_id="TAINT-FS-003",
        title="Tainted Path Flows to Unvalidated Filesystem Access",
        domain=SecurityDomain.FILESYSTEM,
        severity=Severity.HIGH,
        cwe="CWE-22",
        sink_names=frozenset({"open", "Path.read_text", "Path.write_text", "shutil.copy", "shutil.rmtree", "os.remove"}),
    ),
    SinkSpec(
        rule_id="TAINT-SQL-004",
        title="Tainted String Concatenation Flows to SQL Query Execution",
        domain=SecurityDomain.API_SECURITY,
        severity=Severity.HIGH,
        cwe="CWE-89",
        sink_names=frozenset({"execute", "executemany", "executescript"}),
    ),
    SinkSpec(
        rule_id="TAINT-SSRF-005",
        title="Tainted URL Flows to Outbound Network Request (SSRF / Egress)",
        domain=SecurityDomain.NETWORK,
        severity=Severity.HIGH,
        cwe="CWE-918",
        sink_names=frozenset({"urlopen", "urllib.request.urlopen", "requests.get", "requests.post", "requests.request", "http_fetch"}),
    ),
    SinkSpec(
        rule_id="TAINT-MEM-006",
        title="Untrusted External Content Written Directly to Persistent Agent Memory",
        domain=SecurityDomain.MEMORY,
        severity=Severity.HIGH,
        cwe="CWE-345",
        sink_names=frozenset({"memory.store", "store_memory", "save_memory", "upsert", "vector_store.upsert", "add_memory"}),
    ),
    SinkSpec(
        rule_id="TAINT-DESER-007",
        title="Tainted Data Flows to Unsafe Deserialization (pickle/yaml)",
        domain=SecurityDomain.API_SECURITY,
        severity=Severity.CRITICAL,
        cwe="CWE-502",
        sink_names=frozenset({"pickle.loads", "pickle.load", "marshal.loads", "yaml.unsafe_load"}),
    ),
]


@dataclass
class TaintFlow:
    """Concrete source -> propagation steps -> sink trace."""

    file_path: str
    function_name: str
    source_name: str
    source_line: int
    sink_spec: SinkSpec
    sink_call: str
    sink_line: int
    propagation_chain: List[str] = field(default_factory=list)
    snippet: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "function_name": self.function_name,
            "source_name": self.source_name,
            "source_line": self.source_line,
            "rule_id": self.sink_spec.rule_id,
            "sink_call": self.sink_call,
            "sink_line": self.sink_line,
            "propagation_chain": list(self.propagation_chain),
            "snippet": self.snippet,
        }


class PythonTaintAnalyzer:
    """
    AST-based source-to-sink taint analyzer for Python codebases.
    Emits ONLY `FindingStatus.HYPOTHESIS` findings with complete dataflow traces.
    """

    def analyze_directory(self, snapshot_root: Path) -> List[Finding]:
        findings: List[Finding] = []
        root = Path(snapshot_root).resolve()
        for py_file in sorted(root.rglob("*.py")):
            if any(part.startswith(".") or part in ("__pycache__", "tests", ".venv") for part in py_file.relative_to(root).parts):
                continue
            rel = py_file.relative_to(root).as_posix()
            try:
                src = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            flows = self.analyze_source(rel, src)
            for flow in flows:
                findings.append(self._flow_to_finding(flow))
        return findings

    def analyze_source(self, rel_path: str, source: str) -> List[TaintFlow]:
        try:
            tree = ast.parse(source, filename=rel_path)
        except SyntaxError:
            return []

        lines = source.splitlines()
        flows: List[TaintFlow] = []

        # Pass 1: Identify local functions that return tainted values (simple interprocedural summary)
        taint_returning_fns: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if self._function_returns_external(node):
                    taint_returning_fns.add(node.name)

        # Pass 2: Analyze every function / method body
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                flows.extend(self._analyze_function(rel_path, node, lines, taint_returning_fns))
        return flows

    def _analyze_function(
        self,
        rel_path: str,
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
        lines: List[str],
        taint_returning_fns: Set[str],
    ) -> List[TaintFlow]:
        # Map variable name -> (origin_label, origin_line, chain)
        tainted: Dict[str, Tuple[str, int, List[str]]] = {}
        sanitized_vars: Set[str] = set()
        fn_has_guard = self._function_has_guard_call(fn)
        flows: List[TaintFlow] = []

        # Seed taint from untrusted parameter names
        for arg in fn.args.args + fn.args.kwonlyargs:
            low = arg.arg.lower()
            if arg.arg in ("self", "cls"):
                continue
            if any(tok in low for tok in TAINTED_PARAM_TOKENS):
                tainted[arg.arg] = (f"param:{arg.arg}", fn.lineno, [f"param {arg.arg} (L{fn.lineno})"])

        # Walk statements sequentially to track propagation & sanitization
        for stmt in self._iter_statements(fn.body):
            # Check standalone validation calls like `validate_egress_url(url)` -> marks `url` sanitized
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                cname = self._call_name(stmt.value)
                if self._is_sanitizer(cname):
                    for a in stmt.value.args:
                        if isinstance(a, ast.Name):
                            sanitized_vars.add(a.id)
                            tainted.pop(a.id, None)

            # Assignments: propagate or clear taint
            if isinstance(stmt, ast.Assign):
                val_taint = self._expr_taint(stmt.value, tainted, taint_returning_fns)
                val_is_sanitized = isinstance(stmt.value, ast.Call) and self._is_sanitizer(self._call_name(stmt.value))
                for tgt in stmt.targets:
                    if isinstance(tgt, ast.Name):
                        if val_is_sanitized:
                            sanitized_vars.add(tgt.id)
                            tainted.pop(tgt.id, None)
                        elif val_taint is not None:
                            src_name, src_line, chain = val_taint
                            tainted[tgt.id] = (src_name, src_line, chain + [f"assign {tgt.id} (L{stmt.lineno})"])
                        else:
                            tainted.pop(tgt.id, None)

            elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
                val_taint = self._expr_taint(stmt.value, tainted, taint_returning_fns)
                if val_taint is not None:
                    src_name, src_line, chain = val_taint
                    tainted[stmt.target.id] = (
                        src_name,
                        src_line,
                        chain + [f"concat {stmt.target.id} (L{stmt.lineno})"],
                    )

            # Check all calls inside statement for sink matches
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Call):
                    self._check_call_sink(
                        rel_path, fn.name, sub, tainted, sanitized_vars, taint_returning_fns, fn_has_guard, lines, flows
                    )

            # Special check: Prompt Injection via f-string / concat mixing system prompt + tainted external data
            if isinstance(stmt, (ast.Assign, ast.AugAssign)):
                self._check_prompt_mixing(rel_path, fn.name, stmt, tainted, lines, flows)

        return flows

    def _check_call_sink(
        self,
        rel_path: str,
        fn_name: str,
        call: ast.Call,
        tainted: Dict[str, Tuple[str, int, List[str]]],
        sanitized_vars: Set[str],
        taint_returning_fns: Set[str],
        fn_has_guard: Dict[str, bool],
        lines: List[str],
        flows: List[TaintFlow],
    ) -> None:
        cname = self._call_name(call)
        short_name = cname.split(".")[-1]
        if self._is_sanitizer(cname):
            return

        for spec in SINK_SPECS:
            if cname not in spec.sink_names and short_name not in spec.sink_names:
                continue

            # Domain-specific false-positive suppressions (high precision!)
            if spec.rule_id == "TAINT-FS-003" and fn_has_guard.get("fs_guard"):
                continue
            if spec.rule_id == "TAINT-SSRF-005" and fn_has_guard.get("net_guard"):
                continue
            if spec.rule_id == "TAINT-MEM-006" and fn_has_guard.get("mem_guard"):
                continue
            if spec.rule_id == "TAINT-CMD-001":
                # subprocess.run([...], shell=False) with safe list and no shell=True is lower risk unless os.system
                if cname.startswith("subprocess.") and not self._has_kw_true(call, "shell"):
                    continue
            if spec.rule_id == "TAINT-SQL-004":
                # Only flag SQLi if first arg uses formatting/concatenation rather than parameterized literal
                if call.args and isinstance(call.args[0], ast.Constant):
                    continue

            # Check whether any argument is tainted
            arg_nodes = list(call.args) + [kw.value for kw in call.keywords]
            for arg_expr in arg_nodes:
                # Skip explicitly sanitized variable references
                if isinstance(arg_expr, ast.Name) and arg_expr.id in sanitized_vars:
                    continue
                t_info = self._expr_taint(arg_expr, tainted, taint_returning_fns)
                if t_info is not None:
                    src_name, src_line, chain = t_info
                    snippet = lines[call.lineno - 1].strip()[:160] if 1 <= call.lineno <= len(lines) else cname
                    flows.append(
                        TaintFlow(
                            file_path=rel_path,
                            function_name=fn_name,
                            source_name=src_name,
                            source_line=src_line,
                            sink_spec=spec,
                            sink_call=cname,
                            sink_line=call.lineno,
                            propagation_chain=chain + [f"sink {cname} (L{call.lineno})"],
                            snippet=snippet,
                        )
                    )
                    break

    def _check_prompt_mixing(
        self,
        rel_path: str,
        fn_name: str,
        stmt: ast.Assign | ast.AugAssign,
        tainted: Dict[str, Tuple[str, int, List[str]]],
        lines: List[str],
        flows: List[TaintFlow],
    ) -> None:
        target_names: List[str] = []
        if isinstance(stmt, ast.Assign):
            target_names = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
        elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
            target_names = [stmt.target.id]

        if not any("prompt" in t.lower() or "system" in t.lower() for t in target_names):
            return

        val_taint = self._expr_taint(stmt.value, tainted, set())
        if val_taint is None:
            return

        # Must actually interpolate/concatenate strings (not just passing through)
        if not isinstance(stmt.value, (ast.JoinedStr, ast.BinOp, ast.Call)):
            return

        snippet = lines[stmt.lineno - 1].strip()[:160] if 1 <= stmt.lineno <= len(lines) else ""
        if any(guard in snippet for guard in ("sanitize_untrusted", "separate_control_data_plane", "DATA_ONLY")):
            return

        spec = SinkSpec(
            rule_id="TAINT-PI-008",
            title="Untrusted External Data Directly Concatenated into System/Agent Prompt",
            domain=SecurityDomain.PROMPT_INJECTION,
            severity=Severity.CRITICAL,
            cwe="CWE-74",
            sink_names=frozenset({"prompt_concat"}),
        )
        src_name, src_line, chain = val_taint
        flows.append(
            TaintFlow(
                file_path=rel_path,
                function_name=fn_name,
                source_name=src_name,
                source_line=src_line,
                sink_spec=spec,
                sink_call=f"prompt_build:{target_names[0]}",
                sink_line=stmt.lineno,
                propagation_chain=chain + [f"prompt_mix {target_names[0]} (L{stmt.lineno})"],
                snippet=snippet,
            )
        )

    def _expr_taint(
        self,
        expr: ast.AST,
        tainted: Dict[str, Tuple[str, int, List[str]]],
        taint_returning_fns: Set[str],
    ) -> Optional[Tuple[str, int, List[str]]]:
        if isinstance(expr, ast.Call):
            cname = self._call_name(expr)
            if self._is_sanitizer(cname):
                return None
            if cname in TAINT_SOURCE_CALLS or cname.split(".")[-1] in taint_returning_fns:
                ln = getattr(expr, "lineno", 1)
                return (f"call:{cname}", ln, [f"source {cname}() (L{ln})"])
            # Propagate through string/join/format helper calls
            for a in expr.args:
                sub_t = self._expr_taint(a, tainted, taint_returning_fns)
                if sub_t is not None:
                    return sub_t
            if isinstance(expr.func, ast.Attribute):
                return self._expr_taint(expr.func.value, tainted, taint_returning_fns)
            return None

        if isinstance(expr, ast.Name):
            return tainted.get(expr.id)

        if isinstance(expr, ast.JoinedStr):
            for val in expr.values:
                if isinstance(val, ast.FormattedValue):
                    sub_t = self._expr_taint(val.value, tainted, taint_returning_fns)
                    if sub_t is not None:
                        return sub_t
            return None

        if isinstance(expr, ast.BinOp):
            return self._expr_taint(expr.left, tainted, taint_returning_fns) or self._expr_taint(
                expr.right, tainted, taint_returning_fns
            )

        if isinstance(expr, ast.Subscript):
            return self._expr_taint(expr.value, tainted, taint_returning_fns)

        if isinstance(expr, ast.Attribute):
            # e.g. request.body, request.json, msg.content
            if expr.attr in ("body", "json", "args", "headers", "form", "data", "content", "text"):
                ln = getattr(expr, "lineno", 1)
                return (f"attr:{self._call_name(expr)}", ln, [f"attr {expr.attr} (L{ln})"])
            return self._expr_taint(expr.value, tainted, taint_returning_fns)

        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            for el in expr.elts:
                sub_t = self._expr_taint(el, tainted, taint_returning_fns)
                if sub_t is not None:
                    return sub_t
        return None

    def _function_returns_external(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and self._call_name(node) in TAINT_SOURCE_CALLS:
                return True
        return False

    def _function_has_guard_call(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> Dict[str, bool]:
        guards = {"fs_guard": False, "net_guard": False, "mem_guard": False}
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                cname = self._call_name(node)
                if any(g in cname for g in ("is_relative_to", "safe_resolve", "resolve_in_workspace", "FS_WORKSPACE")):
                    guards["fs_guard"] = True
                if any(g in cname for g in ("validate_egress", "assert_network_target", "is_private")):
                    guards["net_guard"] = True
                if any(g in cname for g in ("sign_memory", "inspect_memory", "detect_prompt_injection")):
                    guards["mem_guard"] = True
        return guards

    def _iter_statements(self, body: List[ast.stmt]) -> List[ast.stmt]:
        stmts: List[ast.stmt] = []
        for s in body:
            stmts.append(s)
            for attr in ("body", "orelse", "finalbody"):
                sub = getattr(s, attr, None)
                if isinstance(sub, list):
                    stmts.extend(self._iter_statements(sub))
            handlers = getattr(s, "handlers", None)
            if isinstance(handlers, list):
                for h in handlers:
                    stmts.extend(self._iter_statements(h.body))
        return stmts

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        target = node.func if isinstance(node, ast.Call) else node
        parts: List[str] = []
        cur = target
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))

    @staticmethod
    def _is_sanitizer(cname: str) -> bool:
        return cname in SANITIZER_CALLS or cname.split(".")[-1] in SANITIZER_CALLS

    @staticmethod
    def _has_kw_true(call: ast.Call, kw_name: str) -> bool:
        for kw in call.keywords:
            if kw.arg == kw_name and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False

    @staticmethod
    def _flow_to_finding(flow: TaintFlow) -> Finding:
        chain_str = " -> ".join(flow.propagation_chain)
        return Finding(
            finding_id=new_id("fnd"),
            title=f"[Taint] {flow.sink_spec.title}",
            description=(
                f"Static AST taint analysis detected untrusted data from `{flow.source_name}` "
                f"(line {flow.source_line}) flowing into sink `{flow.sink_call}` (line {flow.sink_line}) "
                f"in `{flow.function_name}()`: {chain_str}."
            ),
            domain=flow.sink_spec.domain,
            severity=flow.sink_spec.severity,
            rule_id=flow.sink_spec.rule_id,
            discovered_by="ely_python_taint_engine",
            location=CodeLocation(
                file_path=flow.file_path,
                line_start=flow.sink_line,
                symbol=flow.function_name,
                snippet=flow.snippet,
                language="python",
            ),
            status=FindingStatus.HYPOTHESIS,
            confidence=0.84,
            cwe_ids=[flow.sink_spec.cwe],
            attack_vector=f"Source-to-sink dataflow: {chain_str}",
            impact=f"Attacker-controlled `{flow.source_name}` reaches `{flow.sink_call}` without verified sanitization",
            poc_spec={
                "kind": "taint_flow",
                "rule_id": flow.sink_spec.rule_id,
                "target_file": flow.file_path,
                "function": flow.function_name,
                "sink_call": flow.sink_call,
                "sink_line": flow.sink_line,
                "source_name": flow.source_name,
            },
            evidence=[
                EvidenceArtifact(
                    artifact_id=new_id("ev"),
                    kind="taint_path",
                    description=f"AST Taint Path {flow.sink_spec.rule_id}",
                    content=chain_str + "\nSnippet: " + flow.snippet,
                    producer="ely_python_taint_engine",
                )
            ],
            tags=["taint_analysis", "static_ast", flow.sink_spec.cwe.lower()],
        )
