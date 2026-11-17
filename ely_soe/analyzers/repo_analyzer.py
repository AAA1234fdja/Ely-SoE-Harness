"""
Component 2 of the 6-Stage Security Harness: Repository & Architecture Analyzer.

Comprehends the target Ely repository before vulnerability hunting begins:
  - Walks the isolated snapshot and inventories languages, files, and LOC.
  - Parses Python ASTs, Rust source files, JS/TS modules, and JSON/YAML/TOML manifests.
  - Discovers architectural security assets (`AttackSurfaceNode`):
      * Multi-agent classes & agent entrypoints
      * Tool definitions & dispatchers
      * Skills / plugins & their declared permissions
      * HTTP/WebSocket API routes & auth handlers
      * Memory / RAG / vector stores
      * Filesystem & archive handlers
      * Subprocess / process runners
      * Rust Core `unsafe` & `extern "C"` FFI boundaries
      * Dependency lockfiles & build scripts
  - Builds directed edges `(caller -> callee/resource)` and explicit `TrustBoundary`
    crossings (External Web -> Researcher Agent, Agent -> Tool/Process, Skill -> Core,
    Python Runtime -> Rust FFI, Evaluated Agent -> Auditor Plane).
  - Extracts the effective `permission_matrix` across agents and skills.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ely_soe.core.models import (
    AttackSurfaceGraph,
    AttackSurfaceNode,
    CodeLocation,
    SecurityDomain,
    TrustBoundary,
    new_id,
)


LANG_BY_EXT: Dict[str, str] = {
    ".py": "python",
    ".rs": "rust",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".toml": "toml",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".sh": "shell",
    ".sql": "sql",
}

IGNORED_DIRS: Set[str] = {
    ".git", "__pycache__", "node_modules", "target", ".venv", "venv", "dist", "build", ".pytest_cache"
}


class RepositoryAnalyzer:
    """Builds a rich `AttackSurfaceGraph` from an isolated Ely target snapshot."""

    def analyze(
        self,
        snapshot_root: Path,
        target_name: str = "ely-instance",
        target_version: str = "unknown",
    ) -> AttackSurfaceGraph:
        root = Path(snapshot_root).resolve()
        languages: Dict[str, int] = {}
        nodes: List[AttackSurfaceNode] = []
        edges: List[Tuple[str, str, str]] = []
        permission_matrix: Dict[str, List[str]] = {}
        total_files = 0
        total_lines = 0
        deps_count = 0

        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if any(part in IGNORED_DIRS or part.startswith(".ely_") for part in path.relative_to(root).parts):
                continue

            ext = path.suffix.lower()
            lang = LANG_BY_EXT.get(ext, "other")
            rel = path.relative_to(root).as_posix()
            total_files += 1
            languages[lang] = languages.get(lang, 0) + 1

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.splitlines()
            total_lines += len(lines)

            if lang == "python":
                py_nodes, py_perms = self._analyze_python(rel, content)
                nodes.extend(py_nodes)
                for k, v in py_perms.items():
                    permission_matrix.setdefault(k, []).extend(v)
            elif lang == "rust":
                nodes.extend(self._analyze_rust(rel, content))
            elif lang in ("javascript", "typescript"):
                nodes.extend(self._analyze_js_ts(rel, content, lang))
            elif path.name in ("Cargo.toml", "package.json", "requirements.txt", "pyproject.toml"):
                dep_nodes, count = self._analyze_dependency_manifest(rel, path.name, content)
                nodes.extend(dep_nodes)
                deps_count += count
            elif "skill" in path.name.lower() and ext in (".json", ".yaml", ".yml"):
                skill_nodes, skill_perms = self._analyze_skill_manifest(rel, content)
                nodes.extend(skill_nodes)
                for k, v in skill_perms.items():
                    permission_matrix.setdefault(k, []).extend(v)

        # Deduplicate permissions per principal
        for k in list(permission_matrix.keys()):
            permission_matrix[k] = sorted(set(permission_matrix[k]))

        edges.extend(self._infer_architectural_edges(nodes))
        trust_boundaries = self._build_trust_boundaries(nodes)

        return AttackSurfaceGraph(
            target_name=target_name,
            target_version=target_version,
            root_path=str(root),
            languages=languages,
            total_files=total_files,
            total_lines=total_lines,
            nodes=nodes,
            edges=edges,
            trust_boundaries=trust_boundaries,
            permission_matrix=permission_matrix,
            dependencies_count=deps_count,
        )

    def _analyze_python(self, rel_path: str, content: str) -> Tuple[List[AttackSurfaceNode], Dict[str, List[str]]]:
        nodes: List[AttackSurfaceNode] = []
        perms: Dict[str, List[str]] = {}

        try:
            tree = ast.parse(content, filename=rel_path)
        except SyntaxError:
            return nodes, perms

        lines = content.splitlines()

        def snip(lineno: int) -> str:
            return lines[lineno - 1].strip()[:140] if 1 <= lineno <= len(lines) else ""

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                low = node.name.lower()
                kind: Optional[str] = None
                domains: List[SecurityDomain] = []
                zone = "internal"
                exposed = False

                if "agent" in low or "researcher" in low or "executor" in low or "orchestrator" in low:
                    kind = "agent"
                    domains = [SecurityDomain.AGENT_ISOLATION, SecurityDomain.PROMPT_INJECTION]
                    zone = "agent_plane"
                    exposed = "researcher" in low
                elif "memory" in low or "rag" in low or "vector" in low:
                    kind = "memory_store"
                    domains = [SecurityDomain.MEMORY, SecurityDomain.AGENT_ISOLATION]
                    zone = "memory_plane"
                elif "skill" in low or "plugin" in low:
                    kind = "skill"
                    domains = [SecurityDomain.SUPPLY_CHAIN, SecurityDomain.TOOL_EXECUTION]
                    zone = "skill_plane"
                elif "tool" in low or "runner" in low:
                    kind = "tool"
                    domains = [SecurityDomain.TOOL_EXECUTION, SecurityDomain.PROCESS_MANAGEMENT]
                    zone = "execution_plane"
                elif "api" in low or "server" in low or "router" in low or "handler" in low:
                    kind = "api_endpoint"
                    domains = [SecurityDomain.API_SECURITY, SecurityDomain.NETWORK]
                    zone = "api_edge"
                    exposed = True
                elif "sandbox" in low or "process" in low:
                    kind = "subprocess_exec"
                    domains = [SecurityDomain.PROCESS_MANAGEMENT, SecurityDomain.FILESYSTEM]
                    zone = "execution_plane"

                if kind:
                    caps = self._extract_class_capabilities(node)
                    if caps:
                        perms[node.name] = caps
                    nodes.append(
                        AttackSurfaceNode(
                            node_id=new_id("asg"),
                            kind=kind,
                            name=node.name,
                            location=CodeLocation(
                                file_path=rel_path,
                                line_start=node.lineno,
                                line_end=getattr(node, "end_lineno", node.lineno),
                                symbol=node.name,
                                snippet=snip(node.lineno),
                                language="python",
                            ),
                            domains=domains,
                            capabilities=caps,
                            exposed_externally=exposed,
                            trust_zone=zone,
                            risk_exposure=self._score_exposure(kind, exposed, caps),
                        )
                    )

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                low = node.name.lower()
                dec_names = [ast.unparse(d) if hasattr(ast, "unparse") else "" for d in node.decorator_list]
                is_route = any(
                    any(m in d.lower() for m in (".get(", ".post(", ".put(", ".delete(", ".route(", "api_route"))
                    for d in dec_names
                )
                if is_route or low.startswith(("handle_", "api_", "endpoint_", "do_get", "do_post")):
                    nodes.append(
                        AttackSurfaceNode(
                            node_id=new_id("asg"),
                            kind="api_endpoint",
                            name=node.name,
                            location=CodeLocation(
                                file_path=rel_path,
                                line_start=node.lineno,
                                line_end=getattr(node, "end_lineno", node.lineno),
                                symbol=node.name,
                                snippet=snip(node.lineno),
                                language="python",
                            ),
                            domains=[SecurityDomain.API_SECURITY, SecurityDomain.NETWORK],
                            exposed_externally=True,
                            trust_zone="api_edge",
                            risk_exposure=7.5,
                        )
                    )
                elif any(k in low for k in ("run_shell", "exec_cmd", "spawn", "execute_tool", "invoke_tool")):
                    nodes.append(
                        AttackSurfaceNode(
                            node_id=new_id("asg"),
                            kind="tool",
                            name=node.name,
                            location=CodeLocation(
                                file_path=rel_path,
                                line_start=node.lineno,
                                line_end=getattr(node, "end_lineno", node.lineno),
                                symbol=node.name,
                                snippet=snip(node.lineno),
                                language="python",
                            ),
                            domains=[SecurityDomain.TOOL_EXECUTION, SecurityDomain.PROCESS_MANAGEMENT],
                            exposed_externally=False,
                            trust_zone="execution_plane",
                            risk_exposure=8.5,
                        )
                    )
                elif any(k in low for k in ("fetch_url", "http_get", "scrape", "download", "web_fetch")):
                    nodes.append(
                        AttackSurfaceNode(
                            node_id=new_id("asg"),
                            kind="network_egress",
                            name=node.name,
                            location=CodeLocation(
                                file_path=rel_path,
                                line_start=node.lineno,
                                line_end=getattr(node, "end_lineno", node.lineno),
                                symbol=node.name,
                                snippet=snip(node.lineno),
                                language="python",
                            ),
                            domains=[SecurityDomain.NETWORK, SecurityDomain.PROMPT_INJECTION],
                            exposed_externally=True,
                            trust_zone="egress_edge",
                            risk_exposure=7.8,
                        )
                    )
                elif any(k in low for k in ("read_file", "write_file", "extract_archive", "load_file")):
                    nodes.append(
                        AttackSurfaceNode(
                            node_id=new_id("asg"),
                            kind="filesystem_handler",
                            name=node.name,
                            location=CodeLocation(
                                file_path=rel_path,
                                line_start=node.lineno,
                                line_end=getattr(node, "end_lineno", node.lineno),
                                symbol=node.name,
                                snippet=snip(node.lineno),
                                language="python",
                            ),
                            domains=[SecurityDomain.FILESYSTEM],
                            exposed_externally=False,
                            trust_zone="storage_plane",
                            risk_exposure=7.0,
                        )
                    )
        return nodes, perms

    def _analyze_rust(self, rel_path: str, content: str) -> List[AttackSurfaceNode]:
        nodes: List[AttackSurfaceNode] = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            if re.search(r'\bextern\s+"C"\s+fn\s+([A-Za-z0-9_]+)', stripped):
                m = re.search(r'\bextern\s+"C"\s+fn\s+([A-Za-z0-9_]+)', stripped)
                fn_name = m.group(1) if m else "ffi_fn"
                nodes.append(
                    AttackSurfaceNode(
                        node_id=new_id("asg"),
                        kind="rust_ffi",
                        name=fn_name,
                        location=CodeLocation(rel_path, idx, idx, fn_name, stripped[:140], "rust"),
                        domains=[SecurityDomain.RUST_CORE, SecurityDomain.PROCESS_MANAGEMENT],
                        exposed_externally=True,
                        trust_zone="rust_core_ffi",
                        risk_exposure=9.0,
                    )
                )
            elif re.search(r"\bunsafe\s+(?:fn|impl)\b", stripped):
                nodes.append(
                    AttackSurfaceNode(
                        node_id=new_id("asg"),
                        kind="rust_unsafe",
                        name=stripped[:64],
                        location=CodeLocation(rel_path, idx, idx, None, stripped[:140], "rust"),
                        domains=[SecurityDomain.RUST_CORE],
                        trust_zone="rust_core",
                        risk_exposure=8.2,
                    )
                )
        if Path(rel_path).name == "build.rs":
            nodes.append(
                AttackSurfaceNode(
                    node_id=new_id("asg"),
                    kind="build_script",
                    name="build.rs",
                    location=CodeLocation(rel_path, 1, len(lines), "main", "Cargo build script", "rust"),
                    domains=[SecurityDomain.SUPPLY_CHAIN, SecurityDomain.RUST_CORE],
                    trust_zone="build_time",
                    risk_exposure=7.5,
                )
            )
        return nodes

    def _analyze_js_ts(self, rel_path: str, content: str, lang: str) -> List[AttackSurfaceNode]:
        nodes: List[AttackSurfaceNode] = []
        for idx, line in enumerate(content.splitlines(), start=1):
            if re.search(r"\b(?:app|router)\.(?:get|post|put|delete|use)\s*\(", line):
                nodes.append(
                    AttackSurfaceNode(
                        node_id=new_id("asg"),
                        kind="api_endpoint",
                        name=line.strip()[:60],
                        location=CodeLocation(rel_path, idx, idx, None, line.strip()[:140], lang),
                        domains=[SecurityDomain.API_SECURITY],
                        exposed_externally=True,
                        trust_zone="api_edge",
                        risk_exposure=7.2,
                    )
                )
            elif re.search(r"\b(?:child_process|execSync|spawn)\b", line):
                nodes.append(
                    AttackSurfaceNode(
                        node_id=new_id("asg"),
                        kind="subprocess_exec",
                        name=line.strip()[:60],
                        location=CodeLocation(rel_path, idx, idx, None, line.strip()[:140], lang),
                        domains=[SecurityDomain.PROCESS_MANAGEMENT, SecurityDomain.TOOL_EXECUTION],
                        trust_zone="execution_plane",
                        risk_exposure=8.0,
                    )
                )
        return nodes

    def _analyze_dependency_manifest(
        self, rel_path: str, fname: str, content: str
    ) -> Tuple[List[AttackSurfaceNode], int]:
        count = 0
        if fname == "package.json":
            try:
                data = json.loads(content)
                count = len(data.get("dependencies", {})) + len(data.get("devDependencies", {}))
            except json.JSONDecodeError:
                count = 0
        elif fname == "requirements.txt":
            count = sum(1 for ln in content.splitlines() if ln.strip() and not ln.strip().startswith("#"))
        elif fname == "Cargo.toml":
            in_deps = False
            for ln in content.splitlines():
                s = ln.strip()
                if s.startswith("["):
                    in_deps = "dependencies" in s
                elif in_deps and "=" in s and not s.startswith("#"):
                    count += 1
        elif fname == "pyproject.toml":
            count = len(re.findall(r'"[a-zA-Z0-9_\-]+[<>=!~]', content))

        node = AttackSurfaceNode(
            node_id=new_id("asg"),
            kind="dependency_manifest",
            name=fname,
            location=CodeLocation(rel_path, 1, len(content.splitlines()), fname, f"{count} dependencies", "manifest"),
            domains=[SecurityDomain.SUPPLY_CHAIN],
            trust_zone="supply_chain",
            risk_exposure=min(9.0, 4.0 + count * 0.25),
            metadata={"dependency_count": count},
        )
        return [node], count

    def _analyze_skill_manifest(
        self, rel_path: str, content: str
    ) -> Tuple[List[AttackSurfaceNode], Dict[str, List[str]]]:
        nodes: List[AttackSurfaceNode] = []
        perms: Dict[str, List[str]] = {}
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return nodes, perms

        skill_name = str(data.get("name", Path(rel_path).stem))
        raw_perms = [str(p) for p in data.get("permissions", [])]
        perms[f"skill:{skill_name}"] = raw_perms
        nodes.append(
            AttackSurfaceNode(
                node_id=new_id("asg"),
                kind="skill",
                name=skill_name,
                location=CodeLocation(rel_path, 1, len(content.splitlines()), skill_name, content[:140], "json"),
                domains=[SecurityDomain.SUPPLY_CHAIN, SecurityDomain.TOOL_EXECUTION, SecurityDomain.AGENT_ISOLATION],
                capabilities=raw_perms,
                exposed_externally=bool(data.get("external_triggers")),
                trust_zone="skill_plane",
                risk_exposure=9.2 if "*" in raw_perms else 6.5,
                metadata={"signed": bool(data.get("signature")), "version": data.get("version", "unknown")},
            )
        )
        return nodes, perms

    @staticmethod
    def _extract_class_capabilities(cls_node: ast.ClassDef) -> List[str]:
        caps: List[str] = []
        for stmt in cls_node.body:
            if isinstance(stmt, ast.Assign):
                for tgt in stmt.targets:
                    if isinstance(tgt, ast.Name) and any(
                        k in tgt.id.lower() for k in ("perm", "cap", "tool", "allow")
                    ):
                        if isinstance(stmt.value, (ast.List, ast.Tuple, ast.Set)):
                            for el in stmt.value.elts:
                                if isinstance(el, ast.Constant) and isinstance(el.value, str):
                                    caps.append(el.value)
        return caps

    @staticmethod
    def _score_exposure(kind: str, exposed: bool, caps: List[str]) -> float:
        base = {
            "agent": 7.5,
            "tool": 8.0,
            "skill": 8.2,
            "api_endpoint": 8.0,
            "memory_store": 7.2,
            "subprocess_exec": 8.8,
            "rust_ffi": 9.0,
        }.get(kind, 5.0)
        if exposed:
            base += 1.0
        if "*" in caps or "/**" in caps:
            base += 1.2
        return min(10.0, round(base, 2))

    @staticmethod
    def _infer_architectural_edges(nodes: List[AttackSurfaceNode]) -> List[Tuple[str, str, str]]:
        edges: List[Tuple[str, str, str]] = []
        agents = [n for n in nodes if n.kind == "agent"]
        tools = [n for n in nodes if n.kind in ("tool", "subprocess_exec", "filesystem_handler", "network_egress")]
        memories = [n for n in nodes if n.kind == "memory_store"]
        apis = [n for n in nodes if n.kind == "api_endpoint"]
        ffis = [n for n in nodes if n.kind == "rust_ffi"]

        for api in apis[:10]:
            for ag in agents[:10]:
                edges.append((api.node_id, ag.node_id, "dispatches_to"))
        for ag in agents[:10]:
            for tl in tools[:15]:
                edges.append((ag.node_id, tl.node_id, "invokes"))
            for mem in memories[:10]:
                edges.append((ag.node_id, mem.node_id, "reads_writes"))
        for tl in tools[:10]:
            for ffi in ffis[:10]:
                edges.append((tl.node_id, ffi.node_id, "calls_ffi"))
        return edges

    @staticmethod
    def _build_trust_boundaries(nodes: List[AttackSurfaceNode]) -> List[TrustBoundary]:
        boundaries: List[TrustBoundary] = []
        by_zone: Dict[str, List[str]] = {}
        for n in nodes:
            by_zone.setdefault(n.trust_zone, []).append(n.node_id)

        specs = [
            ("TB-EXT-API", "External Untrusted -> API Edge", "external_untrusted", "api_edge"),
            ("TB-WEB-AGENT", "External Content -> Agent Plane", "egress_edge", "agent_plane"),
            ("TB-AGENT-EXEC", "Agent Plane -> Tool & Process Execution", "agent_plane", "execution_plane"),
            ("TB-SKILL-CORE", "Third-Party Skills -> Core Runtime", "skill_plane", "agent_plane"),
            ("TB-AGENT-MEM", "Agent Plane -> Persistent Memory / RAG", "agent_plane", "memory_plane"),
            ("TB-PY-RUST-FFI", "Python Orchestrator -> Rust Core FFI", "execution_plane", "rust_core_ffi"),
        ]
        for bid, name, src_z, dst_z in specs:
            crossing = by_zone.get(dst_z, [])[:10]
            if crossing or src_z == "external_untrusted":
                boundaries.append(
                    TrustBoundary(
                        boundary_id=bid,
                        name=name,
                        source_zone=src_z,
                        target_zone=dst_z,
                        crossing_nodes=crossing,
                    )
                )
        return boundaries
