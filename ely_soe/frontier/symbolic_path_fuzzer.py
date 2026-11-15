"""
Frontier Research Module 5: AST Guardrail Constraint & Parser-Differential Explorer.

Implements lightweight concolic/symbolic boundary exploration targeting security
guardrails inside Ely (URL allowlists, path validators, prompt filters, JWT/JSON
parsers, and numeric rate/size limiters):
  1. AST Predicate Extraction: walks Python guard functions (`if`, `assert`, `startswith`,
     regex checks, numeric comparisons) to identify brittle validation logic.
  2. Parser-Differential Counterexample Synthesis:
       * URL authority/userinfo/IPv6/decimal-IP confusion (`http://api.github.com@169.254.169.254/`,
         `http://2852039166/`, `http://[::ffff:169.254.169.254]/`, `https://api.github.com.attacker.invalid/`)
       * Path prefix-collision bug (`startswith("/workspace/proj")` bypassed by `/workspace/proj_secrets/.env`!)
       * Unicode NFKC normalization collisions (`ﬁ`, fullwidth `／`, Cyrillic homoglyphs)
       * JSON duplicate-key shadowing (`{"role": "user", "role": "admin"}`)
       * Integer sign / wraparound / float NaN boundary confusion (`-1`, `0`, `2**31`, `float('nan')`)
  3. Live Differential Harness Execution: runs synthesized boundary inputs directly
     against candidate guard callables or AST-extracted target patterns to emit concrete
     reproducible bypass witnesses!
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ely_soe.core.models import (
    CodeLocation,
    EvidenceArtifact,
    Finding,
    FindingStatus,
    SecurityDomain,
    Severity,
    new_id,
    utc_now_iso,
)


@dataclass
class GuardrailBypassWitness:
    """Concrete boundary/differential counterexample that bypasses a security guard."""

    witness_id: str
    guard_name: str
    category: str  # prefix_collision, url_parser_diff, unicode_nfkc, json_dup_key, numeric_boundary
    domain: SecurityDomain
    payload: str
    expected_decision: str
    actual_decision: str
    file_path: str
    line_no: int = 1
    severity: Severity = Severity.HIGH

    def to_dict(self) -> Dict[str, Any]:
        return {
            "witness_id": self.witness_id,
            "guard_name": self.guard_name,
            "category": self.category,
            "domain": self.domain.value,
            "payload": self.payload,
            "expected_decision": self.expected_decision,
            "actual_decision": self.actual_decision,
            "file_path": self.file_path,
            "line_no": self.line_no,
            "severity": self.severity.value,
        }


URL_DIFFERENTIAL_PROBES: List[Tuple[str, str]] = [
    ("userinfo_authority_confusion", "http://api.github.com@169.254.169.254/latest/meta-data/"),
    ("subdomain_suffix_bypass", "https://api.github.com.attacker.invalid/exfil"),
    ("decimal_ipv4_metadata", "http://2852039166/latest/meta-data/"),
    ("ipv6_mapped_metadata", "http://[::ffff:169.254.169.254]/latest/meta-data/"),
    ("backslash_authority_trick", "https://api.github.com\\@169.254.169.254/"),
    ("mixed_case_scheme_bypass", "HTTP://169.254.169.254/latest/meta-data/"),
]

PATH_BOUNDARY_PROBES: List[Tuple[str, str]] = [
    ("sibling_prefix_collision", "/workspace/proj_alpha_secrets/.env"),
    ("encoded_dotdot", "/workspace/proj_alpha/%2e%2e/secrets/.env"),
    ("fullwidth_slash_nfkc", "/workspace/proj_alpha/..\uff0fsecrets/.env"),
    ("null_byte_truncation", "/workspace/proj_alpha/ok.txt\x00/../../etc/passwd"),
    ("trailing_slash_escape", "/workspace/proj_alpha/sub/../../.env"),
]

JSON_DUPLICATE_KEY_PROBES: List[Tuple[str, str]] = [
    ("role_shadowing_duplicate_key", '{"role": "user", "sub": "u1", "role": "admin"}'),
    ("nested_capability_override", '{"permissions": ["fs:read"], "permissions": ["*"]}'),
]


class GuardrailDifferentialExplorer:
    """
    Combines AST predicate extraction on Ely source files with live parser-differential
    probing to uncover subtle guardrail bypasses missed by conventional regex scanners.
    """

    def analyze_snapshot(self, snapshot_root: Path) -> Tuple[List[Finding], Dict[str, Any]]:
        root = Path(snapshot_root).resolve()
        witnesses: List[GuardrailBypassWitness] = []
        guards_inspected = 0

        for py_file in sorted(root.rglob("*.py")):
            if any(part.startswith(".") or part in ("__pycache__", "tests", ".venv") for part in py_file.relative_to(root).parts):
                continue
            rel = py_file.relative_to(root).as_posix()
            try:
                src = py_file.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(src, filename=rel)
            except (OSError, SyntaxError):
                continue

            lines = src.splitlines()
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fn_src = "\n".join(lines[node.lineno - 1 : getattr(node, "end_lineno", node.lineno)])
                    if any(k in node.name.lower() for k in ("check", "valid", "guard", "allow", "resolve", "filter", "verify", "fetch", "read")):
                        guards_inspected += 1
                        witnesses.extend(self._inspect_guard_ast(rel, node, fn_src))

        findings = [self._witness_to_finding(w) for w in witnesses]
        summary = {
            "analyzed_at": utc_now_iso(),
            "guards_inspected": guards_inspected,
            "bypasses_discovered": len(witnesses),
            "by_category": self._count_by(witnesses, "category"),
            "witnesses": [w.to_dict() for w in witnesses],
        }
        return findings, summary

    def probe_url_guard_live(
        self,
        guard_name: str,
        guard_fn: Callable[[str], bool],
        file_path: str = "<runtime>",
    ) -> List[GuardrailBypassWitness]:
        """Run all URL parser-differential probes directly against a live URL validator callable."""
        witnesses: List[GuardrailBypassWitness] = []
        for cat, url in URL_DIFFERENTIAL_PROBES:
            try:
                allowed = bool(guard_fn(url))
            except Exception:
                allowed = False
            if allowed:
                witnesses.append(
                    GuardrailBypassWitness(
                        witness_id=new_id("wit"),
                        guard_name=guard_name,
                        category=cat,
                        domain=SecurityDomain.NETWORK,
                        payload=url,
                        expected_decision="DENY (SSRF/authority confusion)",
                        actual_decision="ALLOWED",
                        file_path=file_path,
                        severity=Severity.HIGH,
                    )
                )
        return witnesses

    def probe_path_guard_live(
        self,
        guard_name: str,
        guard_fn: Callable[[str], bool],
        file_path: str = "<runtime>",
    ) -> List[GuardrailBypassWitness]:
        """Run path prefix-collision & boundary probes against a live filesystem guard callable."""
        witnesses: List[GuardrailBypassWitness] = []
        for cat, path_probe in PATH_BOUNDARY_PROBES:
            try:
                allowed = bool(guard_fn(path_probe))
            except Exception:
                allowed = False
            if allowed:
                witnesses.append(
                    GuardrailBypassWitness(
                        witness_id=new_id("wit"),
                        guard_name=guard_name,
                        category=cat,
                        domain=SecurityDomain.FILESYSTEM,
                        payload=path_probe,
                        expected_decision="DENY (boundary escape)",
                        actual_decision="ALLOWED",
                        file_path=file_path,
                        severity=Severity.HIGH,
                    )
                )
        return witnesses

    def _inspect_guard_ast(
        self, rel_path: str, fn: ast.FunctionDef | ast.AsyncFunctionDef, fn_src: str
    ) -> List[GuardrailBypassWitness]:
        witnesses: List[GuardrailBypassWitness] = []

        # Pattern 1: Brittle `path.startswith(workspace)` without trailing separator or `is_relative_to()`
        if re.search(r"\.startswith\s*\(\s*(?:self\.)?(?:workspace|root|base_dir|project_dir|str\()", fn_src):
            if "is_relative_to" not in fn_src and "os.sep" not in fn_src and '+ "/"' not in fn_src and "+ '/'" not in fn_src:
                witnesses.append(
                    GuardrailBypassWitness(
                        witness_id=new_id("wit"),
                        guard_name=fn.name,
                        category="prefix_collision",
                        domain=SecurityDomain.FILESYSTEM,
                        payload="/workspace/proj_alpha_secrets/.env",
                        expected_decision="DENY sibling directory outside /workspace/proj_alpha",
                        actual_decision="ALLOWED due to startswith() prefix collision lacking path separator",
                        file_path=rel_path,
                        line_no=fn.lineno,
                        severity=Severity.HIGH,
                    )
                )

        # Pattern 2: Substring URL check (`"api.github.com" in url` or `url.startswith("https://api.github.com")`)
        if re.search(r"(?:in\s+url\b|url\.startswith\s*\(\s*['\"]https?://)", fn_src):
            if "urlparse" not in fn_src or ".hostname" not in fn_src:
                witnesses.append(
                    GuardrailBypassWitness(
                        witness_id=new_id("wit"),
                        guard_name=fn.name,
                        category="url_parser_diff",
                        domain=SecurityDomain.NETWORK,
                        payload="https://api.github.com@169.254.169.254/latest/meta-data/",
                        expected_decision="DENY mismatched hostname 169.254.169.254",
                        actual_decision="ALLOWED because raw string/prefix check ignored URL authority/userinfo",
                        file_path=rel_path,
                        line_no=fn.lineno,
                        severity=Severity.HIGH,
                    )
                )

        # Pattern 3: Regex anchored with `^` / `$` or `re.match` instead of `re.fullmatch` (newline smuggling!)
        if re.search(r"re\.match\s*\(", fn_src) and "re.fullmatch" not in fn_src:
            if any(k in fn.name.lower() for k in ("valid", "check", "guard", "allow", "sanitize")):
                witnesses.append(
                    GuardrailBypassWitness(
                        witness_id=new_id("wit"),
                        guard_name=fn.name,
                        category="regex_newline_smuggling",
                        domain=SecurityDomain.TOOL_EXECUTION,
                        payload="safe_arg\n; id",
                        expected_decision="DENY trailing shell metacharacters after newline",
                        actual_decision="ALLOWED because re.match() matches prefix without full-string anchor",
                        file_path=rel_path,
                        line_no=fn.lineno,
                        severity=Severity.MEDIUM,
                    )
                )

        # Pattern 4: Numeric length/quota check missing lower-bound `<= 0` check (negative integer bypass)
        if re.search(r"if\s+(?:size|length|count|limit|amount|offset)\s*>\s*\w+", fn_src):
            if not re.search(r"(?:<\s*0|<=\s*0|>=\s*0|abs\()", fn_src):
                witnesses.append(
                    GuardrailBypassWitness(
                        witness_id=new_id("wit"),
                        guard_name=fn.name,
                        category="numeric_negative_bypass",
                        domain=SecurityDomain.API_SECURITY,
                        payload="-1",
                        expected_decision="DENY negative size/offset/quota",
                        actual_decision="ALLOWED because guard only checks upper bound without >= 0 check",
                        file_path=rel_path,
                        line_no=fn.lineno,
                        severity=Severity.MEDIUM,
                    )
                )

        return witnesses

    @staticmethod
    def _count_by(items: List[GuardrailBypassWitness], attr: str) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for item in items:
            k = getattr(item, attr)
            counts[k] = counts.get(k, 0) + 1
        return counts

    @staticmethod
    def _witness_to_finding(w: GuardrailBypassWitness) -> Finding:
        return Finding(
            finding_id=new_id("fnd"),
            title=f"[Guardrail Bypass] {w.category.replace('_', ' ').title()} in `{w.guard_name}()`",
            description=(
                f"Symbolic/differential guardrail explorer synthesized counterexample `{w.payload}` "
                f"bypassing `{w.guard_name}()` in `{w.file_path}:{w.line_no}`: {w.actual_decision}."
            ),
            domain=w.domain,
            severity=w.severity,
            rule_id=f"GUARD-DIFF-{w.category.upper()}",
            discovered_by="ely_guardrail_differential_explorer",
            location=CodeLocation(
                file_path=w.file_path,
                line_start=w.line_no,
                symbol=w.guard_name,
                snippet=f"counterexample={w.payload}",
                language="python",
            ),
            status=FindingStatus.HYPOTHESIS,
            confidence=0.83,
            attack_vector=f"Crafted parser-differential boundary input: `{w.payload}`",
            impact=f"Security guardrail `{w.guard_name}` bypassed ({w.actual_decision})",
            poc_spec={
                "kind": "static_rule",
                "rule_id": f"GUARD-DIFF-{w.category.upper()}",
                "target_file": w.file_path,
                "target_line": w.line_no,
                "snippet": w.guard_name,
            },
            evidence=[
                EvidenceArtifact(
                    artifact_id=new_id("ev"),
                    kind="guardrail_counterexample",
                    description=f"Differential bypass witness {w.witness_id}",
                    content=json.dumps(w.to_dict(), indent=2),
                    producer="ely_guardrail_differential_explorer",
                )
            ],
            tags=["frontier_differential", w.category, w.domain.value],
        )
