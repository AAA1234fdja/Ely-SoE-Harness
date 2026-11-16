r"""
Adversarial Deobfuscation, Partial AST Evaluation & Canonical Normalization Engine.

Directly resolves the #1 empirical blind-spot identified by Harness² Self-Adversarial
Stress Testing (where regex-only detectors dropped from 75% -> 25% under evasion!):
  1. **Multi-Layer Payload & String Deobfuscator**:
       - Recursive Base64 (`base64.b64decode("...")`, `atob("...")`, `echo ... | base64 -d`)
       - Recursive Hex / Octal / `\xNN` / `\uNNNN` / `bytes.fromhex("...")` decoding
       - URL percent-encoding (`%27`, `%3C`, double-encoding `%2527`)
       - Unicode NFKC homoglyph normalization & zero-width stealth character stripping
         (`\u200b`, `\u200c`, `\u200d`, `\ufeff`, Cyrillic/Greek confusable folding!)
       - Shell/SQL inline-comment stripping (`UN/**/ION SE/**/LECT`, `c'a't /e't'c/pa's'swd`,
         `${IFS}` whitespace evasion, `$'\x63\x61\x74'` ANSI-C quoting)
       - String reversal (`"metsys"[::-1]`, `"lave"[::-1]`).
  2. **Python AST Partial Evaluator & Dynamic-Sink Resolver**:
       - Constant-folds `'sys' + 'tem'`, `"".join(["ev", "al"])`, `"".join(map(chr, [115, ...]))`,
         `chr(101)+chr(118)+chr(97)+chr(108)`, `f"{'sub'}process"`, and slice reversals `[::-1]`!
       - Tracks local variable bindings & function aliases (`fn = eval; fn(user_input)`,
         `mod = __import__('os'); getattr(mod, 'sys'+'tem')(cmd)`, `importlib.import_module('subprocess')`)!
       - Resolves `getattr(obj, folded_attr)` and `__builtins__[folded_name]` back to canonical
         dangerous sink identities (`os.system`, `subprocess.Popen`, `eval`, `exec`, `pickle.loads`,
         `yaml.load`, `sqlite3.execute`, `urllib.request.urlopen`, `jinja2.Template`)!
  3. **JavaScript & Shell Deobfuscation Normalizer**:
       - Unwraps `window['ev'+'al']`, `Function(atob(...))`, `String.fromCharCode(...)`,
         backtick template concatenation, and Bash `${IFS}` / `base64 -d | sh` chains.
"""

from __future__ import annotations

import ast
import base64
import binascii
import codecs
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import unquote

from ely_soe.core.models import Severity, utc_now_iso
from ely_soe.cyber.models import (
    CVSSv4Metrics,
    CyberDomain,
    CyberVulnerability,
    MitreTactic,
    MitreTechniqueRef,
    VerificationMethod,
    make_cyber_vuln,
)


ZERO_WIDTH_CHARS = ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad", "\u180e")

# Common Cyrillic / Greek / Fullwidth homoglyphs used to evade ASCII security signatures
HOMOGLYPH_MAP: Dict[str, str] = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0455": "s", "\u0458": "j",
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
    "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
    "\u0425": "X", "\u03b1": "a", "\u03bf": "o", "\u03c1": "p", "\u03b5": "e",
    "\u03b9": "i", "\u03ba": "k", "\u03bd": "v", "\u03c7": "x",
}

CANONICAL_DANGEROUS_SINKS: Dict[str, Tuple[str, str, Severity, CyberDomain, str]] = {
    "os.system": ("CYB-DEOBF-CMD-INJ", "Obfuscated OS Command Execution via `os.system`", Severity.CRITICAL, CyberDomain.WEB_INJECTION, "CWE-78"),
    "os.popen": ("CYB-DEOBF-CMD-INJ", "Obfuscated OS Command Execution via `os.popen`", Severity.CRITICAL, CyberDomain.WEB_INJECTION, "CWE-78"),
    "subprocess.Popen": ("CYB-DEOBF-CMD-INJ", "Obfuscated Subprocess Execution (`subprocess.Popen`)", Severity.CRITICAL, CyberDomain.WEB_INJECTION, "CWE-78"),
    "subprocess.run": ("CYB-DEOBF-CMD-INJ", "Obfuscated Subprocess Execution (`subprocess.run`)", Severity.HIGH, CyberDomain.WEB_INJECTION, "CWE-78"),
    "subprocess.call": ("CYB-DEOBF-CMD-INJ", "Obfuscated Subprocess Execution (`subprocess.call`)", Severity.HIGH, CyberDomain.WEB_INJECTION, "CWE-78"),
    "subprocess.check_output": ("CYB-DEOBF-CMD-INJ", "Obfuscated Subprocess Execution (`subprocess.check_output`)", Severity.HIGH, CyberDomain.WEB_INJECTION, "CWE-78"),
    "builtins.eval": ("CYB-DEOBF-CODE-EXEC", "Obfuscated Dynamic Code Execution via `eval()`", Severity.CRITICAL, CyberDomain.WEB_INJECTION, "CWE-94"),
    "builtins.exec": ("CYB-DEOBF-CODE-EXEC", "Obfuscated Dynamic Code Execution via `exec()`", Severity.CRITICAL, CyberDomain.WEB_INJECTION, "CWE-94"),
    "builtins.compile": ("CYB-DEOBF-CODE-EXEC", "Obfuscated Dynamic Code Compilation via `compile()`", Severity.HIGH, CyberDomain.WEB_INJECTION, "CWE-94"),
    "eval": ("CYB-DEOBF-CODE-EXEC", "Obfuscated Dynamic Code Execution via `eval()`", Severity.CRITICAL, CyberDomain.WEB_INJECTION, "CWE-94"),
    "exec": ("CYB-DEOBF-CODE-EXEC", "Obfuscated Dynamic Code Execution via `exec()`", Severity.CRITICAL, CyberDomain.WEB_INJECTION, "CWE-94"),
    "pickle.loads": ("CYB-DEOBF-DESER-RCE", "Obfuscated Unsafe Deserialization via `pickle.loads`", Severity.CRITICAL, CyberDomain.WEB_SSRF_XXE_SSTI_DESER, "CWE-502"),
    "pickle.load": ("CYB-DEOBF-DESER-RCE", "Obfuscated Unsafe Deserialization via `pickle.load`", Severity.CRITICAL, CyberDomain.WEB_SSRF_XXE_SSTI_DESER, "CWE-502"),
    "marshal.loads": ("CYB-DEOBF-DESER-RCE", "Obfuscated Unsafe Deserialization via `marshal.loads`", Severity.CRITICAL, CyberDomain.WEB_SSRF_XXE_SSTI_DESER, "CWE-502"),
    "yaml.load": ("CYB-DEOBF-YAML-RCE", "Obfuscated Unsafe YAML Deserialization via `yaml.load`", Severity.CRITICAL, CyberDomain.WEB_SSRF_XXE_SSTI_DESER, "CWE-502"),
    "yaml.unsafe_load": ("CYB-DEOBF-YAML-RCE", "Obfuscated Unsafe YAML Deserialization via `yaml.unsafe_load`", Severity.CRITICAL, CyberDomain.WEB_SSRF_XXE_SSTI_DESER, "CWE-502"),
    "urllib.request.urlopen": ("CYB-DEOBF-SSRF", "Obfuscated Outbound HTTP Fetch / SSRF Sink (`urlopen`)", Severity.HIGH, CyberDomain.WEB_SSRF_XXE_SSTI_DESER, "CWE-918"),
    "requests.get": ("CYB-DEOBF-SSRF", "Obfuscated Outbound HTTP Fetch / SSRF Sink (`requests.get`)", Severity.HIGH, CyberDomain.WEB_SSRF_XXE_SSTI_DESER, "CWE-918"),
    "requests.post": ("CYB-DEOBF-SSRF", "Obfuscated Outbound HTTP Fetch / SSRF Sink (`requests.post`)", Severity.HIGH, CyberDomain.WEB_SSRF_XXE_SSTI_DESER, "CWE-918"),
    "jinja2.Template": ("CYB-DEOBF-SSTI", "Obfuscated Server-Side Template Injection (`jinja2.Template`)", Severity.CRITICAL, CyberDomain.WEB_SSRF_XXE_SSTI_DESER, "CWE-1336"),
    "cursor.execute": ("CYB-DEOBF-SQLI", "Obfuscated Dynamic SQL Execution (`cursor.execute`)", Severity.CRITICAL, CyberDomain.WEB_INJECTION, "CWE-89"),
    "sqlite3.execute": ("CYB-DEOBF-SQLI", "Obfuscated Dynamic SQL Execution (`sqlite3.execute`)", Severity.CRITICAL, CyberDomain.WEB_INJECTION, "CWE-89"),
    "split.secret_literal": ("CYB-DEOBF-SPLIT-SECRET", "Obfuscated Split/Concatenated Hardcoded Secret Credential", Severity.CRITICAL, CyberDomain.CLOUD_IAM, "CWE-798"),
}

_SPLIT_SECRET_PAT_RE = re.compile(
    r"(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk_live_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z\-_]{35}|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
_SECRET_VAR_NAME_RE = re.compile(r"(?i)(?:aws_?key|aws_?secret|api_?key|secret_?key|private_?key|auth_?token|access_?token|signing_?key|client_?secret)")

SQL_KEYWORDS_RE = re.compile(
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|UNION|DROP|ALTER|CREATE|EXEC|WHERE)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class DeobfuscatedFinding:
    canonical_sink: str
    obfuscation_techniques: Tuple[str, ...]
    line_start: int
    line_end: int
    resolved_expression: str
    raw_snippet: str
    severity: Severity
    cwe_id: str
    rule_id: str
    title: str
    cyber_domain: CyberDomain


@dataclass
class NormalizationReport:
    original_length: int
    normalized_text: str
    layers_unwrapped: List[str] = field(default_factory=list)
    decoded_blobs: List[Dict[str, str]] = field(default_factory=list)
    homoglyphs_replaced: int = 0
    zero_width_stripped: int = 0
    raw_text: str = ""

    @property
    def obfuscation_layers_detected(self) -> int:
        return len(self.layers_unwrapped)

    @property
    def transforms_applied(self) -> List[str]:
        return list(self.layers_unwrapped)

    @property
    def normalized_variants(self) -> List[str]:
        out: List[str] = []
        if self.raw_text:
            out.append(self.raw_text)
        if self.normalized_text and self.normalized_text not in out:
            out.append(self.normalized_text)
        for b in self.decoded_blobs:
            d = b.get("decoded", "")
            if d and d not in out:
                out.append(d)
        return out or [self.normalized_text]


class MultiLayerPayloadNormalizer:
    """Normalizes obfuscated HTTP, SQL, Shell, JS, and Python strings across multiple encoding layers."""

    _RAW_B64_TOKEN_RE = re.compile(r"(?:^|[^A-Za-z0-9+/=])([A-Za-z0-9+/]{24,}={0,2})(?=$|[^A-Za-z0-9+/=])")
    _B64_CALL_RE = re.compile(
        r"""(?:b64decode|urlsafe_b64decode|atob|fromBase64)\s*\(\s*[rb]?['"]([A-Za-z0-9+/=_-]{8,512})['"]\s*\)""",
        re.IGNORECASE,
    )
    _HEX_CALL_RE = re.compile(
        r"""(?:bytes\.fromhex|bytearray\.fromhex|unhexlify)\s*\(\s*['"]([0-9a-fA-F\s]{4,512})['"]\s*\)""",
        re.IGNORECASE,
    )
    _CHR_JS_RE = re.compile(
        r"""String\.fromCharCode\s*\(\s*([0-9,\s]{3,400})\s*\)""",
        re.IGNORECASE,
    )
    _SHELL_B64_PIPE_RE = re.compile(
        r"""echo\s+['"]?([A-Za-z0-9+/=]{8,512})['"]?\s*\|\s*base64\s+(?:-d|--decode)""",
        re.IGNORECASE,
    )
    _SQL_INLINE_COMMENT_RE = re.compile(r"/\*[^*]*\*+(?:[^/*][^*]*\*+)*/")
    _SHELL_QUOTE_SPLIT_RE = re.compile(r"""(?<=[A-Za-z0-9_/.-])(?:''|""|\\(?=[a-zA-Z]))(?=[A-Za-z0-9_/.-])""")
    _HEX_ESCAPE_RE = re.compile(r"(?:\\x([0-9a-fA-F]{2}))+")
    _UNI_ESCAPE_RE = re.compile(r"(?:\\u([0-9a-fA-F]{4}))+")
    _URL_ENC_RE = re.compile(r"%[0-9a-fA-F]{2}")
    _SHELL_IFS_RE = re.compile(r"\$\{IFS\}|\$IFS\b")

    def normalize(self, text: str, *, max_passes: int = 4) -> NormalizationReport:
        cur = text
        layers: List[str] = []
        decoded_blobs: List[Dict[str, str]] = []
        zw_count = 0
        homo_count = 0

        # Pass 0: strip zero-width stealth chars + fold homoglyphs + NFKC
        for ch in ZERO_WIDTH_CHARS:
            if ch in cur:
                zw_count += cur.count(ch)
                cur = cur.replace(ch, "")
        if zw_count:
            layers.append("zero_width_strip")

        rebuilt = []
        for ch in cur:
            repl = HOMOGLYPH_MAP.get(ch)
            if repl is not None:
                homo_count += 1
                rebuilt.append(repl)
            else:
                rebuilt.append(ch)
        cur = "".join(rebuilt)
        if homo_count:
            layers.append("homoglyph_fold")

        nfkc = unicodedata.normalize("NFKC", cur)
        if nfkc != cur:
            cur = nfkc
            layers.append("unicode_nfkc")

        # Multi-pass iterative unwrapping
        for _ in range(max_passes):
            prev = cur

            # 1. Decode inline base64 decode calls (Python / JS)
            def _repl_b64(m: re.Match[str]) -> str:
                raw_b64 = m.group(1)
                dec = self._safe_b64_decode(raw_b64)
                if dec is not None:
                    decoded_blobs.append({"encoding": "base64_call", "encoded": raw_b64[:80], "decoded": dec[:160]})
                    if "base64_call" not in layers:
                        layers.append("base64_call")
                    return repr(dec)
                return m.group(0)

            cur = self._B64_CALL_RE.sub(_repl_b64, cur)

            # 2. Decode shell `echo <b64> | base64 -d`
            def _repl_shell_b64(m: re.Match[str]) -> str:
                raw_b64 = m.group(1)
                dec = self._safe_b64_decode(raw_b64)
                if dec is not None:
                    decoded_blobs.append({"encoding": "shell_base64_pipe", "encoded": raw_b64[:80], "decoded": dec[:160]})
                    if "shell_base64_pipe" not in layers:
                        layers.append("shell_base64_pipe")
                    return dec
                return m.group(0)

            cur = self._SHELL_B64_PIPE_RE.sub(_repl_shell_b64, cur)

            # 3. Decode bytes.fromhex / unhexlify calls
            def _repl_hex(m: re.Match[str]) -> str:
                raw_h = re.sub(r"\s+", "", m.group(1))
                try:
                    dec = bytes.fromhex(raw_h).decode("utf-8", errors="ignore")
                    if dec and self._mostly_printable(dec):
                        decoded_blobs.append({"encoding": "hex_call", "encoded": raw_h[:80], "decoded": dec[:160]})
                        if "hex_call" not in layers:
                            layers.append("hex_call")
                        return repr(dec)
                except ValueError:
                    pass
                return m.group(0)

            cur = self._HEX_CALL_RE.sub(_repl_hex, cur)

            # 4. Decode JS String.fromCharCode(...)
            def _repl_js_chr(m: re.Match[str]) -> str:
                nums = [x.strip() for x in m.group(1).split(",") if x.strip().isdigit()]
                try:
                    dec = "".join(chr(int(n)) for n in nums if 0 <= int(n) <= 0x10FFFF)
                    if dec:
                        decoded_blobs.append({"encoding": "js_fromCharCode", "encoded": m.group(1)[:60], "decoded": dec[:160]})
                        if "js_fromCharCode" not in layers:
                            layers.append("js_fromCharCode")
                        return repr(dec)
                except ValueError:
                    pass
                return m.group(0)

            cur = self._CHR_JS_RE.sub(_repl_js_chr, cur)

            # 5. Decode \xNN and \uNNNN escape sequences inside strings
            def _repl_hex_esc(m: re.Match[str]) -> str:
                seq = m.group(0)
                try:
                    dec = bytes(int(h, 16) for h in re.findall(r"\\x([0-9a-fA-F]{2})", seq)).decode("utf-8", errors="ignore")
                    if dec and self._mostly_printable(dec):
                        if "hex_escape" not in layers:
                            layers.append("hex_escape")
                        return dec
                except ValueError:
                    pass
                return seq

            cur = self._HEX_ESCAPE_RE.sub(_repl_hex_esc, cur)

            def _repl_uni_esc(m: re.Match[str]) -> str:
                seq = m.group(0)
                try:
                    dec = "".join(chr(int(h, 16)) for h in re.findall(r"\\u([0-9a-fA-F]{4})", seq))
                    if dec and self._mostly_printable(dec):
                        if "unicode_escape" not in layers:
                            layers.append("unicode_escape")
                        return dec
                except ValueError:
                    pass
                return seq

            cur = self._UNI_ESCAPE_RE.sub(_repl_uni_esc, cur)

            # 6. URL percent decoding (handles double/triple encoding)
            if self._URL_ENC_RE.search(cur):
                unq = unquote(cur)
                if unq != cur:
                    cur = unq
                    if "url_decode" not in layers:
                        layers.append("url_decode")

            # 7. Shell `${IFS}` & quote-splitting (`c''at /e""tc/passwd`)
            if self._SHELL_IFS_RE.search(cur):
                cur = self._SHELL_IFS_RE.sub(" ", cur)
                if "shell_ifs" not in layers:
                    layers.append("shell_ifs")
            if self._SHELL_QUOTE_SPLIT_RE.search(cur):
                cur = self._SHELL_QUOTE_SPLIT_RE.sub("", cur)
                if "shell_quote_split" not in layers:
                    layers.append("shell_quote_split")

            # 8. SQL inline comment splitting (`UN/**/ION SE/**/LECT`)
            if "/*" in cur and "*/" in cur:
                stripped = self._SQL_INLINE_COMMENT_RE.sub("", cur)
                if stripped != cur and SQL_KEYWORDS_RE.search(stripped):
                    cur = stripped
                    if "sql_inline_comment_strip" not in layers:
                        layers.append("sql_inline_comment_strip")

            # 9. Standalone raw Base64 blob peeling (prompt/payload/secret stealth encoding)
            for bm in self._RAW_B64_TOKEN_RE.finditer(cur):
                tok = bm.group(1)
                if len(tok) % 4 != 0:
                    continue
                dec = self._safe_b64_decode(tok)
                if dec and len(dec) >= 12 and any(c in dec for c in (" ", "/", ":", "(", "=", "'", '"')):
                    if not any(b.get("decoded") == dec[:240] for b in decoded_blobs):
                        decoded_blobs.append({"encoding": "raw_base64_blob", "encoded": tok[:80], "decoded": dec[:240]})
                        if "raw_base64_blob" not in layers:
                            layers.append("raw_base64_blob")

            if cur == prev:
                break

        return NormalizationReport(
            original_length=len(text),
            normalized_text=cur,
            layers_unwrapped=layers,
            decoded_blobs=decoded_blobs,
            homoglyphs_replaced=homo_count,
            zero_width_stripped=zw_count,
            raw_text=text,
        )

    @staticmethod
    def _safe_b64_decode(s: str) -> Optional[str]:
        padded = s + ("=" * ((4 - len(s) % 4) % 4))
        for fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = fn(padded.encode("ascii"))
                dec = raw.decode("utf-8")
                if dec and MultiLayerPayloadNormalizer._mostly_printable(dec):
                    return dec
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
        return None

    @staticmethod
    def _mostly_printable(s: str) -> bool:
        if not s:
            return False
        printable = sum(1 for c in s if c.isprintable() or c in "\t\n\r")
        return (printable / len(s)) >= 0.85


class PythonASTDeobfuscationEngine:
    """
    Performs partial evaluation & symbol/alias resolution on Python AST to expose
    dynamically constructed or obfuscated dangerous security sinks.
    """

    def __init__(self) -> None:
        self.normalizer = MultiLayerPayloadNormalizer()

    def analyze_source(self, source: str, file_path: str = "<snippet>") -> Dict[str, Any]:
        norm = self.normalizer.normalize(source)
        lines = source.splitlines()
        findings: List[DeobfuscatedFinding] = []
        ast_parsed = False

        # Try parsing original source first (preserves exact line numbers), then normalized
        tree: Optional[ast.AST] = None
        for candidate_src in (source, norm.normalized_text):
            try:
                tree = ast.parse(candidate_src)
                ast_parsed = True
                break
            except SyntaxError:
                continue

        if tree is not None:
            findings.extend(self._walk_ast_scopes(tree, lines, norm.layers_unwrapped))

        # Also inspect JS/Shell/non-Python normalized patterns (e.g. window['ev'+'al'], base64|sh, SQLi)
        findings.extend(self._scan_normalized_text_patterns(source, norm, file_path))

        # Deduplicate by (canonical_sink, line_start)
        seen: Set[Tuple[str, int]] = set()
        unique_findings: List[DeobfuscatedFinding] = []
        for f in findings:
            key = (f.canonical_sink, f.line_start)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        vulns = [self._to_cyber_vuln(f, file_path) for f in unique_findings]
        return {
            "analyzed_at": utc_now_iso(),
            "file_path": file_path,
            "ast_parsed": ast_parsed,
            "normalization_layers": norm.layers_unwrapped,
            "decoded_blobs_count": len(norm.decoded_blobs),
            "decoded_blobs": norm.decoded_blobs,
            "homoglyphs_replaced": norm.homoglyphs_replaced,
            "zero_width_stripped": norm.zero_width_stripped,
            "deobfuscated_sinks_found": len(unique_findings),
            "findings": [
                {
                    "canonical_sink": f.canonical_sink,
                    "obfuscation_techniques": list(f.obfuscation_techniques),
                    "line_start": f.line_start,
                    "line_end": f.line_end,
                    "resolved_expression": f.resolved_expression,
                    "severity": f.severity.value,
                    "cwe_id": f.cwe_id,
                }
                for f in unique_findings
            ],
            "vulnerabilities": vulns,
        }

    def scan_directory(self, root_dir: str | Path) -> Dict[str, Any]:
        root = Path(root_dir).resolve()
        exts = {".py", ".js", ".ts", ".sh", ".bash", ".sql"}
        all_vulns: List[CyberVulnerability] = []
        file_reports: List[Dict[str, Any]] = []
        files_scanned = 0

        targets = [root] if root.is_file() else [
            p for p in sorted(root.rglob("*"))
            if p.is_file() and p.suffix.lower() in exts and "__pycache__" not in p.parts
        ]
        for fp in targets:
            files_scanned += 1
            rel = str(fp.relative_to(root)) if root.is_dir() else fp.name
            src = fp.read_text(encoding="utf-8", errors="ignore")
            rep = self.analyze_source(src, rel)
            if rep["deobfuscated_sinks_found"] > 0:
                file_reports.append({k: v for k, v in rep.items() if k != "vulnerabilities"})
                all_vulns.extend(rep["vulnerabilities"])

        return {
            "scanned_at": utc_now_iso(),
            "target": str(root),
            "files_scanned": files_scanned,
            "files_with_obfuscated_sinks": len(file_reports),
            "total_obfuscated_vulns": len(all_vulns),
            "file_reports": file_reports,
            "vulnerabilities": all_vulns,
        }

    def _walk_ast_scopes(
        self,
        tree: ast.AST,
        lines: Sequence[str],
        norm_layers: Sequence[str],
    ) -> List[DeobfuscatedFinding]:
        results: List[DeobfuscatedFinding] = []
        # Track constant string values AND symbolic callable/module aliases
        const_env: Dict[str, Any] = {}
        alias_env: Dict[str, Tuple[str, Set[str]]] = {}  # var -> (canonical_name, techniques)

        # Pre-seed imports
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    alias_env[local] = (alias.name, {"import_alias"} if alias.asname else set())
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for alias in node.names:
                    local = alias.asname or alias.name
                    full = f"{mod}.{alias.name}" if mod else alias.name
                    alias_env[local] = (full, {"import_alias"} if alias.asname else set())

        def eval_expr(expr: ast.AST) -> Tuple[Optional[Any], Set[str]]:
            """Partially evaluate AST expressions into constant strings/bytes/ints."""
            techs: Set[str] = set()
            if isinstance(expr, ast.Constant):
                return expr.value, techs
            if isinstance(expr, ast.Name):
                if expr.id in const_env:
                    return const_env[expr.id], {"var_propagation"}
                return None, techs
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
                lv, lt = eval_expr(expr.left)
                rv, rt = eval_expr(expr.right)
                if isinstance(lv, str) and isinstance(rv, str):
                    return lv + rv, lt | rt | {"string_concat_folding"}
                if isinstance(lv, (int, float)) and isinstance(rv, (int, float)):
                    return lv + rv, lt | rt | {"arith_folding"}
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
                lv, lt = eval_expr(expr.left)
                rv, rt = eval_expr(expr.right)
                if isinstance(lv, str) and rv is not None:
                    try:
                        return lv % rv, lt | rt | {"percent_format_folding"}
                    except Exception:
                        pass
            if isinstance(expr, ast.JoinedStr):
                parts: List[str] = []
                for v in expr.values:
                    if isinstance(v, ast.Constant) and isinstance(v.value, str):
                        parts.append(v.value)
                    elif isinstance(v, ast.FormattedValue):
                        fv, ft = eval_expr(v.value)
                        if isinstance(fv, (str, int, float)):
                            parts.append(str(fv))
                            techs |= ft | {"fstring_folding"}
                        else:
                            return None, techs
                return "".join(parts), techs
            if isinstance(expr, ast.Subscript):
                val, vt = eval_expr(expr.value)
                if isinstance(val, str) and isinstance(expr.slice, ast.Slice):
                    lo = expr.slice.lower.value if isinstance(expr.slice.lower, ast.Constant) else None
                    hi = expr.slice.upper.value if isinstance(expr.slice.upper, ast.Constant) else None
                    st = None
                    if isinstance(expr.slice.step, ast.UnaryOp) and isinstance(expr.slice.step.op, ast.USub) and isinstance(expr.slice.step.operand, ast.Constant):
                        st = -int(expr.slice.step.operand.value)
                    elif isinstance(expr.slice.step, ast.Constant):
                        st = int(expr.slice.step.value)
                    try:
                        return val[lo:hi:st], vt | {"slice_reversal_folding"}
                    except Exception:
                        pass
            if isinstance(expr, ast.Call):
                # chr(N)
                if isinstance(expr.func, ast.Name) and expr.func.id == "chr" and len(expr.args) == 1:
                    av, at = eval_expr(expr.args[0])
                    if isinstance(av, int) and 0 <= av <= 0x10FFFF:
                        return chr(av), at | {"chr_folding"}
                # "".join([...]) or "".join(map(chr, [...])) or "".join(chr(x) for x in [...])
                if isinstance(expr.func, ast.Attribute) and expr.func.attr == "join" and len(expr.args) == 1:
                    sep, st = eval_expr(expr.func.value)
                    if isinstance(sep, str):
                        items, it = eval_sequence(expr.args[0])
                        if items is not None:
                            return sep.join(items), st | it | {"str_join_folding"}
                # base64.b64decode("...").decode() or bytes.fromhex("...").decode()
                if isinstance(expr.func, ast.Attribute) and expr.func.attr == "decode":
                    inner, it = eval_expr(expr.func.value)
                    if isinstance(inner, bytes):
                        return inner.decode("utf-8", errors="ignore"), it | {"bytes_decode"}
                    if isinstance(inner, str):
                        return inner, it
                if isinstance(expr.func, ast.Attribute) and expr.func.attr in ("b64decode", "urlsafe_b64decode") and expr.args:
                    av, at = eval_expr(expr.args[0])
                    if isinstance(av, (str, bytes)):
                        raw_s = av.decode("ascii", errors="ignore") if isinstance(av, bytes) else av
                        dec = MultiLayerPayloadNormalizer._safe_b64_decode(raw_s)
                        if dec is not None:
                            return dec.encode("utf-8"), at | {"base64_decode_folding"}
                if isinstance(expr.func, ast.Attribute) and expr.func.attr == "fromhex" and expr.args:
                    av, at = eval_expr(expr.args[0])
                    if isinstance(av, str):
                        try:
                            return bytes.fromhex(av), at | {"fromhex_folding"}
                        except ValueError:
                            pass
                if isinstance(expr.func, ast.Attribute) and expr.func.attr == "decode" and isinstance(expr.func.value, ast.Call):
                    pass
                # codecs.decode(s, 'rot_13')
                if isinstance(expr.func, ast.Attribute) and expr.func.attr == "decode" and len(expr.args) == 2:
                    a0, t0 = eval_expr(expr.args[0])
                    a1, t1 = eval_expr(expr.args[1])
                    if isinstance(a0, str) and isinstance(a1, str) and a1.lower() in ("rot_13", "rot13"):
                        return codecs.decode(a0, "rot_13"), t0 | t1 | {"rot13_folding"}
            return None, techs

        def eval_sequence(node: ast.AST) -> Tuple[Optional[List[str]], Set[str]]:
            techs: Set[str] = set()
            if isinstance(node, (ast.List, ast.Tuple)):
                out: List[str] = []
                for el in node.elts:
                    ev, et = eval_expr(el)
                    if isinstance(ev, str):
                        out.append(ev)
                        techs |= et
                    else:
                        return None, techs
                return out, techs
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "map" and len(node.args) == 2:
                if isinstance(node.args[0], ast.Name) and node.args[0].id == "chr" and isinstance(node.args[1], (ast.List, ast.Tuple)):
                    out = []
                    for el in node.args[1].elts:
                        ev, et = eval_expr(el)
                        if isinstance(ev, int):
                            out.append(chr(ev))
                            techs |= et | {"map_chr_folding"}
                        else:
                            return None, techs
                    return out, techs
            if isinstance(node, ast.GeneratorExp) and len(node.generators) == 1:
                gen = node.generators[0]
                if isinstance(gen.target, ast.Name) and isinstance(gen.iter, (ast.List, ast.Tuple)):
                    if isinstance(node.elt, ast.Call) and isinstance(node.elt.func, ast.Name) and node.elt.func.id == "chr":
                        out = []
                        for el in gen.iter.elts:
                            ev, et = eval_expr(el)
                            if isinstance(ev, int):
                                out.append(chr(ev))
                                techs |= et | {"genexp_chr_folding"}
                            else:
                                return None, techs
                        return out, techs
            return None, techs

        def resolve_callable(expr: ast.AST) -> Tuple[Optional[str], Set[str]]:
            """Resolve indirect callable references (aliases, getattr, __import__, importlib, __builtins__[...])."""
            if isinstance(expr, ast.Name):
                if expr.id in alias_env:
                    return alias_env[expr.id]
                return expr.id, set()
            if isinstance(expr, ast.Attribute):
                base_name, bt = resolve_callable(expr.value)
                if base_name:
                    return f"{base_name}.{expr.attr}", bt
                return expr.attr, bt
            if isinstance(expr, ast.Subscript):
                # __builtins__['ev' + 'al'] or globals()['eval'] or vars(os)['system']
                base_name, bt = resolve_callable(expr.value)
                key_val, kt = eval_expr(expr.slice)
                if isinstance(key_val, str):
                    if base_name in ("__builtins__", "builtins", "globals", "locals", None):
                        return f"builtins.{key_val}", bt | kt | {"dict_subscript_dispatch"}
                    return f"{base_name}.{key_val}", bt | kt | {"dict_subscript_dispatch"}
            if isinstance(expr, ast.Call):
                callee_name, ct = resolve_callable(expr.func)
                # __import__('os') / importlib.import_module('subprocess')
                if callee_name in ("__import__", "builtins.__import__", "importlib.import_module") and expr.args:
                    mod_v, mt = eval_expr(expr.args[0])
                    if isinstance(mod_v, str):
                        return mod_v, ct | mt | {"dynamic_import"}
                # getattr(mod, 'sys' + 'tem')
                if callee_name in ("getattr", "builtins.getattr") and len(expr.args) >= 2:
                    obj_name, ot = resolve_callable(expr.args[0])
                    attr_v, at = eval_expr(expr.args[1])
                    if obj_name and isinstance(attr_v, str):
                        return f"{obj_name}.{attr_v}", ct | ot | at | {"dynamic_getattr"}
                # globals() / locals() / vars(mod)
                if callee_name in ("globals", "locals"):
                    return callee_name, ct | {"reflective_namespace"}
                if callee_name == "vars" and expr.args:
                    obj_name, ot = resolve_callable(expr.args[0])
                    if obj_name:
                        return obj_name, ct | ot | {"reflective_vars"}
            return None, set()

        def visit_stmts(stmts: Sequence[ast.stmt]) -> None:
            for st in stmts:
                if isinstance(st, ast.Assign):
                    # Constant assignment
                    val, vt = eval_expr(st.value)
                    sym, st_tech = resolve_callable(st.value)
                    for tgt in st.targets:
                        if isinstance(tgt, ast.Name):
                            if val is not None:
                                const_env[tgt.id] = val
                                # Detect deliberately split/folded hardcoded secrets (evasion: split_secret_concat)
                                if isinstance(val, str) and vt and (
                                    _SPLIT_SECRET_PAT_RE.search(val)
                                    or (_SECRET_VAR_NAME_RE.search(tgt.id) and len(val) >= 16)
                                ):
                                    results.append(self._build_finding("split.secret_literal", vt | {"split_secret_concat"}, st, lines))
                            if sym is not None:
                                alias_env[tgt.id] = (sym, st_tech | {"variable_alias"})
                elif isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name) and st.value is not None:
                    val, _ = eval_expr(st.value)
                    sym, st_tech = resolve_callable(st.value)
                    if val is not None:
                        const_env[st.target.id] = val
                    if sym is not None:
                        alias_env[st.target.id] = (sym, st_tech | {"variable_alias"})

                # Inspect all Call nodes inside this statement
                for sub in ast.walk(st):
                    if not isinstance(sub, ast.Call):
                        continue
                    resolved, techs = resolve_callable(sub.func)
                    # Check if normalized/folded SQL string is passed to .execute(...)
                    if resolved and resolved.endswith(".execute") and sub.args:
                        arg0_val, arg0_tech = eval_expr(sub.args[0])
                        if (isinstance(arg0_val, str) and SQL_KEYWORDS_RE.search(arg0_val)) or isinstance(sub.args[0], (ast.BinOp, ast.JoinedStr)):
                            canonical = "cursor.execute"
                            all_t = techs | arg0_tech | set(norm_layers)
                            if all_t or isinstance(sub.args[0], (ast.BinOp, ast.JoinedStr)):
                                results.append(self._build_finding(canonical, all_t or {"dynamic_sql_expr"}, sub, lines))
                            continue

                    if not resolved:
                        continue
                    # Match canonical dangerous sinks
                    matched_sink = None
                    if resolved in CANONICAL_DANGEROUS_SINKS:
                        matched_sink = resolved
                    else:
                        for sink_key in CANONICAL_DANGEROUS_SINKS:
                            if resolved.endswith("." + sink_key):
                                matched_sink = sink_key
                                break

                    if matched_sink:
                        # Check for obfuscated string arguments too (e.g. eval(base64.b64decode(...)))
                        arg_techs: Set[str] = set()
                        for a in sub.args:
                            _, at = eval_expr(a)
                            arg_techs |= at
                        all_techs = techs | arg_techs | set(norm_layers)
                        # Flag whenever obfuscation/indirection is present OR dynamic high-risk sink
                        if all_techs or matched_sink in ("builtins.eval", "builtins.exec", "eval", "exec", "os.system", "pickle.loads", "yaml.load", "yaml.unsafe_load"):
                            results.append(self._build_finding(matched_sink, all_techs or {"direct_dangerous_sink"}, sub, lines))

                # Recurse into compound statement bodies
                for child_body_attr in ("body", "orelse", "finalbody"):
                    child_body = getattr(st, child_body_attr, None)
                    if isinstance(child_body, list):
                        visit_stmts(child_body)
                if isinstance(st, ast.Try):
                    for h in st.handlers:
                        visit_stmts(h.body)

        if isinstance(tree, ast.Module):
            visit_stmts(tree.body)
        return results

    def _scan_normalized_text_patterns(
        self,
        original_source: str,
        norm: NormalizationReport,
        file_path: str,
    ) -> List[DeobfuscatedFinding]:
        out: List[DeobfuscatedFinding] = []
        nt = norm.normalized_text

        # Check decoded blobs & normalized text for high-confidence concealed attack payloads
        checks: Tuple[Tuple[str, str, str, Severity, CyberDomain, str], ...] = (
            (r"""(?:window|globalThis|self)\s*\[\s*['"]eval['"]\s*\]|new\s+Function\s*\(""", "js.eval", "CYB-DEOBF-JS-EVAL", Severity.CRITICAL, CyberDomain.WEB_CLIENT_PROTOCOL, "CWE-94"),
            (r"""(?:union\s+all?\s+select|'\s*or\s*['"]?1['"]?\s*=\s*['"]?1|;\s*drop\s+table)""", "sql.injection_payload", "CYB-DEOBF-SQLI-PAYLOAD", Severity.CRITICAL, CyberDomain.WEB_INJECTION, "CWE-89"),
            (r"""(?:/etc/passwd|/bin/(?:ba)?sh\s+-i|bash\s+-i\s+>&\s+/dev/tcp|nc\s+-e\s+/bin/)""", "shell.obfuscated_cmd", "CYB-DEOBF-SHELL-PAYLOAD", Severity.CRITICAL, CyberDomain.WEB_INJECTION, "CWE-78"),
            (r"""169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200""", "ssrf.obfuscated_imds", "CYB-DEOBF-SSRF-IMDS", Severity.CRITICAL, CyberDomain.WEB_SSRF_XXE_SSTI_DESER, "CWE-918"),
            (r"""<\s*script\b[^>]*>|onerror\s*=|onload\s*=|javascript\s*:""", "xss.obfuscated_dom", "CYB-DEOBF-XSS-PAYLOAD", Severity.HIGH, CyberDomain.WEB_CLIENT_PROTOCOL, "CWE-79"),
            (r"""\{\{[^}]*__(?:class|mro|subclasses|globals|builtins)__""", "ssti.obfuscated_jinja", "CYB-DEOBF-SSTI-PAYLOAD", Severity.CRITICAL, CyberDomain.WEB_SSRF_XXE_SSTI_DESER, "CWE-1336"),
            (r"""\.\./\.\./etc/|\.\.\\\.\.\\windows\\""", "path.obfuscated_traversal", "CYB-DEOBF-PATH-TRAVERSAL", Severity.HIGH, CyberDomain.WEB_SSRF_XXE_SSTI_DESER, "CWE-22"),
        )

        # Also fold JS `'ev' + 'al'` concatenation in normalized text
        folded_nt = re.sub(r"""['"]\s*\+\s*['"]""", "", nt)
        if folded_nt != nt and "js_string_concat_fold" not in norm.layers_unwrapped:
            norm.layers_unwrapped.append("js_string_concat_fold")

        # Inspect both folded normalized text and every decoded blob
        blobs_to_check = [(folded_nt, 1)] + [(b["decoded"], 1) for b in norm.decoded_blobs]
        for text_chunk, approx_line in blobs_to_check:
            for rx, sink_name, rid, sev, dom, cwe in checks:
                m = re.search(rx, text_chunk, re.IGNORECASE)
                if m:
                    techs = tuple(sorted(set(norm.layers_unwrapped or ["normalized_match"])))
                    out.append(DeobfuscatedFinding(
                        canonical_sink=sink_name,
                        obfuscation_techniques=techs,
                        line_start=approx_line,
                        line_end=approx_line,
                        resolved_expression=m.group(0)[:140],
                        raw_snippet=original_source.splitlines()[0][:140] if original_source.splitlines() else "",
                        severity=sev,
                        cwe_id=cwe,
                        rule_id=rid,
                        title=f"[Deobfuscated Evasion | {', '.join(techs[:3])}] Concealed `{sink_name}` Payload Detected",
                        cyber_domain=dom,
                    ))
        return out

    def _build_finding(
        self,
        canonical_sink: str,
        techniques: Set[str],
        node: ast.AST,
        lines: Sequence[str],
    ) -> DeobfuscatedFinding:
        rid, title, sev, dom, cwe = CANONICAL_DANGEROUS_SINKS[canonical_sink]
        ln = getattr(node, "lineno", 1)
        end_ln = getattr(node, "end_lineno", ln)
        snippet = lines[ln - 1].strip()[:140] if 1 <= ln <= len(lines) else ""
        ordered_techs = tuple(sorted(techniques))
        return DeobfuscatedFinding(
            canonical_sink=canonical_sink,
            obfuscation_techniques=ordered_techs,
            line_start=ln,
            line_end=end_ln,
            resolved_expression=f"{canonical_sink}(...) [via {', '.join(ordered_techs)}]",
            raw_snippet=snippet,
            severity=sev,
            cwe_id=cwe,
            rule_id=rid,
            title=f"{title} (evasion: {', '.join(ordered_techs[:3])})",
            cyber_domain=dom,
        )

    @staticmethod
    def _to_cyber_vuln(f: DeobfuscatedFinding, file_path: str) -> CyberVulnerability:
        return make_cyber_vuln(
            rule_id=f.rule_id,
            title=f.title,
            description=(
                f"AST partial evaluation & multi-layer deobfuscator uncovered concealed dangerous sink "
                f"`{f.canonical_sink}` in `{file_path}:{f.line_start}` bypassing naive regex checks "
                f"via techniques `{list(f.obfuscation_techniques)}`."
            ),
            cyber_domain=f.cyber_domain,
            severity=f.severity,
            cwe_ids=[f.cwe_id, "CWE-693"],
            confidence=0.97,
            cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="H")
            if f.severity == Severity.CRITICAL else None,
            mitre_techniques=[MitreTechniqueRef("T1027", "Obfuscated Files or Information", MitreTactic.DEFENSE_EVASION)],
            verification_method=VerificationMethod.STATIC_AST,
            file_path=file_path,
            line_start=f.line_start,
            line_end=f.line_end,
            endpoint_or_asset=f"{file_path}:{f.line_start}",
            code_snippet=f.raw_snippet,
            remediation_guidance=(
                f"Eliminate dynamic/obfuscated invocation of `{f.canonical_sink}` and replace with safe "
                f"static allowlisted APIs (e.g., parameterized SQL, `subprocess.run(..., shell=False)`, `yaml.safe_load`, `json.loads`)."
            ),
            tags=["deobfuscated", "anti-evasion", *f.obfuscation_techniques[:4]],
            discovered_by="ely_cyber_deobfuscation_ast_normalizer",
        )
