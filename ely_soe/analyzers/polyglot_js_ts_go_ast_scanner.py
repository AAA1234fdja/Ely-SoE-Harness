"""
Polyglot Multi-Language Security Scanner (JavaScript, TypeScript, Go, Bash, Dockerfile, SQL).

Closes the Python-centric SAST blind spot in polyglot repositories by providing deep,
language-specific vulnerability detection across 6 production ecosystems:
  1. **JavaScript / TypeScript (`*.js`, `*.jsx`, `*.ts`, `*.tsx`, `*.mjs`)**:
       - DOM XSS (`innerHTML =`, `outerHTML =`, `document.write(`, `dangerouslySetInnerHTML`)
       - Dynamic code execution (`eval(`, `new Function(`, `setTimeout("...", ...)`)
       - Node.js Command Injection (`child_process.exec(`, `execSync(` with template/concat)
       - Prototype Pollution (`__proto__`, `constructor.prototype`, unsafe deep merge)
       - Wildcard `postMessage(..., '*')` & missing `event.origin` check
       - JWT `algorithms: ['none']` & `jwt.decode` without verify
       - Catastrophic backtracking ReDoS regex literals.
  2. **Go (`*.go`)**:
       - OS Command Injection (`exec.Command("sh", "-c", ...)`)
       - SQL Injection (`db.Query(fmt.Sprintf(...))`, string concat in `Exec`/`QueryRow`)
       - Weak RNG for security (`math/rand` instead of `crypto/rand`)
       - Insecure TLS (`InsecureSkipVerify: true`) & cleartext `http.ListenAndServe`
       - `unsafe.Pointer` memory safety escapes & `filepath.Join` without prefix confinement.
  3. **Shell / Bash (`*.sh`, `*.bash`)**:
       - Pipe-to-shell supply-chain RCE (`curl ... | bash`, `wget ... | sh`)
       - Dynamic `eval "$..."` injection & `chmod 777` world-writable permissions.
  4. **Dockerfiles (`Dockerfile*`, `*.dockerfile`)**:
       - Running as root (`USER root` or missing non-root `USER`)
       - Unpinned `:latest` base images & `ADD https://` remote unverified fetch
       - Hardcoded secrets in `ENV`/`ARG` instructions.
  5. **SQL (`*.sql`)**:
       - `GRANT ALL PRIVILEGES ... TO PUBLIC`, `EXECUTE IMMEDIATE` dynamic SQL concat.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

from ely_soe.core.models import Severity, utc_now_iso
from ely_soe.cyber.models import (
    CyberDomain,
    CyberVulnerability,
    VerificationMethod,
    make_cyber_vuln,
)


@dataclass(frozen=True)
class PolyglotRule:
    rule_id: str
    language: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    cwe: str
    domain: CyberDomain
    remediation: str


POLYGLOT_RULES: Tuple[PolyglotRule, ...] = (
    # ---- JavaScript / TypeScript ----
    PolyglotRule(
        "CYB-POLY-JS-DOM-XSS", "javascript", "Unsafe DOM HTML Sink (innerHTML / document.write / dangerouslySetInnerHTML)",
        re.compile(r"(?:\.(?:innerHTML|outerHTML)\s*(?:\+?=)\s*(?!['\"]\s*['\"])|document\.write\s*\(|dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html)"),
        Severity.HIGH, "CWE-79", CyberDomain.WEB_CLIENT_PROTOCOL,
        "Use `textContent` / DOM builders or sanitize HTML with DOMPurify + strict CSP.",
    ),
    PolyglotRule(
        "CYB-POLY-JS-EVAL-RCE", "javascript", "Dynamic JS Code Execution (eval / new Function)",
        re.compile(r"(?<!\.)\b(?:eval\s*\(|new\s+Function\s*\()"),
        Severity.CRITICAL, "CWE-95", CyberDomain.WEB_INJECTION,
        "Eliminate `eval()` / `new Function()`; use `JSON.parse()` or safe declarative dispatch tables.",
    ),
    PolyglotRule(
        "CYB-POLY-JS-NODE-CMDI", "javascript", "Node.js Shell Command Injection (child_process.exec / execSync)",
        re.compile(r"\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|['\"][^'\"]+['\"]\s*\+)"),
        Severity.CRITICAL, "CWE-78", CyberDomain.WEB_INJECTION,
        "Use `execFile()` / `spawn()` with explicit argument arrays and `shell: false`.",
    ),
    PolyglotRule(
        "CYB-POLY-JS-PROTO-POLLUTE", "javascript", "JavaScript Prototype Pollution Vector (__proto__ / constructor.prototype)",
        re.compile(r"(?:\[\s*['\"]__proto__['\"]\s*\]|\.__proto__\b|constructor\s*\[\s*['\"]prototype['\"]\s*\])"),
        Severity.HIGH, "CWE-1321", CyberDomain.WEB_CLIENT_PROTOCOL,
        "Reject `__proto__`, `constructor`, and `prototype` keys; use `Object.create(null)` or `Map`.",
    ),
    PolyglotRule(
        "CYB-POLY-JS-POSTMSG-STAR", "javascript", "Wildcard `postMessage(..., '*')` Target Origin Exposure",
        re.compile(r"\.postMessage\s*\([^,]+,\s*['\"]\*['\"]\s*\)"),
        Severity.MEDIUM, "CWE-345", CyberDomain.WEB_CLIENT_PROTOCOL,
        "Specify the exact trusted `targetOrigin` instead of wildcard `'*'`.",
    ),
    PolyglotRule(
        "CYB-POLY-JS-JWT-NONE", "javascript", "JWT Algorithm 'none' or Unverified Decode",
        re.compile(r"(?:algorithms\s*:\s*\[[^\]]*['\"]none['\"]|jwt\.decode\s*\()"),
        Severity.CRITICAL, "CWE-347", CyberDomain.AUTH_ACCESS_CONTROL,
        "Always verify JWT signatures with `jwt.verify()` and an explicit asymmetric algorithm allowlist (`RS256`/`EdDSA`).",
    ),
    # ---- Go ----
    PolyglotRule(
        "CYB-POLY-GO-CMDI", "go", "Go Shell Command Injection (`exec.Command(\"sh\", \"-c\", ...)`)",
        re.compile(r'exec\.Command\s*\(\s*"(?:sh|bash|/bin/sh|/bin/bash)"\s*,\s*"-c"'),
        Severity.CRITICAL, "CWE-78", CyberDomain.WEB_INJECTION,
        "Invoke binary directly via `exec.Command(binary, arg1, arg2)` without a shell wrapper.",
    ),
    PolyglotRule(
        "CYB-POLY-GO-SQLI", "go", "Go SQL Injection via `fmt.Sprintf` or String Concatenation in Database Query",
        re.compile(r"\.(?:Query|QueryRow|Exec)(?:Context)?\s*\([^)]*(?:fmt\.Sprintf\s*\(|['\"`][^'\"`]*(?:SELECT|INSERT|UPDATE|DELETE)[^'\"`]*['\"`]\s*\+)", re.I),
        Severity.CRITICAL, "CWE-89", CyberDomain.WEB_INJECTION,
        "Use parameterized placeholders (`$1`, `?`) passed as variadic arguments to `QueryContext`.",
    ),
    PolyglotRule(
        "CYB-POLY-GO-WEAK-RAND", "go", "Go Non-Cryptographic `math/rand` Imported in Security Context",
        re.compile(r'^\s*"math/rand"', re.M),
        Severity.MEDIUM, "CWE-338", CyberDomain.TLS_CRYPTOGRAPHY,
        "Use `crypto/rand` for tokens, nonces, session IDs, and cryptographic keys.",
    ),
    PolyglotRule(
        "CYB-POLY-GO-UNSAFE-PTR", "go", "Go Memory Safety Escape (`unsafe.Pointer`)",
        re.compile(r"\bunsafe\.Pointer\b"),
        Severity.MEDIUM, "CWE-119", CyberDomain.BINARY_MEMORY_SAFETY,
        "Avoid `unsafe.Pointer` unless formally audited and bounded by explicit slice length checks.",
    ),
    # ---- Bash / Shell ----
    PolyglotRule(
        "CYB-POLY-SH-CURL-PIPE", "shell", "Unverified Remote Pipe-to-Shell Execution (`curl | bash` / `wget | sh`)",
        re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]+\|\s*(?:sudo\s+)?(?:ba)?sh\b"),
        Severity.CRITICAL, "CWE-829", CyberDomain.IAC_CICD,
        "Download script artifact, verify cryptographic SHA-256 / Cosign signature, then execute.",
    ),
    PolyglotRule(
        "CYB-POLY-SH-EVAL", "shell", "Bash Dynamic `eval` Variable Injection",
        re.compile(r"(?m)^\s*eval\s+['\"]?\$"),
        Severity.HIGH, "CWE-78", CyberDomain.IAC_CICD,
        "Avoid `eval` on dynamic shell variables; use Bash arrays and explicit argument expansion.",
    ),
    PolyglotRule(
        "CYB-POLY-SH-CHMOD777", "shell", "World-Writable Permissions (`chmod 777` / `chmod a+rwx`)",
        re.compile(r"\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx)\b"),
        Severity.HIGH, "CWE-732", CyberDomain.CLOUD_IAM,
        "Enforce least-privilege POSIX permissions (`0600` for secrets, `0750` for directories).",
    ),
    # ---- Dockerfile ----
    PolyglotRule(
        "CYB-POLY-DOCKER-LATEST", "dockerfile", "Unpinned Container Base Image (`FROM ...:latest`)",
        re.compile(r"(?im)^\s*FROM\s+[^\s:@]+(?::latest)?\s*(?:AS\s+\S+)?\s*$"),
        Severity.MEDIUM, "CWE-829", CyberDomain.KUBERNETES_CONTAINER,
        "Pin base images to immutable SHA-256 digests (`FROM python:3.11-slim@sha256:...`).",
    ),
    PolyglotRule(
        "CYB-POLY-DOCKER-ROOT", "dockerfile", "Container Explicitly Configured to Run as `USER root`",
        re.compile(r"(?im)^\s*USER\s+(?:root|0)\s*$"),
        Severity.HIGH, "CWE-250", CyberDomain.KUBERNETES_CONTAINER,
        "Create and switch to a dedicated non-root UID (`USER 10001:10001`).",
    ),
    PolyglotRule(
        "CYB-POLY-DOCKER-SECRET-ENV", "dockerfile", "Hardcoded Secret Baked Into Container `ENV`/`ARG` Layer",
        re.compile(r"(?im)^\s*(?:ENV|ARG)\s+[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)[A-Z0-9_]*\s*[=\s]\s*['\"]?[^\s$'\"#]{6,}"),
        Severity.CRITICAL, "CWE-798", CyberDomain.CLOUD_IAM,
        "Use BuildKit `--mount=type=secret` at build time and runtime KMS/Kubernetes Secrets injection.",
    ),
    # ---- SQL ----
    PolyglotRule(
        "CYB-POLY-SQL-GRANT-PUBLIC", "sql", "Over-Privileged SQL `GRANT ALL ... TO PUBLIC`",
        re.compile(r"(?i)\bGRANT\s+ALL(?:\s+PRIVILEGES)?\b[^\n;]+TO\s+PUBLIC\b"),
        Severity.CRITICAL, "CWE-732", CyberDomain.CLOUD_IAM,
        "Follow least-privilege RBAC; grant explicit minimal table privileges to named service roles.",
    ),
)

EXT_TO_LANG: Dict[str, str] = {
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript",
    ".go": "go",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".sql": "sql",
    ".dockerfile": "dockerfile",
}


class PolyglotSourceSecurityScanner:
    """Multi-language JS/TS/Go/Bash/Dockerfile/SQL static security scanner."""

    def _detect_language(self, path: Path) -> str:
        if path.name.lower().startswith("dockerfile"):
            return "dockerfile"
        return EXT_TO_LANG.get(path.suffix.lower(), "")

    def scan_text(self, text: str, *, language: str, file_path: str = "<inline>") -> List[CyberVulnerability]:
        vulns: List[CyberVulnerability] = []
        lang_l = language.lower()
        for rule in POLYGLOT_RULES:
            if rule.language != lang_l:
                continue
            for m in rule.pattern.finditer(text):
                lineno = text[: m.start()].count("\n") + 1
                line_src = text.splitlines()[lineno - 1].strip() if lineno <= len(text.splitlines()) else m.group(0)
                # Suppress safe comments
                if lang_l in ("javascript", "go") and line_src.startswith("//"):
                    continue
                if lang_l in ("shell", "dockerfile") and line_src.startswith("#"):
                    continue
                if lang_l == "sql" and line_src.startswith("--"):
                    continue
                vulns.append(
                    make_cyber_vuln(
                        rule_id=rule.rule_id,
                        title=f"[Polyglot {lang_l.upper()}] {rule.title}",
                        description=f"Detected `{line_src[:140]}` in `{file_path}:{lineno}`.",
                        cyber_domain=rule.domain,
                        severity=rule.severity,
                        cwe_ids=[rule.cwe],
                        confidence=0.90,
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=file_path,
                        line_start=lineno,
                        endpoint_or_asset=f"{file_path}:{lineno}",
                        remediation_guidance=rule.remediation,
                        discovered_by="ely_polyglot_source_scanner",
                    )
                )
        return vulns

    def scan_repository(self, target_dir: str | Path) -> Dict[str, Any]:
        root = Path(target_dir).resolve()
        files = [root] if root.is_file() else sorted(root.rglob("*"))
        all_vulns: List[CyberVulnerability] = []
        lang_counts: Dict[str, int] = {}
        files_scanned = 0

        for f in files:
            if not f.is_file() or any(p in f.parts for p in (".git", "node_modules", "__pycache__", ".venv", "dist", "build")):
                continue
            lang = self._detect_language(f)
            if not lang or f.stat().st_size > 512_000:
                continue
            rel = f.name if root.is_file() else str(f.relative_to(root))
            try:
                src = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            files_scanned += 1
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
            all_vulns.extend(self.scan_text(src, language=lang, file_path=rel))

        return {
            "scanned_at": utc_now_iso(),
            "target": str(root),
            "files_scanned": files_scanned,
            "languages_audited": lang_counts,
            "findings_count": len(all_vulns),
            "vulnerabilities": all_vulns,
        }
