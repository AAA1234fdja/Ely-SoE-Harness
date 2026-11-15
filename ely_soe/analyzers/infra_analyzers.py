"""
Deep Specialized Security Analyzers for Infrastructure & Runtime Isolation Domains:
  - Domain 6: Filesystem Security (`filesystem`)
  - Domain 7: Process Management (`process_management`)
  - Domain 9: Network Security (`network`)

Identifies path traversals, symlink escapes, Zip-Slip/Tar-Slip archive extraction,
world-writable permissions, unsafe temp files, uncontained subprocess spawning,
parent environment secret leakage, missing POSIX rlimits, cloud-metadata SSRF,
disabled TLS verification, and unrestricted network egress.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from ely_soe.core.models import (
    CodeLocation,
    EvidenceArtifact,
    Finding,
    FindingStatus,
    SecurityDomain,
    Severity,
    new_id,
)


@dataclass(frozen=True)
class InfraRule:
    rule_id: str
    domain: SecurityDomain
    title: str
    severity: Severity
    cwe: str
    pattern: str
    description: str
    impact: str
    suppress_if_file_contains: Tuple[str, ...] = ()
    extensions: Tuple[str, ...] = (".py", ".ts", ".js", ".sh", ".yaml", ".yml", ".json")


INFRA_RULES: List[InfraRule] = [
    # --- Domain 6: Filesystem Security ---
    InfraRule(
        rule_id="FS-TRAV-001",
        domain=SecurityDomain.FILESYSTEM,
        title="Unvalidated os.path.join() File Access Vulnerable to Path Traversal",
        severity=Severity.HIGH,
        cwe="CWE-22",
        pattern=r"(?:open|Path)\s*\(\s*os\.path\.join\s*\([^)]+\)",
        description="File path built with `os.path.join()` without canonical `.resolve()` and `is_relative_to(workspace)` checks allows `../` or absolute-path overrides.",
        impact="Agent reads or overwrites arbitrary files outside its assigned project workspace",
        suppress_if_file_contains=("is_relative_to", "FS_WORKSPACE_ESCAPE", "safe_resolve_path"),
    ),
    InfraRule(
        rule_id="FS-SYMLINK-002",
        domain=SecurityDomain.FILESYSTEM,
        title="Symlink Following Enabled Inside Untrusted Agent Workspace",
        severity=Severity.HIGH,
        cwe="CWE-59",
        pattern=r"(?:follow_symlinks\s*=\s*True|allow_symlinks\s*=\s*True)",
        description="Filesystem helper explicitly follows symlinks, enabling symlink-escape attacks out of the project jail.",
        impact="Compromised executor creates symlink to `/etc/passwd` or `../.env` and exfiltrates host secrets",
    ),
    InfraRule(
        rule_id="FS-ARCHIVE-003",
        domain=SecurityDomain.FILESYSTEM,
        title="Unsafe Archive Extraction (tarfile/zipfile extractall) Vulnerable to Zip-Slip/Tar-Slip",
        severity=Severity.CRITICAL,
        cwe="CWE-22",
        pattern=r"\.extractall\s*\(",
        description="Calling `.extractall()` without verifying every archive member's canonical destination path enables arbitrary file overwrite (Zip-Slip/Tar-Slip).",
        impact="Malicious skill/artifact archive overwrites host scripts, SSH keys, or Ely core files",
        suppress_if_file_contains=("safe_extract", "is_relative_to", "filter='data'", 'filter="data"'),
    ),
    InfraRule(
        rule_id="FS-PERM-004",
        domain=SecurityDomain.FILESYSTEM,
        title="World-Writable File/Directory Permissions (0o777 / 0o666)",
        severity=Severity.MEDIUM,
        cwe="CWE-732",
        pattern=r"os\.chmod\s*\([^,]+,\s*0o?(?:777|666)\b",
        description="Assigning world-writable permissions allows cross-agent or cross-user tampering.",
        impact="Other local agents or processes can modify sensitive workspace or config files",
    ),
    InfraRule(
        rule_id="FS-TEMP-005",
        domain=SecurityDomain.FILESYSTEM,
        title="Predictable /tmp Hardcoded Path Susceptible to Symlink/TOCTOU Hijack",
        severity=Severity.MEDIUM,
        cwe="CWE-377",
        pattern=r"open\s*\(\s*['\"]/tmp/[A-Za-z0-9_.\-]+['\"]",
        description="Using predictable hardcoded `/tmp/...` paths instead of `tempfile.mkstemp`/`TemporaryDirectory` allows symlink pre-creation races.",
        impact="Local privilege/data hijack or cross-agent leakage via shared `/tmp`",
    ),

    # --- Domain 7: Process Management ---
    InfraRule(
        rule_id="PROC-ENV-001",
        domain=SecurityDomain.PROCESS_MANAGEMENT,
        title="Unsanitized Parent Environment (os.environ) Inherited by Child Process",
        severity=Severity.HIGH,
        cwe="CWE-526",
        pattern=r"(?:subprocess\.(?:Popen|run|call)\([^)]*env\s*=\s*os\.environ|inherit_parent_env\s*=\s*True)",
        description="Child process inherits raw parent environment variables, leaking production LLM/DB/GitHub secrets into untrusted agent subprocesses.",
        impact="Compromised secondary process harvests all parent secrets via `print(os.environ)`",
        suppress_if_file_contains=("sanitize_environment", "scrub_env"),
    ),
    InfraRule(
        rule_id="PROC-SANDBOX-002",
        domain=SecurityDomain.PROCESS_MANAGEMENT,
        title="Process Sandbox Disabled or Missing Resource Limits (CPU/RAM/Procs)",
        severity=Severity.CRITICAL,
        cwe="CWE-400",
        pattern=r"(?:disable_sandbox\s*=\s*True|max_processes\s*=\s*(?:None|0|-1|9999)|enforce_rlimits\s*=\s*False)",
        description="Process execution layer disables sandboxing or leaves CPU/memory/process counts unbounded.",
        impact="Fork bombs, memory exhaustion DoS, or unrestricted host breakout by secondary processes",
    ),
    InfraRule(
        rule_id="PROC-ORPHAN-003",
        domain=SecurityDomain.PROCESS_MANAGEMENT,
        title="Subprocess Spawned Without Process-Group Isolation (Orphan/Daemon Persistence Risk)",
        severity=Severity.MEDIUM,
        cwe="CWE-404",
        pattern=r"subprocess\.Popen\s*\(",
        description="Spawning child processes via `subprocess.Popen` without `start_new_session=True` and `os.killpg` lets malicious child daemons survive timeout/teardown.",
        impact="Rogue background process persists after task completion to maintain foothold",
        suppress_if_file_contains=("start_new_session", "killpg"),
    ),
    InfraRule(
        rule_id="PROC-LD-004",
        domain=SecurityDomain.PROCESS_MANAGEMENT,
        title="Dynamic Linker / Runtime Env Injection (LD_PRELOAD / PYTHONPATH)",
        severity=Severity.HIGH,
        cwe="CWE-426",
        pattern=r"(?:LD_PRELOAD|LD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES)\s*['\"]\]\s*=",
        description="Code allows mutating dynamic linker variables for spawned processes.",
        impact="Arbitrary shared-library code injection inside privileged child processes",
    ),

    # --- Domain 9: Network Security ---
    InfraRule(
        rule_id="NET-SSRF-001",
        domain=SecurityDomain.NETWORK,
        title="Unrestricted Outbound HTTP Fetch Vulnerable to SSRF & Cloud Metadata Theft",
        severity=Severity.HIGH,
        cwe="CWE-918",
        pattern=r"(?:urllib\.request\.urlopen\s*\(|requests\.(?:get|post|put|delete|request)\s*\(|allow_any_egress\s*=\s*True)",
        description="Network fetch tool performs outbound HTTP requests without host allowlists or private/link-local IP (`169.254.169.254`) blocking.",
        impact="Attacker pivots through agent to query cloud IAM metadata or internal admin services, or exfiltrates secrets externally",
        suppress_if_file_contains=("validate_egress_url", "ALLOWED_EGRESS_HOSTS", "block_private_ips", "assert_network_target_authorized"),
    ),
    InfraRule(
        rule_id="NET-TLS-002",
        domain=SecurityDomain.NETWORK,
        title="TLS Certificate Verification Disabled (verify=False / CERT_NONE)",
        severity=Severity.HIGH,
        cwe="CWE-295",
        pattern=r"(?:verify\s*=\s*False|ssl\.CERT_NONE|check_hostname\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0)",
        description="TLS certificate validation is explicitly disabled, exposing agent communications to MITM interception.",
        impact="Network attacker intercepts API tokens or injects malicious tool responses in transit",
    ),
    InfraRule(
        rule_id="NET-HTTP-003",
        domain=SecurityDomain.NETWORK,
        title="Cleartext HTTP Endpoint Used for Sensitive Telemetry or Token Exchange",
        severity=Severity.MEDIUM,
        cwe="CWE-319",
        pattern=r"http://(?!127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]|example\.com)[a-zA-Z0-9._\-]+[^\s'\"]*(?:token|auth|api|key|secret|upload|exfil)",
        description="Sensitive API or telemetry URL uses unencrypted `http://` instead of HTTPS.",
        impact="Passive eavesdropper captures tokens or modifies instructions in transit",
    ),
    InfraRule(
        rule_id="NET-BIND-004",
        domain=SecurityDomain.NETWORK,
        title="Internal Control/Debug Service Bound to 0.0.0.0 Without Authentication",
        severity=Severity.MEDIUM,
        cwe="CWE-668",
        pattern=r"(?:host\s*=\s*['\"]0\.0\.0\.0['\"]|\(\s*['\"]0\.0\.0\.0['\"]\s*,)",
        description="Internal agent RPC or admin server binds to all interfaces (`0.0.0.0`) without explicit auth enforcement.",
        impact="Unauthorized network peers on the LAN/container bridge can invoke internal Ely controls",
        suppress_if_file_contains=("verify_jwt", "require_auth", "ELY_PREVIEW_PUBLIC", "hmac.compare_digest"),
    ),
]


class InfrastructureDomainAnalyzer:
    """
    Executes deep static security auditing for Filesystem, Process Management,
    and Network Security domains. Emits HYPOTHESIS findings only.
    """

    def analyze_directory(
        self,
        snapshot_root: Path,
        domains: Optional[List[SecurityDomain]] = None,
    ) -> List[Finding]:
        target_domains = set(domains) if domains else {
            SecurityDomain.FILESYSTEM,
            SecurityDomain.PROCESS_MANAGEMENT,
            SecurityDomain.NETWORK,
        }
        findings: List[Finding] = []
        root = Path(snapshot_root).resolve()

        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if any(part.startswith(".") or part in ("__pycache__", "node_modules", "target", ".venv", "tests") for part in path.relative_to(root).parts):
                continue
            ext = path.suffix.lower()
            rel = path.relative_to(root).as_posix()
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.splitlines()
            for rule in INFRA_RULES:
                if rule.domain not in target_domains:
                    continue
                if ext not in rule.extensions:
                    continue
                if rule.suppress_if_file_contains and any(sup in content for sup in rule.suppress_if_file_contains):
                    continue
                compiled = re.compile(rule.pattern)
                for idx, line in enumerate(lines, start=1):
                    stripped = line.strip()
                    if stripped.startswith(("#", "//", "/*", "*")):
                        continue
                    if compiled.search(line):
                        findings.append(self._build_finding(rule, rel, idx, stripped))
                        break
        return findings

    @staticmethod
    def _build_finding(rule: InfraRule, rel_path: str, line_no: int, snippet: str) -> Finding:
        ext = Path(rel_path).suffix.lower()
        lang = {".py": "python", ".ts": "typescript", ".js": "javascript", ".sh": "shell"}.get(ext, "text")
        return Finding(
            finding_id=new_id("fnd"),
            title=f"[{rule.domain.display_name}] {rule.title}",
            description=rule.description,
            domain=rule.domain,
            severity=rule.severity,
            rule_id=rule.rule_id,
            discovered_by="ely_infra_domain_analyzer",
            location=CodeLocation(
                file_path=rel_path,
                line_start=line_no,
                snippet=snippet[:160],
                language=lang,
            ),
            status=FindingStatus.HYPOTHESIS,
            confidence=0.84,
            cwe_ids=[rule.cwe],
            attack_vector=f"Exploiting `{rule.rule_id}` in `{rel_path}:{line_no}`",
            impact=rule.impact,
            poc_spec={
                "kind": "static_rule",
                "rule_id": rule.rule_id,
                "pattern": rule.pattern,
                "target_file": rel_path,
                "target_line": line_no,
            },
            evidence=[
                EvidenceArtifact(
                    artifact_id=new_id("ev"),
                    kind="infra_audit_match",
                    description=f"Matched infrastructure rule {rule.rule_id} at {rel_path}:{line_no}",
                    content=f"{rel_path}:{line_no}\n{snippet}",
                    producer="ely_infra_domain_analyzer",
                )
            ],
            tags=[rule.domain.value, rule.rule_id.lower(), rule.cwe.lower()],
        )
