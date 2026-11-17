"""
Ethical Scope Authorization Guard, Lab-Only Containment, Secret Scrubber & Main-Instance Barrier.

Enforces Section 3 & Second Part Section 1/3 requirements:
  - Experimental and frontier adversarial tools are strictly limited to authorized
    owned environments and isolated local lab sandboxes.
  - Hard network denylist preventing any probe from touching external/production hosts.
  - Automated Secret & Production Credential Scrubber (regex signatures + Shannon
    entropy detector) ensuring Temporary Adversarial Instances NEVER contain real
    credentials and reports NEVER leak secrets.
  - Main-Instance Read-Only Immutability Verifier computing cryptographic directory
    fingerprints before and after evaluation so the Temporary Adversarial Instance
    is provably incapable of altering the Ely Main Instance.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

from ely_soe.core.crypto_ledger import AuditorKeyring, canonical_json, sha256_hex
from ely_soe.core.models import utc_now_iso


class ScopeViolationError(PermissionError):
    """Raised whenever an operation attempts to exceed authorized lab boundaries."""


@dataclass
class ScopeManifesto:
    """Cryptographically signed authorization manifesto bounding an evaluation run."""

    manifest_id: str
    authorized_by: str
    target_root: str
    sandbox_root: str
    allowed_hosts: List[str] = field(default_factory=lambda: ["127.0.0.1", "localhost", "::1"])
    allow_external_network: bool = False
    allow_main_instance_writes: bool = False  # MUST ALWAYS BE FALSE
    allowed_tools: List[str] = field(
        default_factory=lambda: [
            "static_analyzer",
            "taint_engine",
            "rust_auditor",
            "supply_chain_scanner",
            "fuzzer",
            "red_team_lab",
            "untrusted_agent_sim",
            "validator_sandbox",
        ]
    )
    issued_at: str = field(default_factory=utc_now_iso)
    signature: str = ""

    def canonical_payload(self) -> str:
        return canonical_json(
            {
                "manifest_id": self.manifest_id,
                "authorized_by": self.authorized_by,
                "target_root": os.path.abspath(self.target_root),
                "sandbox_root": os.path.abspath(self.sandbox_root),
                "allowed_hosts": sorted(self.allowed_hosts),
                "allow_external_network": self.allow_external_network,
                "allow_main_instance_writes": self.allow_main_instance_writes,
                "allowed_tools": sorted(self.allowed_tools),
                "issued_at": self.issued_at,
            }
        )

    def sign(self, keyring: AuditorKeyring) -> None:
        self.signature = keyring.sign_scope_manifest(self.canonical_payload())

    def verify(self, keyring: AuditorKeyring) -> bool:
        if not self.signature:
            return False
        return keyring.verify_scope_manifest(self.canonical_payload(), self.signature)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "manifest_id": self.manifest_id,
            "authorized_by": self.authorized_by,
            "target_root": self.target_root,
            "sandbox_root": self.sandbox_root,
            "allowed_hosts": list(self.allowed_hosts),
            "allow_external_network": self.allow_external_network,
            "allow_main_instance_writes": self.allow_main_instance_writes,
            "allowed_tools": list(self.allowed_tools),
            "issued_at": self.issued_at,
            "signature": self.signature,
        }


class SecretScrubber:
    """
    Detects and redacts production credentials, API keys, JWTs, private keys, and
    high-entropy secrets when creating Temporary Adversarial Snapshots or exporting reports.
    """

    SECRET_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
        ("private_key_block", re.compile(r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]+PRIVATE KEY-----")),
        ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b")),
        ("openai_or_llm_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{24,}\b")),
        ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{24,}\b")),
        ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b")),
        ("jwt_token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
        ("db_connection_uri", re.compile(r"\b(?:postgres|postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^\s\"']+")),
        (
            "generic_secret_assignment",
            re.compile(
                r"(?i)\b(api_key|secret_key|access_token|auth_token|private_key|db_password|prod_token|signing_secret)\s*([:=])\s*(['\"])([^'\"]{12,})\3"
            ),
        ),
    ]

    SENSITIVE_FILENAMES: Set[str] = {
        ".env",
        ".env.production",
        ".env.local",
        "id_rsa",
        "id_ed25519",
        "credentials.json",
        "service-account.json",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "secrets.yaml",
        "secrets.yml",
        "master.key",
    }

    SENSITIVE_ENV_SUBSTRINGS: Tuple[str, ...] = (
        "KEY",
        "SECRET",
        "TOKEN",
        "PASS",
        "CRED",
        "AUTH",
        "AWS_",
        "GCP_",
        "AZURE_",
        "OPENAI_",
        "ANTHROPIC_",
        "GLM_",
        "GITHUB_",
        "DATABASE_URL",
    )

    @staticmethod
    def shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        counts: Dict[str, int] = {}
        for ch in s:
            counts[ch] = counts.get(ch, 0) + 1
        length = float(len(s))
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    def scan_text(self, text: str) -> List[Dict[str, Any]]:
        """Identify potential leaked credentials in text without modifying it."""
        hits: List[Dict[str, Any]] = []
        for label, pattern in self.SECRET_PATTERNS:
            for match in pattern.finditer(text):
                line_no = text.count("\n", 0, match.start()) + 1
                hits.append(
                    {
                        "kind": label,
                        "line": line_no,
                        "preview": match.group(0)[:10] + "...[REDACTED]",
                    }
                )
        return hits

    def scrub_text(self, text: str) -> Tuple[str, int]:
        """Redact all recognized secrets and return (scrubbed_text, redaction_count)."""
        redactions = 0
        out = text
        for label, pattern in self.SECRET_PATTERNS:
            if label == "generic_secret_assignment":
                def _repl(m: re.Match[str]) -> str:
                    nonlocal redactions
                    val = m.group(4)
                    if val.startswith("ELY_LAB_REDACTED") or val.startswith("REDACTED"):
                        return m.group(0)
                    redactions += 1
                    return f"{m.group(1)}{m.group(2)}{m.group(3)}ELY_LAB_REDACTED_{label.upper()}{m.group(3)}"

                out = pattern.sub(_repl, out)
            else:
                def _repl_simple(m: re.Match[str], lbl: str = label) -> str:
                    nonlocal redactions
                    redactions += 1
                    return f"ELY_LAB_REDACTED_{lbl.upper()}"

                out = pattern.sub(_repl_simple, out)
        return out, redactions

    def is_sensitive_file(self, path: Path) -> bool:
        name = path.name.lower()
        if name in self.SENSITIVE_FILENAMES:
            return True
        if name.endswith((".pem", ".key", ".p12", ".pfx", ".keystore")):
            return True
        return False

    def sanitize_environment(self, env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Strip all production credentials from process environment before launching a sandbox."""
        source = dict(os.environ) if env is None else dict(env)
        clean: Dict[str, str] = {}
        safe_allowlist = {"PATH", "LANG", "LC_ALL", "TERM", "TZ", "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE"}
        for k, v in source.items():
            upper = k.upper()
            if k in safe_allowlist:
                clean[k] = v
                continue
            if any(sub in upper for sub in self.SENSITIVE_ENV_SUBSTRINGS):
                continue
            if len(v) >= 24 and self.shannon_entropy(v) >= 4.4:
                continue
            clean[k] = v
        clean["ELY_LAB_ISOLATED"] = "1"
        clean["ELY_NO_PROD_CREDENTIALS"] = "1"
        clean["NO_PROXY"] = "*"
        clean["HTTP_PROXY"] = "http://127.0.0.1:0"
        clean["HTTPS_PROXY"] = "http://127.0.0.1:0"
        return clean


class ScopeGuard:
    """
    Runtime enforcer ensuring every security tool, fuzzer, red-team payload, and
    validator stays strictly inside the signed lab ScopeManifesto.
    """

    BLOCKED_CLOUD_METADATA_HOSTS: Set[str] = {
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.goog",
        "100.100.100.200",
        "fd00:ec2::254",
    }

    def __init__(self, manifesto: ScopeManifesto, keyring: AuditorKeyring) -> None:
        if not manifesto.verify(keyring):
            raise ScopeViolationError("ScopeManifesto signature verification failed! Refusing to execute.")
        if manifesto.allow_main_instance_writes:
            raise ScopeViolationError(
                "Architectural violation: Temporary Adversarial Instance may NEVER hold write permission to Main Instance!"
            )
        self.manifesto = manifesto
        self.target_root = Path(manifesto.target_root).resolve()
        self.sandbox_root = Path(manifesto.sandbox_root).resolve()
        self.audit_blocks: List[Dict[str, Any]] = []

    def assert_tool_authorized(self, tool_name: str) -> None:
        if tool_name not in self.manifesto.allowed_tools:
            self._log_block("tool", tool_name, "Tool not listed in signed ScopeManifesto")
            raise ScopeViolationError(f"Tool '{tool_name}' is not authorized by ScopeManifesto {self.manifesto.manifest_id}")

    def assert_write_path_in_sandbox(self, path: str | Path) -> Path:
        resolved = Path(path).resolve()
        # Reject any write to Main Instance target_root!
        if resolved == self.target_root or self.target_root in resolved.parents:
            self._log_block("fs_write", str(resolved), "Blocked write attempt targeting Ely Main Instance")
            raise ScopeViolationError(
                f"MAIN INSTANCE PROTECTION: Blocked write attempt to '{resolved}' inside main target '{self.target_root}'"
            )
        if not (resolved == self.sandbox_root or self.sandbox_root in resolved.parents):
            self._log_block("fs_write", str(resolved), "Blocked write outside isolated sandbox root")
            raise ScopeViolationError(
                f"SANDBOX CONTAINMENT: Write path '{resolved}' escapes sandbox root '{self.sandbox_root}'"
            )
        return resolved

    def assert_read_path_in_scope(self, path: str | Path) -> Path:
        resolved = Path(path).resolve()
        in_sandbox = resolved == self.sandbox_root or self.sandbox_root in resolved.parents
        in_target = resolved == self.target_root or self.target_root in resolved.parents
        if not (in_sandbox or in_target):
            self._log_block("fs_read", str(resolved), "Read path outside both sandbox and authorized target")
            raise ScopeViolationError(f"Path '{resolved}' is outside authorized evaluation scope")
        return resolved

    def assert_network_target_authorized(self, target_url_or_host: str) -> None:
        host = target_url_or_host
        if "://" in target_url_or_host:
            parsed = urlparse(target_url_or_host)
            host = parsed.hostname or ""
        host = host.strip().lower()

        if host in self.BLOCKED_CLOUD_METADATA_HOSTS:
            self._log_block("network", host, "Blocked cloud metadata SSRF endpoint")
            raise ScopeViolationError(f"Network target '{host}' is a forbidden cloud metadata endpoint")

        if not self.manifesto.allow_external_network:
            if host in self.manifesto.allowed_hosts:
                return
            try:
                ip = ipaddress.ip_address(host)
                if ip.is_loopback:
                    return
            except ValueError:
                pass
            self._log_block("network", host, "External network access strictly disabled in isolated lab mode")
            raise ScopeViolationError(
                f"LAB-ONLY NETWORK CONTAINMENT: External target '{host}' blocked (loopback/sandbox only)"
            )

    def _log_block(self, kind: str, target: str, reason: str) -> None:
        self.audit_blocks.append(
            {
                "kind": kind,
                "target": target,
                "reason": reason,
                "timestamp": utc_now_iso(),
            }
        )


def compute_directory_tree_digest(root: Path, ignore_dirs: Sequence[str] = (".git", "__pycache__", ".venv", "node_modules")) -> str:
    """
    Compute a deterministic cryptographic digest of every file path and file content
    under `root`. Used to mathematically prove the Ely Main Instance was NEVER
    modified during an adversarial evaluation run.
    """
    ignore_set = set(ignore_dirs)
    records: List[str] = []
    root_resolved = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root_resolved):
        dirnames[:] = sorted(d for d in dirnames if d not in ignore_set)
        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            if fpath.is_symlink():
                rel = fpath.relative_to(root_resolved).as_posix()
                records.append(f"L:{rel}->{os.readlink(fpath)}")
                continue
            try:
                rel = fpath.relative_to(root_resolved).as_posix()
                file_hash = hashlib.sha256(fpath.read_bytes()).hexdigest()
                records.append(f"F:{rel}:{file_hash}")
            except OSError:
                continue
    return sha256_hex("\n".join(records))
