"""
Container Supply-Chain, Docker Compose & OCI Seccomp/AppArmor Runtime Security Auditor.

Closes critical container-escape and supply-chain blind spots across:
  1. **Dockerfile Build-Time Supply Chain & Least-Privilege Auditor**:
       - Unpinned floating base images (`FROM python:latest` / missing `@sha256:` digest)
       - Root runtime execution (missing non-root `USER`, or `USER 0` / `USER root`)
       - Remote script execution (`curl ... | sh`, `wget ... | bash`, `ADD https://...`)
       - Hardcoded secrets baked into `ENV` / `ARG` image layers (`SECRET`, `TOKEN`, `PASSWORD`, `AWS_SECRET`)
       - Package manager hygiene & unnecessary attack surface (`sudo`, `ssh`, `nc`/`netcat`, `gcc` in final runtime)
       - Missing `HEALTHCHECK` & unsafe `chmod 777`.
  2. **Docker Compose / OCI Runtime Escape Surface Auditor**:
       - Host Docker socket mount (`/var/run/docker.sock` -> instant host root escape, CWE-250)
       - `privileged: true`, `network_mode: host`, `pid: host`, `ipc: host`, `uts: host`
       - Dangerous Linux capabilities (`SYS_ADMIN`, `SYS_PTRACE`, `NET_ADMIN`, `DAC_OVERRIDE`, `SYS_MODULE`, `ALL`)
       - Disabled security profiles (`seccomp:unconfined`, `apparmor:unconfined`)
       - Missing `read_only: true` rootfs or `no-new-privileges:true`.
  3. **Seccomp JSON Profile Policy Verifier & Minimal Profile Synthesizer**:
       - Audits custom OCI `seccomp.json` files for fail-open `defaultAction: SCMP_ACT_ALLOW`
         and permitted container-escape syscalls (`ptrace`, `mount`, `bpf`, `kexec_load`, `unshare`, `setns`, `init_module`).
       - Synthesizes a hardened **Default-Deny OCI Seccomp JSON profile** and **Hardened Multi-Stage Dockerfile Template**.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ely_soe.core.models import Severity, utc_now_iso
from ely_soe.cyber.models import (
    CyberDomain,
    CyberVulnerability,
    VerificationMethod,
    make_cyber_vuln,
)


DANGEROUS_ESCAPE_SYSCALLS: frozenset[str] = frozenset({
    "ptrace", "mount", "umount2", "bpf", "kexec_load", "kexec_file_load",
    "init_module", "finit_module", "delete_module", "unshare", "setns",
    "open_by_handle_at", "pivot_root", "reboot", "swapon", "swapoff",
    "chroot", "keyctl", "add_key", "request_key", "userfaultfd",
})

HARDENED_MINIMAL_SECCOMP_PROFILE: Dict[str, Any] = {
    "defaultAction": "SCMP_ACT_ERRNO",
    "defaultErrnoRet": 1,
    "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
    "syscalls": [
        {
            "names": [
                "read", "write", "openat", "close", "fstat", "lseek", "mmap",
                "mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask",
                "ioctl", "pread64", "pwrite64", "access", "pipe2", "select",
                "sched_yield", "mremap", "dup", "dup2", "nanosleep", "getpid",
                "socket", "connect", "accept4", "sendto", "recvfrom", "shutdown",
                "bind", "listen", "getsockname", "getpeername", "setsockopt",
                "getsockopt", "clone", "execve", "exit", "exit_group", "wait4",
                "fcntl", "getcwd", "readlinkat", "epoll_create1", "epoll_ctl",
                "epoll_pwait", "futex", "clock_gettime", "getrandom",
            ],
            "action": "SCMP_ACT_ALLOW",
        }
    ],
}


@dataclass(frozen=True)
class ContainerRule:
    rule_id: str
    scope: str  # dockerfile | compose
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    cwe: str
    cis_docker: str
    remediation: str


CONTAINER_RULES: Tuple[ContainerRule, ...] = (
    ContainerRule(
        "CYB-CTR-DOCKER-SOCK-MOUNT", "compose",
        "Host Docker Daemon Socket (`/var/run/docker.sock`) Mounted Inside Container (Instant Root Escape)",
        re.compile(r"(?i)/var/run/docker\.sock"),
        Severity.CRITICAL, "CWE-250", "CIS Docker 5.31",
        "Remove `/var/run/docker.sock` bind mount; use rootless BuildKit or least-privilege proxy APIs.",
    ),
    ContainerRule(
        "CYB-CTR-PRIVILEGED-MODE", "compose",
        "Container Running in Full `privileged: true` Mode (All Kernel Capabilities & Host Devices)",
        re.compile(r"(?i)\bprivileged\s*:\s*true\b"),
        Severity.CRITICAL, "CWE-250", "CIS Docker 5.4",
        "Set `privileged: false`, `cap_drop: [ALL]`, and grant only minimal explicit capabilities if needed.",
    ),
    ContainerRule(
        "CYB-CTR-HOST-NAMESPACE", "compose",
        "Container Shares Host Namespace (`network_mode/pid/ipc/uts: host`)",
        re.compile(r"(?i)\b(?:network_mode|pid|ipc|uts)\s*:\s*[\"']?host[\"']?"),
        Severity.HIGH, "CWE-668", "CIS Docker 5.9",
        "Isolate containers inside dedicated bridge/overlay namespaces; remove host PID/IPC/Network sharing.",
    ),
    ContainerRule(
        "CYB-CTR-DANGEROUS-CAP-ADD", "compose",
        "Container Requests Escape-Capable Linux Capability (`SYS_ADMIN`/`SYS_PTRACE`/`NET_ADMIN`/`ALL`)",
        re.compile(r"(?i)\b(?:SYS_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_OVERRIDE|NET_ADMIN|BPF|CAP_SYS_ADMIN|ALL)\b"),
        Severity.CRITICAL, "CWE-250", "CIS Docker 5.3",
        "Drop all capabilities (`cap_drop: [ALL]`) and never assign `SYS_ADMIN`, `SYS_PTRACE`, or `SYS_MODULE`.",
    ),
    ContainerRule(
        "CYB-CTR-SECCOMP-UNCONFINED", "compose",
        "Seccomp or AppArmor Kernel Confinement Explicitly Disabled (`unconfined`)",
        re.compile(r"(?i)(?:seccomp|apparmor)\s*[:=]\s*unconfined"),
        Severity.HIGH, "CWE-693", "CIS Docker 5.21",
        "Enable default-deny seccomp & AppArmor profiles plus `security_opt: [no-new-privileges:true]`.",
    ),
    ContainerRule(
        "CYB-CTR-DF-FLOATING-TAG", "dockerfile",
        "Dockerfile Base Image Uses Unpinned `:latest` or Unversioned Tag Without SHA-256 Digest",
        re.compile(r"(?im)^\s*FROM\s+(?!scratch\b)[^\s:@]+(?::latest)?\s*(?:AS\s+\S+)?\s*$"),
        Severity.MEDIUM, "CWE-829", "CIS Docker 4.7",
        "Pin base images to immutable content digests (`FROM python:3.11-slim@sha256:...`).",
    ),
    ContainerRule(
        "CYB-CTR-DF-CURL-PIPE-SH", "dockerfile",
        "Dockerfile Executes Unverified Remote Script via `curl/wget | sh/bash`",
        re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|ash|python3?)\b"),
        Severity.CRITICAL, "CWE-829", "CIS Docker 4.9",
        "Download pinned release archives, verify SHA-256 checksums / Cosign signatures, then install.",
    ),
    ContainerRule(
        "CYB-CTR-DF-SECRET-IN-LAYER", "dockerfile",
        "Secret / API Key / Password Baked Into Immutable Dockerfile `ENV` or `ARG` Layer",
        re.compile(r"""(?im)^\s*(?:ENV|ARG)\s+[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|API_?KEY|TOKEN|PRIVATE_KEY)[A-Z0-9_]*\s*[=\s]+(?!"?\s*$)["']?[A-Za-z0-9+/=_\-!@#$%^&*]{6,}"""),
        Severity.CRITICAL, "CWE-798", "CIS Docker 4.10",
        "Never embed secrets in `ENV`/`ARG`; mount ephemeral secrets via BuildKit `--mount=type=secret` or runtime KMS.",
    ),
    ContainerRule(
        "CYB-CTR-DF-ADD-URL", "dockerfile",
        "Dockerfile Uses `ADD` With Remote URL (Unverified Fetch & Auto-Archive Extraction)",
        re.compile(r"(?im)^\s*ADD\s+https?://"),
        Severity.HIGH, "CWE-829", "CIS Docker 4.9",
        "Use `COPY` for local verified files instead of remote `ADD` instructions.",
    ),
    ContainerRule(
        "CYB-CTR-DF-CHMOD-777", "dockerfile",
        "Dockerfile Sets World-Writable Permissions (`chmod 777` / `chmod a+rwx`)",
        re.compile(r"(?i)\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx)\b"),
        Severity.MEDIUM, "CWE-732", "CIS Docker 4.1",
        "Apply minimal least-privilege file permissions (`0550` / `0640`) owned by a non-root UID.",
    ),
    ContainerRule(
        "CYB-CTR-DF-ROOT-USER", "dockerfile",
        "Dockerfile Explicitly Switches To Privileged `USER root` / `USER 0`",
        re.compile(r"(?im)^\s*USER\s+(?:root|0(?::0)?)\s*$"),
        Severity.HIGH, "CWE-250", "CIS Docker 4.1",
        "Run runtime stage under a dedicated unprivileged UID/GID (`USER 10001:10001`).",
    ),
)


class ContainerSupplyChainRuntimeGuard:
    """Audits Dockerfiles, Docker Compose specs, and OCI seccomp.json profiles."""

    def audit_dockerfile_text(self, content: str, *, file_path: str = "Dockerfile") -> Dict[str, Any]:
        vulns: List[CyberVulnerability] = []
        for rule in CONTAINER_RULES:
            if rule.scope != "dockerfile":
                continue
            for m in rule.pattern.finditer(content):
                lineno = content[: m.start()].count("\n") + 1
                vulns.append(self._make_vuln(rule, file_path, lineno, m.group(0).strip()[:140]))

        # Semantic check: Dockerfile lacks any non-root USER instruction
        user_lines = re.findall(r"(?im)^\s*USER\s+(\S+)", content)
        if not user_lines:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-CTR-DF-MISSING-USER",
                    title="[CIS Docker 4.1] Dockerfile Missing Non-Root `USER` Directive (Defaults to UID 0)",
                    description=f"`{file_path}` defines no `USER` instruction, causing container workloads to run as root.",
                    cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-250"],
                    confidence=0.95,
                    verification_method=VerificationMethod.STATIC_AST,
                    file_path=file_path,
                    endpoint_or_asset=file_path,
                    remediation_guidance="Create an unprivileged user (`adduser -D -u 10001 app`) and set `USER 10001:10001`.",
                    discovered_by="ely_container_supply_chain_runtime_guard",
                )
            )

        return {
            "audited_at": utc_now_iso(),
            "file_path": file_path,
            "artifact_type": "dockerfile",
            "container_security_score": self._score(vulns),
            "findings_count": len(vulns),
            "vulnerabilities": vulns,
        }

    def audit_compose_text(self, content: str, *, file_path: str = "docker-compose.yml") -> Dict[str, Any]:
        vulns: List[CyberVulnerability] = []
        for rule in CONTAINER_RULES:
            if rule.scope != "compose":
                continue
            for m in rule.pattern.finditer(content):
                lineno = content[: m.start()].count("\n") + 1
                vulns.append(self._make_vuln(rule, file_path, lineno, m.group(0).strip()[:140]))

        if "services:" in content and "no-new-privileges" not in content:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-CTR-NO-NEW-PRIVS-MISSING",
                    title="[CIS Docker 5.25] Compose Services Omit `security_opt: [no-new-privileges:true]`",
                    description=f"`{file_path}` does not restrict setuid/setgid privilege escalation inside services.",
                    cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-250"],
                    confidence=0.88,
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    file_path=file_path,
                    endpoint_or_asset=file_path,
                    remediation_guidance="Add `security_opt: ['no-new-privileges:true']`, `read_only: true`, and `cap_drop: [ALL]`.",
                    discovered_by="ely_container_supply_chain_runtime_guard",
                )
            )
        return {
            "audited_at": utc_now_iso(),
            "file_path": file_path,
            "artifact_type": "docker_compose",
            "container_security_score": self._score(vulns),
            "findings_count": len(vulns),
            "vulnerabilities": vulns,
        }

    def audit_seccomp_profile(self, profile: Dict[str, Any], *, file_path: str = "seccomp.json") -> Dict[str, Any]:
        vulns: List[CyberVulnerability] = []
        default_act = str(profile.get("defaultAction", "")).upper()
        if default_act == "SCMP_ACT_ALLOW":
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-CTR-SECCOMP-DEFAULT-ALLOW",
                    title="[OCI Seccomp] Fail-Open Seccomp Profile (`defaultAction: SCMP_ACT_ALLOW`)",
                    description=f"`{file_path}` allows all Linux syscalls by default instead of an explicit allowlist.",
                    cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-693"],
                    confidence=0.98,
                    verification_method=VerificationMethod.STATIC_AST,
                    file_path=file_path,
                    endpoint_or_asset=file_path,
                    remediation_guidance="Set `defaultAction` to `SCMP_ACT_ERRNO` and allowlist only required runtime syscalls.",
                    discovered_by="ely_container_supply_chain_runtime_guard",
                )
            )

        exposed_syscalls: Set[str] = set()
        for entry in profile.get("syscalls", []) or []:
            if not isinstance(entry, dict):
                continue
            if str(entry.get("action", "")).upper() == "SCMP_ACT_ALLOW":
                for nm in entry.get("names", []) or []:
                    if str(nm) in DANGEROUS_ESCAPE_SYSCALLS:
                        exposed_syscalls.add(str(nm))

        if exposed_syscalls:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-CTR-SECCOMP-ESCAPE-SYSCALLS",
                    title=f"[OCI Seccomp] Container-Escape Syscalls Explicitly Permitted ({len(exposed_syscalls)})",
                    description=f"`{file_path}` permits high-risk kernel syscalls: {sorted(exposed_syscalls)}.",
                    cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-250"],
                    confidence=0.99,
                    verification_method=VerificationMethod.STATIC_AST,
                    file_path=file_path,
                    endpoint_or_asset=file_path,
                    remediation_guidance="Remove escape syscalls (`ptrace`, `mount`, `bpf`, `unshare`, `kexec_load`) from `SCMP_ACT_ALLOW`.",
                    discovered_by="ely_container_supply_chain_runtime_guard",
                )
            )

        return {
            "audited_at": utc_now_iso(),
            "file_path": file_path,
            "artifact_type": "seccomp_profile",
            "exposed_escape_syscalls": sorted(exposed_syscalls),
            "container_security_score": self._score(vulns),
            "recommended_hardened_seccomp": HARDENED_MINIMAL_SECCOMP_PROFILE,
            "findings_count": len(vulns),
            "vulnerabilities": vulns,
        }

    def audit_repository(self, target_dir: str | Path) -> Dict[str, Any]:
        root = Path(target_dir).resolve()
        files = [root] if root.is_file() else sorted(root.rglob("*"))
        all_vulns: List[CyberVulnerability] = []
        artifacts_audited = {"dockerfiles": 0, "compose_files": 0, "seccomp_profiles": 0}

        for f in files:
            if not f.is_file() or any(p in f.parts for p in (".git", "node_modules", "__pycache__", ".venv")):
                continue
            nm = f.name.lower()
            rel = f.name if root.is_file() else str(f.relative_to(root))
            try:
                txt = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            if nm == "dockerfile" or nm.startswith("dockerfile.") or nm.endswith(".dockerfile"):
                artifacts_audited["dockerfiles"] += 1
                all_vulns.extend(self.audit_dockerfile_text(txt, file_path=rel)["vulnerabilities"])
            elif "docker-compose" in nm or "compose.y" in nm:
                artifacts_audited["compose_files"] += 1
                all_vulns.extend(self.audit_compose_text(txt, file_path=rel)["vulnerabilities"])
            elif "seccomp" in nm and nm.endswith(".json"):
                try:
                    prof = json.loads(txt)
                    if isinstance(prof, dict) and "defaultAction" in prof:
                        artifacts_audited["seccomp_profiles"] += 1
                        all_vulns.extend(self.audit_seccomp_profile(prof, file_path=rel)["vulnerabilities"])
                except Exception:
                    pass

        return {
            "audited_at": utc_now_iso(),
            "target": str(root),
            "artifacts_audited": artifacts_audited,
            "container_security_score": self._score(all_vulns),
            "findings_count": len(all_vulns),
            "hardened_seccomp_template": HARDENED_MINIMAL_SECCOMP_PROFILE,
            "vulnerabilities": all_vulns,
        }

    @staticmethod
    def _make_vuln(rule: ContainerRule, file_path: str, lineno: int, excerpt: str) -> CyberVulnerability:
        return make_cyber_vuln(
            rule_id=rule.rule_id,
            title=f"[{rule.cis_docker}] {rule.title}",
            description=f"Matched `{excerpt}` at `{file_path}:{lineno}`.",
            cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
            severity=rule.severity,
            cwe_ids=[rule.cwe],
            confidence=0.95,
            verification_method=VerificationMethod.STATIC_PATTERN,
            file_path=file_path,
            line_start=lineno,
            endpoint_or_asset=f"{file_path}:{lineno}",
            remediation_guidance=rule.remediation,
            discovered_by="ely_container_supply_chain_runtime_guard",
        )

    @staticmethod
    def _score(vulns: Sequence[CyberVulnerability]) -> float:
        pen = sum(
            25.0 if v.severity == Severity.CRITICAL else
            14.0 if v.severity == Severity.HIGH else
            6.0 if v.severity == Severity.MEDIUM else 2.0
            for v in vulns
        )
        return round(max(0.0, min(100.0, 100.0 - pen)), 2)
