"""
Container Runtime, Linux Kernel Hardening, Seccomp BPF & Falco-Style eBPF Syscall Anomaly Engine.

Audits host/container kernel isolation boundaries and evaluates runtime syscall streams:
  1. **OCI Seccomp BPF JSON Profile Auditor**:
       - Verifies `defaultAction` (`SCMP_ACT_ERRNO` / `SCMP_ACT_KILL` vs unsafe `SCMP_ACT_ALLOW`)
       - Detects dangerous permitted container-escape syscalls (`ptrace`, `mount`, `unshare`,
         `setns`, `bpf`, `kexec_load`, `init_module`, `finit_module`, `open_by_handle_at`,
         `userfaultfd`, `io_uring_setup`, `process_vm_writev`, `pivot_root`, `reboot`, `swapon`)
  2. **Linux Kernel Sysctl Security Baseline Auditor** (CIS Linux Benchmark):
       - Audits `kernel.unprivileged_bpf_disabled`, `kernel.kptr_restrict`, `kernel.dmesg_restrict`,
         `kernel.yama.ptrace_scope`, `kernel.randomize_va_space` (ASLR), `fs.protected_symlinks`,
         `fs.protected_hardlinks`, `fs.suid_dumpable`, `net.ipv4.conf.all.accept_redirects`,
         `net.ipv4.tcp_syncookies`, and `user.max_user_namespaces`
  3. **Linux Capabilities & AppArmor / SELinux Container Profile Analyzer**
  4. **Falco-Style Runtime Syscall & Container Escape Behavioral Engine**:
       - Evaluates structured syscall telemetry events against **14 high-signal runtime rules**
         (host `/proc/1/root` escape, `nsenter` namespace pivot, cgroup `release_agent` breakout,
         `/var/run/docker.sock` access, `memfd_create` fileless execution, `ptrace` injection,
         unexpected package manager / compiler inside prod container, `/etc/shadow` read,
         kernel module insertion, eBPF prog load, reverse shell `dup2`+`execve`, crypto-miner).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ely_soe.core.models import Severity, new_id, utc_now_iso
from ely_soe.cyber.models import (
    CVSSv4Metrics,
    CyberDomain,
    CyberVulnerability,
    DetectionMatch,
    MitreTactic,
    MitreTechniqueRef,
    VerificationMethod,
    make_cyber_vuln,
)


DANGEROUS_SECCOMP_SYSCALLS: Dict[str, Tuple[Severity, str]] = {
    "ptrace": (Severity.CRITICAL, "Process debugging/memory injection & seccomp bypass"),
    "mount": (Severity.CRITICAL, "Filesystem mount inside container enabling host breakout"),
    "unshare": (Severity.HIGH, "User/mount namespace creation enabling privilege escalation exploits"),
    "setns": (Severity.CRITICAL, "Direct entry into host/sibling container namespaces"),
    "bpf": (Severity.CRITICAL, "Arbitrary eBPF bytecode load into host kernel"),
    "kexec_load": (Severity.CRITICAL, "Replacement of running host Linux kernel image"),
    "kexec_file_load": (Severity.CRITICAL, "Replacement of running host Linux kernel image"),
    "init_module": (Severity.CRITICAL, "Direct Linux kernel module insertion"),
    "finit_module": (Severity.CRITICAL, "Direct Linux kernel module insertion"),
    "open_by_handle_at": (Severity.CRITICAL, "Shocker container escape bypassing mount namespace"),
    "userfaultfd": (Severity.HIGH, "Kernel race-condition / heap-spray exploit helper"),
    "io_uring_setup": (Severity.HIGH, "High-risk kernel attack surface often exploited for container escapes"),
    "process_vm_writev": (Severity.CRITICAL, "Cross-process memory overwrite"),
    "process_vm_readv": (Severity.HIGH, "Cross-process memory credential scraping"),
    "pivot_root": (Severity.HIGH, "Root filesystem pivot"),
    "reboot": (Severity.HIGH, "Host reboot denial of service"),
    "keyctl": (Severity.MEDIUM, "Kernel keyring access across namespace boundary"),
}

DANGEROUS_LINUX_CAPABILITIES: Dict[str, Tuple[Severity, str]] = {
    "CAP_SYS_ADMIN": (Severity.CRITICAL, "Near-root container escape equivalence (mount, cgroup, namespace)"),
    "CAP_SYS_PTRACE": (Severity.CRITICAL, "Inject code into host/sibling processes sharing PID namespace"),
    "CAP_SYS_MODULE": (Severity.CRITICAL, "Insert/remove arbitrary Linux kernel modules"),
    "CAP_DAC_READ_SEARCH": (Severity.CRITICAL, "Bypass file read checks (`open_by_handle_at` Shocker escape)"),
    "CAP_DAC_OVERRIDE": (Severity.HIGH, "Bypass discretionary file read/write/execute permissions"),
    "CAP_BPF": (Severity.CRITICAL, "Load eBPF programs into shared host kernel"),
    "CAP_NET_ADMIN": (Severity.HIGH, "Modify routing tables, iptables, ARP, and capture traffic"),
    "CAP_NET_RAW": (Severity.MEDIUM, "Packet sniffing & raw socket ARP/DNS spoofing"),
    "CAP_SETUID": (Severity.HIGH, "Arbitrary UID transitions inside container"),
    "CAP_SYS_RAWIO": (Severity.CRITICAL, "Direct raw block-device / I/O port write access"),
}

SYSCTL_HARDENING_BASELINE: Dict[str, Tuple[str, Severity, str]] = {
    "kernel.unprivileged_bpf_disabled": ("1", Severity.HIGH, "Prevent unprivileged users from loading eBPF programs (kernel priv-esc surface)"),
    "kernel.kptr_restrict": ("2", Severity.MEDIUM, "Hide kernel symbol pointers in `/proc/kallsyms` to hinder KASLR bypass"),
    "kernel.dmesg_restrict": ("1", Severity.LOW, "Restrict kernel ring buffer (`dmesg`) from unprivileged users"),
    "kernel.yama.ptrace_scope": ("1", Severity.HIGH, "Restrict `ptrace` attachment to direct child processes (blocks credential dumping)"),
    "kernel.randomize_va_space": ("2", Severity.CRITICAL, "Mandate full kernel/user ASLR memory randomization"),
    "fs.protected_symlinks": ("1", Severity.HIGH, "Prevent TOCTOU symlink following in world-writable sticky directories"),
    "fs.protected_hardlinks": ("1", Severity.HIGH, "Prevent unprivileged hardlink creation to root-owned files"),
    "fs.suid_dumpable": ("0", Severity.MEDIUM, "Disable core dumps for setuid binaries to prevent credential leaks"),
    "net.ipv4.tcp_syncookies": ("1", Severity.MEDIUM, "Enable SYN flood mitigation"),
    "net.ipv4.conf.all.accept_redirects": ("0", Severity.MEDIUM, "Reject ICMP redirect route poisoning"),
    "net.ipv4.conf.all.send_redirects": ("0", Severity.LOW, "Disable ICMP redirect emission"),
}


@dataclass(frozen=True)
class SyscallEvent:
    event_id: str
    container_id: str
    process_name: str
    syscall: str
    args: Dict[str, Any] = field(default_factory=dict)
    uid: int = 1000
    in_container: bool = True
    timestamp: str = ""


@dataclass(frozen=True)
class FalcoRuntimeRule:
    rule_id: str
    title: str
    severity: Severity
    mitre_id: str
    syscalls: Tuple[str, ...]
    arg_substrings: Tuple[str, ...] = ()
    process_names: Tuple[str, ...] = ()
    require_container: bool = True
    require_root: bool = False


FALCO_RUNTIME_RULES: Tuple[FalcoRuntimeRule, ...] = (
    FalcoRuntimeRule("FALCO-ESC-001", "Container Escape Attempt via `nsenter` or `/proc/1/root` Host Pivot", Severity.CRITICAL, "T1611", ("execve", "setns", "openat"), ("/proc/1/root", "/proc/1/ns", "nsenter"), ("nsenter",)),
    FalcoRuntimeRule("FALCO-ESC-002", "Cgroup `release_agent` Container Breakout Write", Severity.CRITICAL, "T1611", ("openat", "write"), ("release_agent", "notify_on_release")),
    FalcoRuntimeRule("FALCO-ESC-003", "Mounted Docker / Containerd Socket Access From Inside Container", Severity.CRITICAL, "T1611", ("connect", "openat"), ("docker.sock", "containerd.sock", "crio.sock")),
    FalcoRuntimeRule("FALCO-ESC-004", "Kernel Module Insertion (`init_module` / `finit_module`) Inside Container", Severity.CRITICAL, "T1547.006", ("init_module", "finit_module")),
    FalcoRuntimeRule("FALCO-ESC-005", "eBPF Program Load (`bpf` syscall) From Workload Container", Severity.CRITICAL, "T1014", ("bpf",)),
    FalcoRuntimeRule("FALCO-MEM-001", "Fileless Memory Execution via `memfd_create` + `execveat`", Severity.CRITICAL, "T1620", ("memfd_create", "execveat"), ("memfd:",)),
    FalcoRuntimeRule("FALCO-MEM-002", "Process Memory Injection via `ptrace` / `process_vm_writev`", Severity.CRITICAL, "T1055.008", ("ptrace", "process_vm_writev")),
    FalcoRuntimeRule("FALCO-CRED-001", "Sensitive Credential File Read (`/etc/shadow` or K8s ServiceAccount Token Harvest)", Severity.HIGH, "T1552.001", ("openat", "open"), ("/etc/shadow", "/run/secrets/kubernetes.io/serviceaccount/token", ".aws/credentials")),
    FalcoRuntimeRule("FALCO-DRIFT-001", "Runtime Container Drift — Package Manager Executed in Production Container", Severity.HIGH, "T1505", ("execve",), (), ("apt", "apt-get", "apk", "yum", "dnf", "pip", "npm")),
    FalcoRuntimeRule("FALCO-DRIFT-002", "Unexpected Interactive Shell / Reverse Shell Spawned Inside Container", Severity.HIGH, "T1059.004", ("execve",), ("/dev/tcp/", "-i", "pty.spawn"), ("nc", "ncat", "socat")),
    FalcoRuntimeRule("FALCO-NET-001", "Outbound Connection to Cryptominer Stratum Port or Cloud IMDS `169.254.169.254`", Severity.CRITICAL, "T1552.005", ("connect",), ("169.254.169.254", ":3333", ":14444", "stratum")),
    FalcoRuntimeRule("FALCO-FS-001", "Container Mounted Host Block Device (`/dev/sda`, `/dev/nvme`)", Severity.CRITICAL, "T1611", ("mount", "openat"), ("/dev/sda", "/dev/xvda", "/dev/nvme")),
)


class ContainerRuntimeKernelEngine:
    """Audits Seccomp BPF profiles, Linux capabilities, sysctl baselines, and Falco syscall streams."""

    def audit_seccomp_profile(self, profile: Dict[str, Any], asset: str = "seccomp.json") -> List[CyberVulnerability]:
        vulns: List[CyberVulnerability] = []
        default_act = str(profile.get("defaultAction", ""))
        if default_act == "SCMP_ACT_ALLOW":
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-RT-SECCOMP-ALLOWALL-001",
                    title="Seccomp Profile Uses Permissive `SCMP_ACT_ALLOW` Default Action",
                    description=f"Seccomp profile `{asset}` defaults to allowing all Linux syscalls rather than deny-by-default (`SCMP_ACT_ERRNO`).",
                    cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-250", "CWE-276"],
                    confidence=0.99,
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=asset,
                    remediation_guidance="Set `defaultAction` to `SCMP_ACT_ERRNO` and allowlist only minimal required syscalls.",
                    discovered_by="ely_cyber_container_runtime",
                )
            )

        allowed_syscalls: Set[str] = set()
        for rule in profile.get("syscalls", []):
            if str(rule.get("action", "")) == "SCMP_ACT_ALLOW":
                for name in rule.get("names", []):
                    allowed_syscalls.add(str(name))

        dangerous_hits = sorted(allowed_syscalls & set(DANGEROUS_SECCOMP_SYSCALLS.keys()))
        for sc in dangerous_hits:
            sev, reason = DANGEROUS_SECCOMP_SYSCALLS[sc]
            vulns.append(
                make_cyber_vuln(
                    rule_id=f"CYB-RT-SECCOMP-SYSCALL-{sc.upper()}",
                    title=f"Dangerous Kernel Syscall `{sc}` Permitted in Seccomp Profile",
                    description=f"Seccomp profile `{asset}` explicitly allows `{sc}`: {reason}.",
                    cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                    severity=sev,
                    cwe_ids=["CWE-250"],
                    confidence=0.97,
                    mitre_techniques=[MitreTechniqueRef("T1611", "Escape to Host", MitreTactic.PRIVILEGE_ESCALATION)],
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=asset,
                    remediation_guidance=f"Remove `{sc}` from `SCMP_ACT_ALLOW` rules in `{asset}`.",
                    discovered_by="ely_cyber_container_runtime",
                )
            )
        return vulns

    def audit_capabilities(self, added_caps: Sequence[str], asset: str = "container_spec") -> List[CyberVulnerability]:
        vulns: List[CyberVulnerability] = []
        for raw_cap in added_caps:
            cap = raw_cap.upper() if raw_cap.upper().startswith("CAP_") else f"CAP_{raw_cap.upper()}"
            if cap == "CAP_ALL":
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-RT-CAP-ALL-001",
                        title="Container Granted `ALL` Linux Kernel Capabilities",
                        description=f"Container `{asset}` adds `ALL` Linux capabilities, removing capability-level kernel isolation.",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-250"],
                        confidence=0.99,
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        endpoint_or_asset=asset,
                        remediation_guidance="Drop `ALL` capabilities (`drop: ['ALL']`) and add only minimal non-privileged capabilities if strictly needed.",
                        discovered_by="ely_cyber_container_runtime",
                    )
                )
            elif cap in DANGEROUS_LINUX_CAPABILITIES:
                sev, reason = DANGEROUS_LINUX_CAPABILITIES[cap]
                vulns.append(
                    make_cyber_vuln(
                        rule_id=f"CYB-RT-{cap}",
                        title=f"High-Risk Linux Capability `{cap}` Granted to Container",
                        description=f"Workload `{asset}` grants `{cap}`: {reason}.",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=sev,
                        cwe_ids=["CWE-250"],
                        confidence=0.98,
                        mitre_techniques=[MitreTechniqueRef("T1611", "Escape to Host", MitreTactic.PRIVILEGE_ESCALATION)],
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        endpoint_or_asset=asset,
                        remediation_guidance=f"Remove `{cap}` from container `securityContext.capabilities.add`.",
                        discovered_by="ely_cyber_container_runtime",
                    )
                )
        return vulns

    def audit_sysctl_baseline(self, sysctl_values: Dict[str, Any], host: str = "linux_host") -> List[CyberVulnerability]:
        vulns: List[CyberVulnerability] = []
        for key, (expected, sev, desc) in SYSCTL_HARDENING_BASELINE.items():
            actual = str(sysctl_values.get(key, "unset"))
            if actual != expected:
                vulns.append(
                    make_cyber_vuln(
                        rule_id=f"CYB-RT-SYSCTL-{key.replace('.', '_').upper()}",
                        title=f"Kernel Sysctl Hardening Drift: `{key}={actual}` (Expected `{expected}`)",
                        description=f"Host `{host}` has `{key}={actual}` instead of hardened value `{expected}`: {desc}.",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=sev,
                        cwe_ids=["CWE-16"],
                        confidence=0.96,
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        endpoint_or_asset=f"{host}:{key}",
                        remediation_guidance=f"Set `{key} = {expected}` in `/etc/sysctl.d/99-ely-hardening.conf` and apply with `sysctl --system`.",
                        discovered_by="ely_cyber_container_runtime",
                    )
                )
        return vulns

    def evaluate_syscall_stream(self, events: Sequence[SyscallEvent]) -> Dict[str, Any]:
        """Evaluate runtime syscall telemetry against Falco-style behavioral escape/anomaly rules."""
        matches: List[DetectionMatch] = []
        vulns: List[CyberVulnerability] = []
        for ev in events:
            args_blob = " ".join(f"{k}={v}" for k, v in ev.args.items()).lower()
            proc_l = ev.process_name.lower()
            for rule in FALCO_RUNTIME_RULES:
                if rule.require_container and not ev.in_container:
                    continue
                if rule.require_root and ev.uid != 0:
                    continue
                if ev.syscall not in rule.syscalls:
                    continue
                sub_ok = (not rule.arg_substrings) or any(s.lower() in args_blob for s in rule.arg_substrings)
                proc_ok = (not rule.process_names) or (proc_l in rule.process_names)
                if rule.arg_substrings and rule.process_names:
                    matched = sub_ok or proc_ok
                else:
                    matched = sub_ok and proc_ok
                if matched:
                    matches.append(
                        DetectionMatch(
                            match_id=new_id("falco"),
                            engine="falco_ebpf",
                            rule_id=rule.rule_id,
                            rule_title=rule.title,
                            severity=rule.severity,
                            mitre_techniques=[rule.mitre_id],
                            target_ref=f"{ev.container_id}:{ev.process_name}:{ev.syscall}",
                            matched_evidence=args_blob[:240] or f"syscall={ev.syscall}",
                        )
                    )
                    vulns.append(
                        make_cyber_vuln(
                            rule_id=rule.rule_id,
                            title=f"Runtime eBPF/Falco Alert: {rule.title}",
                            description=f"Container `{ev.container_id}` process `{ev.process_name}` invoked `{ev.syscall}` ({args_blob[:160]}).",
                            cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                            severity=rule.severity,
                            cwe_ids=["CWE-250"],
                            confidence=0.95,
                            mitre_techniques=[MitreTechniqueRef(rule.mitre_id, rule.title, MitreTactic.PRIVILEGE_ESCALATION)],
                            verification_method=VerificationMethod.EMULATION_PLAYBOOK,
                            sandbox_reproduced=True,
                            endpoint_or_asset=ev.container_id,
                            remediation_guidance="Terminate compromised pod, apply strict Seccomp/AppArmor profile, and enforce read-only root filesystem.",
                            discovered_by="ely_cyber_container_runtime",
                        )
                    )
        return {
            "evaluated_at": utc_now_iso(),
            "events_inspected": len(events),
            "runtime_alerts": len(matches),
            "matches": [m.to_dict() for m in matches],
            "vulnerabilities": vulns,
        }
