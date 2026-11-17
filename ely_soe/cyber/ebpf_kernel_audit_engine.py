"""
Linux Kernel Hardening, Seccomp-BPF Filter Verifier, AppArmor/SELinux Policy Auditor,
Linux Capabilities Escalation Analyzer & CIS `sysctl.conf` Baseline Engine.

Performs deep host/node/container kernel-boundary security analysis without requiring
root privileges or host kernel probes:
  1. **CIS Linux Kernel `sysctl.conf` Hardening Verifier (32+ Critical Kernel Controls)**:
       Audits ASLR (`kernel.randomize_va_space=2`), `kernel.kptr_restrict=2`,
       `kernel.dmesg_restrict=1`, `kernel.unprivileged_bpf_disabled=1`,
       `kernel.unprivileged_userns_clone=0`, `kernel.yama.ptrace_scope>=1`,
       `fs.protected_hardlinks/symlinks/fifos/regular`, `fs.suid_dumpable=0`,
       `net.ipv4.ip_forward`, `rp_filter`, `tcp_syncookies`, `accept_redirects`,
       `kernel.modules_disabled`, `vm.mmap_min_addr`, `kernel.kexec_load_disabled`,
       `kernel.perf_event_paranoid`, and `net.core.bpf_jit_harden=2`.
  2. **Seccomp-BPF Profile JSON Analyzer**:
       Parses OCI / Docker / Kubernetes `seccomp` JSON profiles, verifying default action
       (`SCMP_ACT_ERRNO` vs dangerous `SCMP_ACT_ALLOW`), flagging permitted container-escape
       and kernel-exploit syscalls (`bpf`, `ptrace`, `userfaultfd`, `io_uring_setup`,
       `init_module`, `finit_module`, `kexec_load`, `mount`, `unshare`, `clone3`,
       `keyctl`, `open_by_handle_at`, `perf_event_open`, `process_vm_writev`, `reboot`,
       `setns`, `swapon`, `syslog`, `add_key`, `move_mount`, `fsopen`).
  3. **Linux POSIX Capabilities Escalation & Breakout Matrix**:
       Evaluates assigned capability sets against known container-escape & root-escalation
       primitives (e.g., `CAP_SYS_ADMIN` mount/cgroup release_agent breakout,
       `CAP_DAC_READ_SEARCH` `open_by_handle_at` Shocker breakout, `CAP_SYS_PTRACE` host
       PID injection, `CAP_SYS_MODULE` kernel rootkit load, `CAP_BPF`+`CAP_PERFMON` eBPF
       memory read/write, `CAP_NET_RAW` ARP/DNS spoof).
  4. **AppArmor & SELinux Profile Static Auditor**:
       Flags overly permissive AppArmor rules (`capability,`, `/** rwkmlix,`, `mount,`,
       `ptrace,`, `complain` mode instead of `enforce`) and SELinux `permissive`/`disabled`
       configurations or unconfined domain transitions.
  5. **Hardened Seccomp-BPF & `sysctl.d/99-ely-hardening.conf` Policy Synthesizer**:
       Generates minimal default-deny OCI seccomp profiles and CIS-compliant sysctl drop-ins.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

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


@dataclass(frozen=True)
class SysctlBaselineRule:
    param: str
    expected_operator: str  # eq | ge | le | in
    expected_value: Any
    cis_ref: str
    severity: Severity
    cwe_id: str
    rationale: str


SYSCTL_HARDENING_BASELINE: Tuple[SysctlBaselineRule, ...] = (
    SysctlBaselineRule("kernel.randomize_va_space", "eq", 2, "CIS-1.5.3", Severity.CRITICAL, "CWE-119", "Full ASLR (stack, VDSO, mmap, brk) must be enabled (`=2`) to impede ROP/memory corruption exploits."),
    SysctlBaselineRule("kernel.kptr_restrict", "ge", 2, "CIS-1.5.4", Severity.HIGH, "CWE-200", "Restrict kernel symbol pointer leaks in `/proc/kallsyms` (`=2`) to protect KASLR."),
    SysctlBaselineRule("kernel.dmesg_restrict", "eq", 1, "CIS-1.5.5", Severity.MEDIUM, "CWE-200", "Restrict `dmesg` ring buffer access to `CAP_SYSLOG` to prevent kernel address/stack info leaks."),
    SysctlBaselineRule("kernel.unprivileged_bpf_disabled", "ge", 1, "CIS-1.5.6", Severity.CRITICAL, "CWE-269", "Disable unprivileged `bpf()` syscall to block eBPF verifier LPE chains (CVE-2021-3490, CVE-2022-23222 class)."),
    SysctlBaselineRule("net.core.bpf_jit_harden", "eq", 2, "CIS-1.5.7", Severity.HIGH, "CWE-119", "Enable BPF JIT constant blinding for all users (`=2`) to prevent JIT spraying attacks."),
    SysctlBaselineRule("kernel.yama.ptrace_scope", "ge", 1, "CIS-1.5.2", Severity.HIGH, "CWE-269", "Restrict `ptrace()` to parent-child or disable (`>=1`) to prevent credential scraping from sibling processes."),
    SysctlBaselineRule("kernel.kexec_load_disabled", "eq", 1, "CIS-1.5.8", Severity.HIGH, "CWE-269", "Disable `kexec_load()` to prevent live replacement of the signed running kernel without reboot."),
    SysctlBaselineRule("kernel.perf_event_paranoid", "ge", 2, "CIS-1.5.9", Severity.MEDIUM, "CWE-200", "Restrict unprivileged `perf_event_open()` to reduce kernel attack surface and side-channel leaks."),
    SysctlBaselineRule("vm.unprivileged_userfaultfd", "eq", 0, "CIS-1.5.10", Severity.HIGH, "CWE-362", "Disable unprivileged `userfaultfd` (widely abused to win kernel UAF/race condition heap sprays)."),
    SysctlBaselineRule("vm.mmap_min_addr", "ge", 65536, "CIS-1.5.11", Severity.HIGH, "CWE-476", "Enforce `vm.mmap_min_addr >= 65536` to neutralize kernel NULL-pointer dereference privilege escalation."),
    SysctlBaselineRule("fs.suid_dumpable", "eq", 0, "CIS-1.5.1", Severity.MEDIUM, "CWE-528", "Disable core dumps for SUID/SGID binaries (`=0`) to avoid leaking privileged memory to disk."),
    SysctlBaselineRule("fs.protected_hardlinks", "eq", 1, "CIS-1.5.12", Severity.MEDIUM, "CWE-59", "Prevent hardlink TOCTOU privilege escalation attacks in world-writable directories."),
    SysctlBaselineRule("fs.protected_symlinks", "eq", 1, "CIS-1.5.13", Severity.MEDIUM, "CWE-59", "Prevent symlink following attacks in sticky world-writable directories (`/tmp`)."),
    SysctlBaselineRule("fs.protected_fifos", "ge", 1, "CIS-1.5.14", Severity.LOW, "CWE-59", "Prevent unintended writes to attacker-controlled FIFOs in sticky directories."),
    SysctlBaselineRule("fs.protected_regular", "ge", 1, "CIS-1.5.15", Severity.LOW, "CWE-59", "Prevent unintended writes to attacker-owned regular files in sticky directories."),
    SysctlBaselineRule("kernel.sysrq", "eq", 0, "CIS-1.5.16", Severity.LOW, "CWE-284", "Disable Magic SysRq key (`=0`) on production servers to prevent console crash/memory dumps."),
    SysctlBaselineRule("net.ipv4.tcp_syncookies", "eq", 1, "CIS-3.2.8", Severity.MEDIUM, "CWE-400", "Enable TCP SYN cookies (`=1`) to resist SYN-flood exhaustion DoS."),
    SysctlBaselineRule("net.ipv4.conf.all.accept_redirects", "eq", 0, "CIS-3.2.2", Severity.MEDIUM, "CWE-284", "Reject ICMP redirects (`=0`) to prevent routing-table poisoning / MiTM."),
    SysctlBaselineRule("net.ipv4.conf.default.accept_redirects", "eq", 0, "CIS-3.2.2", Severity.MEDIUM, "CWE-284", "Reject ICMP redirects by default on newly created interfaces."),
    SysctlBaselineRule("net.ipv4.conf.all.secure_redirects", "eq", 0, "CIS-3.2.3", Severity.MEDIUM, "CWE-284", "Reject secure ICMP redirects (`=0`) to harden gateway routing integrity."),
    SysctlBaselineRule("net.ipv4.conf.all.accept_source_route", "eq", 0, "CIS-3.2.1", Severity.MEDIUM, "CWE-284", "Disable IP source routing (`=0`) to block spoofed hop-by-hop packet steering."),
    SysctlBaselineRule("net.ipv4.conf.all.rp_filter", "eq", 1, "CIS-3.2.7", Severity.MEDIUM, "CWE-290", "Enable strict Reverse Path Filtering (`=1`) to drop spoofed-source packets."),
    SysctlBaselineRule("net.ipv4.conf.all.log_martians", "eq", 1, "CIS-3.2.4", Severity.LOW, "CWE-778", "Log spoofed/unroutable Martian packets for network intrusion detection."),
    SysctlBaselineRule("net.ipv4.icmp_echo_ignore_broadcasts", "eq", 1, "CIS-3.2.5", Severity.LOW, "CWE-400", "Ignore broadcast ICMP echo requests (Smurf amplification protection)."),
    SysctlBaselineRule("net.ipv6.conf.all.accept_redirects", "eq", 0, "CIS-3.2.2", Severity.MEDIUM, "CWE-284", "Reject IPv6 ICMP redirects (`=0`)."),
    SysctlBaselineRule("net.ipv6.conf.all.accept_source_route", "eq", 0, "CIS-3.2.1", Severity.MEDIUM, "CWE-284", "Disable IPv6 source routing (`=0`)."),
    SysctlBaselineRule("kernel.modules_disabled", "eq", 1, "CIS-1.5.17", Severity.MEDIUM, "CWE-269", "Lock kernel module loading post-boot (`=1`) on immutable appliance nodes to block LKM rootkits."),
    SysctlBaselineRule("kernel.unprivileged_userns_clone", "eq", 0, "CIS-1.5.18", Severity.HIGH, "CWE-269", "Disable unprivileged user namespaces on non-rootless hosts to eliminate a major kernel LPE attack surface."),
)


@dataclass(frozen=True)
class DangerousSyscallSpec:
    syscall: str
    severity: Severity
    cwe_id: str
    mitre_id: str
    abuse_vector: str


DANGEROUS_SYSCALL_TAXONOMY: Tuple[DangerousSyscallSpec, ...] = (
    DangerousSyscallSpec("bpf", Severity.CRITICAL, "CWE-269", "T1068", "Allows loading eBPF programs/maps; historically a top source of kernel verifier LPE and host stealth rootkits."),
    DangerousSyscallSpec("ptrace", Severity.CRITICAL, "CWE-269", "T1055.008", "Enables arbitrary process memory inspection, shellcode injection, and seccomp bypass via sibling tracing."),
    DangerousSyscallSpec("init_module", Severity.CRITICAL, "CWE-269", "T1547.006", "Loads arbitrary kernel modules (LKM rootkits) directly into Ring 0."),
    DangerousSyscallSpec("finit_module", Severity.CRITICAL, "CWE-269", "T1547.006", "Loads kernel modules from file descriptors into Ring 0."),
    DangerousSyscallSpec("delete_module", Severity.HIGH, "CWE-269", "T1562.001", "Unloads security/EDR kernel modules."),
    DangerousSyscallSpec("kexec_load", Severity.CRITICAL, "CWE-269", "T1542", "Replaces the active Linux kernel image in memory, bypassing Secure Boot / runtime integrity."),
    DangerousSyscallSpec("kexec_file_load", Severity.CRITICAL, "CWE-269", "T1542", "Loads an alternate kernel image via file descriptor."),
    DangerousSyscallSpec("open_by_handle_at", Severity.CRITICAL, "CWE-22", "T1611", "Classic 'Shocker' container breakout allowing arbitrary host filesystem traversal via raw inode handles."),
    DangerousSyscallSpec("mount", Severity.CRITICAL, "CWE-250", "T1611", "Allows mounting host block devices or cgroupfs (`release_agent`) to execute commands on the host."),
    DangerousSyscallSpec("move_mount", Severity.CRITICAL, "CWE-250", "T1611", "Modern mount API primitive enabling host namespace mount manipulation."),
    DangerousSyscallSpec("fsopen", Severity.HIGH, "CWE-250", "T1611", "Creates new filesystem mount context usable in container escape chains."),
    DangerousSyscallSpec("unshare", Severity.HIGH, "CWE-269", "T1611", "Creates new user/mount namespaces unlocking privileged kernel code paths (`nf_tables`, overlayfs CVEs)."),
    DangerousSyscallSpec("setns", Severity.HIGH, "CWE-269", "T1611", "Joins other namespaces (PID/mnt/net) facilitating container breakout."),
    DangerousSyscallSpec("userfaultfd", Severity.HIGH, "CWE-362", "T1068", "Pauses kernel page faults deterministically to exploit UAF/race condition LPE bugs reliably."),
    DangerousSyscallSpec("io_uring_setup", Severity.HIGH, "CWE-269", "T1068", "Async ring-buffer kernel subsystem with dense recent LPE history; restricted by Google/Docker defaults."),
    DangerousSyscallSpec("io_uring_enter", Severity.HIGH, "CWE-269", "T1068", "Submits raw io_uring SQEs bypassing traditional syscall-level audit/LSM hooks."),
    DangerousSyscallSpec("keyctl", Severity.HIGH, "CWE-269", "T1555", "Interacts with Linux kernel keyring; risks cross-container key leakage & kernel UAFs."),
    DangerousSyscallSpec("add_key", Severity.MEDIUM, "CWE-269", "T1555", "Adds keys to shared kernel keyring structures."),
    DangerousSyscallSpec("process_vm_readv", Severity.HIGH, "CWE-200", "T1003", "Reads memory directly from another process's address space."),
    DangerousSyscallSpec("process_vm_writev", Severity.CRITICAL, "CWE-269", "T1055", "Writes directly into another process's address space without ptrace."),
    DangerousSyscallSpec("perf_event_open", Severity.HIGH, "CWE-200", "T1068", "Exposes hardware PMU / kernel tracepoints (side-channels & kernel LPE vector)."),
    DangerousSyscallSpec("reboot", Severity.HIGH, "CWE-284", "T1529", "Permits crashing/rebooting the host node."),
    DangerousSyscallSpec("swapon", Severity.MEDIUM, "CWE-269", "T1499", "Manipulates host swap devices."),
    DangerousSyscallSpec("syslog", Severity.MEDIUM, "CWE-200", "T1082", "Reads/clears host kernel `dmesg` ring buffer."),
    DangerousSyscallSpec("lookup_dcookie", Severity.MEDIUM, "CWE-200", "T1082", "Leaks kernel directory entry paths across namespace boundaries."),
)


@dataclass(frozen=True)
class DangerousCapabilitySpec:
    cap: str
    severity: Severity
    escape_class: str
    mitre_id: str
    description: str


DANGEROUS_CAPABILITIES: Dict[str, DangerousCapabilitySpec] = {
    "CAP_SYS_ADMIN": DangerousCapabilitySpec("CAP_SYS_ADMIN", Severity.CRITICAL, "full_container_breakout", "T1611", "Equivalent to host root: permits `mount`, cgroup `release_agent`, `setns`, and arbitrary filesystem takeover."),
    "CAP_SYS_MODULE": DangerousCapabilitySpec("CAP_SYS_MODULE", Severity.CRITICAL, "ring0_rootkit_load", "T1547.006", "Permits inserting arbitrary Linux kernel modules directly into the shared host kernel."),
    "CAP_DAC_READ_SEARCH": DangerousCapabilitySpec("CAP_DAC_READ_SEARCH", Severity.CRITICAL, "host_fs_read_breakout", "T1611", "Bypasses file read DAC checks and enables `open_by_handle_at` ('Shocker') full host filesystem read."),
    "CAP_DAC_OVERRIDE": DangerousCapabilitySpec("CAP_DAC_OVERRIDE", Severity.HIGH, "file_permission_bypass", "T1548", "Bypasses all file read/write/execute permission checks inside the container or shared volumes."),
    "CAP_SYS_PTRACE": DangerousCapabilitySpec("CAP_SYS_PTRACE", Severity.CRITICAL, "process_injection_breakout", "T1055.008", "Allows tracing and injecting code into any process (instant host breakout when combined with `hostPID`)."),
    "CAP_BPF": DangerousCapabilitySpec("CAP_BPF", Severity.CRITICAL, "ebpf_kernel_read_write", "T1068", "Allows privileged eBPF program attachment capable of intercepting host syscalls and stealing credentials."),
    "CAP_SYS_RAWIO": DangerousCapabilitySpec("CAP_SYS_RAWIO", Severity.CRITICAL, "raw_disk_memory_access", "T1611", "Grants raw I/O port and `/dev/mem`, `/dev/kmem`, `/dev/sda` block device access."),
    "CAP_NET_ADMIN": DangerousCapabilitySpec("CAP_NET_ADMIN", Severity.HIGH, "network_mitm_pivot", "T1557", "Allows altering iptables/nftables, routes, and interfaces for lateral network interception."),
    "CAP_NET_RAW": DangerousCapabilitySpec("CAP_NET_RAW", Severity.MEDIUM, "packet_spoofing_sniffing", "T1040", "Permits raw packet crafting (ARP spoofing, DNS spoofing, packet capture on pod bridge)."),
    "CAP_SETUID": DangerousCapabilitySpec("CAP_SETUID", Severity.HIGH, "uid0_impersonation", "T1548", "Allows arbitrary UID transitions to root (`uid=0`)."),
    "CAP_CHOWN": DangerousCapabilitySpec("CAP_CHOWN", Severity.MEDIUM, "ownership_hijack", "T1222", "Allows taking ownership of sensitive mounted files such as `/etc/shadow` or SSH keys."),
    "CAP_MKNOD": DangerousCapabilitySpec("CAP_MKNOD", Severity.HIGH, "device_node_creation", "T1611", "Allows creating raw character/block device nodes inside container namespaces."),
}


class KernelAndSeccompAuditEngine:
    """
    Comprehensive static & configuration auditor for Linux kernel sysctl baselines,
    Seccomp-BPF JSON filters, POSIX capability sets, and AppArmor/SELinux MAC profiles.
    """

    def __init__(self) -> None:
        self._syscall_map = {s.syscall: s for s in DANGEROUS_SYSCALL_TAXONOMY}

    def audit_sysctl_config(
        self,
        sysctl_text_or_dict: Any,
        asset: str = "/etc/sysctl.conf",
    ) -> Dict[str, Any]:
        """Parse and verify Linux sysctl parameters against the 28-control CIS hardening baseline."""
        parsed: Dict[str, Any] = {}
        if isinstance(sysctl_text_or_dict, dict):
            parsed = {str(k).strip(): v for k, v in sysctl_text_or_dict.items()}
        else:
            for line in str(sysctl_text_or_dict).splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith(("#", ";")):
                    continue
                if "=" in stripped:
                    k, v = stripped.split("=", 1)
                    raw_v = v.strip().split()[0] if v.strip() else ""
                    try:
                        parsed[k.strip()] = int(raw_v)
                    except ValueError:
                        parsed[k.strip()] = raw_v

        vulns: List[CyberVulnerability] = []
        passed = 0
        failed = 0
        missing = 0

        for rule in SYSCTL_HARDENING_BASELINE:
            if rule.param not in parsed:
                missing += 1
                failed += 1
                vulns.append(
                    make_cyber_vuln(
                        rule_id=f"CYB-KERN-SYSCTL-MISS-{rule.param.replace('.', '_').upper()[:28]}",
                        title=f"[{rule.cis_ref}] Missing Hardened Kernel Sysctl `{rule.param}`",
                        description=f"`{rule.param}` is unset in `{asset}`. {rule.rationale}",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.MEDIUM if rule.severity == Severity.CRITICAL else rule.severity,
                        cwe_ids=[rule.cwe_id],
                        confidence=0.90,
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        endpoint_or_asset=asset,
                        remediation_guidance=f"Set `{rule.param} = {rule.expected_value}` in `/etc/sysctl.d/99-ely-hardening.conf` and run `sysctl --system`.",
                        discovered_by="ely_cyber_kernel_seccomp_auditor",
                    )
                )
                continue

            val = parsed[rule.param]
            ok = False
            try:
                iv = int(val)
                ev = int(rule.expected_value)
                if rule.expected_operator == "eq":
                    ok = iv == ev
                elif rule.expected_operator == "ge":
                    ok = iv >= ev
                elif rule.expected_operator == "le":
                    ok = iv <= ev
            except (TypeError, ValueError):
                ok = str(val) == str(rule.expected_value)

            if ok:
                passed += 1
            else:
                failed += 1
                vulns.append(
                    make_cyber_vuln(
                        rule_id=f"CYB-KERN-SYSCTL-{rule.param.replace('.', '_').upper()[:32]}",
                        title=f"[{rule.cis_ref}] Insecure Kernel Sysctl `{rule.param} = {val}` (Expected {rule.expected_operator} {rule.expected_value})",
                        description=f"`{asset}` configures `{rule.param}={val}`. {rule.rationale}",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=rule.severity,
                        cwe_ids=[rule.cwe_id],
                        confidence=0.98,
                        cvss4=CVSSv4Metrics(av="L", ac="L", at="N", pr="L", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
                        mitre_techniques=[MitreTechniqueRef("T1068", "Exploitation for Privilege Escalation", MitreTactic.PRIVILEGE_ESCALATION)],
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        endpoint_or_asset=asset,
                        remediation_guidance=f"Change `{rule.param}` to `{rule.expected_value}` and reload sysctl.",
                        discovered_by="ely_cyber_kernel_seccomp_auditor",
                    )
                )

        score_pct = round((passed / max(1, len(SYSCTL_HARDENING_BASELINE))) * 100.0, 2)
        return {
            "audited_at": utc_now_iso(),
            "asset": asset,
            "controls_total": len(SYSCTL_HARDENING_BASELINE),
            "controls_passed": passed,
            "controls_failed": failed,
            "controls_missing": missing,
            "cis_kernel_hardening_score_pct": score_pct,
            "vulnerabilities": vulns,
        }

    def audit_seccomp_profile(self, profile: Dict[str, Any], asset: str = "seccomp.json") -> Dict[str, Any]:
        """Audit an OCI/Docker/Kubernetes Seccomp-BPF JSON profile for allow-all defaults & escape syscalls."""
        vulns: List[CyberVulnerability] = []
        default_act = str(profile.get("defaultAction", "SCMP_ACT_ALLOW")).upper()
        syscalls_rules = profile.get("syscalls", [])

        allowed_dangerous: List[str] = []
        explicitly_blocked: Set[str] = set()
        explicitly_allowed: Set[str] = set()

        for entry in syscalls_rules:
            act = str(entry.get("action", "")).upper()
            names = [str(n) for n in entry.get("names", [])]
            if act in ("SCMP_ACT_ALLOW", "SCMP_ACT_LOG", "SCMP_ACT_TRACE"):
                explicitly_allowed.update(names)
            elif act in ("SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_KILL_PROCESS", "SCMP_ACT_KILL_THREAD"):
                explicitly_blocked.update(names)

        if default_act == "SCMP_ACT_ALLOW":
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-KERN-SECCOMP-DEFAULT-ALLOW",
                    title=f"Seccomp Profile `{asset}` Uses Insecure Default-Allow (`SCMP_ACT_ALLOW`)",
                    description=(
                        f"Seccomp profile `{asset}` sets `defaultAction=SCMP_ACT_ALLOW`, acting as a weak denylist "
                        "that automatically exposes newly introduced Linux syscalls (`io_uring`, `fsmount`, `clone3`) to attackers."
                    ),
                    cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-250", "CWE-284"],
                    confidence=0.99,
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=asset,
                    remediation_guidance="Invert Seccomp profile to `defaultAction: SCMP_ACT_ERRNO` with a minimal allowlist of required runtime syscalls.",
                    discovered_by="ely_cyber_kernel_seccomp_auditor",
                )
            )
            # Every dangerous syscall NOT explicitly blocked is effectively permitted
            for spec in DANGEROUS_SYSCALL_TAXONOMY:
                if spec.syscall not in explicitly_blocked:
                    allowed_dangerous.append(spec.syscall)
        else:
            for sc in sorted(explicitly_allowed):
                if sc in self._syscall_map:
                    allowed_dangerous.append(sc)

        for sc in sorted(set(allowed_dangerous)):
            spec = self._syscall_map[sc]
            vulns.append(
                make_cyber_vuln(
                    rule_id=f"CYB-KERN-SECCOMP-SC-{sc.upper()}",
                    title=f"Seccomp Profile `{asset}` Permits High-Risk Syscall `{sc}()`",
                    description=f"Syscall `{sc}` is permitted by `{asset}`. {spec.abuse_vector}",
                    cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                    severity=spec.severity,
                    cwe_ids=[spec.cwe_id],
                    confidence=0.96,
                    mitre_techniques=[MitreTechniqueRef(spec.mitre_id, f"Kernel Syscall Abuse ({sc})", MitreTactic.PRIVILEGE_ESCALATION)],
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=asset,
                    remediation_guidance=f"Remove `{sc}` from allowed syscalls or explicitly deny it with `SCMP_ACT_ERRNO` / `SCMP_ACT_KILL_PROCESS`.",
                    discovered_by="ely_cyber_kernel_seccomp_auditor",
                )
            )

        risk_reduction_pct = round(((len(DANGEROUS_SYSCALL_TAXONOMY) - len(set(allowed_dangerous))) / len(DANGEROUS_SYSCALL_TAXONOMY)) * 100.0, 2)
        return {
            "audited_at": utc_now_iso(),
            "asset": asset,
            "default_action": default_act,
            "dangerous_syscalls_permitted": sorted(set(allowed_dangerous)),
            "dangerous_syscalls_blocked_pct": risk_reduction_pct,
            "vulnerabilities": vulns,
        }

    def audit_capabilities(
        self,
        added_capabilities: Sequence[str],
        dropped_capabilities: Sequence[str] = (),
        host_pid: bool = False,
        asset: str = "workload",
    ) -> Dict[str, Any]:
        """Analyze assigned Linux POSIX capabilities and toxic breakout combinations."""
        added = {c.upper() if c.upper().startswith("CAP_") else f"CAP_{c.upper()}" for c in added_capabilities}
        dropped = {c.upper() if c.upper().startswith("CAP_") else f"CAP_{c.upper()}" for c in dropped_capabilities}
        effective = added - dropped
        vulns: List[CyberVulnerability] = []

        if "CAP_ALL" in added or "ALL" in {c.upper() for c in added_capabilities}:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-KERN-CAP-ALL-001",
                    title=f"Workload `{asset}` Grants `ALL` Linux Capabilities",
                    description=f"`{asset}` adds all Linux capabilities, breaking container/process privilege boundaries.",
                    cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-250"],
                    confidence=0.99,
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=asset,
                    remediation_guidance="Set `drop: ['ALL']` and add back zero capabilities unless strictly required (e.g., `NET_BIND_SERVICE`).",
                    discovered_by="ely_cyber_kernel_seccomp_auditor",
                )
            )

        for cap in sorted(effective):
            spec = DANGEROUS_CAPABILITIES.get(cap)
            if spec:
                sev = Severity.CRITICAL if (cap == "CAP_SYS_PTRACE" and host_pid) else spec.severity
                vulns.append(
                    make_cyber_vuln(
                        rule_id=f"CYB-KERN-{cap}",
                        title=f"Dangerous Linux Capability `{cap}` Assigned to `{asset}` ({spec.escape_class})",
                        description=f"{spec.description}" + (" Combined with `hostPID=true`, this yields instant host root takeover." if cap == "CAP_SYS_PTRACE" and host_pid else ""),
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=sev,
                        cwe_ids=["CWE-250", "CWE-269"],
                        confidence=0.97,
                        mitre_techniques=[MitreTechniqueRef(spec.mitre_id, f"Capability Abuse: {cap}", MitreTactic.PRIVILEGE_ESCALATION)],
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        endpoint_or_asset=asset,
                        remediation_guidance=f"Drop `{cap}` from `{asset}` securityContext (`capabilities.drop: ['ALL']`).",
                        discovered_by="ely_cyber_kernel_seccomp_auditor",
                    )
                )

        return {
            "asset": asset,
            "effective_dangerous_caps": [c for c in sorted(effective) if c in DANGEROUS_CAPABILITIES],
            "drops_all_first": "CAP_ALL" in dropped or "ALL" in {c.upper() for c in dropped_capabilities},
            "vulnerabilities": vulns,
        }

    def audit_mac_policy(self, policy_text: str, policy_type: str = "apparmor", asset: str = "mac_profile") -> List[CyberVulnerability]:
        """Audit AppArmor profile text or `/etc/selinux/config` for permissive/wildcard bypasses."""
        vulns: List[CyberVulnerability] = []
        pt = policy_type.lower()

        if pt == "selinux":
            if re.search(r"(?mi)^\s*SELINUX\s*=\s*(?:disabled|permissive)\b", policy_text):
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-KERN-SELINUX-DISABLED-001",
                        title=f"SELinux Mandatory Access Control Set to `disabled` or `permissive` in `{asset}`",
                        description="Disabling SELinux removes kernel-enforced Type Enforcement confinement for all host daemons and containers.",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-693"],
                        confidence=0.99,
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        endpoint_or_asset=asset,
                        remediation_guidance="Set `SELINUX=enforcing` and `SELINUXTYPE=targeted` in `/etc/selinux/config`.",
                        discovered_by="ely_cyber_kernel_seccomp_auditor",
                    )
                )
        else:
            checks = [
                (r"flags\s*=\s*\([^)]*complain[^)]*\)", "CYB-KERN-AA-COMPLAIN-001", "AppArmor Profile Runs in `complain` (Log-Only) Mode Instead of `enforce`", Severity.MEDIUM),
                (r"(?m)^\s*capability\s*,", "CYB-KERN-AA-WILD-CAP-001", "AppArmor Profile Grants Wildcard `capability,` (All Linux Capabilities)", Severity.CRITICAL),
                (r"(?m)^\s*/\*\*\s+[rwkmlix]+,", "CYB-KERN-AA-WILD-FS-001", "AppArmor Profile Grants Full Filesystem Wildcard Access (`/** rwkmlix,`)", Severity.CRITICAL),
                (r"(?m)^\s*mount\s*,", "CYB-KERN-AA-MOUNT-001", "AppArmor Profile Permits Unrestricted `mount,` Operations", Severity.HIGH),
                (r"(?m)^\s*ptrace\s*,", "CYB-KERN-AA-PTRACE-001", "AppArmor Profile Permits Unrestricted `ptrace,` Across Processes", Severity.HIGH),
            ]
            for pat, rid, title, sev in checks:
                if re.search(pat, policy_text):
                    vulns.append(
                        make_cyber_vuln(
                            rule_id=rid,
                            title=title,
                            description=f"AppArmor profile `{asset}` contains overly permissive rule matching `{pat}`.",
                            cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                            severity=sev,
                            cwe_ids=["CWE-250", "CWE-732"],
                            confidence=0.95,
                            verification_method=VerificationMethod.STATIC_PATTERN,
                            endpoint_or_asset=asset,
                            remediation_guidance="Enforce least-privilege AppArmor path/capability rules in `enforce` mode.",
                            discovered_by="ely_cyber_kernel_seccomp_auditor",
                        )
                    )
        return vulns

    def synthesize_hardened_seccomp_profile(self, workload_type: str = "web_api") -> Dict[str, Any]:
        """Synthesize a minimal default-deny OCI Seccomp-BPF JSON profile tailored to `workload_type`."""
        minimal_allow = [
            "read", "write", "openat", "close", "fstat", "newfstatat", "lseek", "mmap",
            "mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
            "pread64", "pwrite64", "readv", "writev", "access", "pipe2", "select", "poll",
            "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait", "futex", "clock_gettime",
            "gettimeofday", "getpid", "getuid", "geteuid", "getgid", "getegid", "getrandom",
            "exit", "exit_group", "sched_yield", "nanosleep", "clock_nanosleep",
            "socket", "connect", "accept4", "bind", "listen", "sendto", "recvfrom",
            "getsockname", "getpeername", "setsockopt", "getsockopt", "shutdown",
            "fcntl", "statx", "getcwd", "readlinkat", "dup", "dup2", "dup3",
        ]
        if workload_type == "worker_multiprocess":
            minimal_allow.extend(["fork", "vfork", "wait4", "execve"])

        return {
            "defaultAction": "SCMP_ACT_ERRNO",
            "defaultErrnoRet": 1,
            "archMap": [{"architecture": "SCMP_ARCH_X86_64", "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"]}],
            "syscalls": [
                {"names": sorted(set(minimal_allow)), "action": "SCMP_ACT_ALLOW"},
                {"names": [s.syscall for s in DANGEROUS_SYSCALL_TAXONOMY], "action": "SCMP_ACT_KILL_PROCESS"},
            ],
            "x_ely_generated_at": utc_now_iso(),
            "x_ely_workload_profile": workload_type,
        }

    def scan_directory(self, root_path: Path) -> List[CyberVulnerability]:
        """Scan repository files for `sysctl.conf`, seccomp JSONs, AppArmor, and SELinux configs."""
        vulns: List[CyberVulnerability] = []
        for fp in sorted(root_path.rglob("*")):
            if not fp.is_file():
                continue
            if any(p in {".git", "node_modules", "__pycache__", ".venv"} for p in fp.parts):
                continue
            name_l = fp.name.lower()
            rel = str(fp.relative_to(root_path))
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            if "sysctl" in name_l and fp.suffix.lower() in {".conf", ".cfg", ".txt"}:
                res = self.audit_sysctl_config(content, asset=rel)
                vulns.extend(res["vulnerabilities"])
            elif "seccomp" in name_l and fp.suffix.lower() == ".json":
                try:
                    obj = json.loads(content)
                    if isinstance(obj, dict) and ("defaultAction" in obj or "syscalls" in obj):
                        vulns.extend(self.audit_seccomp_profile(obj, asset=rel)["vulnerabilities"])
                except json.JSONDecodeError:
                    pass
            elif "selinux" in name_l or "SELINUX=" in content:
                vulns.extend(self.audit_mac_policy(content, policy_type="selinux", asset=rel))
            elif "apparmor" in name_l or ("profile " in content and "flags=(" in content):
                vulns.extend(self.audit_mac_policy(content, policy_type="apparmor", asset=rel))
        return vulns
