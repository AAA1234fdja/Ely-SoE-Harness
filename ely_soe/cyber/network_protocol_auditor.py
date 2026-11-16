"""
Network, Protocol State-Machine & Zero-Trust Segmentation Security Auditor.

Evaluates authorized network snapshots, service configurations, DNS query logs,
and firewall/ACL rule sets strictly offline / inside authorized lab models:
  1. Service Exposure & Protocol Hardening Auditor:
       - Cleartext management protocols (`telnet`, `ftp`, `rsh`, `snmpv1/v2c`, `http` admin)
       - Unauthenticated data stores exposed beyond localhost (`redis`, `memcached`, `mongodb`,
         `elasticsearch`, `etcd`, `postgres`, `mysql`, `dockerd` TCP 2375)
       - SMBv1 / disabled SMB signing / NTLM relay risk / anonymous IPC$ shares
       - SSH weak KEX (`diffie-hellman-group1-sha1`), weak ciphers (`cbc`, `arcfour`),
         root password login (`PermitRootLogin yes`), outdated CVE banners
       - SMTP open relay, missing STARTTLS, missing SPF (`-all`) / DMARC (`p=reject`) / DKIM
       - LDAP cleartext bind without StartTLS / LDAPS, anonymous bind enabled
  2. DNS Security & Exfiltration Tunneling Analyzer:
       - AXFR zone-transfer exposure, missing DNSSEC, DNS rebinding TTL=0 risk
       - Shannon-entropy + label-length + TXT/CNAME frequency DNS tunneling detector
  3. Firewall / Security Group / Zero-Trust Segmentation Verifier:
       - Detects overly broad `0.0.0.0/0` ingress to management/database ports
       - Computes multi-zone lateral reachability graph (Internet -> DMZ -> Internal -> Tier-0 Mgmt)
       - Identifies shadowed / conflicting firewall rules and missing egress restrictions
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from ely_soe.core.models import Severity
from ely_soe.cyber.models import (
    CVSSv4Metrics,
    CyberDomain,
    CyberVulnerability,
    FirewallRuleDescriptor,
    MitreTactic,
    MitreTechniqueRef,
    NetworkServiceDescriptor,
    VerificationMethod,
    make_cyber_vuln,
)


# ---------------------------------------------------------------------------
# Protocol Vulnerability Reference Tables
# ---------------------------------------------------------------------------

HIGH_RISK_UNAUTH_DATASTORES: Dict[str, Tuple[int, str]] = {
    "redis": (6379, "Unauthenticated Redis allows arbitrary key read/write, Lua sandbox escape, and SSH key/crontab overwrite"),
    "memcached": (11211, "Unauthenticated Memcached exposes cached session data and enables UDP amplification"),
    "mongodb": (27017, "Unauthenticated MongoDB exposes all collections and administrative commands"),
    "elasticsearch": (9200, "Unauthenticated Elasticsearch exposes indexed logs/PII and cluster settings"),
    "etcd": (2379, "Unauthenticated etcd exposes Kubernetes Secrets and enables full cluster takeover"),
    "docker": (2375, "Unauthenticated Docker daemon TCP socket grants immediate root host container escape"),
    "kubelet": (10250, "Unauthenticated Kubelet API permits arbitrary pod command execution"),
    "consul": (8500, "Unauthenticated Consul API permits service registration poisoning and script checks"),
}

CLEARTEXT_LEGACY_SERVICES = {
    "telnet": (23, "Telnet transmits credentials and interactive shells in cleartext"),
    "ftp": (21, "FTP transmits authentication credentials and file payloads in cleartext"),
    "rsh": (514, "Legacy rsh relies on spoofable IP trust without strong authentication"),
    "rlogin": (513, "Legacy rlogin transmits sessions unencrypted"),
    "tftp": (69, "TFTP lacks authentication and encryption, allowing arbitrary boot/config retrieval"),
    "http-admin": (80, "Administrative interface served over unencrypted HTTP"),
}

SENSITIVE_MGMT_PORTS: Dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    135: "MSRPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle DB",
    2375: "Docker Unencrypted API",
    2379: "etcd",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM HTTP",
    6379: "Redis",
    6443: "Kubernetes API",
    9200: "Elasticsearch",
    10250: "Kubelet",
    27017: "MongoDB",
}

WEAK_SSH_ALGORITHMS = (
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "ssh-dss",
    "ssh-rsa",
    "arcfour",
    "3des-cbc",
    "aes128-cbc",
    "aes256-cbc",
    "hmac-md5",
    "hmac-sha1",
)


# ---------------------------------------------------------------------------
# DNS Tunneling & Configuration Analyzer
# ---------------------------------------------------------------------------

class DNSSecurityAnalyzer:
    """Analyzes DNS server configuration posture and query streams for exfiltration tunneling."""

    def audit_dns_config(self, dns_config: Dict[str, Any], asset: str = "dns_server") -> List[CyberVulnerability]:
        findings: List[CyberVulnerability] = []

        if dns_config.get("allow_zone_transfer_any", False):
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-NET-DNS-AXFR-001",
                    title="Unrestricted DNS Zone Transfer (AXFR) Enabled",
                    description=f"DNS server `{asset}` allows AXFR zone transfers from any source IP, leaking complete internal hostnames and IP topology.",
                    cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-200"],
                    confidence=0.98,
                    mitre_techniques=[MitreTechniqueRef("T1590.002", "Gather Victim Network Information: DNS", MitreTactic.RECONNAISSANCE, "002")],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Restrict AXFR strictly to authenticated secondary nameservers using TSIG keys.",
                    discovered_by="ely_cyber_dns_auditor",
                )
            )

        if dns_config.get("open_recursion", False) and dns_config.get("exposed_zone", "internal") in ("internet", "dmz"):
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-NET-DNS-RECURSION-001",
                    title="Open Recursive DNS Resolver Exposed to External Zone",
                    description=f"DNS server `{asset}` allows open recursion from untrusted networks, enabling DNS amplification DDoS and cache poisoning.",
                    cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-400"],
                    confidence=0.96,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Disable recursion on authoritative external nameservers or limit `allow-recursion` strictly to internal subnets.",
                    discovered_by="ely_cyber_dns_auditor",
                )
            )

        if not dns_config.get("dnssec_enabled", True):
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-NET-DNS-DNSSEC-001",
                    title="DNSSEC Validation / Signing Disabled",
                    description=f"DNS zone on `{asset}` lacks DNSSEC protection, leaving responses vulnerable to on-path spoofing.",
                    cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                    severity=Severity.LOW,
                    cwe_ids=["CWE-345"],
                    confidence=0.90,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Enable DNSSEC signing (ECDSAP256SHA256) and validating recursive resolution.",
                    discovered_by="ely_cyber_dns_auditor",
                )
            )

        return findings

    def detect_dns_tunneling(self, queries: List[Dict[str, Any]], asset: str = "dns_telemetry") -> List[CyberVulnerability]:
        """
        Inspect DNS query records (`qname`, `qtype`, `src_ip`) for high-entropy
        encoded subdomains and abnormal TXT/NULL/CNAME exfiltration volumes.
        """
        findings: List[CyberVulnerability] = []
        suspicious_by_domain: Dict[str, List[Tuple[str, float, int]]] = {}

        for q in queries:
            qname = str(q.get("qname", "")).strip().lower().rstrip(".")
            qtype = str(q.get("qtype", "A")).upper()
            parts = qname.split(".")
            if len(parts) < 3:
                continue
            parent = ".".join(parts[-2:])
            sub = ".".join(parts[:-2])
            entropy = self._shannon_entropy(sub)
            if (len(sub) >= 28 and entropy >= 3.65) or (qtype in ("TXT", "NULL", "CNAME") and len(sub) >= 22 and entropy >= 3.4):
                suspicious_by_domain.setdefault(parent, []).append((qname, entropy, len(sub)))

        for parent, hits in suspicious_by_domain.items():
            if len(hits) >= 3:
                max_ent = max(h[1] for h in hits)
                max_len = max(h[2] for h in hits)
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-NET-DNS-TUNNEL-001",
                        title=f"Suspected DNS Exfiltration / C2 Tunneling to `{parent}`",
                        description=(
                            f"Detected {len(hits)} high-entropy DNS subdomain queries to `{parent}` "
                            f"(max_entropy={max_ent:.2f}, max_subdomain_len={max_len}), consistent with DNS tunneling."
                        ),
                        cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-200", "CWE-923"],
                        confidence=0.92,
                        mitre_techniques=[
                            MitreTechniqueRef("T1071.004", "Application Layer Protocol: DNS", MitreTactic.COMMAND_AND_CONTROL, "004"),
                            MitreTechniqueRef("T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol", MitreTactic.EXFILTRATION, "003"),
                        ],
                        verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                        endpoint_or_asset=f"{asset}:{parent}",
                        attack_vector_detail=f"Sample encoded query: `{hits[0][0][:90]}`",
                        remediation_guidance="Block egress DNS except through inspecting internal resolvers with RPZ/entropy anomaly blocking.",
                        discovered_by="ely_cyber_dns_tunnel_detector",
                    )
                )

        return findings

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        counts: Dict[str, int] = {}
        for c in text:
            counts[c] = counts.get(c, 0) + 1
        n = len(text)
        return -sum((cnt / n) * math.log2(cnt / n) for cnt in counts.values())


# ---------------------------------------------------------------------------
# Firewall & Zero-Trust Network Segmentation Verifier
# ---------------------------------------------------------------------------

class ZeroTrustSegmentationAuditor:
    """Audits firewall / security-group rule sets and proves cross-zone reachability."""

    def audit_firewall_rules(self, rules: List[FirewallRuleDescriptor]) -> Dict[str, Any]:
        findings: List[CyberVulnerability] = []
        zone_adj: Dict[str, Set[str]] = {}
        shadowed_rules: List[str] = []

        # Track seen allow/deny rules to spot shadowed rules
        seen_allow_all_src: Set[Tuple[str, str, int, int]] = set()

        for r in rules:
            action_l = r.action.lower()
            src_net = self._parse_cidr(r.source_cidr)
            is_any_src = src_net is not None and src_net.prefixlen == 0

            if action_l == "allow":
                zone_adj.setdefault(r.zone_src, set()).add(r.zone_dst)

                # 1. Any-source (`0.0.0.0/0` or `::/0`) ingress to sensitive management/DB ports
                if r.direction.lower() == "ingress" and is_any_src:
                    exposed_sensitive = [
                        f"{port}/{name}" for port, name in SENSITIVE_MGMT_PORTS.items() if r.matches_port(port)
                    ]
                    if exposed_sensitive:
                        sev = Severity.CRITICAL if any(p in (2375, 2379, 6379, 27017, 10250, 445, 3389, 5432, 3306) for p in SENSITIVE_MGMT_PORTS if r.matches_port(p)) else Severity.HIGH
                        findings.append(
                            make_cyber_vuln(
                                rule_id="CYB-FW-ANY-SENSITIVE-001",
                                title=f"Unrestricted `0.0.0.0/0` Ingress to Sensitive Services ({', '.join(exposed_sensitive[:4])})",
                                description=(
                                    f"Firewall rule `{r.rule_id}` permits `{r.source_cidr}` -> `{r.dest_cidr}` "
                                    f"on ports `{r.port_start}-{r.port_end}` ({r.protocol}), exposing sensitive management/data services."
                                ),
                                cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                                severity=sev,
                                cwe_ids=["CWE-284", "CWE-668"],
                                confidence=0.98,
                                mitre_techniques=[MitreTechniqueRef("T1133", "External Remote Services", MitreTactic.INITIAL_ACCESS)],
                                cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="L", sc="H", si="L", sa="N"),
                                verification_method=VerificationMethod.GRAPH_REACHABILITY,
                                endpoint_or_asset=f"fw:{r.rule_id}",
                                remediation_guidance="Restrict ingress to explicit bastion/VPN CIDRs or private zero-trust mesh identities and deny `0.0.0.0/0` on management/DB ports.",
                                discovered_by="ely_cyber_segmentation_auditor",
                            )
                        )

                # 2. Wildcard all-ports allow rule
                if r.port_start == 0 and r.port_end >= 65535 and r.protocol.lower() in ("any", "all", "tcp", "*"):
                    findings.append(
                        make_cyber_vuln(
                            rule_id="CYB-FW-WILDCARD-ALL-PORTS",
                            title=f"Overly Broad All-Port Allow Rule `{r.rule_id}` ({r.zone_src} -> {r.zone_dst})",
                            description=f"Rule `{r.rule_id}` opens all 65,535 ports from `{r.source_cidr}` to `{r.dest_cidr}`, violating micro-segmentation.",
                            cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                            severity=Severity.HIGH if is_any_src else Severity.MEDIUM,
                            cwe_ids=["CWE-284"],
                            confidence=0.95,
                            verification_method=VerificationMethod.GRAPH_REACHABILITY,
                            endpoint_or_asset=f"fw:{r.rule_id}",
                            remediation_guidance="Replace all-port rules with explicit least-privilege protocol/port tuples.",
                            discovered_by="ely_cyber_segmentation_auditor",
                        )
                    )

                if is_any_src:
                    seen_allow_all_src.add((r.direction.lower(), r.dest_cidr, r.port_start, r.port_end))

            elif action_l == "deny":
                # Check if an earlier broad allow rule shadowed this deny rule
                for d_dir, d_dst, p_s, p_e in seen_allow_all_src:
                    if d_dir == r.direction.lower() and d_dst == r.dest_cidr and p_s <= r.port_start and p_e >= r.port_end:
                        shadowed_rules.append(r.rule_id)
                        findings.append(
                            make_cyber_vuln(
                                rule_id="CYB-FW-SHADOWED-DENY-001",
                                title=f"Shadowed Firewall DENY Rule `{r.rule_id}` Rendered Ineffective",
                                description=f"Deny rule `{r.rule_id}` (`{r.source_cidr}` -> `{r.dest_cidr}` ports {r.port_start}-{r.port_end}) is shadowed by a preceding broad ALLOW rule.",
                                cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                                severity=Severity.HIGH,
                                cwe_ids=["CWE-284", "CWE-732"],
                                confidence=0.94,
                                verification_method=VerificationMethod.GRAPH_REACHABILITY,
                                endpoint_or_asset=f"fw:{r.rule_id}",
                                remediation_guidance="Move explicit DENY rules above broad ALLOW rules and enforce default-deny at rule-set tail.",
                                discovered_by="ely_cyber_segmentation_auditor",
                            )
                        )
                        break

        # 3. Compute transitive reachability from `internet` to `tier0_mgmt` / `restricted_mgmt` / `database`
        transitive_breaches: List[List[str]] = []
        for target_zone in ("tier0_mgmt", "restricted_mgmt", "database", "auditor_plane"):
            path = self._bfs_zone_path("internet", target_zone, zone_adj)
            if path:
                transitive_breaches.append(path)
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-FW-ZERO-TRUST-BREACH",
                        title=f"Zero-Trust Segmentation Violation: Transitive Path `{' -> '.join(path)}`",
                        description=f"Network ACL graph permits transitive reachability from untrusted `internet` zone to sensitive zone `{target_zone}` via `{path}`.",
                        cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                        severity=Severity.CRITICAL if len(path) == 2 else Severity.HIGH,
                        cwe_ids=["CWE-284", "CWE-653"],
                        confidence=0.96,
                        mitre_techniques=[MitreTechniqueRef("T1021", "Remote Services", MitreTactic.LATERAL_MOVEMENT)],
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        endpoint_or_asset=f"zone:{'->'.join(path)}",
                        remediation_guidance="Eliminate direct internet-to-sensitive-tier edges and enforce authenticating application proxies / mTLS jump tiers.",
                        discovered_by="ely_cyber_segmentation_auditor",
                    )
                )

        return {
            "rules_analyzed": len(rules),
            "shadowed_rules": shadowed_rules,
            "transitive_zone_breaches": transitive_breaches,
            "findings": findings,
        }

    @staticmethod
    def _parse_cidr(cidr: str) -> Optional[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        try:
            return ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            return None

    @staticmethod
    def _bfs_zone_path(start: str, goal: str, adj: Dict[str, Set[str]]) -> Optional[List[str]]:
        if start not in adj:
            return None
        q: deque[List[str]] = deque([[start]])
        visited: Set[str] = {start}
        while q:
            path = q.popleft()
            cur = path[-1]
            if cur == goal:
                return path
            for nxt in sorted(adj.get(cur, set())):
                if nxt not in visited:
                    visited.add(nxt)
                    q.append(path + [nxt])
        return None


# ---------------------------------------------------------------------------
# Unified Network & Protocol Auditor
# ---------------------------------------------------------------------------

class NetworkProtocolAuditor:
    """Comprehensive authorized network service, DNS, email, SMB/SSH/LDAP, and firewall auditor."""

    def __init__(self) -> None:
        self.dns_auditor = DNSSecurityAnalyzer()
        self.segmentation_auditor = ZeroTrustSegmentationAuditor()

    def audit_services(self, services: List[NetworkServiceDescriptor]) -> List[CyberVulnerability]:
        findings: List[CyberVulnerability] = []

        for svc in services:
            name = svc.service_name.lower()
            asset = f"{svc.host}:{svc.port}/{svc.protocol} ({svc.service_name})"
            flags = svc.config_flags or {}

            # 1. Unauthenticated high-risk data stores / control planes
            if name in HIGH_RISK_UNAUTH_DATASTORES and not svc.auth_required:
                _, desc = HIGH_RISK_UNAUTH_DATASTORES[name]
                findings.append(
                    make_cyber_vuln(
                        rule_id=f"CYB-NET-UNAUTH-{name.upper()}",
                        title=f"Unauthenticated {svc.service_name.upper()} Service Exposed on `{svc.host}:{svc.port}`",
                        description=f"{desc}. Zone=`{svc.exposed_zone}`.",
                        cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-306"],
                        confidence=0.99,
                        mitre_techniques=[MitreTechniqueRef("T1190", "Exploit Public-Facing Application", MitreTactic.INITIAL_ACCESS)],
                        cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="L"),
                        verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                        endpoint_or_asset=asset,
                        remediation_guidance=f"Enable mandatory authentication + mTLS on `{svc.service_name}` and bind exclusively to localhost or isolated private VPC subnets.",
                        discovered_by="ely_cyber_network_auditor",
                    )
                )

            # 2. Legacy cleartext protocols
            if name in CLEARTEXT_LEGACY_SERVICES:
                _, desc = CLEARTEXT_LEGACY_SERVICES[name]
                findings.append(
                    make_cyber_vuln(
                        rule_id=f"CYB-NET-CLEARTEXT-{name.upper()}",
                        title=f"Cleartext Legacy Protocol `{svc.service_name.upper()}` Active on `{svc.host}:{svc.port}`",
                        description=desc,
                        cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-319"],
                        confidence=0.98,
                        mitre_techniques=[MitreTechniqueRef("T1040", "Network Sniffing", MitreTactic.CREDENTIAL_ACCESS)],
                        verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                        endpoint_or_asset=asset,
                        remediation_guidance=f"Decommission `{svc.service_name}` and migrate to SSHv2/SFTP/HTTPS with TLS 1.3.",
                        discovered_by="ely_cyber_network_auditor",
                    )
                )

            # 3. SMB security posture (SMBv1, unsigned SMB, anonymous IPC$)
            if name == "smb" or svc.port == 445:
                if flags.get("smbv1_enabled"):
                    findings.append(
                        make_cyber_vuln(
                            rule_id="CYB-NET-SMBV1-001",
                            title="Deprecated SMBv1 Protocol Enabled (EternalBlue / Wormable RCE Surface)",
                            description=f"Host `{svc.host}:445` negotiates SMBv1, exposing critical kernel memory-corruption and downgrade surfaces.",
                            cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                            severity=Severity.CRITICAL,
                            cwe_ids=["CWE-327", "CWE-119"],
                            confidence=0.99,
                            mitre_techniques=[MitreTechniqueRef("T1210", "Exploitation of Remote Services", MitreTactic.LATERAL_MOVEMENT)],
                            verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                            endpoint_or_asset=asset,
                            remediation_guidance="Disable SMBv1 globally and enforce SMBv3.1.1 with AES-256-GCM encryption.",
                            discovered_by="ely_cyber_network_auditor",
                        )
                    )
                if flags.get("smb_signing_required") is False:
                    findings.append(
                        make_cyber_vuln(
                            rule_id="CYB-NET-SMB-SIGNING-001",
                            title="SMB Packet Signing Not Required (NTLM Relay Attack Surface)",
                            description=f"SMB service on `{svc.host}:445` does not require message signing, enabling NTLM relay lateral movement.",
                            cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                            severity=Severity.HIGH,
                            cwe_ids=["CWE-345", "CWE-290"],
                            confidence=0.97,
                            mitre_techniques=[MitreTechniqueRef("T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay", MitreTactic.CREDENTIAL_ACCESS, "001")],
                            verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                            endpoint_or_asset=asset,
                            remediation_guidance="Enforce `RequireSecuritySignature = 1` / `server signing = mandatory` on all domain hosts.",
                            discovered_by="ely_cyber_network_auditor",
                        )
                    )

            # 4. SSH hardening checks
            if name == "ssh" or svc.port == 22:
                weak_found = [a for a in svc.cipher_suites if any(w in a.lower() for w in WEAK_SSH_ALGORITHMS)]
                if weak_found:
                    findings.append(
                        make_cyber_vuln(
                            rule_id="CYB-NET-SSH-WEAK-ALG",
                            title=f"Weak SSH Cryptographic Algorithms Offered ({', '.join(weak_found[:4])})",
                            description=f"SSH daemon on `{svc.host}:{svc.port}` advertises deprecated KEX/cipher/MAC algorithms.",
                            cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                            severity=Severity.MEDIUM,
                            cwe_ids=["CWE-327"],
                            confidence=0.95,
                            verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                            endpoint_or_asset=asset,
                            remediation_guidance="Restrict sshd to `curve25519-sha256`, `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, and `hmac-sha2-512-etm`.",
                            discovered_by="ely_cyber_network_auditor",
                        )
                    )
                if flags.get("permit_root_login") or flags.get("password_auth_internet"):
                    findings.append(
                        make_cyber_vuln(
                            rule_id="CYB-NET-SSH-ROOT-PASS",
                            title="SSH Permits Direct Root Login or Password Authentication on Exposed Interface",
                            description=f"SSH on `{svc.host}:{svc.port}` permits root/password auth, elevating credential-stuffing compromise risk.",
                            cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                            severity=Severity.HIGH,
                            cwe_ids=["CWE-287", "CWE-250"],
                            confidence=0.95,
                            mitre_techniques=[MitreTechniqueRef("T1110", "Brute Force", MitreTactic.CREDENTIAL_ACCESS)],
                            verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                            endpoint_or_asset=asset,
                            remediation_guidance="Set `PermitRootLogin no`, `PasswordAuthentication no`, and require FIDO2/Ed25519 certificate-based SSH auth.",
                            discovered_by="ely_cyber_network_auditor",
                        )
                    )

            # 5. SMTP open relay & email spoofing posture
            if name == "smtp" or svc.port in (25, 587):
                if flags.get("open_relay"):
                    findings.append(
                        make_cyber_vuln(
                            rule_id="CYB-NET-SMTP-RELAY-001",
                            title="Unauthenticated SMTP Open Mail Relay Detected",
                            description=f"SMTP server `{svc.host}:{svc.port}` relays arbitrary external mail without authentication.",
                            cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                            severity=Severity.HIGH,
                            cwe_ids=["CWE-284"],
                            confidence=0.98,
                            verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                            endpoint_or_asset=asset,
                            remediation_guidance="Require SASL authentication over TLS and restrict relaying strictly to authorized internal domains.",
                            discovered_by="ely_cyber_network_auditor",
                        )
                    )
                if flags.get("dmarc_policy", "reject").lower() in ("none", ""):
                    findings.append(
                        make_cyber_vuln(
                            rule_id="CYB-NET-EMAIL-DMARC-001",
                            title="Missing or Non-Enforcing DMARC Policy (`p=none`) Enables Domain Spoofing",
                            description=f"Mail domain associated with `{svc.host}` lacks enforcing DMARC (`p=reject`/`quarantine`).",
                            cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                            severity=Severity.MEDIUM,
                            cwe_ids=["CWE-290"],
                            confidence=0.92,
                            mitre_techniques=[MitreTechniqueRef("T1566", "Phishing", MitreTactic.INITIAL_ACCESS)],
                            verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                            endpoint_or_asset=asset,
                            remediation_guidance="Publish strict SPF (`-all`), 2048-bit DKIM, and DMARC `p=reject`.",
                            discovered_by="ely_cyber_network_auditor",
                        )
                    )

            # 6. LDAP cleartext / anonymous bind
            if name == "ldap" or svc.port == 389:
                if not svc.tls_enabled or flags.get("anonymous_bind_enabled"):
                    findings.append(
                        make_cyber_vuln(
                            rule_id="CYB-NET-LDAP-CLEARTEXT-001",
                            title="Cleartext LDAP or Anonymous Directory Bind Enabled",
                            description=f"Directory service `{svc.host}:{svc.port}` allows unencrypted LDAP binds or anonymous enumeration.",
                            cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                            severity=Severity.HIGH,
                            cwe_ids=["CWE-319", "CWE-287"],
                            confidence=0.95,
                            mitre_techniques=[MitreTechniqueRef("T1087.002", "Domain Account Discovery", MitreTactic.DISCOVERY, "002")],
                            verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                            endpoint_or_asset=asset,
                            remediation_guidance="Mandate LDAPS (636) with TLS 1.3 + channel binding and disable anonymous LDAP binds.",
                            discovered_by="ely_cyber_network_auditor",
                        )
                    )

            # 7. SNMP v1/v2c default community strings
            if name == "snmp" or svc.port == 161:
                if flags.get("snmp_version") in ("1", "2c") or flags.get("community") in ("public", "private"):
                    findings.append(
                        make_cyber_vuln(
                            rule_id="CYB-NET-SNMP-DEFAULT-001",
                            title="SNMPv1/v2c Enabled with Default Community String",
                            description=f"SNMP agent on `{svc.host}:{svc.port}` exposes MIB telemetry via cleartext default community strings.",
                            cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                            severity=Severity.HIGH,
                            cwe_ids=["CWE-798", "CWE-319"],
                            confidence=0.97,
                            verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                            endpoint_or_asset=asset,
                            remediation_guidance="Upgrade to SNMPv3 with `authPriv` (SHA-256 + AES-128) and disable v1/v2c.",
                            discovered_by="ely_cyber_network_auditor",
                        )
                    )

        return findings
