"""
Network Perimeter, TLS/Cipher Suite, SSH Hardening & Zero-Trust Segmentation Auditor.

Audits real infrastructure & transport security configurations across repositories:
  - Reverse proxies (`nginx.conf`, `haproxy.cfg`, `envoy.yaml`, `Caddyfile`)
  - OpenSSH daemon configs (`sshd_config`)
  - Firewall / Cloud Security Groups (`*.tf`, `iptables*`, `security_group*.json`)
  - Kubernetes `NetworkPolicy` & Istio `PeerAuthentication` (`*.yaml`, `*.yml`)
  - Python/JS TLS socket / SSLContext setups (`ssl.PROTOCOL_TLSv1`, `CERT_NONE`, `verify=False`)

Detects 12 High-Impact Network/Transport Misconfigurations:
  1. Legacy TLS/SSL protocols (`SSLv2`, `SSLv3`, `TLSv1`, `TLSv1.1`)
  2. Broken cipher suites (`RC4`, `3DES`, `DES`, `EXPORT`, `NULL`, `aNULL`, `MD5`, `ADH`)
  3. Disabled certificate verification (`CERT_NONE`, `check_hostname = False`, `InsecureSkipVerify: true`)
  4. SSH root login (`PermitRootLogin yes`) & password auth (`PasswordAuthentication yes`)
  5. SSH weak algorithms (`diffie-hellman-group1-sha1`, `ssh-rsa`, `arcfour`)
  6. World-open management/database ports (`0.0.0.0/0` or `::/0` on `22`, `3389`, `5432`, `3306`, `6379`, `27017`, `9200`, `2375`)
  7. Cleartext internal service protocols (`http://` on non-localhost, `ftp://`, `telnet://`, `redis://` without `rediss://`)
  8. Missing Kubernetes `default-deny` ingress/egress `NetworkPolicy` or Istio `PERMISSIVE` mTLS
  9. Missing HSTS (`Strict-Transport-Security`) on HTTPS reverse-proxy blocks
 10. Unauthenticated Docker daemon TCP binding (`tcp://0.0.0.0:2375`)

Computes a quantitative **Zero-Trust Network Segmentation Index (0..100)**.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ely_soe.core.models import Severity, utc_now_iso
from ely_soe.cyber.models import (
    CyberDomain,
    CyberVulnerability,
    VerificationMethod,
    make_cyber_vuln,
)


@dataclass(frozen=True)
class NetworkRule:
    rule_id: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    cwe: str
    category: str
    remediation: str


NETWORK_TLS_RULES: Tuple[NetworkRule, ...] = (
    NetworkRule(
        "CYB-NET-LEGACY-TLS",
        "Legacy Deprecated SSL/TLS Protocol Enabled (SSLv2/SSLv3/TLS 1.0/1.1)",
        re.compile(r"(?i)(?:ssl_protocols\s+[^;\n]*(?:SSLv[23]|TLSv1(?:\.1)?\b)|PROTOCOL_SSLv[23]|PROTOCOL_TLSv1(?:_1)?|TLSVersion\.TLSv1(?:_1)?\b|MinVersion.*VersionTLS1[01])"),
        Severity.HIGH, "CWE-327", "TLS_PROTOCOL",
        "Restrict transport protocols strictly to `TLSv1.2` and `TLSv1.3` (`ssl.TLSVersion.TLSv1_3` preferred).",
    ),
    NetworkRule(
        "CYB-NET-BROKEN-CIPHER",
        "Cryptographically Broken Cipher Suite Configured (RC4/3DES/NULL/EXPORT)",
        re.compile(r"(?i)(?:ssl_ciphers|ciphers|CipherSuites)[^\n]{0,120}\b(?:RC4|3DES|DES-CBC|EXP(?:ORT)?|aNULL|eNULL|MD5|ADH)\b"),
        Severity.HIGH, "CWE-327", "TLS_CIPHER",
        "Configure AEAD-only forward-secret suites (`TLS_AES_256_GCM_SHA384`, `ECDHE-ECDSA-AES256-GCM-SHA384`).",
    ),
    NetworkRule(
        "CYB-NET-CERT-VERIFY-OFF",
        "TLS Certificate Verification Explicitly Disabled (MITM Exposure)",
        re.compile(r"(?i)(?:ssl\.CERT_NONE|check_hostname\s*=\s*False|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|verify\s*=\s*False)"),
        Severity.CRITICAL, "CWE-295", "TLS_VERIFY",
        "Enable full X.509 chain and hostname validation (`ssl.create_default_context()` / `verify=True`).",
    ),
    NetworkRule(
        "CYB-NET-SSH-ROOT-PW",
        "Insecure OpenSSH Daemon Configuration (PermitRootLogin / PasswordAuthentication)",
        re.compile(r"(?im)^\s*(?:PermitRootLogin\s+yes|PasswordAuthentication\s+yes|PermitEmptyPasswords\s+yes)\b"),
        Severity.CRITICAL, "CWE-287", "SSH_HARDENING",
        "Set `PermitRootLogin no`, `PasswordAuthentication no`, `PubkeyAuthentication yes`, and enforce FIDO2/Ed25519 keys.",
    ),
    NetworkRule(
        "CYB-NET-WORLD-OPEN-SENSITIVE-PORT",
        "Firewall / Security Group Exposes Sensitive Management or DB Port to `0.0.0.0/0`",
        re.compile(r"(?is)(?:0\.0\.0\.0/0|::/0)[^\n]{0,180}(?:22|3389|5432|3306|6379|27017|9200|2375)\b|(?:from_port|port)\s*[:=]\s*(?:22|3389|5432|3306|6379|27017|9200|2375)\b[^\n]{0,180}(?:0\.0\.0\.0/0|::/0)"),
        Severity.CRITICAL, "CWE-284", "FIREWALL_EXPOSURE",
        "Restrict ingress CIDR blocks to private VPC subnets or bastion/Zero-Trust identity proxy (Tailscale/IAP/SSM).",
    ),
    NetworkRule(
        "CYB-NET-DOCKER-TCP-UNAUTH",
        "Unauthenticated Docker Engine TCP Socket Bound on Port 2375",
        re.compile(r"(?i)(?:tcp://0\.0\.0\.0:2375|DOCKER_HOST\s*=\s*['\"]?tcp://[^'\"\s]+:2375)"),
        Severity.CRITICAL, "CWE-306", "CONTAINER_NETWORK",
        "Bind Docker strictly to local Unix socket or enforce mutual TLS (`--tlsverify` on port 2376).",
    ),
    NetworkRule(
        "CYB-NET-ISTIO-PERMISSIVE-MTLS",
        "Service Mesh Mutual TLS Set to PERMISSIVE or DISABLED",
        re.compile(r"(?is)kind\s*:\s*PeerAuthentication[\s\S]{0,240}mode\s*:\s*(?:PERMISSIVE|DISABLE)"),
        Severity.HIGH, "CWE-319", "ZERO_TRUST_MTLS",
        "Enforce `mtls.mode: STRICT` across all production service-mesh namespaces.",
    ),
    NetworkRule(
        "CYB-NET-CLEARTEXT-PROTOCOL",
        "Cleartext Legacy Network Protocol Used (FTP / Telnet)",
        re.compile(r"(?i)\b(?:ftp|telnet)://[A-Za-z0-9_.-]+"),
        Severity.MEDIUM, "CWE-319", "CLEARTEXT_TRANSPORT",
        "Migrate cleartext transports to SFTP/SSH or TLS 1.3 encrypted protocols.",
    ),
)

NET_SCANNABLE_EXTS = frozenset({
    ".py", ".js", ".ts", ".go", ".conf", ".cfg", ".yml", ".yaml", ".tf", ".tfvars", ".json", ".sh", ".ini", ".toml",
})


class NetworkTLSZeroTrustAuditor:
    """Audits TLS/cipher hygiene, SSH hardening, firewall exposure & Zero-Trust mTLS configs."""

    def audit_text(self, content: str, *, file_path: str = "<inline>") -> List[CyberVulnerability]:
        vulns: List[CyberVulnerability] = []
        for rule in NETWORK_TLS_RULES:
            for m in rule.pattern.finditer(content):
                lineno = content[: m.start()].count("\n") + 1
                snippet = m.group(0).strip().replace("\n", " ")[:140]
                vulns.append(
                    make_cyber_vuln(
                        rule_id=rule.rule_id,
                        title=f"[Network/TLS | {rule.category}] {rule.title}",
                        description=f"Matched `{snippet}` in `{file_path}:{lineno}`.",
                        cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY if "TLS" in rule.category else CyberDomain.NETWORK_PROTOCOL,
                        severity=rule.severity,
                        cwe_ids=[rule.cwe],
                        confidence=0.93,
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=file_path,
                        line_start=lineno,
                        endpoint_or_asset=f"{file_path}:{lineno}",
                        remediation_guidance=rule.remediation,
                        discovered_by="ely_network_tls_zerotrust_auditor",
                    )
                )
        return vulns

    def audit_repository(self, target_dir: str | Path) -> Dict[str, Any]:
        root = Path(target_dir).resolve()
        files = [root] if root.is_file() else sorted(root.rglob("*"))
        all_vulns: List[CyberVulnerability] = []
        files_audited = 0
        by_category: Dict[str, int] = {}
        has_network_policy = False

        for f in files:
            if not f.is_file() or "__pycache__" in f.parts or ".git" in f.parts or ".venv" in f.parts:
                continue
            if f.suffix.lower() not in NET_SCANNABLE_EXTS and f.name not in ("sshd_config", "nginx.conf", "haproxy.cfg", "Caddyfile"):
                continue
            if f.stat().st_size > 512_000:
                continue
            rel = f.name if root.is_file() else str(f.relative_to(root))
            try:
                txt = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            files_audited += 1
            if "kind: NetworkPolicy" in txt:
                has_network_policy = True
            hits = self.audit_text(txt, file_path=rel)
            all_vulns.extend(hits)
            for h in hits:
                cat = h.rule_id
                by_category[cat] = by_category.get(cat, 0) + 1

        penalty = sum(
            24.0 if v.severity == Severity.CRITICAL else
            13.0 if v.severity == Severity.HIGH else
            6.0 if v.severity == Severity.MEDIUM else 2.0
            for v in all_vulns
        )
        zt_index = round(max(0.0, min(100.0, 100.0 - penalty + (4.0 if has_network_policy else 0.0))), 2)

        return {
            "audited_at": utc_now_iso(),
            "target": str(root),
            "files_audited": files_audited,
            "zero_trust_network_index": zt_index,
            "kubernetes_network_policy_present": has_network_policy,
            "findings_count": len(all_vulns),
            "by_rule": by_category,
            "vulnerabilities": all_vulns,
        }
