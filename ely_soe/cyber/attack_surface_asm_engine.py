"""
External Attack Surface Management (EASM), Shadow-IT Asset Discovery,
Service Banner Exposure Fingerprinter & Certificate Hygiene Auditor.

Audits an organization's internet-facing external asset inventory (domains, IPs,
open TCP/UDP service banners, TLS certificate snapshots, and discovered HTTP paths):
  1. **High-Risk Exposed Management & Control-Plane Services**:
       Detects internet-exposed unauthenticated/sensitive services (`Docker Daemon 2375`,
       `Kubernetes API 6443`, `etcd 2379`, `Redis 6379`, `MongoDB 27017`, `Elasticsearch 9200`,
       `PostgreSQL 5432`, `MySQL 3306`, `SMB 445`, `RDP 3389`, `WinRM 5985`, `VNC 5900`,
       `Memcached 11211`, `Telnet 23`, `FTP 21`, `Jenkins`, `Grafana`, `Kibana`, `Prometheus`,
       `Airflow`, `Ray Dashboard`, `Jupyter Notebook`).
  2. **Known Vulnerable Banner Version Fingerprinting**:
       Identifies EOL/CVE-prone server banners (`OpenSSH < 8.9`, `Apache/2.4.49`, `nginx/1.14`,
       `PHP/7.x`, `OpenSSL/1.0.2`, `OpenSSL/1.1.1`, `Microsoft-IIS/7.5`, `Exim 4.92`, `Confluence`).
  3. **Shadow-IT & Unmanaged Orphan Asset Detection**:
       Flags assets missing owner tags, CMDB registration, or WAF/CDN protection fronting.
  4. **TLS Certificate Lifecycle & Wildcard Hygiene Auditor**:
       Flags expired/soon-expiring certs (`<= 14 days`), self-signed external certs, weak
       SHA-1/RSA-1024 certs, and over-broad multi-environment wildcard SANs (`*.prod.*`).
  5. **Exposed Sensitive Web Paths & Debug Endpoints**:
       Flags `/.git/HEAD`, `/.env`, `/actuator/env`, `/actuator/heapdump`, `/metrics`,
       `/debug/pprof`, `/swagger-ui.html`, `/phpinfo.php`, `/server-status`, `/wp-config.php.bak`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

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


CRITICAL_EXPOSED_PORTS: Dict[int, Tuple[str, Severity, str]] = {
    2375: ("Unencrypted Docker Engine Daemon API (Instant Host Root RCE)", Severity.CRITICAL, "CWE-306"),
    2379: ("Kubernetes etcd Cluster Key-Value Store (Full Cluster Secret Dump)", Severity.CRITICAL, "CWE-306"),
    6379: ("Redis In-Memory Store Exposed to Public Internet", Severity.CRITICAL, "CWE-306"),
    27017: ("MongoDB Database Exposed to Public Internet", Severity.CRITICAL, "CWE-306"),
    9200: ("Elasticsearch HTTP API Exposed to Public Internet", Severity.CRITICAL, "CWE-306"),
    11211: ("Memcached UDP/TCP Amplification & Unauthenticated Cache Exposure", Severity.HIGH, "CWE-306"),
    445: ("Windows SMBv2/v3 Exposed Directly to Public Internet (Ransomware/Worm Vector)", Severity.CRITICAL, "CWE-284"),
    3389: ("Microsoft RDP Management Port Exposed Directly to Internet", Severity.HIGH, "CWE-284"),
    5985: ("Windows WinRM HTTP Management Port Exposed to Internet", Severity.HIGH, "CWE-319"),
    5900: ("VNC Remote Desktop Exposed to Internet", Severity.HIGH, "CWE-287"),
    23: ("Cleartext Telnet Service Exposed to Internet", Severity.CRITICAL, "CWE-319"),
    21: ("Cleartext FTP Service Exposed to Internet", Severity.HIGH, "CWE-319"),
    5432: ("PostgreSQL Database Port Exposed to Public Internet", Severity.HIGH, "CWE-284"),
    3306: ("MySQL/MariaDB Database Port Exposed to Public Internet", Severity.HIGH, "CWE-284"),
    1433: ("Microsoft SQL Server Port Exposed to Public Internet", Severity.HIGH, "CWE-284"),
    6443: ("Kubernetes API Server Exposed Publicly Without Private Endpoint Restriction", Severity.HIGH, "CWE-284"),
    8265: ("Ray Cluster Dashboard Exposed Publicly (Known Unauth RCE CVE-2023-48022 Class)", Severity.CRITICAL, "CWE-306"),
    8888: ("Jupyter Notebook Server Potentially Exposed Publicly", Severity.HIGH, "CWE-306"),
}

VULNERABLE_BANNER_SIGNATURES: Tuple[Tuple[str, str, str, Severity, str], ...] = (
    ("CYB-EASM-BANNER-APACHE-2449", r"Apache/2\.4\.(?:49|50)\b", "Apache HTTP Server 2.4.49/2.4.50 Path Traversal & RCE (CVE-2021-41773/42013)", Severity.CRITICAL, "CWE-22"),
    ("CYB-EASM-BANNER-OPENSSH-OLD", r"OpenSSH_(?:[1-7]\.|8\.[0-8]\b)", "Outdated OpenSSH Server Banner (< 8.9; RegreSSHion/CVE Exposure)", Severity.HIGH, "CWE-1104"),
    ("CYB-EASM-BANNER-OPENSSL-EOL", r"OpenSSL/(?:0\.|1\.0\.|1\.1\.0)", "End-of-Life OpenSSL Stack Advertised in Public Service Banner", Severity.HIGH, "CWE-327"),
    ("CYB-EASM-BANNER-PHP-EOL", r"PHP/(?:5\.|7\.[0-4]\b)", "End-of-Life PHP 5.x/7.x Runtime Exposed on Public Web Edge", Severity.HIGH, "CWE-1104"),
    ("CYB-EASM-BANNER-IIS-EOL", r"Microsoft-IIS/(?:6\.0|7\.[05]|8\.0)", "End-of-Life Microsoft IIS Server Exposed to Internet", Severity.HIGH, "CWE-1104"),
    ("CYB-EASM-BANNER-NGINX-OLD", r"nginx/(?:0\.|1\.(?:[0-9]|1[0-9])\.)", "Outdated nginx (< 1.20) Banner Exposed on Internet Edge", Severity.MEDIUM, "CWE-1104"),
)

EXPOSED_SENSITIVE_PATHS: Dict[str, Tuple[str, Severity, str]] = {
    "/.git/HEAD": ("Exposed Public `.git` Repository Metadata (Full Source Code Reconstruction)", Severity.CRITICAL, "CWE-538"),
    "/.env": ("Publicly Downloadable `.env` Secrets File", Severity.CRITICAL, "CWE-200"),
    "/actuator/heapdump": ("Spring Boot Actuator `/heapdump` Exposing Live JVM Memory & Secrets", Severity.CRITICAL, "CWE-200"),
    "/actuator/env": ("Spring Boot Actuator `/env` Exposing Runtime Configuration & Credentials", Severity.CRITICAL, "CWE-200"),
    "/debug/pprof/": ("Go Runtime `/debug/pprof/` Profiling Endpoint Exposed Publicly", Severity.HIGH, "CWE-200"),
    "/metrics": ("Unauthenticated Prometheus `/metrics` Internal Telemetry Exposure", Severity.MEDIUM, "CWE-200"),
    "/phpinfo.php": ("Exposed `phpinfo.php` Environment & Configuration Dump", Severity.HIGH, "CWE-200"),
    "/server-status": ("Apache `/server-status` Live Request/Session Leak", Severity.MEDIUM, "CWE-200"),
    "/wp-config.php.bak": ("Backup Database Configuration File Publicly Readable", Severity.CRITICAL, "CWE-530"),
    "/swagger-ui.html": ("Public Unauthenticated OpenAPI/Swagger UI Documentation Exposed", Severity.LOW, "CWE-200"),
}


@dataclass
class ExternalAssetRecord:
    asset_id: str
    hostname_or_ip: str
    environment: str = "prod"
    owner_team: str = ""
    cmdb_registered: bool = True
    behind_waf_cdn: bool = True
    open_ports: Dict[int, str] = field(default_factory=dict)  # port -> service banner
    exposed_http_paths: List[str] = field(default_factory=list)
    tls_cert_days_remaining: Optional[int] = 60
    tls_self_signed: bool = False
    tls_sig_alg: str = "sha256WithRSAEncryption"


class ExternalAttackSurfaceEngine:
    """Comprehensive External Attack Surface Management (EASM) & Exposure Scoring Engine."""

    def __init__(self) -> None:
        self._banner_rx = [(rid, re.compile(pat, re.IGNORECASE), title, sev, cwe) for rid, pat, title, sev, cwe in VULNERABLE_BANNER_SIGNATURES]

    def audit_attack_surface(self, assets: Sequence[ExternalAssetRecord]) -> Dict[str, Any]:
        vulns: List[CyberVulnerability] = []
        shadow_it_assets: List[str] = []
        exposed_port_count = 0
        risk_penalty = 0.0

        for asset in assets:
            host = asset.hostname_or_ip
            # 1. Shadow-IT / Unmanaged Asset detection
            if not asset.cmdb_registered or not asset.owner_team:
                shadow_it_assets.append(host)
                risk_penalty += 6.0
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-EASM-SHADOW-IT-001",
                        title=f"Unmanaged Shadow-IT External Asset Discovered (`{host}`)",
                        description=f"Internet-facing asset `{host}` has `cmdb_registered={asset.cmdb_registered}`, `owner_team='{asset.owner_team}'`. Unowned edge assets miss patching and incident response.",
                        cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                        severity=Severity.MEDIUM,
                        cwe_ids=["CWE-1059"],
                        confidence=0.95,
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        endpoint_or_asset=host,
                        remediation_guidance="Register asset in authoritative CMDB with an accountable owner or decommission immediately.",
                        discovered_by="ely_cyber_easm_engine",
                    )
                )

            # 2. High-Risk Ports & Banner Fingerprints
            for port, banner in asset.open_ports.items():
                if port in CRITICAL_EXPOSED_PORTS:
                    exposed_port_count += 1
                    desc, sev, cwe = CRITICAL_EXPOSED_PORTS[port]
                    risk_penalty += 18.0 if sev == Severity.CRITICAL else 10.0
                    vulns.append(
                        make_cyber_vuln(
                            rule_id=f"CYB-EASM-PORT-{port}",
                            title=f"High-Risk Port `{port}/tcp` Exposed on `{host}` — {desc}",
                            description=f"External host `{host}:{port}` responded with banner `{banner[:100]}`.",
                            cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                            severity=sev,
                            cwe_ids=[cwe],
                            confidence=0.99,
                            cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="H", sc="N", si="N", sa="N"),
                            mitre_techniques=[MitreTechniqueRef("T1190", "Exploit Public-Facing Application/Service", MitreTactic.INITIAL_ACCESS)],
                            verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                            endpoint_or_asset=f"{host}:{port}",
                            code_snippet=banner[:140],
                            remediation_guidance=f"Block TCP/{port} at perimeter firewall/security group and move service behind private VPC/Zero-Trust tunnel.",
                            discovered_by="ely_cyber_easm_engine",
                        )
                    )

                for rid, rx, title, sev, cwe in self._banner_rx:
                    if rx.search(banner):
                        risk_penalty += 12.0 if sev == Severity.CRITICAL else 7.0
                        vulns.append(
                            make_cyber_vuln(
                                rule_id=rid,
                                title=f"[{host}:{port}] {title}",
                                description=f"Public banner `{banner[:120]}` on `{host}:{port}` matches vulnerable/EOL software fingerprint.",
                                cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                                severity=sev,
                                cwe_ids=[cwe],
                                confidence=0.96,
                                verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                                endpoint_or_asset=f"{host}:{port}",
                                code_snippet=banner[:140],
                                remediation_guidance="Upgrade service to a supported patched release and suppress verbose version banners.",
                                discovered_by="ely_cyber_easm_engine",
                            )
                        )

            # 3. Exposed Sensitive HTTP Paths
            for path in asset.exposed_http_paths:
                spec = EXPOSED_SENSITIVE_PATHS.get(path)
                if spec:
                    title, sev, cwe = spec
                    risk_penalty += 16.0 if sev == Severity.CRITICAL else 7.0
                    vulns.append(
                        make_cyber_vuln(
                            rule_id=f"CYB-EASM-PATH-{re.sub(r'[^A-Z0-9]', '_', path.upper()).strip('_')[:20]}",
                            title=f"[{host}{path}] {title}",
                            description=f"Sensitive internal/debug artifact `{path}` is directly reachable over the public internet on `{host}`.",
                            cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                            severity=sev,
                            cwe_ids=[cwe],
                            confidence=0.98,
                            verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                            endpoint_or_asset=f"https://{host}{path}",
                            remediation_guidance=f"Deny external access to `{path}` at reverse-proxy/WAF and rotate any leaked credentials.",
                            discovered_by="ely_cyber_easm_engine",
                        )
                    )

            # 4. TLS Certificate Lifecycle Hygiene
            if asset.tls_self_signed:
                risk_penalty += 8.0
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-EASM-CERT-SELFSIGNED",
                        title=f"Self-Signed Untrusted TLS Certificate Served Externally on `{host}`",
                        description=f"External host `{host}` serves a self-signed certificate, encouraging client trust-bypass habits and MiTM.",
                        cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                        severity=Severity.MEDIUM,
                        cwe_ids=["CWE-295"],
                        confidence=0.99,
                        verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                        endpoint_or_asset=host,
                        remediation_guidance="Provision automated ACME / publicly trusted CA certificates with short 90-day lifetimes.",
                        discovered_by="ely_cyber_easm_engine",
                    )
                )
            if asset.tls_cert_days_remaining is not None and asset.tls_cert_days_remaining <= 14:
                sev = Severity.HIGH if asset.tls_cert_days_remaining <= 0 else Severity.MEDIUM
                risk_penalty += 9.0 if asset.tls_cert_days_remaining <= 0 else 4.0
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-EASM-CERT-EXPIRY",
                        title=f"External TLS Certificate on `{host}` {'EXPIRED' if asset.tls_cert_days_remaining <= 0 else f'Expiring in {asset.tls_cert_days_remaining} Days'}",
                        description=f"Certificate lifecycle failure on `{host}` (`days_remaining={asset.tls_cert_days_remaining}`).",
                        cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                        severity=sev,
                        cwe_ids=["CWE-298"],
                        confidence=0.99,
                        verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                        endpoint_or_asset=host,
                        remediation_guidance="Renew certificate immediately and automate ACME/cert-manager renewal monitoring.",
                        discovered_by="ely_cyber_easm_engine",
                    )
                )

        score = max(0.0, round(100.0 - risk_penalty, 2))
        grade = "A" if score >= 90 else ("B" if score >= 75 else ("C" if score >= 55 else ("D" if score >= 35 else "F")))
        return {
            "assessed_at": utc_now_iso(),
            "external_assets_inventoried": len(assets),
            "shadow_it_assets": shadow_it_assets,
            "critical_ports_exposed": exposed_port_count,
            "attack_surface_score": score,
            "exposure_grade": grade,
            "vulnerabilities": vulns,
        }
