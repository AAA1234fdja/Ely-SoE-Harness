"""
Generalized Cybersecurity Testing & Adversary Emulation Orchestrator.

Coordinates all `ely_soe.cyber` engines under strict `ScopeGuard` authorization:
  - Repository static & semantic analysis across Web, Auth, Crypto, API, K8s, IaC/CI-CD,
    Binary/Memory Safety, Firmware/IoT/OT, and YARA signatures
  - Optional live loopback-only dynamic probing against `AuthorizedSyntheticCyberRange`
    or an explicitly authorized local loopback URL (`127.0.0.1` / `localhost`)
  - Enterprise Cloud IAM privilege-escalation graph + Active Directory Tier-0 attack graph
    + Network/DNS/Zero-Trust firewall segmentation audits
  - 14-tactic MITRE ATT&CK sandbox adversary emulation + Sigma detective coverage scoring
  - CVSS v4.0 / EPSS / CISA KEV composite risk prioritization
  - Multi-domain Exploit-Chain Planning + Min-Cut Remediation Chokepoints
  - Automated STRIDE Data-Flow Threat Modeling + Grammar Fuzzer corpus generation
"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from ely_soe.core.models import Finding, Severity, new_id, utc_now_iso
from ely_soe.core.scope_guard import ScopeGuard, ScopeViolationError
from ely_soe.cyber.api_microservices_engine import APIMicroservicesSecurityEngine
from ely_soe.cyber.auth_access_control_engine import AuthAccessControlEngine
from ely_soe.cyber.binary_memory_engine import BinaryAndMemorySafetyEngine
from ely_soe.cyber.cloud_iam_engine import CloudIAMSecurityEngine
from ely_soe.cyber.cvss4_risk_engine import CyberRiskPrioritizationEngine
from ely_soe.cyber.detection_sigma_yara import SigmaDetectionEngine, YaraStyleScanner
from ely_soe.cyber.exploit_chain_planner import GeneralizedExploitChainPlanner
from ely_soe.cyber.firmware_iot_ot_engine import FirmwareIoTOTSecurityEngine
from ely_soe.cyber.grammar_fuzzer import GrammarAwareSecurityFuzzer
from ely_soe.cyber.iac_cicd_engine import IaCAndCICDSecurityEngine
from ely_soe.cyber.identity_ad_engine import ADCSTemplateConfig, IdentityAndADSecurityEngine
from ely_soe.cyber.k8s_container_engine import KubernetesAndContainerSecurityEngine
from ely_soe.cyber.mitre_attack_emulator import (
    EnterpriseDefensePosture,
    MitreAttackEmulationEngine,
)
from ely_soe.cyber.models import (
    AssetCriticality,
    CloudIAMPolicyStatement,
    CloudPrincipalNode,
    CyberAssessmentSummary,
    CyberDomain,
    CyberVulnerability,
    FirewallRuleDescriptor,
    HttpProbeRequest,
    HttpProbeResponse,
    IdentityDirectoryEdge,
    IdentityDirectoryObject,
    NetworkServiceDescriptor,
)
from ely_soe.cyber.network_protocol_auditor import (
    DNSSecurityAnalyzer,
    NetworkProtocolAuditor,
    ZeroTrustSegmentationAuditor,
)
from ely_soe.cyber.sandbox_targets import AuthorizedSyntheticCyberRange
from ely_soe.cyber.threat_model_stride import AutomatedStrideThreatModeler
from ely_soe.cyber.tls_crypto_auditor import TLSCryptoAuditor
from ely_soe.cyber.web_client_protocol_engine import WebClientProtocolEngine
from ely_soe.cyber.web_injection_engine import WebInjectionSecurityEngine
from ely_soe.cyber.web_ssrf_xxe_ssti_deser import WebServerSideVulnEngine


ALL_CYBER_DOMAINS: Tuple[str, ...] = tuple(d.value for d in CyberDomain)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def build_local_http_probe_handler(base_url: str, timeout_s: float = 4.0) -> Callable[[HttpProbeRequest], HttpProbeResponse]:
    """Build a loopback-only HTTP adapter mapping `HttpProbeRequest` -> `HttpProbeResponse`."""
    parsed = urllib.parse.urlparse(base_url)
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ScopeViolationError(
            f"HTTP probe handler is strictly restricted to loopback sandboxes (got '{parsed.hostname}')."
        )
    opener = urllib.request.build_opener(_NoRedirectHandler)
    base = base_url.rstrip("/")

    def _handler(req: HttpProbeRequest) -> HttpProbeResponse:
        qs = urllib.parse.urlencode(req.query_params, doseq=True) if req.query_params else ""
        path = req.path if req.path.startswith("/") else f"/{req.path}"
        url = f"{base}{path}" + (f"?{qs}" if qs else "")
        data = req.body.encode("utf-8") if req.body else None
        headers = dict(req.headers)
        if req.cookies and "Cookie" not in headers:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in req.cookies.items())
        if data is not None and "Content-Type" not in headers:
            headers["Content-Type"] = req.content_type

        ureq = urllib.request.Request(url=url, data=data, headers=headers, method=req.method.upper())
        t0 = time.perf_counter()
        try:
            with opener.open(ureq, timeout=timeout_s) as resp:
                raw_body = resp.read().decode("utf-8", errors="replace")
                resp_headers = {k: v for k, v in resp.headers.items()}
                status = int(resp.status)
        except urllib.error.HTTPError as err:
            raw_body = err.read().decode("utf-8", errors="replace") if err.fp else str(err)
            resp_headers = {k: v for k, v in err.headers.items()} if err.headers else {}
            status = int(err.code)
        except Exception as exc:
            return HttpProbeResponse(status_code=0, headers={}, body=str(exc), elapsed_ms=(time.perf_counter() - t0) * 1000.0)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return HttpProbeResponse(
            status_code=status,
            headers=resp_headers,
            body=raw_body,
            elapsed_ms=elapsed_ms,
        )

    return _handler


class GeneralizedCyberOrchestrator:
    """Unified ScopeGuard-governed multi-domain cybersecurity testing orchestrator."""

    def __init__(self, scope_guard: Optional[ScopeGuard] = None) -> None:
        self.scope_guard = scope_guard
        self.risk_engine = CyberRiskPrioritizationEngine()
        self.web_inj = WebInjectionSecurityEngine()
        self.web_client = WebClientProtocolEngine()
        self.web_server = WebServerSideVulnEngine()
        self.auth_engine = AuthAccessControlEngine()
        self.api_engine = APIMicroservicesSecurityEngine()
        self.net_auditor = NetworkProtocolAuditor()
        self.dns_analyzer = DNSSecurityAnalyzer()
        self.seg_auditor = ZeroTrustSegmentationAuditor()
        self.tls_crypto = TLSCryptoAuditor()
        self.cloud_iam = CloudIAMSecurityEngine()
        self.k8s_engine = KubernetesAndContainerSecurityEngine()
        self.iac_cicd = IaCAndCICDSecurityEngine()
        self.ad_engine = IdentityAndADSecurityEngine()
        self.binary_engine = BinaryAndMemorySafetyEngine()
        self.iot_ot_engine = FirmwareIoTOTSecurityEngine()
        self.mitre_emulator = MitreAttackEmulationEngine()
        self.sigma_engine = SigmaDetectionEngine()
        self.yara_scanner = YaraStyleScanner()
        self.chain_planner = GeneralizedExploitChainPlanner()
        self.stride_modeler = AutomatedStrideThreatModeler()
        self.grammar_fuzzer = GrammarAwareSecurityFuzzer()

    def assess_target(
        self,
        target_path: Optional[Path] = None,
        domains: Optional[Sequence[str]] = None,
        run_synthetic_range: bool = False,
        hardened_range: bool = False,
        run_enterprise_simulation: bool = True,
        run_mitre_emulation: bool = True,
        defense_posture: Optional[EnterpriseDefensePosture] = None,
        live_local_url: Optional[str] = None,
        asset_criticality: AssetCriticality = AssetCriticality.TIER_1_PRODUCTION,
        exposure_zone: str = "internet",
    ) -> Dict[str, Any]:
        """Execute a full or domain-filtered generalized cybersecurity assessment."""
        t0 = time.perf_counter()
        started_at = utc_now_iso()
        assessment_id = new_id("cyber")

        resolved_path: Optional[Path] = None
        if target_path is not None:
            resolved_path = Path(target_path).resolve()
            if self.scope_guard is not None:
                self.scope_guard.assert_path_in_scope(resolved_path)

        if live_local_url is not None:
            self._assert_local_authorized_url(live_local_url)

        active_domains: Set[str] = set(domains) if domains else set(ALL_CYBER_DOMAINS)
        all_vulns: List[CyberVulnerability] = []
        binary_profiles = []
        domain_timings_ms: Dict[str, float] = {}
        artifacts: Dict[str, Any] = {}
        all_detections = []

        # 1. Repository static & semantic analysis engines
        if resolved_path is not None and resolved_path.exists():
            static_dispatch = [
                (CyberDomain.WEB_INJECTION.value, lambda: self.web_inj.scan_directory(resolved_path)),
                (CyberDomain.WEB_CLIENT_PROTOCOL.value, lambda: self.web_client.scan_directory(resolved_path)),
                (CyberDomain.WEB_SSRF_XXE_SSTI_DESER.value, lambda: self.web_server.scan_directory(resolved_path)),
                (CyberDomain.AUTH_ACCESS_CONTROL.value, lambda: self.auth_engine.scan_directory(resolved_path)),
                (CyberDomain.API_MICROSERVICES.value, lambda: self.api_engine.scan_directory(resolved_path)),
                (CyberDomain.TLS_CRYPTOGRAPHY.value, lambda: self.tls_crypto.scan_directory(resolved_path)),
                (CyberDomain.CLOUD_IAM.value, lambda: self.cloud_iam.scan_policy_json_files(resolved_path)),
                (CyberDomain.KUBERNETES_CONTAINER.value, lambda: self.k8s_engine.scan_directory(resolved_path)),
                (CyberDomain.IAC_CICD.value, lambda: self.iac_cicd.scan_directory(resolved_path)),
                (CyberDomain.FIRMWARE_IOT_OT.value, lambda: self.iot_ot_engine.scan_directory(resolved_path)),
            ]
            for dom_name, runner in static_dispatch:
                if dom_name in active_domains:
                    ts = time.perf_counter()
                    found = runner()
                    all_vulns.extend(found)
                    domain_timings_ms[dom_name] = round((time.perf_counter() - ts) * 1000.0, 2)

            if CyberDomain.BINARY_MEMORY_SAFETY.value in active_domains:
                ts = time.perf_counter()
                bin_vulns, bin_profs = self.binary_engine.scan_directory(resolved_path)
                all_vulns.extend(bin_vulns)
                binary_profiles.extend(bin_profs)
                domain_timings_ms[CyberDomain.BINARY_MEMORY_SAFETY.value] = round((time.perf_counter() - ts) * 1000.0, 2)

            if CyberDomain.DETECTION_ENGINEERING.value in active_domains:
                ts = time.perf_counter()
                yara_hits = self.yara_scanner.scan_directory(resolved_path)
                all_detections.extend(yara_hits)
                artifacts["yara_matches"] = [m.to_dict() for m in yara_hits]
                domain_timings_ms["yara_scan"] = round((time.perf_counter() - ts) * 1000.0, 2)

        # 2. Optional Authorized Synthetic Cyber Range (127.0.0.1 loopback live DAST)
        if run_synthetic_range or live_local_url:
            ts = time.perf_counter()
            if live_local_url:
                live_vulns = self._probe_local_http_target(live_local_url)
                all_vulns.extend(live_vulns)
                artifacts["live_range"] = {"url": live_local_url, "hardened": False, "live_findings": len(live_vulns)}
            else:
                with AuthorizedSyntheticCyberRange(hardened=hardened_range) as srange:
                    live_vulns = self._probe_local_http_target(srange.base_url)
                    all_vulns.extend(live_vulns)
                    artifacts["live_range"] = {
                        "url": srange.base_url,
                        "hardened": hardened_range,
                        "live_findings": len(live_vulns),
                    }
            domain_timings_ms["live_dast_range"] = round((time.perf_counter() - ts) * 1000.0, 2)

        # 3. Enterprise Cloud IAM / AD / Network Reference Simulation Models (when enabled)
        if run_enterprise_simulation:
            if CyberDomain.CLOUD_IAM.value in active_domains:
                ts = time.perf_counter()
                iam_principals = self._build_reference_cloud_iam_graph(hardened=hardened_range)
                iam_report = self.cloud_iam.audit_principal_graph(iam_principals)
                all_vulns.extend(iam_report.get("findings", []))
                artifacts["cloud_iam_graph"] = {k: v for k, v in iam_report.items() if k != "findings"}
                domain_timings_ms["cloud_iam_graph"] = round((time.perf_counter() - ts) * 1000.0, 2)

            if CyberDomain.IDENTITY_ACTIVE_DIRECTORY.value in active_domains:
                ts = time.perf_counter()
                ad_objs, ad_edges, adcs_tpls = self._build_reference_ad_estate(hardened=hardened_range)
                ad_report = self.ad_engine.audit_directory_estate(ad_objs, ad_edges, adcs_tpls)
                all_vulns.extend(ad_report.get("findings", []))
                artifacts["active_directory_graph"] = {k: v for k, v in ad_report.items() if k != "findings"}
                domain_timings_ms["active_directory_graph"] = round((time.perf_counter() - ts) * 1000.0, 2)

            if CyberDomain.NETWORK_PROTOCOL.value in active_domains:
                ts = time.perf_counter()
                fw_rules, dns_cfg, svcs = self._build_reference_network_estate(hardened=hardened_range)
                fw_report = self.seg_auditor.audit_firewall_rules(fw_rules)
                dns_vulns = self.dns_analyzer.audit_dns_config(dns_cfg, asset="ns1.enterprise.local")
                svc_vulns = self.net_auditor.audit_services(svcs)
                all_vulns.extend(fw_report.get("findings", []))
                all_vulns.extend(dns_vulns)
                all_vulns.extend(svc_vulns)
                artifacts["network_zero_trust"] = {
                    "firewall_findings": len(fw_report.get("findings", [])),
                    "shadowed_rules": fw_report.get("shadowed_rules", []),
                    "dns_findings": len(dns_vulns),
                    "service_findings": len(svc_vulns),
                }
                domain_timings_ms["network_zero_trust"] = round((time.perf_counter() - ts) * 1000.0, 2)

        # 4. MITRE ATT&CK Adversary Emulation & Sigma Detective Coverage
        emulation_summary: Dict[str, Any] = {}
        if run_mitre_emulation and (
            CyberDomain.ADVERSARY_EMULATION.value in active_domains
            or CyberDomain.DETECTION_ENGINEERING.value in active_domains
        ):
            ts = time.perf_counter()
            posture = defense_posture or (
                EnterpriseDefensePosture.hardened_enterprise()
                if hardened_range
                else EnterpriseDefensePosture.vulnerable_baseline()
            )
            emu = self.mitre_emulator.run_campaign(posture=posture)
            sigma_cov = self.sigma_engine.measure_purple_team_coverage(emu)
            all_detections.extend(sigma_cov.get("raw_matches", []))
            emulation_summary = {
                k: v for k, v in emu.items() if k not in {"telemetry_events", "findings"}
            }
            artifacts["mitre_emulation"] = emulation_summary
            artifacts["mitre_navigator_json"] = self.mitre_emulator.export_attack_navigator_layer(emu)
            artifacts["sigma_detection"] = {k: v for k, v in sigma_cov.items() if k != "raw_matches"}
            if CyberDomain.ADVERSARY_EMULATION.value in active_domains:
                all_vulns.extend(emu.get("findings", []))
            domain_timings_ms["mitre_and_sigma"] = round((time.perf_counter() - ts) * 1000.0, 2)

        # 5. Deduplicate & Enrich/Prioritize with CVSS v4.0 / EPSS / CISA KEV
        deduped = self._deduplicate(all_vulns)
        risk_summary = self.risk_engine.enrich_and_prioritize(
            deduped,
            asset_criticality=asset_criticality,
            exposure_zone=exposure_zone,
        )

        # 6. Multi-Domain Exploit Chain Planning
        chain_report = self.chain_planner.plan_chains(deduped)
        artifacts["exploit_chains"] = {k: v for k, v in chain_report.items() if k != "raw_chains"}

        # 7. Automated STRIDE Threat Modeling
        stride_report = self.stride_modeler.build_threat_model(resolved_path, deduped)
        artifacts["stride_threat_model"] = stride_report

        # 8. Grammar Fuzzer Corpus Overview
        if CyberDomain.THREAT_MODELING.value in active_domains:
            artifacts["grammar_fuzzer"] = self.grammar_fuzzer.run_self_verification_suite()

        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in deduped:
            sev_counts[v.severity.value] = sev_counts.get(v.severity.value, 0) + 1

        if sev_counts["critical"] > 0 or chain_report["max_chain_risk"] >= 70.0:
            gate_verdict = "BLOCKED"
        elif sev_counts["high"] > 2:
            gate_verdict = "CONDITIONAL"
        else:
            gate_verdict = "APPROVED"

        summary_obj = CyberAssessmentSummary(
            assessment_id=assessment_id,
            target_name=(resolved_path.name if resolved_path else (live_local_url or "synthetic_enterprise_range")),
            target_root=str(resolved_path or live_local_url or "synthetic_enterprise_range"),
            started_at=started_at,
            completed_at=utc_now_iso(),
            domains_executed=sorted(active_domains),
            vulnerabilities=deduped,
            exploit_chains=chain_report.get("raw_chains", []),
            detection_matches=all_detections,
            emulation_summary=emulation_summary,
            threat_model=stride_report,
            binary_profiles=binary_profiles,
            risk_summary=risk_summary,
            domain_scores=risk_summary.get("domain_scores", {}),
            overall_cyber_posture=float(risk_summary.get("overall_cyber_posture", 100.0)),
        )

        summary_dict = summary_obj.to_dict()
        summary_dict["gate_verdict"] = gate_verdict
        summary_dict["max_cvss4"] = risk_summary.get("max_cvss4", 0.0)
        summary_dict["mean_cvss4"] = risk_summary.get("mean_cvss4", 0.0)
        summary_dict["detection_coverage_pct"] = float(
            artifacts.get("sigma_detection", {}).get("detective_coverage_pct", 0.0)
        )
        summary_dict["exploit_chains_identified"] = chain_report["kill_chains_found"]

        total_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        return {
            "assessment_id": assessment_id,
            "duration_ms": total_ms,
            "gate_verdict": gate_verdict,
            "summary": summary_dict,
            "portfolio_risk": risk_summary,
            "domain_timings_ms": domain_timings_ms,
            "vulnerabilities": [v.to_dict() for v in deduped],
            "raw_vulnerabilities": deduped,
            "artifacts": artifacts,
        }

    def _probe_local_http_target(self, base_url: str) -> List[CyberVulnerability]:
        """Run dynamic sandbox HTTP probes against an authorized loopback application."""
        handler = build_local_http_probe_handler(base_url)
        found: List[CyberVulnerability] = []
        found.extend(self.web_inj.probe_sandbox_endpoint(handler, endpoint="/api/search", param_name="q"))
        found.extend(self.web_client.probe_sandbox_endpoint(handler, endpoint="/api/search", param_name="q"))
        found.extend(self.web_client.probe_sandbox_endpoint(handler, endpoint="/redirect", param_name="next"))
        found.extend(
            self.web_server.probe_sandbox_ssrf_ssti_path(
                handler,
                ssrf_endpoint="/api/v1/preview",
                ssti_endpoint="/api/v1/render",
            )
        )

        hdr = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
        pay = base64.urlsafe_b64encode(b'{"sub":"1001","role":"user"}').decode().rstrip("=")
        found.extend(
            self.auth_engine.probe_sandbox_access_control(
                handler,
                user_a_token=f"{hdr}.{pay}.invalid",
                user_b_resource_path="/api/v1/users/1002",
                admin_endpoint="/api/v1/admin/config",
                profile_update_endpoint="/api/v1/users/1001",
                race_redeem_endpoint="/api/v1/coupons/redeem",
            )
        )
        return found

    @staticmethod
    def _build_reference_cloud_iam_graph(hardened: bool = False) -> List[CloudPrincipalNode]:
        if hardened:
            return [
                CloudPrincipalNode(
                    principal_id="arn:aws:iam::111122223333:role/app-readonly",
                    provider="aws",
                    principal_type="role",
                    account_id="111122223333",
                    is_admin=False,
                    mfa_enforced=True,
                    statements=[
                        CloudIAMPolicyStatement(
                            sid="ReadAppBucket",
                            effect="Allow",
                            actions=["s3:GetObject"],
                            resources=["arn:aws:s3:::prod-app-data/*"],
                        )
                    ],
                )
            ]
        return [
            CloudPrincipalNode(
                principal_id="arn:aws:iam::111122223333:role/ci-deployer",
                provider="aws",
                principal_type="role",
                account_id="111122223333",
                is_admin=False,
                is_external_facing=True,
                mfa_enforced=False,
                statements=[
                    CloudIAMPolicyStatement(
                        sid="PassAndLambda",
                        effect="Allow",
                        actions=["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction", "sts:AssumeRole"],
                        resources=["*"],
                    ),
                ],
                trust_principals=["*"],
            ),
            CloudPrincipalNode(
                principal_id="arn:aws:iam::111122223333:role/prod-admin",
                provider="aws",
                principal_type="role",
                account_id="111122223333",
                is_admin=True,
                mfa_enforced=False,
                statements=[CloudIAMPolicyStatement(sid="Admin", effect="Allow", actions=["*"], resources=["*"])],
                trust_principals=["arn:aws:iam::111122223333:role/ci-deployer"],
            ),
        ]

    @staticmethod
    def _build_reference_ad_estate(
        hardened: bool = False,
    ) -> Tuple[List[IdentityDirectoryObject], List[IdentityDirectoryEdge], List[ADCSTemplateConfig]]:
        if hardened:
            objs = [
                IdentityDirectoryObject("u-dev", "dev_alice", "user", "corp.local", tier=2),
                IdentityDirectoryObject("g-da", "Domain Admins", "group", "corp.local", tier=0),
            ]
            return objs, [], []
        objs = [
            IdentityDirectoryObject("u-dev", "dev_alice", "user", "corp.local", tier=2, dont_req_preauth=True),
            IdentityDirectoryObject("u-svc", "svc_sql_prod", "user", "corp.local", tier=1, spns=["MSSQLSvc/sql01.corp.local:1433"]),
            IdentityDirectoryObject("c-app", "APP-SRV01$", "computer", "corp.local", tier=1, unconstrained_delegation=True),
            IdentityDirectoryObject("g-da", "Domain Admins", "group", "corp.local", tier=0, admin_count=True),
        ]
        edges = [
            IdentityDirectoryEdge("u-dev", "u-svc", "WriteDacl", 0.90, "T1222", "Excessive ACL on service account"),
            IdentityDirectoryEdge("u-svc", "g-da", "DCSync", 0.95, "T1003.006", "Replicating Directory Changes All"),
        ]
        tpls = [
            ADCSTemplateConfig(
                template_name="CorpUserSmartcard",
                ca_name="CORP-ROOT-CA01",
                enrollee_supplies_subject=True,
                client_auth_eku=True,
                manager_approval_required=False,
                low_priv_enroll_principals=["Domain Users"],
            )
        ]
        return objs, edges, tpls

    @staticmethod
    def _build_reference_network_estate(
        hardened: bool = False,
    ) -> Tuple[List[FirewallRuleDescriptor], Dict[str, Any], List[NetworkServiceDescriptor]]:
        if hardened:
            return (
                [
                    FirewallRuleDescriptor("FW-H1", "ingress", "allow", "10.0.1.0/24", "10.0.2.0/24", "tcp", 443, 443, "dmz", "app", "HTTPS internal"),
                ],
                {"allow_zone_transfer_any": False, "dnssec_enabled": True, "dmarc_policy": "reject", "spf_strict": True},
                [NetworkServiceDescriptor("10.0.2.10", 443, "tcp", "https", tls_enabled=True, auth_required=True)],
            )
        fw = [
            FirewallRuleDescriptor("FW-1", "ingress", "allow", "0.0.0.0/0", "10.0.10.0/24", "tcp", 22, 22, "internet", "prod", "SSH from Internet"),
            FirewallRuleDescriptor("FW-2", "ingress", "allow", "0.0.0.0/0", "10.0.20.0/24", "tcp", 5432, 5432, "internet", "data", "Postgres from Internet"),
            FirewallRuleDescriptor("FW-3", "ingress", "deny", "0.0.0.0/0", "10.0.20.0/24", "tcp", 5432, 5432, "internet", "data", "Shadowed DB Deny"),
        ]
        dns_cfg = {"allow_zone_transfer_any": True, "dnssec_enabled": False, "dmarc_policy": "none", "spf_strict": False}
        svcs = [
            NetworkServiceDescriptor("10.0.20.5", 6379, "tcp", "redis", tls_enabled=False, auth_required=False),
            NetworkServiceDescriptor("10.0.10.8", 445, "tcp", "smb", tls_enabled=False, auth_required=True, config_flags={"smb_signing": False, "smbv1_enabled": True}),
        ]
        return fw, dns_cfg, svcs

    @staticmethod
    def _assert_local_authorized_url(url: str) -> None:
        parsed = urllib.parse.urlparse(url)
        if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ScopeViolationError(
                f"Live dynamic cybersecurity probing is strictly restricted to authorized loopback sandboxes "
                f"(127.0.0.1/localhost), got host '{parsed.hostname}'."
            )

    @staticmethod
    def _deduplicate(vulns: List[CyberVulnerability]) -> List[CyberVulnerability]:
        seen: Set[Tuple[str, str, int]] = set()
        out: List[CyberVulnerability] = []
        for v in vulns:
            key = (v.rule_id, v.file_path or v.endpoint_or_asset, v.line_start)
            if key in seen:
                continue
            seen.add(key)
            out.append(v)
        return out

    @staticmethod
    def to_core_findings(vulns: Sequence[CyberVulnerability]) -> List[Finding]:
        return [v.to_soe_finding() for v in vulns]
