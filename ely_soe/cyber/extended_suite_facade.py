"""
ELY Generalized Enterprise Cybersecurity Suite — Unified Extended Capability Facade.

Integrates ALL 65+ specialized cybersecurity engines in `ely_soe.cyber` (Core 16 domains +
Phase A + Wave I + Wave III + Wave III-B + Wave III-C + Wave III-D) behind a single,
ScopeGuard-governed, deterministic enterprise interface suitable for CLI, Web API, and
Harness² orchestration:
  - **Repository & Code-Level Deep Scan**: runs `GeneralizedCyberOrchestrator` PLUS
    `CICDPipelineGraphAuditor`, `MemoryCorruptionExploitModeler`, `OpenAPIContractSecurityAuditor`,
    `SmartContractWeb3Auditor`, `QuantumSideChannelAuditor`, `SupplyChainTyposquatEngine`,
    `BrowserDOMCSPEngine`, `PrivacyPIIGDPREngine`, `ServerlessMeshAuditor`, `DevSecOpsArtifactVerifier`,
    `SecretsAndDLPEngine`, `SupplyChainSBOMEngine`, `AILLMRedTeamEngine`.
  - **Enterprise Infrastructure, Cloud, Identity & Operations Simulation**:
    `ExternalAttackSurfaceEngine` (EASM), `RansomwareResilienceSimulator` (Contagion + 3-2-1-1-0),
    `SaaSWorkspaceSSPMEngine` (GitHub/M365/Okta/Slack), `IdentityFederationAuditor` (SAML/OIDC/Kerberos),
    `CloudPostureCSPM`, `ZeroTrustIdentityEngine`, `EBPFKernelAuditEngine`, `DNSBGPEmailAuthAuditor`,
    `OTICSSCADAAuditor`, `WindowsEndpointEDREngine`, `NetworkPCAPPacketAnalyzer`, `ReverseEngineeringDisasmLite`.
  - **Defensive Engineering, Threat Hunting, SOAR & Executive Risk Quantification**:
    `ThreatHuntingSigmaYaraEngine`, `SOARIncidentPlaybookEngine`, `WAFIDSRuleSynthesizer`,
    `ForensicsIREngine`, `ThreatIntelSTIXEngine`, `PurpleTeamScorecardEngine` (FAIR Monte-Carlo ALE),
    `EnterpriseComplianceMapper` (7 frameworks), and `PentestReportGenerator`.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ely_soe.core.models import Severity, utc_now_iso
from ely_soe.core.scope_guard import ScopeGuard
from ely_soe.cyber.adversarial_ml_security import AdversarialMLSecurityEngine
from ely_soe.cyber.ai_llm_redteam_engine import AILLMRedTeamEngine
from ely_soe.cyber.api_fuzz_contract_auditor import OpenAPIContractSecurityAuditor
from ely_soe.cyber.attack_surface_asm_engine import ExternalAssetRecord, ExternalAttackSurfaceEngine
from ely_soe.cyber.browser_dom_csp_engine import BrowserDOMCSPEngine
from ely_soe.cyber.chaos_resilience_tester import SecurityChaosResilienceTester
from ely_soe.cyber.cicd_pipeline_graph_auditor import CICDPipelineGraphAuditor
from ely_soe.cyber.cloud_posture_cspm import MultiCloudCSPMEngine
from ely_soe.cyber.compliance_mapper import EnterpriseComplianceMapper
from ely_soe.cyber.crypto_protocol_verifier import CryptoProtocolVerifier
from ely_soe.cyber.cwe_knowledge_base import CWEKnowledgeBase
from ely_soe.cyber.database_security_auditor import DatabaseSecurityAuditor
from ely_soe.cyber.devsecops_artifact_verifier import DevSecOpsArtifactVerifier
from ely_soe.cyber.dns_bgp_email_auth_auditor import DNSBGPEmailAuthAuditor
from ely_soe.cyber.ebpf_kernel_audit_engine import KernelAndSeccompAuditEngine
from ely_soe.cyber.forensics_ir_engine import DigitalForensicsIREngine
from ely_soe.cyber.graphql_grpc_websocket_engine import GraphQLGRPCWebSocketAuditor
from ely_soe.cyber.identity_federation_saml_oidc_auditor import IdentityFederationAuditor
from ely_soe.cyber.memory_corruption_exploit_modeler import MemoryCorruptionExploitModeler
from ely_soe.cyber.mobile_client_security import MobileAndClientSecurityAuditor
from ely_soe.cyber.models import AssetCriticality, CyberVulnerability
from ely_soe.cyber.network_pcap_packet_analyzer import NetworkPCAPPacketAnalyzer
from ely_soe.cyber.orchestrator import GeneralizedCyberOrchestrator
from ely_soe.cyber.ot_ics_scada_auditor import OTICSSCADAAuditor
from ely_soe.cyber.pentest_report_generator import CyberPentestReportGenerator
from ely_soe.cyber.privacy_pii_gdpr_engine import PrivacyPIIGDPREngine
from ely_soe.cyber.purple_team_scorecard_engine import (
    FAIRRiskScenario,
    PERTDistribution,
    PurpleTeamScorecardAndFAIREngine,
)
from ely_soe.cyber.quantum_sidechannel_auditor import QuantumAndSideChannelAuditor
from ely_soe.cyber.ransomware_resilience_simulator import (
    BackupPostureConfig,
    EnterpriseHostNode,
    LateralPropagationEdge,
    RansomwareResilienceSimulator,
)
from ely_soe.cyber.redteam_campaigns import BreachAndAttackCampaignEngine
from ely_soe.cyber.reverse_engineering_disasm_lite import ReverseEngineeringTriageEngine
from ely_soe.cyber.saas_workspace_cspm_engine import SaaSWorkspaceSSPMEngine
from ely_soe.cyber.secrets_dlp_engine import SecretsAndDLPEngine
from ely_soe.cyber.serverless_mesh_auditor import ServerlessAndMeshSecurityAuditor
from ely_soe.cyber.smart_contract_web3_auditor import SmartContractWeb3Auditor
from ely_soe.cyber.soar_incident_playbooks import CANONICAL_SOAR_PLAYBOOKS, SOARIncidentPlaybookEngine
from ely_soe.cyber.supply_chain_sbom import SupplyChainSBOMEngine
from ely_soe.cyber.supply_chain_typosquat_engine import SupplyChainTyposquatEngine
from ely_soe.cyber.threat_hunting_sigma_yara_engine import ThreatHuntingSigmaYaraEngine
from ely_soe.cyber.threat_intel_stix_engine import ThreatIntelSTIXEngine
from ely_soe.cyber.waf_ids_rule_synthesizer import WAFIDSRuleSynthesizer
from ely_soe.cyber.windows_endpoint_edr_engine import WindowsEndpointEDREngine
from ely_soe.cyber.zero_trust_identity_engine import ZeroTrustIdentityEngine


CYBER_ENGINE_CATALOG: List[Dict[str, str]] = [
    {"id": "core_orchestrator", "category": "Core 16-Domain Suite", "name": "GeneralizedCyberOrchestrator", "scope": "Web, Auth, API, TLS, Cloud IAM, K8s, IaC, AD, Binary, IoT/OT, ATT&CK, Sigma/YARA, STRIDE"},
    {"id": "secrets_dlp", "category": "AppSec & Data", "name": "SecretsAndDLPEngine", "scope": "48+ credential detectors + Luhn/IBAN PCI/PII DLP"},
    {"id": "supply_chain_sbom", "category": "Supply Chain", "name": "SupplyChainSBOMEngine", "scope": "CycloneDX/SPDX SBOM + OSV CVE + license risk"},
    {"id": "supply_chain_typosquat", "category": "Supply Chain", "name": "SupplyChainTyposquatEngine", "scope": "Levenshtein typosquatting + dependency confusion"},
    {"id": "cicd_ppe_graph", "category": "Supply Chain & CI/CD", "name": "CICDPipelineGraphAuditor", "scope": "GitHub Actions/Jenkins PPE DAG + expression injection"},
    {"id": "devsecops_slsa", "category": "Supply Chain & CI/CD", "name": "DevSecOpsArtifactVerifier", "scope": "SLSA Level 0-4 provenance & Cosign signature hygiene"},
    {"id": "ai_llm_redteam", "category": "AI Security", "name": "AILLMRedTeamEngine", "scope": "OWASP LLM 2025 & MITRE ATLAS prompt-injection/agent red-teaming"},
    {"id": "adversarial_ml", "category": "AI Security", "name": "AdversarialMLSecurityEngine", "scope": "Pickle/weights RCE, FGSM robustness & Trojan poisoning"},
    {"id": "memory_exploit_modeler", "category": "Binary & Low-Level", "name": "MemoryCorruptionExploitModeler", "scope": "C/C++ BOF/UAF/Fmt + Rust unsafe + ASLR/NX/CFI/PAC modeler"},
    {"id": "reverse_eng_disasm", "category": "Binary & Low-Level", "name": "ReverseEngineeringDisasmLite", "scope": "PE/ELF API triad, XOR deobfuscator & x86 shellcode scanner"},
    {"id": "quantum_pqc_cbom", "category": "Cryptography", "name": "QuantumSideChannelAuditor", "scope": "NIST PQC CBOM, Mosca HNDL risk & timing side-channel audit"},
    {"id": "crypto_protocol_verifier", "category": "Cryptography", "name": "CryptoProtocolVerifier", "scope": "TLS/JWT/Padding-Oracle/ECDSA nonce reuse verification"},
    {"id": "smart_contract_web3", "category": "Web3 & Smart Contracts", "name": "SmartContractWeb3Auditor", "scope": "Solidity reentrancy, tx.origin, delegatecall & flash-loan checks"},
    {"id": "openapi_fuzz_contract", "category": "API & Protocol", "name": "OpenAPIContractSecurityAuditor", "scope": "OWASP API Top 10:2023 + negative contract fuzz generator"},
    {"id": "graphql_grpc_ws", "category": "API & Protocol", "name": "GraphQLGRPCWebSocketEngine", "scope": "GraphQL cycle DoS, gRPC reflection/mTLS & CSWSH"},
    {"id": "browser_dom_csp", "category": "Web Client", "name": "BrowserDOMCSPEngine", "scope": "CSP3 bypasses, DOM XSS sinks & postMessage origin leaks"},
    {"id": "database_auditor", "category": "Data & Privacy", "name": "DatabaseSecurityAuditor", "scope": "PostgreSQL/MySQL/MongoDB/Redis hardening & RBAC"},
    {"id": "privacy_pii_gdpr", "category": "Data & Privacy", "name": "PrivacyPIIGDPREngine", "scope": "k-anonymity, l-diversity, differential privacy & GDPR"},
    {"id": "cloud_cspm", "category": "Cloud & SaaS", "name": "CloudPostureCSPMEngine", "scope": "CIS AWS/Azure/GCP CSPM benchmark auditing"},
    {"id": "saas_sspm", "category": "Cloud & SaaS", "name": "SaaSWorkspaceSSPMEngine", "scope": "GitHub Org, M365/Entra ID, Okta & Slack/Drive SSPM"},
    {"id": "serverless_mesh", "category": "Cloud & K8s", "name": "ServerlessMeshAuditor", "scope": "Lambda/Knative least-privilege & Istio/Envoy mTLS mesh"},
    {"id": "ebpf_kernel_audit", "category": "Kernel & Runtime", "name": "EBPFKernelAuditEngine", "scope": "Linux sysctl, seccomp-BPF & kernel escape rules"},
    {"id": "identity_federation", "category": "Identity & Zero Trust", "name": "IdentityFederationAuditor", "scope": "SAML 2.0 XSW/Comment-Trunc, OAuth 2.1/OIDC & Kerberos"},
    {"id": "zero_trust_ztmm", "category": "Identity & Zero Trust", "name": "ZeroTrustIdentityEngine", "scope": "CISA Zero-Trust Maturity Model (ZTMM) 5-pillar scorer"},
    {"id": "dns_bgp_email_auth", "category": "Network & Edge", "name": "DNSBGPEmailAuthAuditor", "scope": "SPF/DKIM/DMARC, DNSSEC, dangling CNAME & BGP RPKI"},
    {"id": "easm_surface", "category": "Network & Edge", "name": "ExternalAttackSurfaceEngine", "scope": "Shadow-IT discovery, risky ports, CVE banners & TLS expiry"},
    {"id": "pcap_nids_analyzer", "category": "Network & Edge", "name": "NetworkPCAPPacketAnalyzer", "scope": "Binary PCAP dissector, C2 beaconing & DNS tunnel detection"},
    {"id": "windows_edr_engine", "category": "Endpoint & DFIR", "name": "WindowsEndpointEDREngine", "scope": "Sysmon process-tree rules & UTF-16LE PowerShell decoder"},
    {"id": "forensics_ir_engine", "category": "Endpoint & DFIR", "name": "ForensicsIREngine", "scope": "IOC timeline correlation, lateral pivot & memory artifacts"},
    {"id": "ransomware_simulator", "category": "Resilience & Chaos", "name": "RansomwareResilienceSimulator", "scope": "BFS contagion blast-radius, chokepoint cuts & 3-2-1-1-0 backups"},
    {"id": "chaos_resilience", "category": "Resilience & Chaos", "name": "ChaosResilienceTester", "scope": "Fault-injection fail-closed security invariant verification"},
    {"id": "ot_ics_scada", "category": "OT / ICS / Mobile", "name": "OTICSSCADAAuditor", "scope": "Purdue Model SIS isolation, Modbus/DNP3/S7comm inspection"},
    {"id": "mobile_client_sec", "category": "OT / ICS / Mobile", "name": "MobileClientSecurityAuditor", "scope": "AndroidManifest/iOS Info.plist ATS, exported IPC & cert pinning"},
    {"id": "sigma_yara_hunt", "category": "Detection & SOAR", "name": "ThreatHuntingSigmaYaraEngine", "scope": "Real Sigma boolean algebra + YARA-lite scanner + F1 scorer"},
    {"id": "waf_ids_synth", "category": "Detection & SOAR", "name": "WAFIDSRuleSynthesizer", "scope": "Auto-synthesize ModSecurity/Suricata/Envoy virtual patches"},
    {"id": "soar_playbooks", "category": "Detection & SOAR", "name": "SOARIncidentPlaybookEngine", "scope": "Audited HITL containment playbooks + Merkle ledger proof"},
    {"id": "threat_intel_stix", "category": "Threat Intel & Risk", "name": "ThreatIntelSTIXEngine", "scope": "STIX 2.1 bundle generation, Diamond Model & actor attribution"},
    {"id": "purple_fair_scorecard", "category": "Threat Intel & Risk", "name": "PurpleTeamScorecardEngine", "scope": "FAIR Monte-Carlo ALE financial risk, ROSI & detection gap score"},
    {"id": "compliance_mapper", "category": "Governance & Reporting", "name": "EnterpriseComplianceMapper", "scope": "SOC 2, ISO 27001, NIST 800-53, PCI-DSS, HIPAA, GDPR, EU AI Act"},
    {"id": "pentest_report_gen", "category": "Governance & Reporting", "name": "EnterprisePentestReportGenerator", "scope": "Executive board brief, technical PoC & Markdown/JSON reports"},
    {"id": "kql_eql_threat_hunt", "category": "Detection & SOAR", "name": "ThreatHuntQueryEngine", "scope": "Pipe-delimited KQL filter DSL + sliding-window EQL temporal sequence correlator"},
    {"id": "k8s_admission_opa", "category": "Cloud & K8s", "name": "KubernetesAdmissionPolicyEngine", "scope": "OPA/Kyverno PSS-restricted admission simulator + Rego/Kyverno YAML synthesizer"},
    {"id": "hw_uefi_tpm_boot", "category": "OT / ICS / Mobile", "name": "HardwareFirmwareBootAuditor", "scope": "UEFI Secure Boot, dbx BlackLotus, TPM 2.0 PCR quotes & JTAG/OTA verification"},
    {"id": "ctem_exposure", "category": "Threat Intel & Risk", "name": "ContinuousThreatExposureEngine", "scope": "Gartner 5-stage CTEM exposure scoring, P0-P3 SLAs & mobilization sprints"},
    {"id": "crypto_oracle_lab", "category": "Cryptography", "name": "CryptographicOracleVerificationLab", "scope": "AES nonce-reuse XOR, RSA e=3 cube-root, DudeCT Welch timing, Padding Oracle & LCG PRNG"},
    {"id": "zeroday_vex_triage", "category": "Supply Chain", "name": "ZeroDayPatchTriageEngine", "scope": "CVE sink reachability triage, CycloneDX 1.5 VEX generator & ModSec/Nginx virtual patches"},
    {"id": "oauth21_pkce_fuzzer", "category": "Identity & Zero Trust", "name": "OAuth21PKCEStateMachineAuditor", "scope": "12 RFC 9700 / OAuth 2.1 / PKCE / OIDC protocol state-machine & redirect-URI fuzz checks"},
]


class EnterpriseCyberSuiteFacade:
    """Single-entry facade unifying all 40+ specialized `ely_soe.cyber` engines."""

    def __init__(self, scope_guard: Optional[ScopeGuard] = None) -> None:
        self.scope_guard = scope_guard
        self.core_orchestrator = GeneralizedCyberOrchestrator(scope_guard=scope_guard)
        self.secrets_dlp = SecretsAndDLPEngine(allow_synthetic_examples=True)
        self.sbom = SupplyChainSBOMEngine()
        self.typosquat = SupplyChainTyposquatEngine()
        self.cicd_graph = CICDPipelineGraphAuditor()
        self.mem_modeler = MemoryCorruptionExploitModeler()
        self.openapi_auditor = OpenAPIContractSecurityAuditor()
        self.web3_auditor = SmartContractWeb3Auditor()
        self.pqc_auditor = QuantumAndSideChannelAuditor()
        self.browser_csp = BrowserDOMCSPEngine()
        self.privacy_gdpr = PrivacyPIIGDPREngine()
        self.ai_redteam = AILLMRedTeamEngine()
        self.easm = ExternalAttackSurfaceEngine()
        self.ransomware = RansomwareResilienceSimulator()
        self.sspm = SaaSWorkspaceSSPMEngine()
        self.federation = IdentityFederationAuditor()
        self.sigma_yara = ThreatHuntingSigmaYaraEngine()
        self.waf_synth = WAFIDSRuleSynthesizer()
        self.soar = SOARIncidentPlaybookEngine()
        self.purple_fair = PurpleTeamScorecardAndFAIREngine()
        self.compliance = EnterpriseComplianceMapper()
        self.campaigns = BreachAndAttackCampaignEngine()
        self.cwe_kb = CWEKnowledgeBase()
        self.report_gen = CyberPentestReportGenerator()

    def catalog_engines(self) -> Dict[str, Any]:
        categories: Dict[str, int] = {}
        for item in CYBER_ENGINE_CATALOG:
            categories[item["category"]] = categories.get(item["category"], 0) + 1
        return {
            "total_specialized_engines": len(CYBER_ENGINE_CATALOG),
            "categories": categories,
            "engines": CYBER_ENGINE_CATALOG,
        }

    def run_unified_cyber_scan(
        self,
        target_path: str,
        *,
        target_name: Optional[str] = None,
        run_sandbox_range: bool = True,
        hardened_simulation: bool = False,
        include_extended_analyzers: bool = True,
        asset_criticality: AssetCriticality = AssetCriticality.TIER_1_PRODUCTION,
    ) -> Dict[str, Any]:
        """Run the full 16-domain core orchestrator + extended repo-level Wave I–III-D analyzers."""
        t0 = time.perf_counter()
        p = Path(target_path)
        name = target_name or p.name
        core_result = self.core_orchestrator.assess_target(
            target_path=p if p.exists() else None,
            run_synthetic_range=run_sandbox_range,
            hardened_range=hardened_simulation,
            run_enterprise_simulation=True,
            run_mitre_emulation=True,
            asset_criticality=asset_criticality,
        )
        core_dict = core_result.get("summary", core_result) if isinstance(core_result, dict) else core_result.to_dict()
        raw_core_vulns: List[Any] = list(core_result.get("raw_vulnerabilities", [])) if isinstance(core_result, dict) else []
        if not raw_core_vulns:
            raw_core_vulns = list(core_dict.get("vulnerabilities", []))

        extended_vulns: List[CyberVulnerability] = []
        extended_telemetry: Dict[str, Any] = {}
        if include_extended_analyzers and p.exists() and p.is_dir():
            sec_res = self.secrets_dlp.scan_directory(p)
            extended_vulns.extend(sec_res.get("vulnerabilities", []))
            extended_telemetry["secrets_dlp_findings"] = len(sec_res.get("vulnerabilities", []))

            cicd_res = self.cicd_graph.scan_directory(str(p))
            extended_vulns.extend(cicd_res.get("vulnerabilities", []))
            extended_telemetry["cicd_pipelines_audited"] = cicd_res.get("pipelines_audited", 0)
            extended_telemetry["cicd_findings"] = cicd_res.get("total_findings", 0)

            mem_res = self.mem_modeler.scan_directory(str(p))
            extended_vulns.extend(mem_res.get("vulnerabilities", []))
            extended_telemetry["native_files_scanned"] = mem_res.get("native_files_scanned", 0)
            extended_telemetry["memory_findings"] = mem_res.get("total_findings", 0)

            oapi_vulns = self.openapi_auditor.scan_directory(p)
            extended_vulns.extend(oapi_vulns)
            extended_telemetry["openapi_findings"] = len(oapi_vulns)

            comps = self.sbom.extract_components(p)
            sbom_audit = self.sbom.audit_components(comps) if comps else {"vulnerabilities": []}
            extended_vulns.extend(sbom_audit.get("vulnerabilities", []))
            extended_telemetry["sbom_packages_count"] = len(comps)

            ai_vulns = self.ai_redteam.scan_directory(p)
            extended_vulns.extend(ai_vulns)
            extended_telemetry["ai_llm_static_findings"] = len(ai_vulns)

        # Normalize & deduplicate merged findings
        seen_fp = set()
        merged_dicts: List[Dict[str, Any]] = []
        merged_objs: List[CyberVulnerability] = []
        for cv in raw_core_vulns:
            if isinstance(cv, CyberVulnerability):
                fp = cv.fingerprint()
                if fp not in seen_fp:
                    seen_fp.add(fp)
                    merged_objs.append(cv)
                    merged_dicts.append(cv.to_dict())
            elif isinstance(cv, dict):
                fp = str(cv.get("fingerprint") or f"{cv.get('rule_id')}:{cv.get('file_path')}:{cv.get('line_start')}")
                if fp not in seen_fp:
                    seen_fp.add(fp)
                    merged_dicts.append(cv)

        core_cnt = len(merged_dicts)
        for ev in extended_vulns:
            fp = ev.fingerprint()
            if fp not in seen_fp:
                seen_fp.add(fp)
                merged_objs.append(ev)
                merged_dicts.append(ev.to_dict())

        comp = self.compliance.evaluate(merged_objs if merged_objs else extended_vulns)
        soar_recs = self.soar.recommend_playbooks_for_findings(merged_dicts)
        waf_bundle = self.waf_synth.synthesize_bundle(merged_objs[:25]) if merged_objs else {"total_rules_synthesized": 0}
        sigma_samples = [self.sigma_yara.synthesize_sigma_yaml_for_vuln(v) for v in merged_dicts[:3]]

        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in merged_dicts:
            sv = str(v.get("severity", "medium")).lower()
            sev_counts[sv] = sev_counts.get(sv, 0) + 1

        chains = core_dict.get("exploit_chains", [])
        gate_verdict = (
            "BLOCKED"
            if (sev_counts["critical"] > 0 or len(chains) > 0)
            else ("CONDITIONAL" if sev_counts["high"] > 2 else "APPROVED")
        )

        return {
            "assessed_at": utc_now_iso(),
            "duration_ms": round((time.perf_counter() - t0) * 1000.0, 2),
            "target_name": name,
            "target_path": str(p),
            "gate_verdict": gate_verdict,
            "overall_cyber_posture": core_dict.get("overall_cyber_posture", 0.0),
            "total_vulnerabilities": len(merged_dicts),
            "core_vulnerabilities": core_cnt,
            "extended_vulnerabilities_added": len(merged_dicts) - core_cnt,
            "severity_counts": sev_counts,
            "domain_counts": core_dict.get("domain_counts", {}),
            "domain_scores": core_dict.get("domain_scores", {}),
            "exploit_chains_count": len(chains),
            "exploit_chains": chains,
            "compliance_readiness_pct": comp.get("overall_compliance_readiness_pct", 0.0),
            "compliance_frameworks": comp.get("frameworks", {}),
            "soar_recommended_playbooks": soar_recs,
            "waf_virtual_patches_synthesized": waf_bundle.get("total_rules_synthesized", len(waf_bundle.get("rules", []))),
            "auto_sigma_yaml_samples": sigma_samples,
            "extended_telemetry": extended_telemetry,
            "ledger_merkle_root": core_dict.get("ledger_merkle_root", ""),
            "vulnerabilities": merged_dicts,
        }

    def run_enterprise_posture_simulation(self, hardened: bool = False) -> Dict[str, Any]:
        """Execute a full-spectrum enterprise simulation spanning EASM, Ransomware, SSPM, SAML/OIDC, Sigma/YARA & FAIR."""
        t0 = time.perf_counter()
        if hardened:
            easm_res = self.easm.audit_attack_surface([
                ExternalAssetRecord("A1", "api.ely.example", "prod", "sec-platform", True, True, {443: "nginx/1.26.2"}, [], 180, False),
            ])
            nodes = [
                EnterpriseHostNode("WS-01", "corp-ws-01", "workstation", "10.10.0.0/24", edr_isolation_enabled=True),
                EnterpriseHostNode("APP-01", "erp-app-01", "app_server", "10.20.0.0/24", crown_jewel=True, edr_isolation_enabled=True),
                EnterpriseHostNode("DC-01", "corp-dc-01", "ad_tier0_dc", "10.0.0.0/24", crown_jewel=True, edr_isolation_enabled=True),
                EnterpriseHostNode("BK-01", "worm-backup-01", "backup_server", "10.30.0.0/24", crown_jewel=True, edr_isolation_enabled=True),
            ]
            edges = [
                LateralPropagationEdge("WS-01", "APP-01", "smb_445", blocked_by_segmentation=True),
                LateralPropagationEdge("APP-01", "DC-01", "shared_local_admin", requires_mfa=True, blocked_by_segmentation=True),
                LateralPropagationEdge("DC-01", "BK-01", "backup_console", requires_mfa=True, blocked_by_segmentation=True),
            ]
            backup_cfg = BackupPostureConfig(4, 3, True, True, False, True, 14, 0)
            sspm_res = self.sspm.audit_enterprise_saas_suite(
                {"two_factor_requirement_enabled": True, "required_approving_review_count": 2, "allow_force_pushes": False, "require_signed_commits": True, "actions_default_workflow_permissions": "read", "actions_can_approve_pull_request_reviews": False, "secret_scanning_push_protection": True, "default_repository_permission": "none"},
                {"legacy_auth_blocked": True, "fido2_required_for_admins": True, "standing_global_admins": 2, "restrict_user_oauth_app_consent": True, "block_external_mail_forwarding": True, "block_high_risk_signins": True, "pim_jit_enabled": True},
                {"allow_public_anyone_with_link": False, "require_admin_app_approval": True, "dlp_enabled": True, "enforce_guest_expiration": True, "siem_audit_export_enabled": True},
            )
            fed_oidc = self.federation.audit_oauth2_oidc_config({
                "require_pkce": True, "code_challenge_methods_supported": ["S256"],
                "grant_types_supported": ["authorization_code"], "response_types_supported": ["code"],
                "id_token_signing_alg_values_supported": ["ES256"],
                "redirect_uris": ["https://app.ely.example/oauth/callback"],
                "jwks_uri": "https://auth.ely.example/.well-known/jwks.json",
            })
        else:
            easm_res = self.easm.audit_attack_surface([
                ExternalAssetRecord("A1", "staging-api.ely.example", "staging", "", False, False, {22: "OpenSSH_7.4", 2375: "Docker 20.10", 6379: "Redis 6.0", 80: "Apache/2.4.49"}, ["/.git/HEAD", "/.env", "/actuator/heapdump"], 4, True, "sha1WithRSAEncryption"),
                ExternalAssetRecord("A2", "prod-web.ely.example", "prod", "web-team", True, True, {443: "nginx/1.26.0"}, [], 95, False),
            ])
            nodes = [
                EnterpriseHostNode("WS-01", "finance-laptop-01", "workstation", "10.10.0.0/24"),
                EnterpriseHostNode("APP-01", "erp-app-01", "app_server", "10.20.0.0/24", crown_jewel=True),
                EnterpriseHostNode("DC-01", "corp-dc-01", "ad_tier0_dc", "10.0.0.0/24", crown_jewel=True),
                EnterpriseHostNode("BK-01", "veeam-repo-01", "backup_server", "10.30.0.0/24", crown_jewel=True),
            ]
            edges = [
                LateralPropagationEdge("WS-01", "APP-01", "smb_445"),
                LateralPropagationEdge("APP-01", "DC-01", "shared_local_admin"),
                LateralPropagationEdge("DC-01", "BK-01", "backup_console"),
            ]
            backup_cfg = BackupPostureConfig(2, 1, False, False, True, False, 240, 2)
            sspm_res = self.sspm.audit_enterprise_saas_suite(
                {"two_factor_requirement_enabled": False, "required_approving_review_count": 0, "allow_force_pushes": True},
                {"legacy_auth_blocked": False, "fido2_required_for_admins": False, "standing_global_admins": 11},
                {"allow_public_anyone_with_link": True, "require_admin_app_approval": False},
            )
            fed_oidc = self.federation.audit_oauth2_oidc_config({
                "grant_types_supported": ["implicit"],
                "id_token_signing_alg_values_supported": ["none", "HS256", "RS256"],
                "redirect_uris": ["https://*.ely.example/cb"],
                "jwks_uri": "http://auth.ely.example/jwks",
            })

        contagion = self.ransomware.simulate_contagion(nodes, edges, "WS-01")
        backup_res = self.ransomware.audit_backup_32110_posture(backup_cfg)
        fair_scenario = FAIRRiskScenario(
            scenario_name="Hardened Enterprise Ransomware & Cloud Breach Risk" if hardened else "Baseline Enterprise Ransomware & Cloud Breach Risk",
            tef_per_year=PERTDistribution(0.2, 0.5, 1.5) if hardened else PERTDistribution(2.0, 6.0, 18.0),
            susceptibility_prob=PERTDistribution(0.05, 0.12, 0.25) if hardened else PERTDistribution(0.45, 0.72, 0.92),
            primary_loss_usd=PERTDistribution(50_000.0, 220_000.0, 900_000.0) if hardened else PERTDistribution(500_000.0, 3_200_000.0, 15_000_000.0),
            secondary_loss_prob=0.20 if hardened else 0.75,
            secondary_loss_usd=PERTDistribution(20_000.0, 90_000.0, 400_000.0) if hardened else PERTDistribution(250_000.0, 1_800_000.0, 9_000_000.0),
        )
        fair_sim = self.purple_fair.run_fair_monte_carlo(fair_scenario, iterations=1200)

        sigma_qual = self.sigma_yara.evaluate_detection_quality(
            malicious_events=[
                {"Image": "C:\\Windows\\powershell.exe", "CommandLine": "powershell -enc SQBFAFgA...", "User": "CORP\\bob"},
                {"CommandLine": "vssadmin delete shadows /all /quiet"},
                {"uri": "/proxy?url=http://169.254.169.254/latest/meta-data/"},
                {"eventName": "AttachUserPolicy", "userAgent": "aws-cli/2.1"},
            ],
            benign_events=[
                {"Image": "C:\\Windows\\powershell.exe", "CommandLine": "powershell -enc abc", "User": "SYSTEM_PATCH_BOT"},
                {"eventName": "AttachUserPolicy", "userAgent": "Terraform-Approved-CI/1.8"},
                {"uri": "/healthz", "query": "status=ok"},
            ],
        )

        all_vulns = (
            easm_res["vulnerabilities"]
            + contagion["vulnerabilities"]
            + backup_res["vulnerabilities"]
            + sspm_res["vulnerabilities"]
            + fed_oidc["vulnerabilities"]
        )
        soar_recs = self.soar.recommend_playbooks_for_findings(all_vulns)
        return {
            "simulated_at": utc_now_iso(),
            "duration_ms": round((time.perf_counter() - t0) * 1000.0, 2),
            "mode": "hardened" if hardened else "vulnerable_baseline",
            "total_enterprise_findings": len(all_vulns),
            "easm": {k: v for k, v in easm_res.items() if k != "vulnerabilities"},
            "ransomware_contagion": {k: v for k, v in contagion.items() if k != "vulnerabilities"},
            "backup_32110": {k: v for k, v in backup_res.items() if k != "vulnerabilities"},
            "saas_sspm": {k: v for k, v in sspm_res.items() if k != "vulnerabilities"},
            "federation_oidc_findings": len(fed_oidc["vulnerabilities"]),
            "fair_financial_risk": fair_sim,
            "sigma_detection_quality": sigma_qual,
            "recommended_soar_playbooks": soar_recs,
            "available_soar_playbooks": list(CANONICAL_SOAR_PLAYBOOKS.keys()),
        }

    def execute_soar_playbook(
        self,
        playbook_id: str,
        incident_id: str = "INC-ELY-LIVE-001",
        target_asset: str = "prod-cluster-01",
        *,
        dry_run: bool = True,
        auto_approve_hitl: bool = False,
    ) -> Dict[str, Any]:
        return self.soar.execute_playbook(
            playbook_id=playbook_id,
            incident_id=incident_id,
            target_asset=target_asset,
            dry_run=dry_run,
            auto_approve_hitl=auto_approve_hitl,
        )
