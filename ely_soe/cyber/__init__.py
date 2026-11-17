"""
ELY Generalized Cybersecurity Attack Simulation & Vulnerability Testing Suite (`ely_soe.cyber`).

Authorized-only, ScopeGuard-governed multi-domain cybersecurity assessment suite spanning:
  1. Web Injection (SQLi, NoSQLi, OS Command, LDAP, XPath, Code Eval)
  2. Web Client & Protocol (XSS, CSRF, CORS, Smuggling, Cache Poisoning, CSP/Headers)
  3. Server-Side Web (SSRF/IMDS, XXE, SSTI, Deserialization, ZipSlip, ReDoS)
  4. Authentication, JWT, OAuth2/SAML, IDOR/BOLA, BFLA, Mass Assignment & Race Conditions
  5. API & Microservices (OpenAPI 3.x OWASP API Top 10, GraphQL DoS, gRPC/mTLS)
  6. Network Services, DNS Tunneling & Zero-Trust Firewall Segmentation
  7. TLS/PKI Handshake & Cryptographic Code Auditing
  8. Multi-Cloud IAM Privilege-Escalation Graph Solver (AWS/GCP/Azure)
  9. Kubernetes Pod/RBAC & Container/Dockerfile Security Auditing
 10. Infrastructure-as-Code (Terraform/CFN/Ansible) & CI/CD Supply-Chain (GitHub Actions/GitLab/Jenkins)
 11. Active Directory, Kerberos, ADCS ESC1–ESC8 & Tier-0 Attack Graph Solver
 12. Native Binary Hardening (ELF/PE checksec) & C/C++/Go Memory Safety Auditing
 13. Embedded Firmware, IoT (MQTT/BLE) & ICS/OT (Modbus/S7comm/DNP3/BACnet/OPC-UA)
 14. 14-Tactic MITRE ATT&CK Authorized Adversary Emulation & Navigator v4.5 Export
 15. Sigma Log Detection & YARA-Style Byte/Hex/Regex Detection Engineering
 16. CVSS v4.0 + EPSS + KEV Risk Prioritization, Exploit-Chain Planning, STRIDE Threat Modeling & Grammar Fuzzing
"""

from ely_soe.cyber.api_microservices_engine import APIMicroservicesSecurityEngine
from ely_soe.cyber.auth_access_control_engine import AuthAccessControlEngine, JWTSecurityAuditor
from ely_soe.cyber.binary_memory_engine import BinaryAndMemorySafetyEngine, BinaryHeaderSecurityAnalyzer
from ely_soe.cyber.cloud_iam_engine import CloudIAMSecurityEngine
from ely_soe.cyber.cvss4_risk_engine import CVSSv4Calculator, CyberRiskPrioritizationEngine
from ely_soe.cyber.detection_sigma_yara import (
    BUILTIN_SIGMA_RULES,
    BUILTIN_YARA_RULES,
    SigmaDetectionEngine,
    SigmaRule,
    YaraSignatureRule,
    YaraStyleScanner,
)
from ely_soe.cyber.exploit_chain_planner import GeneralizedExploitChainPlanner
from ely_soe.cyber.firmware_iot_ot_engine import FirmwareIoTOTSecurityEngine
from ely_soe.cyber.grammar_fuzzer import GrammarAwareSecurityFuzzer
from ely_soe.cyber.iac_cicd_engine import IaCAndCICDSecurityEngine
from ely_soe.cyber.identity_ad_engine import ADCSTemplateConfig, IdentityAndADSecurityEngine
from ely_soe.cyber.k8s_container_engine import KubernetesAndContainerSecurityEngine
from ely_soe.cyber.mitre_attack_emulator import (
    EnterpriseDefensePosture,
    MITRE_EMULATION_CATALOG,
    MitreAttackEmulationEngine,
)
from ely_soe.cyber.models import (
    AssetCriticality,
    BinarySecurityProfile,
    CloudIAMPolicyStatement,
    CloudPrincipalNode,
    CVSSv4Metrics,
    CyberAssessmentSummary,
    CyberDomain,
    CyberVulnerability,
    DetectionMatch,
    FirewallRuleDescriptor,
    GeneralizedExploitChain,
    HttpProbeRequest,
    HttpProbeResponse,
    IdentityDirectoryEdge,
    IdentityDirectoryObject,
    MitreTactic,
    NetworkServiceDescriptor,
    TelemetryEvent,
)
from ely_soe.cyber.network_protocol_auditor import (
    DNSSecurityAnalyzer,
    NetworkProtocolAuditor,
    ZeroTrustSegmentationAuditor,
)
from ely_soe.cyber.orchestrator import (
    ALL_CYBER_DOMAINS,
    GeneralizedCyberOrchestrator,
    build_local_http_probe_handler,
)
from ely_soe.cyber.sandbox_targets import AuthorizedSyntheticCyberRange
from ely_soe.cyber.threat_model_stride import AutomatedStrideThreatModeler
from ely_soe.cyber.tls_crypto_auditor import TLSCryptoAuditor
from ely_soe.cyber.web_client_protocol_engine import (
    HttpDesyncAndSmugglingAnalyzer,
    HttpSecurityHeaderAuditor,
    WebClientProtocolEngine,
)
from ely_soe.cyber.web_injection_engine import WebInjectionSecurityEngine
from ely_soe.cyber.web_ssrf_xxe_ssti_deser import (
    SSRFUrlValidatorAndBypassDetector,
    WebServerSideVulnEngine,
)
# Extended Enterprise Suite Facade + Wave I–III-D Specialized Engines
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
from ely_soe.cyber.cryptographic_fuzz_oracle_lab import CryptographicOracleVerificationLab
from ely_soe.cyber.database_security_auditor import DatabaseSecurityAuditor
from ely_soe.cyber.devsecops_artifact_verifier import DevSecOpsArtifactVerifier
from ely_soe.cyber.dns_bgp_email_auth_auditor import DNSBGPEmailAuthAuditor
from ely_soe.cyber.ebpf_kernel_audit_engine import KernelAndSeccompAuditEngine
from ely_soe.cyber.extended_suite_facade import CYBER_ENGINE_CATALOG, EnterpriseCyberSuiteFacade
from ely_soe.cyber.forensics_ir_engine import DigitalForensicsIREngine
from ely_soe.cyber.graphql_grpc_websocket_engine import GraphQLGRPCWebSocketAuditor
from ely_soe.cyber.hardware_firmware_boot_auditor import (
    HardwareFirmwareBootAuditor,
    PlatformBootAttestationSnapshot,
)
from ely_soe.cyber.identity_federation_saml_oidc_auditor import IdentityFederationAuditor
from ely_soe.cyber.kubernetes_admission_policy_engine import KubernetesAdmissionPolicyEngine
from ely_soe.cyber.memory_corruption_exploit_modeler import (
    BinaryMitigationProfile,
    MemoryCorruptionExploitModeler,
)
from ely_soe.cyber.mobile_client_security import MobileAndClientSecurityAuditor
from ely_soe.cyber.network_pcap_packet_analyzer import NetworkPCAPPacketAnalyzer
from ely_soe.cyber.oauth_oidc_pkce_state_machine_fuzzer import (
    OAuth21PKCEStateMachineAuditor,
    OAuthServerPolicyConfig,
)
from ely_soe.cyber.ot_ics_scada_auditor import OTICSSCADAAuditor
from ely_soe.cyber.pentest_report_generator import CyberPentestReportGenerator
from ely_soe.cyber.privacy_pii_gdpr_engine import PrivacyPIIGDPREngine
from ely_soe.cyber.purple_team_scorecard_engine import PurpleTeamScorecardAndFAIREngine
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
from ely_soe.cyber.threat_exposure_ctem_engine import (
    CTEMAssetScope,
    ContinuousThreatExposureEngine,
)
from ely_soe.cyber.threat_hunt_playbook_dsl import (
    BUILTIN_SEQUENCE_HUNT_RULES,
    SequenceHuntRule,
    ThreatHuntQueryEngine,
)
from ely_soe.cyber.threat_hunting_sigma_yara_engine import ThreatHuntingSigmaYaraEngine
from ely_soe.cyber.threat_intel_stix_engine import ThreatIntelSTIXEngine
from ely_soe.cyber.waf_ids_rule_synthesizer import WAFIDSRuleSynthesizer
from ely_soe.cyber.windows_endpoint_edr_engine import WindowsEndpointEDREngine
from ely_soe.cyber.zero_trust_identity_engine import ZeroTrustIdentityEngine
from ely_soe.cyber.zeroday_patch_triage_engine import (
    BUILTIN_ZERODAY_ADVISORIES,
    ZeroDayAdvisory,
    ZeroDayPatchTriageEngine,
)

__all__ = [
    "ADCSTemplateConfig",
    "ALL_CYBER_DOMAINS",
    "APIMicroservicesSecurityEngine",
    "AssetCriticality",
    "AuthAccessControlEngine",
    "AuthorizedSyntheticCyberRange",
    "AutomatedStrideThreatModeler",
    "BUILTIN_SIGMA_RULES",
    "BUILTIN_YARA_RULES",
    "BUILTIN_ZERODAY_ADVISORIES",
    "ZeroDayAdvisory",
    "ZeroDayPatchTriageEngine",
    "BinaryAndMemorySafetyEngine",
    "BinaryHeaderSecurityAnalyzer",
    "BinarySecurityProfile",
    "CVSSv4Calculator",
    "CVSSv4Metrics",
    "CloudIAMPolicyStatement",
    "CloudIAMSecurityEngine",
    "CloudPrincipalNode",
    "CyberAssessmentSummary",
    "CyberDomain",
    "CyberRiskPrioritizationEngine",
    "CyberVulnerability",
    "DNSSecurityAnalyzer",
    "DetectionMatch",
    "EnterpriseDefensePosture",
    "FirewallRuleDescriptor",
    "FirmwareIoTOTSecurityEngine",
    "GeneralizedCyberOrchestrator",
    "GeneralizedExploitChain",
    "GeneralizedExploitChainPlanner",
    "GrammarAwareSecurityFuzzer",
    "HttpDesyncAndSmugglingAnalyzer",
    "HttpProbeRequest",
    "HttpProbeResponse",
    "HttpSecurityHeaderAuditor",
    "IaCAndCICDSecurityEngine",
    "IdentityAndADSecurityEngine",
    "IdentityDirectoryEdge",
    "IdentityDirectoryObject",
    "JWTSecurityAuditor",
    "KubernetesAndContainerSecurityEngine",
    "MITRE_EMULATION_CATALOG",
    "MitreAttackEmulationEngine",
    "MitreTactic",
    "NetworkProtocolAuditor",
    "NetworkServiceDescriptor",
    "SSRFUrlValidatorAndBypassDetector",
    "SigmaDetectionEngine",
    "SigmaRule",
    "TLSCryptoAuditor",
    "TelemetryEvent",
    "WebClientProtocolEngine",
    "WebInjectionSecurityEngine",
    "WebServerSideVulnEngine",
    "YaraSignatureRule",
    "YaraStyleScanner",
    "ZeroTrustSegmentationAuditor",
    "build_local_http_probe_handler",
    "AILLMRedTeamEngine",
    "AdversarialMLSecurityEngine",
    "BackupPostureConfig",
    "BinaryMitigationProfile",
    "BreachAndAttackCampaignEngine",
    "BrowserDOMCSPEngine",
    "CANONICAL_SOAR_PLAYBOOKS",
    "CICDPipelineGraphAuditor",
    "CYBER_ENGINE_CATALOG",
    "CyberPentestReportGenerator",
    "DNSBGPEmailAuthAuditor",
    "DatabaseSecurityAuditor",
    "DevSecOpsArtifactVerifier",
    "DigitalForensicsIREngine",
    "EnterpriseComplianceMapper",
    "EnterpriseCyberSuiteFacade",
    "EnterpriseHostNode",
    "ExternalAssetRecord",
    "ExternalAttackSurfaceEngine",
    "GraphQLGRPCWebSocketAuditor",
    "HardwareFirmwareBootAuditor",
    "IdentityFederationAuditor",
    "KernelAndSeccompAuditEngine",
    "KubernetesAdmissionPolicyEngine",
    "LateralPropagationEdge",
    "MemoryCorruptionExploitModeler",
    "MobileAndClientSecurityAuditor",
    "MultiCloudCSPMEngine",
    "NetworkPCAPPacketAnalyzer",
    "OAuth21PKCEStateMachineAuditor",
    "OAuthServerPolicyConfig",
    "OTICSSCADAAuditor",
    "OpenAPIContractSecurityAuditor",
    "PlatformBootAttestationSnapshot",
    "PrivacyPIIGDPREngine",
    "PurpleTeamScorecardAndFAIREngine",
    "QuantumAndSideChannelAuditor",
    "RansomwareResilienceSimulator",
    "ReverseEngineeringTriageEngine",
    "SOARIncidentPlaybookEngine",
    "SaaSWorkspaceSSPMEngine",
    "SecretsAndDLPEngine",
    "SecurityChaosResilienceTester",
    "SequenceHuntRule",
    "ServerlessAndMeshSecurityAuditor",
    "SmartContractWeb3Auditor",
    "SupplyChainSBOMEngine",
    "SupplyChainTyposquatEngine",
    "BUILTIN_SEQUENCE_HUNT_RULES",
    "CTEMAssetScope",
    "ContinuousThreatExposureEngine",
    "CryptographicOracleVerificationLab",
    "ThreatHuntQueryEngine",
    "ThreatHuntingSigmaYaraEngine",
    "ThreatIntelSTIXEngine",
    "WAFIDSRuleSynthesizer",
    "WindowsEndpointEDREngine",
    "ZeroTrustIdentityEngine",
]
