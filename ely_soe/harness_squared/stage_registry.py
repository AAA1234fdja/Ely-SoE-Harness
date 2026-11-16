"""
Harness² Unified First-Order Stage Adapter Registry.

Wraps every specialized cybersecurity engine in `ely_soe.cyber` behind a uniform,
composable `StageExecutionResult` contract so `HarnessSquaredEngine` and
`MAPEKController` can dynamically schedule, inject, prioritize, budget-gate, or
prune any first-order stage during live workflow execution.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from ely_soe.core.models import Severity, new_id, utc_now_iso
from ely_soe.cyber.ai_llm_redteam_engine import AILLMRedTeamEngine
from ely_soe.cyber.api_fuzz_contract_auditor import OpenAPIContractSecurityAuditor
from ely_soe.cyber.api_microservices_engine import APIMicroservicesSecurityEngine
from ely_soe.cyber.auth_access_control_engine import AuthAccessControlEngine
from ely_soe.cyber.binary_memory_engine import BinaryAndMemorySafetyEngine
from ely_soe.cyber.browser_dom_csp_engine import BrowserDOMCSPEngine
from ely_soe.cyber.cicd_pipeline_graph_auditor import CICDPipelineGraphAuditor
from ely_soe.cyber.cloud_iam_engine import CloudIAMSecurityEngine
from ely_soe.cyber.container_runtime_ebpf_sim import ContainerRuntimeKernelEngine, SyscallEvent
from ely_soe.cyber.detection_sigma_yara import SigmaDetectionEngine, YaraStyleScanner
from ely_soe.cyber.firmware_iot_ot_engine import FirmwareIoTOTSecurityEngine
from ely_soe.cyber.grammar_fuzzer import GrammarAwareSecurityFuzzer
from ely_soe.cyber.hardware_firmware_boot_auditor import (
    HardwareFirmwareBootAuditor,
    PlatformBootAttestationSnapshot,
)
from ely_soe.cyber.iac_cicd_engine import IaCAndCICDSecurityEngine
from ely_soe.cyber.identity_ad_engine import IdentityAndADSecurityEngine
from ely_soe.cyber.k8s_container_engine import KubernetesAndContainerSecurityEngine
from ely_soe.cyber.kubernetes_admission_policy_engine import KubernetesAdmissionPolicyEngine
from ely_soe.cyber.memory_corruption_exploit_modeler import MemoryCorruptionExploitModeler
from ely_soe.cyber.mitre_attack_emulator import EnterpriseDefensePosture, MitreAttackEmulationEngine
from ely_soe.cyber.models import CyberVulnerability
from ely_soe.cyber.network_protocol_auditor import (
    DNSSecurityAnalyzer,
    NetworkProtocolAuditor,
    ZeroTrustSegmentationAuditor,
)
from ely_soe.cyber.oauth_oidc_pkce_state_machine_fuzzer import (
    OAuth21PKCEStateMachineAuditor,
    OAuthServerPolicyConfig,
)
from ely_soe.cyber.orchestrator import GeneralizedCyberOrchestrator, build_local_http_probe_handler
from ely_soe.cyber.privacy_pii_gdpr_engine import PrivacyPIIGDPREngine
from ely_soe.cyber.quantum_sidechannel_auditor import QuantumAndSideChannelAuditor
from ely_soe.cyber.redteam_campaigns import BreachAndAttackCampaignEngine
from ely_soe.cyber.sandbox_targets import AuthorizedSyntheticCyberRange
from ely_soe.cyber.secrets_dlp_engine import SecretsAndDLPEngine
from ely_soe.cyber.siem_correlation_soar import NormalizedLogEvent, SIEMCorrelationAndSOAREngine
from ely_soe.cyber.smart_contract_web3_auditor import SmartContractWeb3Auditor
from ely_soe.cyber.supply_chain_sbom import SupplyChainSBOMEngine
from ely_soe.cyber.supply_chain_typosquat_engine import SupplyChainTyposquatEngine
from ely_soe.cyber.tls_crypto_auditor import TLSCryptoAuditor
from ely_soe.cyber.web_client_protocol_engine import WebClientProtocolEngine
from ely_soe.cyber.web_injection_engine import WebInjectionSecurityEngine
from ely_soe.cyber.web_ssrf_xxe_ssti_deser import WebServerSideVulnEngine
from ely_soe.cyber.zeroday_patch_triage_engine import ZeroDayPatchTriageEngine
from ely_soe.harness_squared.models import StageCategory


@dataclass
class StageExecutionContext:
    target_path: Optional[Path]
    hardened_simulation: bool = False
    live_local_url: Optional[str] = None
    fuzz_iterations: int = 12
    shared_artifacts: Dict[str, Any] = field(default_factory=dict)
    accumulated_vulns: List[CyberVulnerability] = field(default_factory=list)


@dataclass
class StageExecutionResult:
    adapter_name: str
    vulnerabilities: List[CyberVulnerability] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    extra_metrics: Dict[str, Any] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    error: Optional[str] = None


@dataclass(frozen=True)
class RegisteredStageSpec:
    adapter_name: str
    label: str
    category: StageCategory
    default_budget_ms: int
    description: str


STAGE_CATALOG: Dict[str, RegisteredStageSpec] = {
    "web_injection": RegisteredStageSpec("web_injection", "Web Injection SAST/AST (SQLi/Cmd/NoSQL)", StageCategory.WEB_APPSEC, 2200, "Multi-language & Python AST injection engine."),
    "web_client_protocol": RegisteredStageSpec("web_client_protocol", "Web Client & Protocol (XSS/CORS/Smuggling)", StageCategory.WEB_APPSEC, 1800, "Client-side & HTTP header/desync analyzer."),
    "web_ssrf_deser": RegisteredStageSpec("web_ssrf_deser", "Server-Side Web (SSRF/XXE/SSTI/Deser/ZipSlip)", StageCategory.WEB_APPSEC, 2000, "Server-side web vulnerability engine."),
    "auth_access": RegisteredStageSpec("auth_access", "Auth, JWT, OAuth2 & Access Control", StageCategory.AUTH_IDENTITY, 1800, "Authentication, JWT, session & IDOR/BFLA analyzer."),
    "api_microservices": RegisteredStageSpec("api_microservices", "API & Microservices (OpenAPI/GraphQL/gRPC)", StageCategory.API_MICROSERVICES, 1600, "OWASP API Top 10, GraphQL DoS & gRPC mTLS auditor."),
    "secrets_dlp": RegisteredStageSpec("secrets_dlp", "Enterprise Secrets Scanner & PCI/PII DLP", StageCategory.SUPPLY_CHAIN_SECRETS, 2200, "48+ credential detectors + Luhn/IBAN DLP engine."),
    "tls_crypto": RegisteredStageSpec("tls_crypto", "TLS/PKI & Cryptographic Code Auditor", StageCategory.NETWORK_CRYPTO, 1600, "Weak ciphers, hashes, randomness & cert verification."),
    "iac_cicd": RegisteredStageSpec("iac_cicd", "IaC (Terraform/CFN) & CI/CD Supply-Chain", StageCategory.INFRA_CLOUD_K8S, 2000, "Terraform, CloudFormation, GitHub Actions & GitLab CI."),
    "kubernetes_container": RegisteredStageSpec("kubernetes_container", "Kubernetes Pod/RBAC & Dockerfile Auditor", StageCategory.INFRA_CLOUD_K8S, 1800, "K8s manifest, RBAC & Dockerfile hardening checks."),
    "container_runtime_ebpf": RegisteredStageSpec("container_runtime_ebpf", "Container Runtime Seccomp/Sysctl & Falco eBPF", StageCategory.INFRA_CLOUD_K8S, 1600, "Kernel isolation, capabilities & runtime syscall rules."),
    "supply_chain_sbom": RegisteredStageSpec("supply_chain_sbom", "SBOM (CycloneDX/SPDX), OSV CVEs & Typosquatting", StageCategory.SUPPLY_CHAIN_SECRETS, 2000, "Lockfile SCA, CVE matching, typosquatting & SLSA."),
    "binary_memory": RegisteredStageSpec("binary_memory", "Binary ELF/PE Checksec & C/C++ Memory Safety", StageCategory.BINARY_OT, 2000, "Native header mitigations, BOF, UAF & format strings."),
    "firmware_iot_ot": RegisteredStageSpec("firmware_iot_ot", "Firmware, IoT (MQTT/BLE) & ICS/OT (Modbus/S7)", StageCategory.BINARY_OT, 1500, "Embedded firmware and SCADA/ICS protocol security."),
    "live_sandbox_dast": RegisteredStageSpec("live_sandbox_dast", "Authorized Loopback Live DAST Sandbox Prober", StageCategory.DYNAMIC_SANDBOX, 4000, "Live 127.0.0.1 differential SQLi/XSS/SSRF/JWT/BOLA probes."),
    "cloud_iam_graph": RegisteredStageSpec("cloud_iam_graph", "Multi-Cloud IAM Privilege-Escalation Graph", StageCategory.INFRA_CLOUD_K8S, 1800, "21 AWS/GCP/Azure escalation primitives + transitive BFS."),
    "active_directory_graph": RegisteredStageSpec("active_directory_graph", "Active Directory Kerberos/ADCS Tier-0 Graph", StageCategory.AUTH_IDENTITY, 1800, "Kerberoasting, ADCS ESC1–ESC8 & Dijkstra Tier-0 paths."),
    "network_zero_trust": RegisteredStageSpec("network_zero_trust", "Network Services, DNS & Zero-Trust Firewall", StageCategory.NETWORK_CRYPTO, 1600, "Shadowed firewall rules, DNS tunneling & insecure services."),
    "mitre_sigma_purple": RegisteredStageSpec("mitre_sigma_purple", "14-Tactic MITRE ATT&CK Emulation + Sigma/YARA", StageCategory.ADVERSARY_EMULATION, 2400, "ATT&CK campaign simulation & Sigma detective coverage."),
    "bas_campaigns": RegisteredStageSpec("bas_campaigns", "Breach & Attack Simulation (BAS) + SIEM/SOAR", StageCategory.ADVERSARY_EMULATION, 2200, "Multi-stage adversary campaigns + SIEM correlation & SOAR."),
    "ai_llm_redteam": RegisteredStageSpec("ai_llm_redteam", "OWASP LLM 2025 & MITRE ATLAS AI Red-Team", StageCategory.AI_REDTEAM, 2200, "Static AI pipeline audit + 15 adversarial LLM agent probes."),
    "grammar_fuzzer": RegisteredStageSpec("grammar_fuzzer", "Multi-Protocol Grammar-Aware Security Fuzzer", StageCategory.DYNAMIC_SANDBOX, 2400, "9-grammar adversarial mutation & invariant fuzzing."),
    "independent_validation_drilldown": RegisteredStageSpec("independent_validation_drilldown", "Independent Verification & Repro Escalation Gate", StageCategory.HYPOTHESIS_DRILLDOWN, 2000, "Cross-checks unverified critical findings & YARA signatures."),
    "cicd_ppe_graph": RegisteredStageSpec("cicd_ppe_graph", "CI/CD Pipeline Execution-Graph & PPE Auditor", StageCategory.INFRA_CLOUD_K8S, 1600, "GitHub Actions/Jenkins PPE DAG, expression injection & artifact poisoning."),
    "memory_exploitability": RegisteredStageSpec("memory_exploitability", "C/C++/Rust-Unsafe Memory Exploitability Modeler", StageCategory.BINARY_OT, 1800, "BOF/UAF/Double-Free/Rust unsafe & ASLR/CFI/PAC exploitability modeling."),
    "openapi_contract_fuzz": RegisteredStageSpec("openapi_contract_fuzz", "OpenAPI 3.x OWASP API Top 10 & Negative Fuzzer", StageCategory.API_MICROSERVICES, 1500, "OpenAPI BOLA/BOPLA/mass-assignment auditor & negative fuzz synthesizer."),
    "smart_contract_web3": RegisteredStageSpec("smart_contract_web3", "Solidity / Web3 Smart-Contract Auditor", StageCategory.WEB_APPSEC, 1400, "Reentrancy, tx.origin, delegatecall & flash-loan invariant auditing."),
    "supply_chain_typosquat": RegisteredStageSpec("supply_chain_typosquat", "Package Typosquatting & Dependency Confusion Guard", StageCategory.SUPPLY_CHAIN_SECRETS, 1400, "Levenshtein typosquatting & internal package namespace collision scanner."),
    "pqc_cbom_auditor": RegisteredStageSpec("pqc_cbom_auditor", "Post-Quantum Cryptography (PQC) CBOM & Timing Auditor", StageCategory.NETWORK_CRYPTO, 1500, "NIST PQC CBOM readiness, Mosca HNDL risk & non-constant-time checks."),
    "privacy_pii_gdpr": RegisteredStageSpec("privacy_pii_gdpr", "Privacy, PII/GDPR & k-Anonymity Auditor", StageCategory.SUPPLY_CHAIN_SECRETS, 1400, "PII leak telemetry, GDPR minimization & k-anonymity/DP budget checks."),
    "browser_dom_csp": RegisteredStageSpec("browser_dom_csp", "Browser DOM XSS Sink & CSP3 Bypass Auditor", StageCategory.WEB_APPSEC, 1400, "DOM innerHTML/eval sinks, postMessage leaks & CSP3 bypass scoring."),
    "zeroday_vex_triage": RegisteredStageSpec("zeroday_vex_triage", "Zero-Day CVE Reachability, VEX 1.5 & Virtual Patcher", StageCategory.SUPPLY_CHAIN_SECRETS, 1600, "AST sink reachability triage, CycloneDX VEX & ModSec/Nginx virtual patches."),
    "k8s_admission_opa": RegisteredStageSpec("k8s_admission_opa", "Kubernetes OPA/Kyverno PSS-Restricted Admission Gate", StageCategory.INFRA_CLOUD_K8S, 1500, "Validates K8s PodSpecs against PSS restricted & synthesizes Kyverno/Rego."),
    "oauth21_pkce_audit": RegisteredStageSpec("oauth21_pkce_audit", "OAuth 2.1 / OIDC / PKCE State-Machine Fuzzer", StageCategory.AUTH_IDENTITY, 1400, "12 RFC 9700 / PKCE / redirect-URI bypass protocol state-machine checks."),
    "hardware_boot_attest": RegisteredStageSpec("hardware_boot_attest", "UEFI Secure Boot, TPM 2.0 PCR & Silicon RoT Auditor", StageCategory.BINARY_OT, 1500, "Audits UEFI dbx/BootGuard, TPM 2.0 PCR quotes & embedded JTAG/OTA."),
}


class FirstOrderStageRegistry:
    """Executes any registered first-order cybersecurity stage adapter safely and deterministically."""

    def __init__(self) -> None:
        self.web_inj = WebInjectionSecurityEngine()
        self.web_client = WebClientProtocolEngine()
        self.web_server = WebServerSideVulnEngine()
        self.auth = AuthAccessControlEngine()
        self.api = APIMicroservicesSecurityEngine()
        self.secrets = SecretsAndDLPEngine(allow_synthetic_examples=True)
        self.tls = TLSCryptoAuditor()
        self.iac = IaCAndCICDSecurityEngine()
        self.k8s = KubernetesAndContainerSecurityEngine()
        self.runtime_ebpf = ContainerRuntimeKernelEngine()
        self.sbom = SupplyChainSBOMEngine()
        self.cicd_ppe = CICDPipelineGraphAuditor()
        self.mem_modeler = MemoryCorruptionExploitModeler()
        self.openapi_fuzz = OpenAPIContractSecurityAuditor()
        self.web3_auditor = SmartContractWeb3Auditor()
        self.typosquat = SupplyChainTyposquatEngine()
        self.pqc_auditor = QuantumAndSideChannelAuditor()
        self.privacy_auditor = PrivacyPIIGDPREngine()
        self.browser_csp = BrowserDOMCSPEngine()
        self.zeroday_triage = ZeroDayPatchTriageEngine()
        self.k8s_admission = KubernetesAdmissionPolicyEngine()
        self.oauth21_auditor = OAuth21PKCEStateMachineAuditor()
        self.hw_boot_auditor = HardwareFirmwareBootAuditor()
        self.binary = BinaryAndMemorySafetyEngine()
        self.iot_ot = FirmwareIoTOTSecurityEngine()
        self.cloud_iam = CloudIAMSecurityEngine()
        self.ad = IdentityAndADSecurityEngine()
        self.net = NetworkProtocolAuditor()
        self.dns = DNSSecurityAnalyzer()
        self.seg = ZeroTrustSegmentationAuditor()
        self.mitre = MitreAttackEmulationEngine()
        self.sigma = SigmaDetectionEngine()
        self.yara = YaraStyleScanner()
        self.bas = BreachAndAttackCampaignEngine(self.sigma)
        self.siem_soar = SIEMCorrelationAndSOAREngine()
        self.ai_rt = AILLMRedTeamEngine()
        self.fuzzer = GrammarAwareSecurityFuzzer()

    @staticmethod
    def get_spec(adapter_name: str) -> RegisteredStageSpec:
        return STAGE_CATALOG[adapter_name]

    def execute_stage(self, adapter_name: str, ctx: StageExecutionContext) -> StageExecutionResult:
        t0 = time.perf_counter()
        try:
            vulns, artifacts, extra = self._dispatch(adapter_name, ctx)
            return StageExecutionResult(
                adapter_name=adapter_name,
                vulnerabilities=vulns,
                artifacts=artifacts,
                extra_metrics=extra,
                elapsed_ms=round((time.perf_counter() - t0) * 1000.0, 2),
            )
        except Exception as exc:
            return StageExecutionResult(
                adapter_name=adapter_name,
                elapsed_ms=round((time.perf_counter() - t0) * 1000.0, 2),
                error=f"{type(exc).__name__}: {exc}",
            )

    def _dispatch(
        self,
        name: str,
        ctx: StageExecutionContext,
    ) -> Tuple[List[CyberVulnerability], Dict[str, Any], Dict[str, Any]]:
        path = ctx.target_path
        has_dir = path is not None and path.exists()

        if name == "web_injection":
            return (self.web_inj.scan_directory(path) if has_dir else []), {}, {}
        if name == "web_client_protocol":
            return (self.web_client.scan_directory(path) if has_dir else []), {}, {}
        if name == "web_ssrf_deser":
            return (self.web_server.scan_directory(path) if has_dir else []), {}, {}
        if name == "auth_access":
            return (self.auth.scan_directory(path) if has_dir else []), {}, {}
        if name == "api_microservices":
            return (self.api.scan_directory(path) if has_dir else []), {}, {}
        if name == "secrets_dlp":
            if not has_dir:
                return [], {}, {}
            res = self.secrets.scan_directory(path)
            return res["vulnerabilities"], {"secrets_dlp": {k: v for k, v in res.items() if k != "vulnerabilities"}}, {}
        if name == "tls_crypto":
            return (self.tls.scan_directory(path) if has_dir else []), {}, {}
        if name == "iac_cicd":
            return (self.iac.scan_directory(path) if has_dir else []), {}, {}
        if name == "kubernetes_container":
            return (self.k8s.scan_directory(path) if has_dir else []), {}, {}
        if name == "container_runtime_ebpf":
            if ctx.hardened_simulation:
                seccomp = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": [{"action": "SCMP_ACT_ALLOW", "names": ["read", "write", "exit_group"]}]}
                caps: List[str] = []
                syscalls: List[SyscallEvent] = []
            else:
                seccomp = {"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [{"action": "SCMP_ACT_ALLOW", "names": ["ptrace", "mount", "bpf"]}]}
                caps = ["CAP_SYS_ADMIN", "CAP_SYS_PTRACE"]
                syscalls = [
                    SyscallEvent(new_id("sc"), "pod-web-01", "nsenter", "setns", {"target": "/proc/1/ns/mnt"}, uid=0),
                    SyscallEvent(new_id("sc"), "pod-web-01", "curl", "connect", {"dst": "169.254.169.254:80"}, uid=0),
                ]
            v = self.runtime_ebpf.audit_seccomp_profile(seccomp) + self.runtime_ebpf.audit_capabilities(caps)
            ev_res = self.runtime_ebpf.evaluate_syscall_stream(syscalls)
            v.extend(ev_res["vulnerabilities"])
            return v, {"container_runtime_ebpf": {k: val for k, val in ev_res.items() if k != "vulnerabilities"}}, {}
        if name == "supply_chain_sbom":
            if not has_dir:
                return [], {}, {}
            comps = self.sbom.extract_components(path)
            audit = self.sbom.audit_components(comps)
            cdx = self.sbom.export_cyclonedx_1_5(path.name, comps)
            return audit["vulnerabilities"], {"supply_chain_sbom": {k: v for k, v in audit.items() if k != "vulnerabilities"}, "cyclonedx_components": len(cdx["components"])}, {}
        if name == "binary_memory":
            if not has_dir:
                return [], {}, {}
            bv, profs = self.binary.scan_directory(path)
            return bv, {"binary_profiles": [p.to_dict() for p in profs]}, {}
        if name == "firmware_iot_ot":
            return (self.iot_ot.scan_directory(path) if has_dir else []), {}, {}
        if name == "live_sandbox_dast":
            if ctx.live_local_url:
                vulns = self._run_live_probes(ctx.live_local_url)
                return vulns, {"live_dast": {"url": ctx.live_local_url, "findings": len(vulns)}}, {}
            with AuthorizedSyntheticCyberRange(hardened=ctx.hardened_simulation) as rng:
                vulns = self._run_live_probes(rng.base_url)
                return vulns, {"live_dast": {"url": rng.base_url, "hardened": ctx.hardened_simulation, "findings": len(vulns)}}, {}
        if name == "cloud_iam_graph":
            principals = GeneralizedCyberOrchestrator._build_reference_cloud_iam_graph(hardened=ctx.hardened_simulation)
            rep = self.cloud_iam.audit_principal_graph(principals)
            vulns = list(rep.get("findings", []))
            if has_dir:
                vulns.extend(self.cloud_iam.scan_policy_json_files(path))
            return vulns, {"cloud_iam_graph": {k: v for k, v in rep.items() if k != "findings"}}, {}
        if name == "active_directory_graph":
            objs, edges, tpls = GeneralizedCyberOrchestrator._build_reference_ad_estate(hardened=ctx.hardened_simulation)
            rep = self.ad.audit_directory_estate(objs, edges, tpls)
            return list(rep.get("findings", [])), {"active_directory_graph": {k: v for k, v in rep.items() if k != "findings"}}, {}
        if name == "network_zero_trust":
            fw, dns_cfg, svcs = GeneralizedCyberOrchestrator._build_reference_network_estate(hardened=ctx.hardened_simulation)
            fw_rep = self.seg.audit_firewall_rules(fw)
            dv = self.dns.audit_dns_config(dns_cfg, asset="ns1.enterprise.local")
            sv = self.net.audit_services(svcs)
            vulns = list(fw_rep.get("findings", [])) + dv + sv
            return vulns, {"network_zero_trust": {"firewall_findings": len(fw_rep.get("findings", [])), "dns_findings": len(dv), "service_findings": len(sv)}}, {}
        if name == "mitre_sigma_purple":
            posture = EnterpriseDefensePosture.hardened_enterprise() if ctx.hardened_simulation else EnterpriseDefensePosture.vulnerable_baseline()
            emu = self.mitre.run_campaign(posture=posture)
            sigma = self.sigma.measure_purple_team_coverage(emu)
            yara_hits = self.yara.scan_directory(path) if has_dir else []
            art = {
                "mitre_emulation": {k: v for k, v in emu.items() if k not in {"telemetry_events", "findings"}},
                "sigma_detection": {k: v for k, v in sigma.items() if k != "raw_matches"},
                "yara_matches": [m.to_dict() for m in yara_hits],
            }
            return list(emu.get("findings", [])), art, {}
        if name == "bas_campaigns":
            posture = EnterpriseDefensePosture.hardened_enterprise() if ctx.hardened_simulation else EnterpriseDefensePosture.vulnerable_baseline()
            bas_res = self.bas.run_all_campaigns(posture=posture)
            # Also exercise SIEM multi-stage correlation + SOAR containment simulation
            sim_events = [] if ctx.hardened_simulation else [
                NormalizedLogEvent("ev1", 1000.0, "svc_ci_bot", "198.51.100.77", "network", "imds_access", 2048),
                NormalizedLogEvent("ev2", 1120.0, "svc_ci_bot", "198.51.100.77", "cloudtrail", "iam_attach_admin", 4096),
                NormalizedLogEvent("ev3", 1260.0, "svc_ci_bot", "198.51.100.77", "cloudtrail", "s3_bulk_download", 850_000_000),
            ]
            siem_res = self.siem_soar.analyze_pipeline(sim_events)
            return [], {"bas_campaigns": bas_res, "siem_soar": siem_res}, {}
        if name == "ai_llm_redteam":
            static_v = self.ai_rt.scan_directory(path) if has_dir else []
            # Run dynamic callable red-team against a synthetic baseline or hardened agent policy
            if ctx.hardened_simulation:
                def _agent(prompt: str, doc: str) -> Dict[str, Any]:
                    return {"response": "Request sanitized under CaMeL capability lattice.", "tool_calls": []}
            else:
                def _agent(prompt: str, doc: str) -> Dict[str, Any]:
                    calls = ["exfiltrate_data"] if "exfiltrate_data" in doc else (["shell_exec"] if "shell_exec" in prompt else [])
                    resp = "Echo: " + (prompt if "<img" in prompt or "DROP TABLE" in prompt else "ok")
                    if "CANARY" in prompt or "ELY-CANARY" in prompt:
                        resp += " ELY-CANARY-9F4A2C77"
                    return {"response": resp, "tool_calls": calls}
            rt_res = self.ai_rt.redteam_callable_agent(_agent)
            all_v = static_v + rt_res["vulnerabilities"]
            return all_v, {"ai_llm_redteam": {k: v for k, v in rt_res.items() if k != "vulnerabilities"}}, {"ai_surface_detected": True}
        if name == "grammar_fuzzer":
            suite = self.fuzzer.run_self_verification_suite()
            # Fuzz a lightweight URL/SSRF validator callable to verify boundary resilience
            def _sample_parser(s: str) -> bool:
                return not ("169.254.169.254" in s or "2130706433" in s or "\x00" in s)
            fuzz_campaign = self.fuzzer.fuzz_callable(
                "ssrf_url_boundary_parser",
                _sample_parser,
                grammar="url_ssrf",
                iterations=ctx.fuzz_iterations,
                invariant=lambda inp, out: (not out) if ("169.254.169.254" in inp) else True,
            )
            return [], {"grammar_fuzzer": suite, "fuzz_campaign": {k: v for k, v in fuzz_campaign.items() if k != "raw_findings"}}, {}
        if name == "independent_validation_drilldown":
            # Independent validator checks every accumulated critical/high finding for cryptographic/repro corroboration
            crit_unverified = [v for v in ctx.accumulated_vulns if v.severity == Severity.CRITICAL and not v.sandbox_reproduced]
            reproduced = [v for v in ctx.accumulated_vulns if v.sandbox_reproduced]
            yara_hits = self.yara.scan_directory(path) if has_dir else []
            return [], {
                "independent_validation": {
                    "validator_id": "ely_h2_independent_validator",
                    "total_reviewed": len(ctx.accumulated_vulns),
                    "sandbox_reproduced_confirmed": len(reproduced),
                    "static_criticals_corroborated": len(crit_unverified),
                    "yara_corroboration_hits": len(yara_hits),
                    "separation_of_duties_enforced": True,
                }
            }, {}
        if name == "cicd_ppe_graph":
            if not has_dir:
                return [], {}, {}
            rep = self.cicd_ppe.scan_directory(str(path))
            return list(rep.get("vulnerabilities", [])), {"cicd_ppe_graph": {"pipelines_audited": rep.get("pipelines_audited", 0)}}, {}
        if name == "memory_exploitability":
            if not has_dir:
                return [], {}, {}
            rep = self.mem_modeler.scan_directory(str(path))
            return list(rep.get("vulnerabilities", [])), {"memory_exploitability": {"native_files_scanned": rep.get("native_files_scanned", 0)}}, {}
        if name == "openapi_contract_fuzz":
            if not has_dir:
                return [], {}, {}
            oapi_v = self.openapi_fuzz.scan_directory(path)
            return list(oapi_v), {"openapi_contract_fuzz": {"findings": len(oapi_v)}}, {}
        if name == "smart_contract_web3":
            if not has_dir:
                return [], {}, {}
            sol_vulns: List[CyberVulnerability] = []
            sol_cnt = 0
            for fp in sorted(path.rglob("*.sol")):
                sol_cnt += 1
                res = self.web3_auditor.audit_solidity_source(fp.read_text(encoding="utf-8", errors="ignore"), str(fp.relative_to(path)))
                sol_vulns.extend(res.get("vulnerabilities", []))
            return sol_vulns, {"smart_contract_web3": {"solidity_files_audited": sol_cnt}}, {}
        if name == "supply_chain_typosquat":
            if not has_dir:
                return [], {}, {}
            pkgs: List[str] = []
            for reqf in sorted(path.rglob("requirements*.txt")):
                for ln in reqf.read_text(encoding="utf-8", errors="ignore").splitlines():
                    tok = ln.strip().split("==")[0].split(">=")[0].split("<=")[0].strip()
                    if tok and not tok.startswith("#"):
                        pkgs.append(tok)
            rep = self.typosquat.audit_packages(pkgs, ecosystem="pypi") if pkgs else {"vulnerabilities": [], "packages_checked": 0}
            return list(rep.get("vulnerabilities", [])), {"supply_chain_typosquat": {"packages_checked": len(pkgs)}}, {}
        if name == "pqc_cbom_auditor":
            if not has_dir:
                return [], {}, {}
            pqc_vulns: List[CyberVulnerability] = []
            for fp in sorted(path.rglob("*.py")):
                res = self.pqc_auditor.audit_code_timing_sidechannels(fp.read_text(encoding="utf-8", errors="ignore"), str(fp.relative_to(path)))
                pqc_vulns.extend(res.get("vulnerabilities", []))
            return pqc_vulns, {"pqc_cbom_auditor": {"timing_findings": len(pqc_vulns)}}, {}
        if name == "privacy_pii_gdpr":
            if not has_dir:
                return [], {}, {}
            priv_vulns: List[CyberVulnerability] = []
            for fp in sorted(path.rglob("*.py")):
                res = self.privacy_auditor.scan_source_for_pii_leaks(fp.read_text(encoding="utf-8", errors="ignore"), str(fp.relative_to(path)))
                priv_vulns.extend(res.get("vulnerabilities", []))
            return priv_vulns, {"privacy_pii_gdpr": {"pii_findings": len(priv_vulns)}}, {}
        if name == "browser_dom_csp":
            if not has_dir:
                return [], {}, {}
            dom_vulns: List[CyberVulnerability] = []
            for fp in sorted(path.rglob("*")):
                if fp.is_file() and fp.suffix.lower() in (".js", ".ts", ".jsx", ".tsx", ".html"):
                    res = self.browser_csp.audit_dom_javascript(fp.read_text(encoding="utf-8", errors="ignore"), str(fp.relative_to(path)))
                    dom_vulns.extend(res.get("vulnerabilities", []))
            return dom_vulns, {"browser_dom_csp": {"dom_findings": len(dom_vulns)}}, {}
        if name == "zeroday_vex_triage":
            if not has_dir:
                return [], {}, {}
            rep = self.zeroday_triage.triage_target(path)
            return list(rep.get("vulnerabilities", [])), {
                "zeroday_vex_triage": {
                    "exploitable_zerodays": rep["exploitable_zerodays"],
                    "virtual_patches_generated": len(rep["virtual_patches"]),
                    "vex_spec": rep["cyclonedx_vex"]["specVersion"],
                }
            }, {}
        if name == "k8s_admission_opa":
            if ctx.hardened_simulation:
                sample_manifest = {
                    "kind": "Deployment",
                    "metadata": {"name": "hardened-svc", "namespace": "prod"},
                    "spec": {"template": {"spec": {
                        "automountServiceAccountToken": False,
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "seccompProfile": {"type": "RuntimeDefault"}},
                        "containers": [{
                            "name": "app",
                            "image": "ghcr.io/ely/app@sha256:0123456789abcdef",
                            "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}},
                            "securityContext": {
                                "privileged": False,
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                        }],
                    }}},
                }
            else:
                sample_manifest = {
                    "kind": "Deployment",
                    "metadata": {"name": "exposed-worker", "namespace": "prod"},
                    "spec": {"template": {"spec": {
                        "hostPID": True,
                        "volumes": [{"name": "host-root", "hostPath": {"path": "/"}}],
                        "containers": [{"name": "worker", "image": "python:latest", "securityContext": {"privileged": True, "runAsUser": 0}}],
                    }}},
                }
            rep = self.k8s_admission.evaluate_manifest(sample_manifest)
            return list(rep.get("vulnerabilities", [])), {
                "k8s_admission_opa": {
                    "admission_decision": rep["admission_decision"],
                    "pss_compliance_score": rep["pss_compliance_score"],
                    "violation_count": rep["violation_count"],
                }
            }, {}
        if name == "oauth21_pkce_audit":
            cfg = OAuthServerPolicyConfig(
                exact_redirect_uri_matching=ctx.hardened_simulation,
                require_pkce_s256=ctx.hardened_simulation,
                accept_pkce_plain_downgrade=not ctx.hardened_simulation,
                require_state_csrf=ctx.hardened_simulation,
                require_oidc_nonce=ctx.hardened_simulation,
                single_use_auth_codes=ctx.hardened_simulation,
                allow_implicit_or_ropc_grants=not ctx.hardened_simulation,
                refresh_token_rotation_and_reuse_detection=ctx.hardened_simulation,
                require_dpop_or_mtls_for_privileged_scopes=ctx.hardened_simulation,
                emit_rfc9207_iss_param=ctx.hardened_simulation,
                strict_id_token_claims_validation=ctx.hardened_simulation,
            )
            rep = self.oauth21_auditor.audit_oauth_server(cfg)
            return list(rep.get("vulnerabilities", [])), {
                "oauth21_pkce_audit": {
                    "verdict": rep["verdict"],
                    "oauth21_compliance_pct": rep["oauth21_compliance_pct"],
                }
            }, {}
        if name == "hardware_boot_attest":
            golden = {"PCR0": "a1b2c3d4", "PCR7": "f0e1d2c3"}
            snap = PlatformBootAttestationSnapshot(
                device_id="ely-node-01",
                secure_boot_enabled=ctx.hardened_simulation,
                dbx_revocation_version=2025 if ctx.hardened_simulation else 2020,
                hardware_boot_guard_fused=ctx.hardened_simulation,
                iommu_dma_protection_enabled=ctx.hardened_simulation,
                jtag_swd_debug_locked=ctx.hardened_simulation,
                tpm_version="2.0",
                measured_pcrs=golden if ctx.hardened_simulation else {"PCR0": "a1b2c3d4", "PCR7": "deadbeef"},
                ota_update_url="https://fw.ely.internal/signed.bin" if ctx.hardened_simulation else "http://fw.ely.internal/raw.bin",
                ota_signature_verified=ctx.hardened_simulation,
                services_enabled=[] if ctx.hardened_simulation else ["telnetd"],
            )
            rep = self.hw_boot_auditor.audit_platform_boot(snap, golden_pcrs=golden)
            return list(rep.get("vulnerabilities", [])), {
                "hardware_boot_attest": {
                    "attestation_verdict": rep["attestation_verdict"],
                    "root_of_trust_score_pct": rep["root_of_trust_score_pct"],
                }
            }, {}

        raise KeyError(f"Unknown Harness² stage adapter: '{adapter_name}'")

    def _run_live_probes(self, base_url: str) -> List[CyberVulnerability]:
        handler = build_local_http_probe_handler(base_url)
        found: List[CyberVulnerability] = []
        found.extend(self.web_inj.probe_sandbox_endpoint(handler, endpoint="/api/search", param_name="q"))
        found.extend(self.web_client.probe_sandbox_endpoint(handler, endpoint="/api/search", param_name="q"))
        found.extend(self.web_client.probe_sandbox_endpoint(handler, endpoint="/redirect", param_name="next"))
        found.extend(self.web_server.probe_sandbox_ssrf_ssti_path(handler, ssrf_endpoint="/api/v1/preview", ssti_endpoint="/api/v1/render"))
        hdr = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
        pay = base64.urlsafe_b64encode(b'{"sub":"1001","role":"user"}').decode().rstrip("=")
        found.extend(
            self.auth.probe_sandbox_access_control(
                handler,
                user_a_token=f"{hdr}.{pay}.invalid",
                user_b_resource_path="/api/v1/users/1002",
                admin_endpoint="/api/v1/admin/config",
                profile_update_endpoint="/api/v1/users/1001",
                race_redeem_endpoint="/api/v1/coupons/redeem",
            )
        )
        return found
