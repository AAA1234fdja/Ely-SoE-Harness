"""Comprehensive unit & integration tests for the Generalized Enterprise Cyber Suite (47 engines)."""

from __future__ import annotations

import unittest
from pathlib import Path

from ely_soe.cyber import (
    BackupPostureConfig,
    BinaryMitigationProfile,
    CICDPipelineGraphAuditor,
    CTEMAssetScope,
    CYBER_ENGINE_CATALOG,
    ContinuousThreatExposureEngine,
    CryptographicOracleVerificationLab,
    EnterpriseCyberSuiteFacade,
    EnterpriseDefensePosture,
    EnterpriseHostNode,
    GeneralizedCyberOrchestrator,
    HardwareFirmwareBootAuditor,
    IdentityFederationAuditor,
    KubernetesAdmissionPolicyEngine,
    LateralPropagationEdge,
    MemoryCorruptionExploitModeler,
    OAuth21PKCEStateMachineAuditor,
    OAuthServerPolicyConfig,
    PlatformBootAttestationSnapshot,
    RansomwareResilienceSimulator,
    SOARIncidentPlaybookEngine,
    ThreatHuntQueryEngine,
    ThreatHuntingSigmaYaraEngine,
    ZeroDayPatchTriageEngine,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
V0_9 = REPO_ROOT / "lab_targets" / "ely_specimen" / "v0_9"
V1_0_HARDENED = REPO_ROOT / "lab_targets" / "ely_specimen" / "v1_0_hardened"


class TestGeneralizedCyberSuite(unittest.TestCase):
    def test_catalog_contains_all_47_specialized_engines(self) -> None:
        self.assertGreaterEqual(len(CYBER_ENGINE_CATALOG), 47)
        ids = [e["id"] for e in CYBER_ENGINE_CATALOG]
        self.assertEqual(len(ids), len(set(ids)))

    def test_core_orchestrator_discriminates_vulnerable_vs_hardened(self) -> None:
        orch = GeneralizedCyberOrchestrator()
        r_vuln = orch.assess_target(
            V0_9,
            run_synthetic_range=False,
            hardened_range=False,
            defense_posture=EnterpriseDefensePosture.vulnerable_baseline(),
        )
        r_hard = orch.assess_target(
            V1_0_HARDENED,
            run_synthetic_range=False,
            hardened_range=True,
            defense_posture=EnterpriseDefensePosture.hardened_enterprise(),
        )
        self.assertEqual(r_vuln["summary"]["gate_verdict"], "BLOCKED")
        self.assertGreater(len(r_vuln["summary"]["vulnerabilities"]), len(r_hard["summary"]["vulnerabilities"]) * 3)
        self.assertGreater(
            r_hard["summary"]["overall_cyber_posture"],
            r_vuln["summary"]["overall_cyber_posture"] + 40.0,
        )

    def test_unified_facade_scan_and_enterprise_simulation(self) -> None:
        facade = EnterpriseCyberSuiteFacade()
        scan = facade.run_unified_cyber_scan(V0_9, hardened_simulation=False)
        self.assertEqual(scan["gate_verdict"], "BLOCKED")
        self.assertGreaterEqual(scan["total_vulnerabilities"], 40)
        self.assertGreater(len(scan["soar_recommended_playbooks"]), 0)

        sim = facade.run_enterprise_posture_simulation(hardened=False)
        self.assertGreaterEqual(sim["total_enterprise_findings"], 20)
        self.assertGreater(sim["fair_financial_risk"]["mean_ale_usd"], 1_000_000.0)
        self.assertEqual(sim["sigma_detection_quality"]["f1_score"], 1.0)

    def test_soar_merkle_verified_playbook_execution(self) -> None:
        soar = SOARIncidentPlaybookEngine()
        res = soar.execute_playbook(
            "PB-RANSOMWARE-ISOLATION",
            incident_id="INC-UNIT-01",
            target_asset="prod-web-01",
            dry_run=True,
        )
        self.assertTrue(res["ledger_verified"])
        self.assertGreaterEqual(len(res["step_results"]), 4)

    def test_ransomware_contagion_and_backup_posture(self) -> None:
        sim = RansomwareResilienceSimulator()
        hosts = [
            EnterpriseHostNode("H-WEB", "dmz-web", "dmz", "10.0.1.0/24", crown_jewel=False, edr_isolation_enabled=False),
            EnterpriseHostNode("H-APP", "app-srv", "corp", "10.0.2.0/24", crown_jewel=False, edr_isolation_enabled=False),
            EnterpriseHostNode("H-DC", "dc-01", "tier0_dc", "10.0.0.0/24", crown_jewel=True, edr_isolation_enabled=False),
        ]
        edges = [
            LateralPropagationEdge("H-WEB", "H-APP", "smb_psexec"),
            LateralPropagationEdge("H-APP", "H-DC", "kerberos_delegation"),
        ]
        res = sim.simulate_contagion(hosts, edges, patient_zero_id="H-WEB")
        self.assertIn("H-DC", res["crown_jewels_compromised"])
        self.assertGreater(res["blast_radius_pct"], 80.0)
        backup = sim.audit_backup_32110_posture(BackupPostureConfig())
        self.assertLess(backup["resilience_score_pct"], 50.0)

    def test_cicd_ppe_memory_federation_and_sigma_engines(self) -> None:
        cicd = CICDPipelineGraphAuditor()
        sample_wf = (
            "on: pull_request_target\n"
            "permissions: write-all\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
            "      - run: echo ${{ github.event.pull_request.title }}\n"
        )
        c_res = cicd.audit_github_workflow(sample_wf, ".github/workflows/pr.yml")
        self.assertGreaterEqual(len(c_res["vulnerabilities"]), 3)

        mem = MemoryCorruptionExploitModeler()
        m_res = mem.audit_c_cpp_source("void f(char *s){ char buf[16]; strcpy(buf, s); printf(s); }", "vuln.c")
        self.assertGreaterEqual(len(m_res["vulnerabilities"]), 2)
        prof = mem.model_exploitability(
            "stack_buffer_overflow",
            BinaryMitigationProfile(nx_dep=False, pie_aslr=False, stack_canary=False, full_relro=False),
        )
        self.assertGreaterEqual(prof["exploitability_score"], 75.0)

        fed = IdentityFederationAuditor()
        f_res = fed.audit_saml_response_xml(
            "<Response><Assertion><NameID>admin</NameID></Assertion><Assertion><NameID>evil</NameID></Assertion></Response>"
        )
        self.assertGreaterEqual(len(f_res["vulnerabilities"]), 3)

        sig = ThreatHuntingSigmaYaraEngine()
        ev = sig.evaluate_detection_quality(
            [{"Image": "C:\\Windows\\powershell.exe", "CommandLine": "powershell -enc SQBFAFgA", "User": "CORP\\bob"}],
            [{"Image": "/usr/bin/python3", "CommandLine": "python3 app.py"}],
        )
        self.assertGreater(ev["f1_score"], 0.8)

    def test_kql_eql_threat_hunt_and_k8s_admission_and_hardware_boot(self) -> None:
        hq = ThreatHuntQueryEngine()
        events = [
            {"timestamp": 10.0, "event_type": "process", "host": "H1", "parent_image": "winword.exe", "image": "powershell.exe", "command_line": "powershell -enc A"},
            {"timestamp": 25.0, "event_type": "process", "host": "H1", "image": "powershell.exe", "command_line": "powershell -enc B"},
            {"timestamp": 40.0, "event_type": "network", "host": "H1", "dst_port": 443, "dst_is_external": True},
        ]
        kql = hq.execute_kql_query("process | where image contains 'powershell' | count by host", events)
        self.assertEqual(kql["matched_count"], 2)
        seq = hq.correlate_sequences(events)
        self.assertEqual(seq["sequence_detections_count"], 1)

        k8s = KubernetesAdmissionPolicyEngine()
        bad_dep = {
            "kind": "Deployment",
            "metadata": {"name": "bad", "namespace": "prod"},
            "spec": {"template": {"spec": {
                "hostPID": True,
                "volumes": [{"name": "r", "hostPath": {"path": "/"}}],
                "containers": [{"name": "c", "image": "nginx:latest", "securityContext": {"privileged": True, "runAsUser": 0}}],
            }}},
        }
        adm = k8s.evaluate_manifest(bad_dep)
        self.assertEqual(adm["admission_decision"], "DENY")
        self.assertIn("ClusterPolicy", adm["synthesized_kyverno_yaml"])
        self.assertIn("package ely.kubernetes.admission", adm["synthesized_opa_rego"])

        hw = HardwareFirmwareBootAuditor()
        hw_res = hw.audit_platform_boot(
            PlatformBootAttestationSnapshot("gw-1", secure_boot_enabled=False, measured_pcrs={"PCR0": "aa", "PCR7": "bad"}),
            golden_pcrs={"PCR0": "aa", "PCR7": "good"},
        )
        self.assertEqual(hw_res["attestation_verdict"], "UNTRUSTED_QUARANTINE")
        self.assertEqual(len(hw_res["pcr_mismatches"]), 1)

    def test_ctem_crypto_oracle_zeroday_vex_and_oauth21_auditor(self) -> None:
        ctem = ContinuousThreatExposureEngine()
        c_res = ctem.evaluate_ctem_cycle(
            [{"rule_id": "SQLI-1", "severity": "critical", "kev_listed": True, "sandbox_reproduced": True, "cwe_ids": ["CWE-89"]}],
            asset_scope=CTEMAssetScope("A1", "core-api", "sec", "tier0_crown_jewel", True, True),
            chain_rule_ids=["SQLI-1"],
        )
        self.assertEqual(c_res["sla_distribution"]["P0_24H"], 1)

        clab = CryptographicOracleVerificationLab()
        ks = b"\x33" * 12
        p1, p2 = b"KNOWN_BLOCK!", b"TOP_SECRET!!"
        nr = clab.test_nonce_reuse_xor_recovery(
            bytes(a ^ b for a, b in zip(p1, ks)),
            bytes(a ^ b for a, b in zip(p2, ks)),
            p1,
        )
        self.assertTrue(nr["vulnerable"])
        self.assertEqual(nr["recovered_plaintext_2_utf8"], "TOP_SECRET!!")

        m = int.from_bytes(b"OK", "big")
        rsa = clab.test_rsa_low_exponent_cube_root(pow(m, 3), exponent_e=3)
        self.assertTrue(rsa["exact_recovery"])
        self.assertEqual(rsa["recovered_plaintext_utf8"], "OK")

        wt = clab.test_welch_timing_sidechannel([50, 51, 49, 50, 52, 48], [95, 96, 94, 97, 93, 95])
        self.assertTrue(wt["timing_leak_proven"])

        zt = ZeroDayPatchTriageEngine()
        zv = zt.triage_target(V0_9)
        zh = zt.triage_target(V1_0_HARDENED)
        self.assertGreater(zv["exploitable_zerodays"], zh["exploitable_zerodays"])
        self.assertEqual(zv["cyclonedx_vex"]["bomFormat"], "CycloneDX")

        oa = OAuth21PKCEStateMachineAuditor()
        oa_bad = oa.audit_oauth_server(OAuthServerPolicyConfig())
        oa_good = oa.audit_oauth_server(OAuthServerPolicyConfig(
            exact_redirect_uri_matching=True, require_pkce_s256=True, accept_pkce_plain_downgrade=False,
            require_state_csrf=True, require_oidc_nonce=True, single_use_auth_codes=True,
            allow_implicit_or_ropc_grants=False, refresh_token_rotation_and_reuse_detection=True,
            require_dpop_or_mtls_for_privileged_scopes=True, emit_rfc9207_iss_param=True,
            strict_id_token_claims_validation=True,
        ))
        self.assertEqual(oa_bad["verdict"], "VULNERABLE_OAUTH_STATE_MACHINE")
        self.assertEqual(oa_good["verdict"], "HARDENED_OAUTH21_COMPLIANT")
        self.assertEqual(oa_good["oauth21_compliance_pct"], 100.0)


if __name__ == "__main__":
    unittest.main()
