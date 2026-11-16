"""
Ransomware Lateral Blast-Radius Contagion Simulator, 3-2-1-1-0 Immutable Backup Verifier
& Enterprise Tier-0 Isolation Readiness Engine.

Quantitatively models worst-case enterprise ransomware propagation BEFORE an incident occurs:
  1. **Deterministic Graph Contagion Simulator**:
       Given an enterprise topology of hosts/subnets/hypervisors/backup-servers/Domain-Controllers
       connected by lateral traversal edges (`SMB/445`, `RDP/3389`, `WinRM`, `SSH`, `ESXi_API`,
       `Shared_AD_Cred`, `Backup_Admin_Portal`), simulates lateral spread from any patient-zero
       host (`initial_compromise`) to compute:
         - Total reachable hosts & percentage of enterprise crown jewels encrypted
         - Hop-by-hop propagation wave timeline (Wave 0 -> Wave K)
         - Whether **Tier-0 Active Directory Domain Controllers** or **Backup Repositories**
           are reached (catastrophic recovery-destruction condition!).
  2. **Minimal Cut / Chokepoint Edge Segmentation Recommender**:
       Runs exact single-edge ablation across every lateral conduit to rank the exact firewall
       or identity-tiering boundaries whose enforcement shrinks ransomware blast radius the most!
  3. **3-2-1-1-0 Ransomware Backup Immutability Auditor**:
       Verifies: `>=3` copies, `>=2` distinct media types, `>=1` offsite, `>=1` air-gapped /
       WORM Object-Lock immutable copy (with non-AD-joined separate MFA credentials!), and
       `0` unverified recovery-drill errors.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

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


@dataclass
class EnterpriseHostNode:
    host_id: str
    hostname: str
    tier: str  # workstation | app_server | db_server | hypervisor_esxi | backup_server | ad_tier0_dc
    subnet: str
    crown_jewel: bool = False
    edr_isolation_enabled: bool = False


@dataclass
class LateralPropagationEdge:
    src_host: str
    dst_host: str
    vector: str  # smb_445 | rdp_3389 | winrm | ssh_shared_key | shared_local_admin | backup_console | esxi_ssh
    requires_mfa: bool = False
    blocked_by_segmentation: bool = False


@dataclass
class BackupPostureConfig:
    total_copies: int = 3
    distinct_media_types: int = 2
    has_offsite_copy: bool = True
    has_immutable_worm_or_airgap: bool = False
    backup_joined_to_corporate_ad: bool = True
    backup_console_requires_phishing_resistant_mfa: bool = False
    last_restore_drill_days_ago: int = 180
    restore_drill_errors: int = 0


class RansomwareResilienceSimulator:
    """Simulates ransomware lateral contagion, ranks segmentation chokepoints, and audits 3-2-1-1-0 backups."""

    def simulate_contagion(
        self,
        nodes: Sequence[EnterpriseHostNode],
        edges: Sequence[LateralPropagationEdge],
        patient_zero_id: str,
    ) -> Dict[str, Any]:
        """Run deterministic BFS contagion from `patient_zero_id` + single-edge chokepoint ablation."""
        nmap = {n.host_id: n for n in nodes}
        active_edges = [e for e in edges if not e.blocked_by_segmentation and not e.requires_mfa]

        waves, compromised = self._bfs_spread(patient_zero_id, active_edges)
        tot_hosts = max(1, len(nodes))
        blast_pct = round((len(compromised) / tot_hosts) * 100.0, 2)

        crown_jewels_total = [n.host_id for n in nodes if n.crown_jewel]
        crown_jewels_hit = [h for h in crown_jewels_total if h in compromised]
        tier0_hit = [n.host_id for n in nodes if n.tier == "ad_tier0_dc" and n.host_id in compromised]
        backups_hit = [n.host_id for n in nodes if n.tier == "backup_server" and n.host_id in compromised]

        # Single-edge chokepoint ablation: which single edge removal saves the MOST hosts?
        chokepoints: List[Dict[str, Any]] = []
        for idx, e in enumerate(active_edges):
            if e.src_host not in compromised or e.dst_host not in compromised:
                continue
            reduced_edges = [ed for j, ed in enumerate(active_edges) if j != idx]
            _, comp_without = self._bfs_spread(patient_zero_id, reduced_edges)
            saved = len(compromised) - len(comp_without)
            if saved > 0:
                chokepoints.append({
                    "edge": f"{e.src_host} -> {e.dst_host}",
                    "vector": e.vector,
                    "hosts_saved_if_blocked": saved,
                    "blast_radius_reduction_pct": round((saved / tot_hosts) * 100.0, 2),
                })
        chokepoints.sort(key=lambda c: c["hosts_saved_if_blocked"], reverse=True)

        vulns: List[CyberVulnerability] = []
        if tier0_hit:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-RANSOM-TIER0-REACHABLE",
                    title=f"Ransomware Contagion From `{patient_zero_id}` Reaches Active Directory Tier-0 DC(s) {tier0_hit}",
                    description=(
                        f"Lateral propagation across unsegmented SMB/RDP/shared-admin paths reached {len(compromised)}/{tot_hosts} hosts "
                        f"({blast_pct}%) including Tier-0 Domain Controller(s) {tier0_hit}, enabling instant GPO-wide domain encryption."
                    ),
                    cyber_domain=CyberDomain.IDENTITY_ACTIVE_DIRECTORY,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-284", "CWE-269"],
                    confidence=0.98,
                    cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="L", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
                    mitre_techniques=[MitreTechniqueRef("T1486", "Data Encrypted for Impact (Domain-Wide)", MitreTactic.IMPACT)],
                    verification_method=VerificationMethod.GRAPH_REACHABILITY,
                    endpoint_or_asset=f"{patient_zero_id}->{tier0_hit[0]}",
                    remediation_guidance="Enforce AD Tier-0 PAW isolation, LAPS unique local admin passwords, and block workstation-to-server SMB/RDP.",
                    discovered_by="ely_cyber_ransomware_simulator",
                )
            )
        if backups_hit:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-RANSOM-BACKUP-REACHABLE",
                    title=f"Ransomware Contagion Reaches Enterprise Backup Infrastructure {backups_hit}",
                    description=f"Backup server(s) {backups_hit} are reachable along lateral paths from `{patient_zero_id}`, risking total recovery wipe.",
                    cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-284"],
                    confidence=0.99,
                    mitre_techniques=[MitreTechniqueRef("T1490", "Inhibit System Recovery", MitreTactic.IMPACT)],
                    verification_method=VerificationMethod.GRAPH_REACHABILITY,
                    endpoint_or_asset=backups_hit[0],
                    remediation_guidance="Isolate backup control planes off corporate AD, enforce hardware FIDO2 MFA, and enable S3/WORM Object Lock immutability.",
                    discovered_by="ely_cyber_ransomware_simulator",
                )
            )

        return {
            "simulated_at": utc_now_iso(),
            "patient_zero": patient_zero_id,
            "total_hosts": len(nodes),
            "compromised_hosts_count": len(compromised),
            "blast_radius_pct": blast_pct,
            "crown_jewels_compromised": crown_jewels_hit,
            "tier0_dc_compromised": tier0_hit,
            "backup_servers_compromised": backups_hit,
            "propagation_waves": waves,
            "top_segmentation_chokepoints": chokepoints[:10],
            "vulnerabilities": vulns,
        }

    def audit_backup_32110_posture(self, cfg: BackupPostureConfig, asset: str = "enterprise_backups") -> Dict[str, Any]:
        """Audit backup resilience against the 3-2-1-1-0 ransomware immutability standard."""
        vulns: List[CyberVulnerability] = []
        checks = {
            "3_copies": cfg.total_copies >= 3,
            "2_media_types": cfg.distinct_media_types >= 2,
            "1_offsite": cfg.has_offsite_copy,
            "1_immutable_worm_airgap": cfg.has_immutable_worm_or_airgap,
            "0_ad_domain_decoupled": not cfg.backup_joined_to_corporate_ad,
            "phishing_resistant_mfa": cfg.backup_console_requires_phishing_resistant_mfa,
            "0_recent_clean_restore_drill": cfg.last_restore_drill_days_ago <= 90 and cfg.restore_drill_errors == 0,
        }

        if not cfg.has_immutable_worm_or_airgap:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-RANSOM-BACKUP-NO-WORM",
                    title="Enterprise Backups Lack Immutable WORM Object-Lock or Air-Gapped Copy",
                    description="Without immutable WORM/air-gapped backups, attackers who compromise backup admins can permanently delete all restore points.",
                    cyber_domain=CyberDomain.CLOUD_IAM,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-693"],
                    confidence=0.99,
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=asset,
                    remediation_guidance="Enable Compliance-mode WORM Object Lock (minimum 30-day retention) on offsite immutable backup vaults.",
                    discovered_by="ely_cyber_ransomware_simulator",
                )
            )
        if cfg.backup_joined_to_corporate_ad:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-RANSOM-BACKUP-AD-JOINED",
                    title="Backup Infrastructure Is Joined to Corporate Active Directory (Single Point of Ransomware Wipe)",
                    description="Domain-joined backup servers inherit Domain Admin compromises, allowing attackers to destroy backups immediately after AD takeover.",
                    cyber_domain=CyberDomain.IDENTITY_ACTIVE_DIRECTORY,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-269"],
                    confidence=0.99,
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=asset,
                    remediation_guidance="Remove backup servers from corporate AD and enforce dedicated non-federated identity with hardware FIDO2 MFA.",
                    discovered_by="ely_cyber_ransomware_simulator",
                )
            )
        if not checks["0_recent_clean_restore_drill"]:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-RANSOM-BACKUP-UNTESTED",
                    title=f"Backup Recovery Drill Overdue ({cfg.last_restore_drill_days_ago}d ago) or Had Errors ({cfg.restore_drill_errors})",
                    description="Untested backups frequently fail during real ransomware recovery due to corruption or missing KMS keys.",
                    cyber_domain=CyberDomain.CLOUD_IAM,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-693"],
                    confidence=0.95,
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=asset,
                    remediation_guidance="Run automated quarterly bare-metal/isolated-VPC recovery drills validating 0 restore errors and RTO/RPO.",
                    discovered_by="ely_cyber_ransomware_simulator",
                )
            )

        passed = sum(1 for v in checks.values() if v)
        return {
            "audited_at": utc_now_iso(),
            "asset": asset,
            "checks": checks,
            "resilience_score_pct": round((passed / len(checks)) * 100.0, 2),
            "vulnerabilities": vulns,
        }

    @staticmethod
    def _bfs_spread(start: str, edges: Sequence[LateralPropagationEdge]) -> Tuple[List[Dict[str, Any]], Set[str]]:
        adj: Dict[str, List[LateralPropagationEdge]] = {}
        for e in edges:
            adj.setdefault(e.src_host, []).append(e)

        visited: Set[str] = {start}
        q: deque[Tuple[str, int]] = deque([(start, 0)])
        waves_map: Dict[int, List[str]] = {0: [start]}

        while q:
            cur, depth = q.popleft()
            for e in adj.get(cur, ()):
                if e.dst_host not in visited:
                    visited.add(e.dst_host)
                    waves_map.setdefault(depth + 1, []).append(e.dst_host)
                    q.append((e.dst_host, depth + 1))

        waves = [{"wave": w, "newly_compromised": hosts} for w, hosts in sorted(waves_map.items())]
        return waves, visited
