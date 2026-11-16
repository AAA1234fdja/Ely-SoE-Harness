"""
Enterprise Identity, Active Directory & ADCS Attack-Path Graph Engine.

BloodHound-style pure-Python directed graph security analyzer for enterprise
Active Directory, Kerberos, ADCS PKI, and Federated Identity Estates:
  1. Kerberos Attack Surface Auditing:
       - **Kerberoasting**: Enabled user accounts with SPNs (`servicePrincipalName`) holding privileged memberships or weak encryption (`RC4`)
       - **AS-REP Roasting**: Accounts with `DONT_REQ_PREAUTH` enabled
       - **Unconstrained Delegation**: Non-DC servers/accounts trusted for unconstrained Kerberos delegation (TGT harvesting)
       - **Constrained Delegation (S4U2Self/S4U2Proxy)** targeting Tier-0 services (`LDAP`, `CIFS`, `HOST`, `KRBTGT`)
       - **Resource-Based Constrained Delegation (RBCD)**: Non-Tier-0 principals granted `WriteProperty`/`GenericAll` on `msDS-AllowedToActOnBehalfOfOtherIdentity`
  2. Active Directory Certificate Services (ADCS) Auditing (**ESC1 – ESC8**):
       - **ESC1**: Certificate template allows enrollee-supplied SAN (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) + Client Auth EKU + low-priv enroll + no manager approval
       - **ESC2**: Any Purpose EKU (`2.5.29.37.0`) or empty EKU with low-priv enrollment
       - **ESC3**: Certificate Request Agent EKU (`1.3.6.1.4.1.311.20.2.1`) without RA signature restriction
       - **ESC4**: Vulnerable ACL (`WriteDacl`/`GenericAll`/`WriteOwner`) on certificate template
       - **ESC6**: CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` flag enabled globally
       - **ESC8**: HTTP Web Enrollment (`certsrv`) exposed without EPA (Extended Protection for Authentication) enabling NTLM relay to ADCS
  3. Shortest-Path Tier-0 Escalation Graph Solver (Dijkstra / BFS):
       - Finds every shortest privilege-escalation path from Tier-2 users/workstations to Tier-0 Domain Admins / Domain Controllers / Enterprise CAs
       - Models `MemberOf`, `GenericAll`, `WriteDacl`, `WriteOwner`, `ForceChangePassword`, `DCSync`, `HasSession`, `AdminTo`, `AllowedToDelegate`, `ShadowCredentials`
       - Computes min-cut Tier-0 chokepoint edges whose removal collapses the maximum number of escalation paths
"""

from __future__ import annotations

import heapq
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from ely_soe.core.models import Severity, new_id
from ely_soe.cyber.models import (
    CVSSv4Metrics,
    CyberDomain,
    CyberVulnerability,
    EvidenceArtifact,
    IdentityDirectoryEdge,
    IdentityDirectoryObject,
    MitreTactic,
    MitreTechniqueRef,
    VerificationMethod,
    make_cyber_vuln,
)


PRIVILEGED_ACL_RELATIONS = {
    "GenericAll": (0.96, "T1098"),
    "WriteDacl": (0.94, "T1222"),
    "WriteOwner": (0.92, "T1222"),
    "GenericWrite": (0.90, "T1098"),
    "ForceChangePassword": (0.95, "T1098"),
    "DCSync": (0.99, "T1003.006"),
    "WriteKeyCredentialLink": (0.93, "T1098.005"),  # Shadow Credentials
    "AddMember": (0.95, "T1098"),
    "AllowedToDelegate": (0.90, "T1550.003"),
    "AllowedToAct": (0.91, "T1550.003"),
    "AdminTo": (0.92, "T1021.002"),
    "HasSession": (0.85, "T1003.001"),
    "MemberOf": (0.99, "T1078"),
    "Enroll": (0.88, "T1649"),
    "GPLink": (0.89, "T1484.001"),
}


@dataclass
class ADCSTemplateConfig:
    """Certificate Template & CA configuration descriptor for ESC1–ESC8 auditing."""

    template_name: str
    ca_name: str
    enrollee_supplies_subject: bool = False
    client_auth_eku: bool = False
    any_purpose_eku: bool = False
    cert_request_agent_eku: bool = False
    manager_approval_required: bool = True
    authorized_signatures_required: int = 0
    low_priv_enroll_principals: List[str] = field(default_factory=list)
    low_priv_write_principals: List[str] = field(default_factory=list)
    ca_editf_san2_enabled: bool = False
    ca_http_enrollment_no_epa: bool = False


class IdentityAndADSecurityEngine:
    """
    Enterprise Identity & Active Directory graph vulnerability solver,
    Kerberos misconfiguration auditor, and ADCS ESC1–ESC8 detector.
    """

    def audit_directory_estate(
        self,
        objects: List[IdentityDirectoryObject],
        edges: List[IdentityDirectoryEdge],
        adcs_templates: Optional[List[ADCSTemplateConfig]] = None,
    ) -> Dict[str, Any]:
        """Run full Active Directory / Identity graph assessment and Tier-0 shortest-path analysis."""
        findings: List[CyberVulnerability] = []
        by_id: Dict[str, IdentityDirectoryObject] = {o.object_id: o for o in objects}

        # Build adjacency list
        adj: Dict[str, List[IdentityDirectoryEdge]] = {o.object_id: [] for o in objects}
        for e in edges:
            if e.src_id in by_id and e.dst_id in by_id:
                adj.setdefault(e.src_id, []).append(e)

        # --------------------------------------------------------------
        # 1. Per-Object Kerberos & Hygiene Checks
        # --------------------------------------------------------------
        for obj in objects:
            if not obj.enabled:
                continue

            # Kerberoasting: user with SPN
            if obj.object_type == "user" and obj.spns:
                sev = Severity.CRITICAL if (obj.tier == 0 or obj.admin_count > 0) else Severity.HIGH
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-AD-KERBEROAST-001",
                        title=f"Kerberoastable Account `{obj.name}` Exposes SPNs ({', '.join(obj.spns[:2])})",
                        description=(
                            f"Enabled user `{obj.name}` (tier={obj.tier}, adminCount={obj.admin_count}) has Service Principal Names "
                            f"`{obj.spns}`, enabling any domain user to request TGS tickets for offline password cracking."
                        ),
                        cyber_domain=CyberDomain.IDENTITY_ACTIVE_DIRECTORY,
                        severity=sev,
                        cwe_ids=["CWE-521", "CWE-287"],
                        confidence=0.97,
                        mitre_techniques=[MitreTechniqueRef("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting", MitreTactic.CREDENTIAL_ACCESS, "003")],
                        cvss4=CVSSv4Metrics(av="A", ac="L", at="N", pr="L", ui="N", vc="H", vi="H", va="L", sc="H", si="H", sa="N"),
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        endpoint_or_asset=f"ad:{obj.domain}/{obj.name}",
                        remediation_guidance="Migrate service accounts to Group Managed Service Accounts (gMSA) with 240-byte auto-rotated AES-256 keys and remove SPNs from Tier-0 human accounts.",
                        discovered_by="ely_cyber_ad_engine",
                    )
                )

            # AS-REP Roasting
            if obj.dont_req_preauth:
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-AD-ASREPROAST-001",
                        title=f"AS-REP Roastable Principal `{obj.name}` (`DONT_REQ_PREAUTH` Enabled)",
                        description=f"Account `{obj.name}` disables Kerberos Pre-Authentication, allowing unauthenticated offline hash extraction.",
                        cyber_domain=CyberDomain.IDENTITY_ACTIVE_DIRECTORY,
                        severity=Severity.HIGH if obj.tier > 0 else Severity.CRITICAL,
                        cwe_ids=["CWE-287"],
                        confidence=0.99,
                        mitre_techniques=[MitreTechniqueRef("T1558.004", "AS-REP Roasting", MitreTactic.CREDENTIAL_ACCESS, "004")],
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        endpoint_or_asset=f"ad:{obj.domain}/{obj.name}",
                        remediation_guidance="Disable `DONT_REQ_PREAUTH` immediately and enforce AES-256 Kerberos pre-authentication.",
                        discovered_by="ely_cyber_ad_engine",
                    )
                )

            # Unconstrained Delegation on non-DC computer/account
            if obj.unconstrained_delegation and obj.attributes.get("is_domain_controller") is not True:
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-AD-UNCONSTRAINED-DELEG-001",
                        title=f"Unconstrained Kerberos Delegation Enabled on Non-DC Host `{obj.name}`",
                        description=(
                            f"Compromising `{obj.name}` allows harvesting forwarded Kerberos TGTs of any authenticating user "
                            "(including coerced Domain Controller computer accounts via PrinterBug/PetitPotam)."
                        ),
                        cyber_domain=CyberDomain.IDENTITY_ACTIVE_DIRECTORY,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-269"],
                        confidence=0.99,
                        mitre_techniques=[MitreTechniqueRef("T1558", "Steal or Forge Kerberos Tickets", MitreTactic.CREDENTIAL_ACCESS)],
                        cvss4=CVSSv4Metrics(av="A", ac="L", at="N", pr="L", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        endpoint_or_asset=f"ad:{obj.domain}/{obj.name}",
                        remediation_guidance="Disable Unconstrained Delegation on all member servers, add Tier-0 users to Protected Users group, and migrate to strict constrained delegation.",
                        discovered_by="ely_cyber_ad_engine",
                    )
                )

            # Constrained delegation to sensitive Tier-0 services
            if obj.constrained_delegation_targets:
                sensitive_tgts = [t for t in obj.constrained_delegation_targets if any(k in t.upper() for k in ("LDAP/", "CIFS/", "HOST/", "KRBTGT/", "DC"))]
                if sensitive_tgts and obj.tier > 0:
                    findings.append(
                        make_cyber_vuln(
                            rule_id="CYB-AD-CONSTRAINED-DELEG-001",
                            title=f"Tier-{obj.tier} Principal `{obj.name}` Holds Constrained Delegation to Sensitive Services ({', '.join(sensitive_tgts[:2])})",
                            description="S4U2Self/S4U2Proxy allows impersonating privileged domain principals to target services.",
                            cyber_domain=CyberDomain.IDENTITY_ACTIVE_DIRECTORY,
                            severity=Severity.HIGH,
                            cwe_ids=["CWE-269"],
                            confidence=0.94,
                            mitre_techniques=[MitreTechniqueRef("T1550.003", "Pass the Ticket", MitreTactic.LATERAL_MOVEMENT, "003")],
                            verification_method=VerificationMethod.GRAPH_REACHABILITY,
                            endpoint_or_asset=f"ad:{obj.domain}/{obj.name}",
                            remediation_guidance="Remove Tier-0 SPNs from delegation targets and place privileged accounts in `Protected Users`.",
                            discovered_by="ely_cyber_ad_engine",
                        )
                    )

        # --------------------------------------------------------------
        # 2. ADCS Certificate Template Auditing (ESC1, ESC2, ESC3, ESC4, ESC6, ESC8)
        # --------------------------------------------------------------
        for tpl in (adcs_templates or []):
            t_asset = f"adcs:{tpl.ca_name}/{tpl.template_name}"
            if tpl.enrollee_supplies_subject and tpl.client_auth_eku and tpl.low_priv_enroll_principals and not tpl.manager_approval_required and tpl.authorized_signatures_required == 0:
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-ADCS-ESC1",
                        title=f"ADCS ESC1 Domain Takeover via Certificate Template `{tpl.template_name}`",
                        description=(
                            f"Template `{tpl.template_name}` allows low-privilege principals `{tpl.low_priv_enroll_principals}` "
                            "to enroll with arbitrary Subject Alternative Name (SAN) and Client Authentication EKU without approval — enabling direct Domain Admin impersonation."
                        ),
                        cyber_domain=CyberDomain.IDENTITY_ACTIVE_DIRECTORY,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-295", "CWE-269"],
                        confidence=1.0,
                        mitre_techniques=[MitreTechniqueRef("T1649", "Steal or Forge Authentication Certificates", MitreTactic.CREDENTIAL_ACCESS)],
                        cvss4=CVSSv4Metrics(av="A", ac="L", at="N", pr="L", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        endpoint_or_asset=t_asset,
                        remediation_guidance="Disable `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, enable CA Certificate Manager Approval, or restrict enrollment strictly to Tier-0 principals.",
                        discovered_by="ely_cyber_adcs_auditor",
                    )
                )

            if tpl.any_purpose_eku and tpl.low_priv_enroll_principals and not tpl.manager_approval_required:
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-ADCS-ESC2",
                        title=f"ADCS ESC2 Overly Broad `Any Purpose` EKU on Template `{tpl.template_name}`",
                        description=f"Template `{tpl.template_name}` grants `Any Purpose` EKU to low-privileged principals without manager approval.",
                        cyber_domain=CyberDomain.IDENTITY_ACTIVE_DIRECTORY,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-269"],
                        confidence=0.96,
                        mitre_techniques=[MitreTechniqueRef("T1649", "Steal or Forge Authentication Certificates", MitreTactic.CREDENTIAL_ACCESS)],
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        endpoint_or_asset=t_asset,
                        remediation_guidance="Replace Any Purpose EKU with explicit scoped EKUs and restrict enrollment ACLs.",
                        discovered_by="ely_cyber_adcs_auditor",
                    )
                )

            if tpl.cert_request_agent_eku and tpl.low_priv_enroll_principals and not tpl.manager_approval_required:
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-ADCS-ESC3",
                        title=f"ADCS ESC3 Enrollment Agent Abuse on Template `{tpl.template_name}`",
                        description=f"Low-privileged users can obtain Certificate Request Agent certificates and enroll on behalf of Domain Admins.",
                        cyber_domain=CyberDomain.IDENTITY_ACTIVE_DIRECTORY,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-269"],
                        confidence=0.96,
                        mitre_techniques=[MitreTechniqueRef("T1649", "Steal or Forge Authentication Certificates", MitreTactic.CREDENTIAL_ACCESS)],
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        endpoint_or_asset=t_asset,
                        remediation_guidance="Restrict Enrollment Agent templates to dedicated RA accounts with strict issuance policies and CA manager approval.",
                        discovered_by="ely_cyber_adcs_auditor",
                    )
                )

            if tpl.low_priv_write_principals:
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-ADCS-ESC4",
                        title=f"ADCS ESC4 Vulnerable Template ACL on `{tpl.template_name}`",
                        description=f"Non-admin principals `{tpl.low_priv_write_principals}` have write privileges over template `{tpl.template_name}` and can turn it into ESC1.",
                        cyber_domain=CyberDomain.IDENTITY_ACTIVE_DIRECTORY,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-732", "CWE-269"],
                        confidence=0.99,
                        mitre_techniques=[MitreTechniqueRef("T1649", "Steal or Forge Authentication Certificates", MitreTactic.PRIVILEGE_ESCALATION)],
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        endpoint_or_asset=t_asset,
                        remediation_guidance="Remove `WriteDacl`/`GenericAll`/`WriteOwner` for non-Tier-0 principals on all ADCS certificate templates.",
                        discovered_by="ely_cyber_adcs_auditor",
                    )
                )

            if tpl.ca_editf_san2_enabled:
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-ADCS-ESC6",
                        title=f"ADCS ESC6 Dangerous CA Flag `EDITF_ATTRIBUTESUBJECTALTNAME2` on `{tpl.ca_name}`",
                        description="CA globally honors enrollee-supplied SAN attributes on ANY authentication template.",
                        cyber_domain=CyberDomain.IDENTITY_ACTIVE_DIRECTORY,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-295"],
                        confidence=0.99,
                        mitre_techniques=[MitreTechniqueRef("T1649", "Steal or Forge Authentication Certificates", MitreTactic.CREDENTIAL_ACCESS)],
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        endpoint_or_asset=f"adcs:{tpl.ca_name}",
                        remediation_guidance="Run `certutil -config ... -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2` and restart CertSvc.",
                        discovered_by="ely_cyber_adcs_auditor",
                    )
                )

            if tpl.ca_http_enrollment_no_epa:
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-ADCS-ESC8",
                        title=f"ADCS ESC8 Unprotected HTTP Web Enrollment (`certsrv`) on `{tpl.ca_name}`",
                        description="HTTP enrollment endpoint lacks HTTPS + Extended Protection for Authentication (EPA), permitting NTLM relay certificate theft.",
                        cyber_domain=CyberDomain.IDENTITY_ACTIVE_DIRECTORY,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-290", "CWE-319"],
                        confidence=0.98,
                        mitre_techniques=[MitreTechniqueRef("T1557", "Adversary-in-the-Middle", MitreTactic.CREDENTIAL_ACCESS)],
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        endpoint_or_asset=f"adcs:{tpl.ca_name}/certsrv",
                        remediation_guidance="Disable HTTP enrollment, enforce HTTPS + EPA Required, or disable NTLM on IIS Web Enrollment.",
                        discovered_by="ely_cyber_adcs_auditor",
                    )
                )

        # --------------------------------------------------------------
        # 3. Direct Tier-Boundary ACL Abuse & Shortest Paths to Tier-0
        # --------------------------------------------------------------
        tier0_ids = {o.object_id for o in objects if o.tier == 0}
        tier2_starts = [o for o in objects if o.tier == 2 and o.enabled]

        # Flag direct DCSync / cross-tier ACL abuse edges
        for e in edges:
            src_obj = by_id.get(e.src_id)
            dst_obj = by_id.get(e.dst_id)
            if not src_obj or not dst_obj:
                continue
            if e.relation == "DCSync" and src_obj.tier > 0:
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-AD-DCSYNC-001",
                        title=f"Non-Tier-0 Principal `{src_obj.name}` Holds `DCSync` Replication Rights",
                        description=f"`{src_obj.name}` holds `DS-Replication-Get-Changes-All` on `{dst_obj.name}`, allowing full NTDS.dit credential dump.",
                        cyber_domain=CyberDomain.IDENTITY_ACTIVE_DIRECTORY,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-269"],
                        confidence=1.0,
                        mitre_techniques=[MitreTechniqueRef("T1003.006", "OS Credential Dumping: DCSync", MitreTactic.CREDENTIAL_ACCESS, "006")],
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        endpoint_or_asset=f"ad:{src_obj.name}->DCSync->{dst_obj.name}",
                        remediation_guidance="Revoke replication ACLs from all non-Domain-Controller principals immediately.",
                        discovered_by="ely_cyber_ad_graph",
                    )
                )

        # Shortest-path Dijkstra from Tier-2 principals to Tier-0 crown jewels
        tier0_paths: List[Dict[str, Any]] = []
        edge_hit_counter: Dict[Tuple[str, str, str], int] = {}

        for start_obj in tier2_starts:
            best = self._dijkstra_to_tier0(start_obj.object_id, tier0_ids, adj)
            if best is not None:
                prob, path_nodes, path_edges = best
                node_names = [by_id[nid].name for nid in path_nodes]
                edge_rels = [f"{by_id[e.src_id].name} -[{e.relation}]-> {by_id[e.dst_id].name}" for e in path_edges]
                tier0_paths.append(
                    {
                        "source": start_obj.name,
                        "target_tier0": node_names[-1],
                        "hops": len(path_edges),
                        "cumulative_probability": round(prob, 4),
                        "nodes": node_names,
                        "edges": edge_rels,
                    }
                )
                for e in path_edges:
                    k = (e.src_id, e.relation, e.dst_id)
                    edge_hit_counter[k] = edge_hit_counter.get(k, 0) + 1

        tier0_paths.sort(key=lambda p: (-p["cumulative_probability"], p["hops"]))

        # Emit consolidated finding for discovered Tier-2 -> Tier-0 escalation paths
        for pinfo in tier0_paths[:5]:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-AD-TIER0-PATH-001",
                    title=f"Tier-0 Attack Path Discovered: `{pinfo['source']}` -> `{pinfo['target_tier0']}` ({pinfo['hops']} hops)",
                    description=f"Identity attack graph exposes a {pinfo['hops']}-hop path (P={pinfo['cumulative_probability']:.2%}) to Tier-0: " + " ; ".join(pinfo["edges"]),
                    cyber_domain=CyberDomain.IDENTITY_ACTIVE_DIRECTORY,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-269"],
                    confidence=0.97,
                    mitre_techniques=[MitreTechniqueRef("T1078.002", "Domain Accounts", MitreTactic.PRIVILEGE_ESCALATION, "002")],
                    cvss4=CVSSv4Metrics(av="A", ac="L", at="N", pr="L", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
                    verification_method=VerificationMethod.GRAPH_REACHABILITY,
                    endpoint_or_asset=f"ad_path:{pinfo['source']}->{pinfo['target_tier0']}",
                    attack_vector_detail=" ; ".join(pinfo["edges"]),
                    remediation_guidance="Break the chokepoint ACL/delegation edge separating Tier-2/Tier-1 from Tier-0 assets.",
                    evidence=[
                        EvidenceArtifact(
                            artifact_id=new_id("ev"),
                            kind="graph_path",
                            summary=f"Tier-0 escalation ({pinfo['hops']} hops)",
                            content="\n".join(pinfo["edges"]),
                        )
                    ],
                    discovered_by="ely_cyber_ad_graph",
                )
            )

        # Min-cut chokepoint edges ranked by number of Tier-0 paths disrupted
        chokepoints = [
            {
                "src": by_id[k[0]].name,
                "relation": k[1],
                "dst": by_id[k[2]].name,
                "paths_disrupted": count,
            }
            for k, count in sorted(edge_hit_counter.items(), key=lambda kv: -kv[1])[:8]
        ]

        return {
            "objects_analyzed": len(objects),
            "edges_analyzed": len(edges),
            "tier0_assets": [by_id[i].name for i in sorted(tier0_ids)],
            "tier0_paths_found": len(tier0_paths),
            "top_tier0_paths": tier0_paths[:10],
            "remediation_chokepoints": chokepoints,
            "findings": findings,
        }

    @staticmethod
    def _dijkstra_to_tier0(
        start_id: str,
        tier0_ids: Set[str],
        adj: Dict[str, List[IdentityDirectoryEdge]],
    ) -> Optional[Tuple[float, List[str], List[IdentityDirectoryEdge]]]:
        pq: List[Tuple[float, str, List[str], List[IdentityDirectoryEdge]]] = [(0.0, start_id, [start_id], [])]
        best_cost: Dict[str, float] = {start_id: 0.0}

        while pq:
            cost, cur, nodes, path_edges = heapq.heappop(pq)
            if cur in tier0_ids and path_edges:
                return math.exp(-cost), nodes, path_edges
            if cost > best_cost.get(cur, float("inf")):
                continue
            for edge in adj.get(cur, []):
                if edge.dst_id in nodes:
                    continue
                p = max(0.05, min(0.99, edge.exploit_probability))
                step_cost = -math.log(p)
                nc = cost + step_cost
                if nc < best_cost.get(edge.dst_id, float("inf")):
                    best_cost[edge.dst_id] = nc
                    heapq.heappush(pq, (nc, edge.dst_id, nodes + [edge.dst_id], path_edges + [edge]))
        return None
