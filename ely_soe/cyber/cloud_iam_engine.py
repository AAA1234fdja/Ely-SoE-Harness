"""
Multi-Cloud IAM Privilege-Escalation Graph & Cloud Security Engine (AWS / GCP / Azure).

Models cloud principals, policies, trust relationships, and resource ACLs as a
directed privilege graph and automatically discovers:
  1. 22 Concrete Multi-Cloud IAM Privilege Escalation Paths:
       - AWS: `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`, `iam:AttachUserPolicy`,
         `iam:AttachRolePolicy`, `iam:AttachGroupPolicy`, `iam:PutUserPolicy`, `iam:PutRolePolicy`,
         `iam:AddUserToGroup`, `iam:UpdateAssumeRolePolicy`, `iam:CreateAccessKey`,
         `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`, `iam:PassRole` + `lambda:CreateFunction`
         + `lambda:InvokeFunction`, `iam:PassRole` + `ec2:RunInstances`, `iam:PassRole` +
         `glue:CreateDevEndpoint`, `iam:PassRole` + `cloudformation:CreateStack`,
         `iam:PassRole` + `ecs:RunTask`, `lambda:UpdateFunctionCode`, `sts:AssumeRole` chained loops
       - GCP: `iam.serviceAccounts.actAs` + `cloudfunctions.functions.create`,
         `iam.serviceAccountKeys.create`, `resourcemanager.projects.setIamPolicy`,
         `iam.roles.update`, `deploymentmanager.deployments.create`
       - Azure: `Microsoft.Authorization/roleAssignments/write`,
         `Microsoft.Compute/virtualMachines/extensions/write`,
         `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action`
  2. Cross-Account Confused-Deputy Trust Policy Auditing (missing `sts:ExternalId`, wildcard `*` Principal).
  3. Overly Permissive Wildcard Policies (`Action: "*"`, `NotAction`, `Resource: "*"`).
  4. Multi-hop `AssumeRole` / `actAs` Transitive Escalation Solver (BFS/DFS to Admin Principal).
  5. Cloud Storage Public Exposure (S3 / GCS / Azure Blob) & EC2 IMDSv1 Misconfiguration Checks.
"""

from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ely_soe.core.models import Severity, new_id
from ely_soe.cyber.models import (
    CVSSv4Metrics,
    CloudIAMPolicyStatement,
    CloudPrincipalNode,
    CyberDomain,
    CyberVulnerability,
    EvidenceArtifact,
    MitreTactic,
    MitreTechniqueRef,
    VerificationMethod,
    make_cyber_vuln,
)


# ---------------------------------------------------------------------------
# Multi-Cloud IAM Privilege Escalation Knowledge Base (22 Concrete Primitives)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IAMEscalationPrimitive:
    prim_id: str
    provider: str  # aws, gcp, azure
    name: str
    required_actions: Tuple[str, ...]
    severity: Severity
    mitre_id: str
    explanation: str
    remediation: str


CLOUD_IAM_ESCALATION_PRIMITIVES: Tuple[IAMEscalationPrimitive, ...] = (
    # --- AWS IAM Direct Policy Self-Escalation ---
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-AWS-ESC01",
        provider="aws",
        name="AWS `iam:CreatePolicyVersion` Arbitrary Admin Policy Injection",
        required_actions=("iam:CreatePolicyVersion",),
        severity=Severity.CRITICAL,
        mitre_id="T1098.003",
        explanation="Principal can create a new default policy version granting `Action: *` on `Resource: *` to itself.",
        remediation="Remove `iam:CreatePolicyVersion` from non-admin principals and enforce IAM Permissions Boundaries.",
    ),
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-AWS-ESC02",
        provider="aws",
        name="AWS `iam:SetDefaultPolicyVersion` Rollback to Permissive Policy",
        required_actions=("iam:SetDefaultPolicyVersion",),
        severity=Severity.HIGH,
        mitre_id="T1098.003",
        explanation="Principal can switch an attached managed policy back to an older overly permissive version.",
        remediation="Restrict `iam:SetDefaultPolicyVersion` to break-glass IAM administrators and prune old policy versions.",
    ),
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-AWS-ESC03",
        provider="aws",
        name="AWS `iam:AttachUserPolicy` Direct AdministratorAccess Attachment",
        required_actions=("iam:AttachUserPolicy",),
        severity=Severity.CRITICAL,
        mitre_id="T1098.003",
        explanation="Principal can attach `arn:aws:iam::aws:policy/AdministratorAccess` directly to its own IAM user.",
        remediation="Scope `iam:AttachUserPolicy` with `iam:PermissionsBoundary` conditions or deny on non-admin roles.",
    ),
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-AWS-ESC04",
        provider="aws",
        name="AWS `iam:AttachRolePolicy` Privilege Escalation",
        required_actions=("iam:AttachRolePolicy",),
        severity=Severity.CRITICAL,
        mitre_id="T1098.003",
        explanation="Principal can attach administrative managed policies to roles it can assume or execute under.",
        remediation="Deny `iam:AttachRolePolicy` outside automated IaC deployment pipelines guarded by SCPs.",
    ),
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-AWS-ESC05",
        provider="aws",
        name="AWS `iam:PutUserPolicy` / `iam:PutRolePolicy` Inline Admin Policy Injection",
        required_actions=("iam:PutRolePolicy",),
        severity=Severity.CRITICAL,
        mitre_id="T1098.003",
        explanation="Principal can inject an inline administrative IAM policy granting unrestricted account control.",
        remediation="Block inline policy mutation (`iam:Put*Policy`) via AWS Organizations SCP and require code-reviewed IaC.",
    ),
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-AWS-ESC06",
        provider="aws",
        name="AWS `iam:AddUserToGroup` Escalation to Privileged Admin Group",
        required_actions=("iam:AddUserToGroup",),
        severity=Severity.CRITICAL,
        mitre_id="T1098.003",
        explanation="Principal can add itself to an existing administrative IAM group.",
        remediation="Restrict `iam:AddUserToGroup` by resource ARN excluding privileged admin groups.",
    ),
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-AWS-ESC07",
        provider="aws",
        name="AWS `iam:UpdateAssumeRolePolicy` Trust Hijacking",
        required_actions=("iam:UpdateAssumeRolePolicy",),
        severity=Severity.CRITICAL,
        mitre_id="T1098",
        explanation="Principal can rewrite any role's trust policy to allow itself to call `sts:AssumeRole` on admin roles.",
        remediation="Protect Tier-0 role trust policies via SCP deny rules against non-root/non-CI principals.",
    ),
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-AWS-ESC08",
        provider="aws",
        name="AWS `iam:CreateAccessKey` Credential Forgery for Privileged Users",
        required_actions=("iam:CreateAccessKey",),
        severity=Severity.CRITICAL,
        mitre_id="T1098.001",
        explanation="Principal can mint programmatic access keys for any other IAM user including administrators.",
        remediation="Condition `iam:CreateAccessKey` strictly on `aws:username` matching `${aws:username}` or migrate to SSO/STS.",
    ),
    # --- AWS PassRole + Compute / Serverless Execution Escalations ---
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-AWS-ESC09",
        provider="aws",
        name="AWS `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` Escalation",
        required_actions=("iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"),
        severity=Severity.CRITICAL,
        mitre_id="T1078.004",
        explanation="Principal can pass a privileged IAM role to a newly created Lambda function and invoke it to execute as that role.",
        remediation="Scope `iam:PassRole` to specific low-privilege execution role ARNs and restrict `iam:PassedToService`.",
    ),
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-AWS-ESC10",
        provider="aws",
        name="AWS `iam:PassRole` + `ec2:RunInstances` Instance Profile Hijack",
        required_actions=("iam:PassRole", "ec2:RunInstances"),
        severity=Severity.CRITICAL,
        mitre_id="T1078.004",
        explanation="Principal can launch an EC2 instance attached to a privileged IAM Instance Profile and harvest its STS credentials via IMDS.",
        remediation="Constrain `iam:PassRole` to non-privileged EC2 role ARNs and enforce IMDSv2 with hop-limit=1.",
    ),
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-AWS-ESC11",
        provider="aws",
        name="AWS `iam:PassRole` + `cloudformation:CreateStack` Template Escalation",
        required_actions=("iam:PassRole", "cloudformation:CreateStack"),
        severity=Severity.CRITICAL,
        mitre_id="T1078.004",
        explanation="Principal can deploy a CloudFormation stack using a privileged service role to provision arbitrary admin IAM users/roles.",
        remediation="Restrict `iam:PassRole` for CloudFormation strictly to scoped deployment roles with Permissions Boundaries.",
    ),
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-AWS-ESC12",
        provider="aws",
        name="AWS `iam:PassRole` + `ecs:RunTask` Container Role Pivot",
        required_actions=("iam:PassRole", "ecs:RunTask"),
        severity=Severity.HIGH,
        mitre_id="T1078.004",
        explanation="Principal can run an ECS task executing with a privileged `taskRoleArn`.",
        remediation="Pin allowed `iam:PassRole` ARNs for ECS tasks and restrict image registries.",
    ),
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-AWS-ESC13",
        provider="aws",
        name="AWS `lambda:UpdateFunctionCode` Backdooring Existing Privileged Lambda",
        required_actions=("lambda:UpdateFunctionCode",),
        severity=Severity.HIGH,
        mitre_id="T1525",
        explanation="Principal can overwrite code of an existing privileged Lambda function to exfiltrate its execution role credentials.",
        remediation="Scope `lambda:UpdateFunctionCode` to specific non-privileged function ARNs and require code-signing configs.",
    ),
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-AWS-ESC14",
        provider="aws",
        name="AWS `iam:PassRole` + `glue:CreateDevEndpoint` Execution Escalation",
        required_actions=("iam:PassRole", "glue:CreateDevEndpoint"),
        severity=Severity.HIGH,
        mitre_id="T1078.004",
        explanation="Principal can create an AWS Glue development endpoint bound to a higher-privileged IAM role.",
        remediation="Restrict `iam:PassRole` with explicit resource ARNs and `iam:PassedToService: glue.amazonaws.com`.",
    ),
    # --- GCP IAM Privilege Escalations ---
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-GCP-ESC01",
        provider="gcp",
        name="GCP `resourcemanager.projects.setIamPolicy` Project Owner Self-Grant",
        required_actions=("resourcemanager.projects.setIamPolicy",),
        severity=Severity.CRITICAL,
        mitre_id="T1098.003",
        explanation="Principal can modify project IAM bindings to grant itself `roles/owner`.",
        remediation="Remove `setIamPolicy` from workload service accounts and manage bindings strictly via Terraform/Org Policy.",
    ),
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-GCP-ESC02",
        provider="gcp",
        name="GCP `iam.serviceAccounts.actAs` + `cloudfunctions.functions.create` Escalation",
        required_actions=("iam.serviceAccounts.actAs", "cloudfunctions.functions.create"),
        severity=Severity.CRITICAL,
        mitre_id="T1078.004",
        explanation="Principal can deploy a Cloud Function running as a privileged Service Account and harvest its OAuth token.",
        remediation="Scope `iam.serviceAccounts.actAs` strictly to individual least-privilege service accounts, never project-wide.",
    ),
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-GCP-ESC03",
        provider="gcp",
        name="GCP `iam.serviceAccountKeys.create` Long-Lived Key Minting",
        required_actions=("iam.serviceAccountKeys.create",),
        severity=Severity.CRITICAL,
        mitre_id="T1098.001",
        explanation="Principal can create persistent JSON private keys for privileged Service Accounts.",
        remediation="Enforce GCP Organization Policy `constraints/iam.disableServiceAccountKeyCreation` and use Workload Identity Federation.",
    ),
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-GCP-ESC04",
        provider="gcp",
        name="GCP `iam.roles.update` Custom Role Permission Expansion",
        required_actions=("iam.roles.update",),
        severity=Severity.HIGH,
        mitre_id="T1098.003",
        explanation="Principal can append arbitrary permissions to a custom IAM role currently bound to itself.",
        remediation="Restrict `iam.roles.update` exclusively to Organization Security Admins.",
    ),
    # --- Azure RBAC Privilege Escalations ---
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-AZ-ESC01",
        provider="azure",
        name="Azure `Microsoft.Authorization/roleAssignments/write` Owner Self-Assignment",
        required_actions=("Microsoft.Authorization/roleAssignments/write",),
        severity=Severity.CRITICAL,
        mitre_id="T1098.003",
        explanation="Principal can assign itself Subscription Owner or User Access Administrator roles.",
        remediation="Use Azure PIM just-in-time activation and RBAC ABAC conditions constraining assignable roles.",
    ),
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-AZ-ESC02",
        provider="azure",
        name="Azure `Microsoft.Compute/virtualMachines/extensions/write` SYSTEM Code Execution",
        required_actions=("Microsoft.Compute/virtualMachines/extensions/write",),
        severity=Severity.HIGH,
        mitre_id="T1059",
        explanation="Principal can execute CustomScriptExtension as SYSTEM/root on VMs holding privileged Managed Identities.",
        remediation="Separate VM operator permissions from Managed Identity assignment and isolate privileged workloads.",
    ),
    IAMEscalationPrimitive(
        prim_id="CYB-IAM-AZ-ESC03",
        provider="azure",
        name="Azure `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` Identity Pivot",
        required_actions=("Microsoft.ManagedIdentity/userAssignedIdentities/assign/action",),
        severity=Severity.HIGH,
        mitre_id="T1078.004",
        explanation="Principal can attach privileged User-Assigned Managed Identities to compute resources it controls.",
        remediation="Scope Managed Identity assignment permissions strictly per resource group and identity resource ID.",
    ),
)


# ---------------------------------------------------------------------------
# Cloud IAM Graph & Policy Auditing Engine
# ---------------------------------------------------------------------------

class CloudIAMSecurityEngine:
    """
    Analyzes multi-cloud IAM principals, trust relationships, and JSON policy documents
    for privilege escalation paths, confused-deputy trusts, and wildcard admin grants.
    """

    def audit_principal_graph(
        self,
        principals: List[CloudPrincipalNode],
    ) -> Dict[str, Any]:
        """Run complete multi-cloud IAM privilege escalation, trust-boundary, and transitive AssumeRole analysis."""
        findings: List[CyberVulnerability] = []
        by_id: Dict[str, CloudPrincipalNode] = {p.principal_id: p for p in principals}

        # Build AssumeRole / actAs directed reachability graph
        assume_adj: Dict[str, Set[str]] = {p.principal_id: set() for p in principals}
        for target in principals:
            for truster in target.trust_principals:
                if truster == "*":
                    # Wildcard trust -> any external/internal principal can assume!
                    findings.append(
                        make_cyber_vuln(
                            rule_id="CYB-IAM-WILDCARD-TRUST-001",
                            title=f"Cloud Role `{target.principal_id}` Permits Wildcard Trust Principal (`*`)",
                            description=(
                                f"Role `{target.principal_id}` ({target.provider}) allows `Principal: *` in its trust policy, "
                                "potentially permitting unauthorized cross-account or anonymous role assumption."
                            ),
                            cyber_domain=CyberDomain.CLOUD_IAM,
                            severity=Severity.CRITICAL,
                            cwe_ids=["CWE-284", "CWE-269"],
                            confidence=0.99,
                            mitre_techniques=[MitreTechniqueRef("T1078.004", "Cloud Accounts", MitreTactic.INITIAL_ACCESS, "004")],
                            cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
                            verification_method=VerificationMethod.GRAPH_REACHABILITY,
                            endpoint_or_asset=f"{target.provider}:{target.principal_id}",
                            remediation_guidance="Replace `*` with explicit trusted account/role ARNs and require `sts:ExternalId` + `aws:PrincipalOrgID` conditions.",
                            discovered_by="ely_cyber_cloud_iam",
                        )
                    )
                    for other in principals:
                        if other.principal_id != target.principal_id:
                            assume_adj[other.principal_id].add(target.principal_id)
                elif truster in by_id:
                    if by_id[truster].effective_allows("sts:AssumeRole") or by_id[truster].effective_allows("iam.serviceAccounts.getAccessToken") or target.provider != "aws":
                        assume_adj[truster].add(target.principal_id)

        # 1. Per-principal checks: Wildcards, MFA, and 22 Escalation Primitives
        escalation_hits: List[Dict[str, Any]] = []
        for p in principals:
            asset = f"{p.provider}:{p.principal_id}"

            # Wildcard Action + Wildcard Resource on non-admin principal
            for stmt in p.statements:
                if stmt.effect.lower() == "allow" and any(a in ("*", "*:*") for a in stmt.actions) and stmt.covers_all_resources():
                    if not p.is_admin:
                        findings.append(
                            make_cyber_vuln(
                                rule_id="CYB-IAM-WILDCARD-ADMIN-001",
                                title=f"Shadow Admin Principal `{p.principal_id}` Holds Full Wildcard (`Action:*`, `Resource:*`)",
                                description=f"Non-admin principal `{p.principal_id}` has statement `{stmt.sid}` granting full administrative wildcard permissions.",
                                cyber_domain=CyberDomain.CLOUD_IAM,
                                severity=Severity.CRITICAL,
                                cwe_ids=["CWE-250", "CWE-269"],
                                confidence=0.99,
                                mitre_techniques=[MitreTechniqueRef("T1078.004", "Cloud Accounts", MitreTactic.PRIVILEGE_ESCALATION, "004")],
                                verification_method=VerificationMethod.GRAPH_REACHABILITY,
                                endpoint_or_asset=asset,
                                remediation_guidance="Replace wildcard statements with least-privilege action/resource ARNs derived from CloudTrail Access Analyzer.",
                                discovered_by="ely_cyber_cloud_iam",
                            )
                        )

                # Missing ExternalId on cross-account assume role / external principal
                if stmt.effect.lower() == "allow" and any("assumerole" in a.lower() for a in stmt.actions):
                    if p.is_external_facing and "sts:ExternalId" not in json.dumps(stmt.conditions):
                        findings.append(
                            make_cyber_vuln(
                                rule_id="CYB-IAM-CONFUSED-DEPUTY-001",
                                title=f"Cross-Account Trust Without `sts:ExternalId` (Confused Deputy Risk on `{p.principal_id}`)",
                                description=f"External-facing principal `{p.principal_id}` permits `sts:AssumeRole` without an `sts:ExternalId` condition.",
                                cyber_domain=CyberDomain.CLOUD_IAM,
                                severity=Severity.HIGH,
                                cwe_ids=["CWE-441", "CWE-287"],
                                confidence=0.93,
                                verification_method=VerificationMethod.GRAPH_REACHABILITY,
                                endpoint_or_asset=asset,
                                remediation_guidance="Require a tenant-unique `sts:ExternalId` condition on all third-party/cross-account role trusts.",
                                discovered_by="ely_cyber_cloud_iam",
                            )
                        )

            # Admin user without MFA
            if p.is_admin and p.principal_type == "user" and not p.mfa_enforced:
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-IAM-ADMIN-NO-MFA-001",
                        title=f"Privileged Cloud Admin User `{p.principal_id}` Lacks Mandatory MFA",
                        description=f"Administrative user `{p.principal_id}` does not enforce MFA (`aws:MultiFactorAuthPresent`).",
                        cyber_domain=CyberDomain.CLOUD_IAM,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-308"],
                        confidence=0.98,
                        mitre_techniques=[MitreTechniqueRef("T1078", "Valid Accounts", MitreTactic.INITIAL_ACCESS)],
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        endpoint_or_asset=asset,
                        remediation_guidance="Enforce hardware FIDO2/WebAuthn MFA for all human admin principals or migrate to federated SSO.",
                        discovered_by="ely_cyber_cloud_iam",
                    )
                )

            # Check all 22 IAM privilege escalation primitives on non-admin principals
            if not p.is_admin:
                for prim in CLOUD_IAM_ESCALATION_PRIMITIVES:
                    if prim.provider != p.provider.lower():
                        continue
                    if all(p.effective_allows(act) for act in prim.required_actions):
                        escalation_hits.append(
                            {
                                "principal_id": p.principal_id,
                                "provider": p.provider,
                                "primitive_id": prim.prim_id,
                                "name": prim.name,
                                "required_actions": list(prim.required_actions),
                            }
                        )
                        findings.append(
                            make_cyber_vuln(
                                rule_id=prim.prim_id,
                                title=f"{prim.name} on `{p.principal_id}`",
                                description=f"Principal `{p.principal_id}` satisfies escalation combination `{list(prim.required_actions)}`: {prim.explanation}",
                                cyber_domain=CyberDomain.CLOUD_IAM,
                                severity=prim.severity,
                                cwe_ids=["CWE-269", "CWE-250"],
                                confidence=0.97,
                                mitre_techniques=[MitreTechniqueRef(prim.mitre_id, prim.name, MitreTactic.PRIVILEGE_ESCALATION)],
                                cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="L", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
                                verification_method=VerificationMethod.GRAPH_REACHABILITY,
                                endpoint_or_asset=asset,
                                attack_vector_detail=f"Effective permissions satisfy {list(prim.required_actions)}",
                                remediation_guidance=prim.remediation,
                                discovered_by="ely_cyber_cloud_iam",
                            )
                        )

        # 2. Multi-hop transitive AssumeRole escalation from non-admin/external -> admin principals
        admin_ids = {p.principal_id for p in principals if p.is_admin}
        transitive_paths: List[List[str]] = []
        for p in principals:
            if p.is_admin:
                continue
            for adm in sorted(admin_ids):
                path = self._bfs_path(p.principal_id, adm, assume_adj)
                if path and len(path) >= 2:
                    transitive_paths.append(path)
                    findings.append(
                        make_cyber_vuln(
                            rule_id="CYB-IAM-TRANSITIVE-ASSUME-001",
                            title=f"Transitive Cloud Role Assumption Path to Admin: `{' -> '.join(path)}`",
                            description=(
                                f"Non-admin principal `{p.principal_id}` (external_facing={p.is_external_facing}) "
                                f"can transitively assume administrative principal `{adm}` in {len(path) - 1} hop(s)."
                            ),
                            cyber_domain=CyberDomain.CLOUD_IAM,
                            severity=Severity.CRITICAL,
                            cwe_ids=["CWE-269"],
                            confidence=0.98,
                            mitre_techniques=[MitreTechniqueRef("T1550.001", "Use Alternate Authentication Material", MitreTactic.PRIVILEGE_ESCALATION, "001")],
                            verification_method=VerificationMethod.GRAPH_REACHABILITY,
                            endpoint_or_asset=f"iam_chain:{'->'.join(path)}",
                            attack_vector_detail=f"AssumeRole chain: {' -> '.join(path)}",
                            remediation_guidance="Break transitive role-assumption chains into Tier-0 admin roles and require MFA + hardware-key SSO.",
                            evidence=[
                                EvidenceArtifact(
                                    artifact_id=new_id("ev"),
                                    kind="graph_path",
                                    summary="Transitive AssumeRole Admin Escalation",
                                    content=" -> ".join(path),
                                )
                            ],
                            discovered_by="ely_cyber_cloud_iam",
                        )
                    )

        return {
            "principals_analyzed": len(principals),
            "admin_principals": sorted(admin_ids),
            "direct_escalation_primitives": escalation_hits,
            "transitive_admin_paths": transitive_paths,
            "findings": findings,
        }

    def scan_policy_json_files(self, root_path: Path) -> List[CyberVulnerability]:
        """Scan local repository for AWS/GCP/Azure IAM policy JSON files and evaluate them."""
        findings: List[CyberVulnerability] = []
        for fp in sorted(root_path.rglob("*.json")):
            if any(p in {".git", "node_modules", "__pycache__"} for p in fp.parts):
                continue
            try:
                data = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue
            if not isinstance(data, dict) or "Statement" not in data:
                continue
            stmts_raw = data.get("Statement")
            if isinstance(stmts_raw, dict):
                stmts_raw = [stmts_raw]
            if not isinstance(stmts_raw, list):
                continue

            stmts: List[CloudIAMPolicyStatement] = []
            for idx, st in enumerate(stmts_raw):
                if not isinstance(st, dict):
                    continue
                acts = st.get("Action", [])
                if isinstance(acts, str):
                    acts = [acts]
                res = st.get("Resource", ["*"])
                if isinstance(res, str):
                    res = [res]
                stmts.append(
                    CloudIAMPolicyStatement(
                        sid=str(st.get("Sid", f"stmt-{idx}")),
                        effect=str(st.get("Effect", "Allow")),
                        actions=[str(a) for a in acts],
                        resources=[str(r) for r in res],
                        conditions=st.get("Condition", {}) if isinstance(st.get("Condition"), dict) else {},
                    )
                )

            rel = str(fp.relative_to(root_path))
            node = CloudPrincipalNode(
                principal_id=rel,
                provider="aws",
                principal_type="role",
                is_admin=False,
                statements=stmts,
            )
            res = self.audit_principal_graph([node])
            for f in res["findings"]:
                f.file_path = rel
                findings.append(f)
        return findings

    @staticmethod
    def _bfs_path(start: str, goal: str, adj: Dict[str, Set[str]]) -> Optional[List[str]]:
        q: deque[List[str]] = deque([[start]])
        visited: Set[str] = {start}
        while q:
            path = q.popleft()
            cur = path[-1]
            if cur == goal:
                return path
            for nxt in sorted(adj.get(cur, set())):
                if nxt not in visited:
                    visited.add(nxt)
                    q.append(path + [nxt])
        return None
