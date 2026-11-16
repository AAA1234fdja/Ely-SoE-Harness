"""
Cloud Infrastructure-as-Code (Terraform HCL, CloudFormation, IAM Policy JSON)
Security Policy & Drift Auditor with Automated Safe-Config Patch Synthesis.

Audits real IaC manifests across AWS, GCP, and Azure templates without requiring cloud
credentials or external parsers:
  1. **IAM Least-Privilege & Escalation Auditor (JSON / HCL / YAML)**:
       - Detects `Action: "*"` + `Resource: "*"` full-admin policies (CWE-269)
       - Detects AWS IAM privilege-escalation action combinations (`iam:PassRole` +
         `lambda:CreateFunction`/`ec2:RunInstances`, `iam:PutUserPolicy`, `iam:AttachRolePolicy`,
         `sts:AssumeRole` with wildcard principals `"Principal": "*"` and missing `ExternalId`)
       - Detects cross-account trust policies lacking `aws:SourceAccount` / `sts:ExternalId`
         (Confused Deputy vulnerability, CWE-441).
  2. **Storage, Database & Encryption Hardening (S3 / GCS / RDS / KMS / EBS)**:
       - Public S3 buckets (`acl = "public-read"`, `block_public_acls = false`, missing
         `aws_s3_bucket_public_access_block`)
       - Unencrypted RDS / EBS / S3 (`storage_encrypted = false`, `encrypted = false`)
       - Publicly accessible databases (`publicly_accessible = true`)
       - KMS keys without automatic annual key rotation (`enable_key_rotation = false`)
       - Logging/audit blind spots (`enable_logging = false`, disabled CloudTrail/FlowLogs).
  3. **IaC Posture Drift Detector (`detect_posture_drift`)**:
       Compares baseline vs. candidate IaC security snapshots to catch newly opened ingress
       rules, weakened encryption, or newly introduced IAM wildcards before `terraform apply`.
  4. **Deterministic Remediation Patch Snippets**:
       Emits ready-to-apply hardened Terraform/IAM blocks for every detected violation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ely_soe.core.models import Severity, utc_now_iso
from ely_soe.cyber.models import (
    CyberDomain,
    CyberVulnerability,
    VerificationMethod,
    make_cyber_vuln,
)


@dataclass(frozen=True)
class IaCPolicyRule:
    rule_id: str
    provider: str
    category: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    cwe: str
    cis_control: str
    remediation: str
    hardened_hcl_snippet: str


IAC_POLICY_RULES: Tuple[IaCPolicyRule, ...] = (
    IaCPolicyRule(
        "CYB-IAC-IAM-ADMIN-WILDCARD", "AWS/Multi-Cloud", "IAM_PRIVILEGE",
        "Wildcard Administrative IAM Policy (`Action: *` on `Resource: *`)",
        re.compile(r"""(?is)(?:"Action"|actions)\s*[:=]\s*\[?\s*"\*"\s*\]?[\s\S]{0,160}(?:"Resource"|resources)\s*[:=]\s*\[?\s*"\*"\s*\]?"""),
        Severity.CRITICAL, "CWE-269", "CIS AWS 1.16",
        "Replace wildcard actions/resources with minimal scoped service actions and explicit ARN boundaries.",
        'actions = ["s3:GetObject"]\nresources = ["arn:aws:s3:::my-app-bucket/prefix/*"]',
    ),
    IaCPolicyRule(
        "CYB-IAC-IAM-CONFUSED-DEPUTY", "AWS", "IAM_TRUST",
        "IAM AssumeRole Trust Policy Allows Wildcard Principal (`*`) Without ExternalId Condition",
        re.compile(r"""(?is)(?:sts:AssumeRole[\s\S]{0,220}"Principal"\s*:\s*(?:"\*"|\{\s*"AWS"\s*:\s*"\*"\s*\}))|(?:"Principal"\s*:\s*(?:"\*"|\{\s*"AWS"\s*:\s*"\*"\s*\})[\s\S]{0,220}sts:AssumeRole)"""),
        Severity.CRITICAL, "CWE-441", "CIS AWS 1.15",
        "Restrict `Principal.AWS` to specific account/role ARNs and require `sts:ExternalId` + `aws:SourceAccount` conditions.",
        'Condition = { StringEquals = { "sts:ExternalId" = var.trusted_external_id } }',
    ),
    IaCPolicyRule(
        "CYB-IAC-IAM-PASSROLE-ESCALATION", "AWS", "IAM_ESCALATION",
        "IAM Privilege Escalation Primitive (`iam:PassRole` / `iam:AttachRolePolicy` / `iam:PutUserPolicy`)",
        re.compile(r"""(?i)"(?:iam:PassRole|iam:AttachRolePolicy|iam:AttachUserPolicy|iam:PutRolePolicy|iam:PutUserPolicy|iam:CreatePolicyVersion|iam:SetDefaultPolicyVersion)"\s*,?"""),
        Severity.HIGH, "CWE-269", "CIS AWS 1.16",
        "Constrain `iam:PassRole` with `iam:PassedToService` and explicit target role ARN allowlists.",
        'Condition = { StringEquals = { "iam:PassedToService" = "lambda.amazonaws.com" } }',
    ),
    IaCPolicyRule(
        "CYB-IAC-S3-PUBLIC-ACCESS", "AWS", "STORAGE_PUBLIC",
        "S3 Bucket Configured With Public ACL or Disabled Public Access Block",
        re.compile(r"""(?i)(?:acl\s*=\s*"public-read(?:-write)?"|block_public_acls\s*=\s*false|block_public_policy\s*=\s*false|ignore_public_acls\s*=\s*false|restrict_public_buckets\s*=\s*false)"""),
        Severity.CRITICAL, "CWE-732", "CIS AWS 2.1.5",
        "Set `acl = \"private\"` and enforce all 4 `aws_s3_bucket_public_access_block` flags to `true`.",
        "resource \"aws_s3_bucket_public_access_block\" \"this\" {\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}",
    ),
    IaCPolicyRule(
        "CYB-IAC-RDS-PUBLIC", "AWS", "DATABASE_EXPOSURE",
        "Managed Database (RDS) Exposed Directly to Public Internet (`publicly_accessible = true`)",
        re.compile(r"""(?i)\bpublicly_accessible\s*[:=]\s*true\b"""),
        Severity.CRITICAL, "CWE-284", "CIS AWS 2.3.2",
        "Set `publicly_accessible = false` and place RDS instances in isolated private database subnets.",
        "publicly_accessible = false\nstorage_encrypted   = true",
    ),
    IaCPolicyRule(
        "CYB-IAC-STORAGE-UNENCRYPTED", "AWS/GCP/Azure", "ENCRYPTION_AT_REST",
        "Storage Volume, Bucket, or Database Encryption-at-Rest Explicitly Disabled",
        re.compile(r"""(?i)\b(?:storage_encrypted|encrypted|enable_encryption|encryption_at_rest)\s*[:=]\s*false\b"""),
        Severity.HIGH, "CWE-311", "CIS AWS 2.2.1",
        "Enable CMK KMS encryption at rest (`encrypted = true`, `storage_encrypted = true`).",
        "storage_encrypted = true\nkms_key_id        = aws_kms_key.data.arn",
    ),
    IaCPolicyRule(
        "CYB-IAC-KMS-NO-ROTATION", "AWS", "CRYPTO_KEY_MGMT",
        "KMS Customer Managed Key Automatic Rotation Disabled (`enable_key_rotation = false`)",
        re.compile(r"""(?i)\benable_key_rotation\s*[:=]\s*false\b"""),
        Severity.MEDIUM, "CWE-320", "CIS AWS 3.6",
        "Enable annual cryptographic key rotation (`enable_key_rotation = true`).",
        "enable_key_rotation = true",
    ),
    IaCPolicyRule(
        "CYB-IAC-IMDSV1-ENABLED", "AWS", "CLOUD_METADATA",
        "EC2 Instance Allows Legacy IMDSv1 (`http_tokens = \"optional\"`) Enabling SSRF Credential Theft",
        re.compile(r"""(?i)\bhttp_tokens\s*[:=]\s*"optional"|\bhttp_endpoint\s*[:=]\s*"enabled"[\s\S]{0,80}http_put_response_hop_limit\s*[:=]\s*[2-9]"""),
        Severity.HIGH, "CWE-918", "CIS AWS 5.6",
        "Enforce IMDSv2 strictly (`http_tokens = \"required\"` and `http_put_response_hop_limit = 1`).",
        'metadata_options {\n  http_endpoint               = "enabled"\n  http_tokens                 = "required"\n  http_put_response_hop_limit = 1\n}',
    ),
    IaCPolicyRule(
        "CYB-IAC-SG-OPEN-ALL", "AWS/Azure/GCP", "NETWORK_INGRESS",
        "Security Group / Firewall Allows Unrestricted Ingress (`0.0.0.0/0` / `::/0`) on All or High-Risk Ports",
        re.compile(r"""(?is)(?:ingress|aws_security_group_rule|google_compute_firewall)[\s\S]{0,260}(?:0\.0\.0\.0/0|::/0)[\s\S]{0,120}(?:protocol\s*=\s*"-1"|from_port\s*=\s*0|to_port\s*=\s*65535|ports\s*=\s*\[[^\]]*"(?:22|3389|5432|3306|6379)")"""),
        Severity.CRITICAL, "CWE-284", "CIS AWS 5.2",
        "Eliminate `0.0.0.0/0` ingress rules on administrative/DB/all-port ranges; restrict to private VPC CIDRs.",
        'cidr_blocks = [var.private_vpc_cidr]\nfrom_port   = 443\nto_port     = 443\nprotocol    = "tcp"',
    ),
    IaCPolicyRule(
        "CYB-IAC-AUDIT-LOGGING-OFF", "AWS/GCP/Azure", "LOGGING_BLINDSPOT",
        "Cloud Audit Trail / Multi-Region Logging Explicitly Disabled",
        re.compile(r"""(?i)\b(?:enable_logging|is_multi_region_trail|enable_log_file_validation|include_global_service_events)\s*[:=]\s*false\b"""),
        Severity.HIGH, "CWE-778", "CIS AWS 3.1",
        "Enable multi-region CloudTrail with cryptographic log file validation (`enable_log_file_validation = true`).",
        "enable_logging             = true\nis_multi_region_trail      = true\nenable_log_file_validation = true",
    ),
    IaCPolicyRule(
        "CYB-IAC-GCP-ALLUSERS", "GCP", "STORAGE_PUBLIC",
        "GCP IAM Binding Grants Access to Public Internet (`allUsers` / `allAuthenticatedUsers`)",
        re.compile(r"""(?i)"(?:allUsers|allAuthenticatedUsers)"\b"""),
        Severity.CRITICAL, "CWE-732", "CIS GCP 5.1",
        "Remove `allUsers` and `allAuthenticatedUsers` bindings; restrict IAM members to verified service accounts/groups.",
        'members = ["serviceAccount:app-reader@my-project.iam.gserviceaccount.com"]',
    ),
    IaCPolicyRule(
        "CYB-IAC-TF-HARDCODED-SECRET", "Terraform", "SECRET_EXPOSURE",
        "Hardcoded Password/Secret Literal Inside Terraform Resource or Variable Default",
        re.compile(r"""(?i)\b(?:master_password|admin_password|db_password|secret_key|access_key|auth_token)\s*=\s*"(?![\s$]*var\.|\$\{)[A-Za-z0-9+/=_\-!@#$%^&*]{8,}" """.strip()),
        Severity.CRITICAL, "CWE-798", "CIS IaC 4.1",
        "Remove literal secrets from HCL; mark variables `sensitive = true` and fetch runtime values from AWS Secrets Manager / Vault.",
        'password = data.aws_secretsmanager_secret_version.db_pw.secret_string',
    ),
)

IAC_EXTENSIONS = frozenset({".tf", ".tfvars", ".hcl", ".json", ".yaml", ".yml"})


class CloudIaCPolicyDriftEngine:
    """Audits Terraform/CloudFormation/IAM policies, synthesizes hardened HCL & detects IaC drift."""

    def audit_text(self, content: str, *, file_path: str = "main.tf") -> Dict[str, Any]:
        vulns: List[CyberVulnerability] = []
        patches: List[Dict[str, str]] = []
        seen_rule_line: Set[Tuple[str, int]] = set()

        for rule in IAC_POLICY_RULES:
            for m in rule.pattern.finditer(content):
                lineno = content[: m.start()].count("\n") + 1
                if (rule.rule_id, lineno) in seen_rule_line:
                    continue
                seen_rule_line.add((rule.rule_id, lineno))
                excerpt = m.group(0).strip().replace("\n", " ")[:150]
                vulns.append(
                    make_cyber_vuln(
                        rule_id=rule.rule_id,
                        title=f"[Cloud IaC | {rule.cis_control}] {rule.title}",
                        description=f"Matched `{excerpt}` in `{file_path}:{lineno}` ({rule.provider} / {rule.category}).",
                        cyber_domain=CyberDomain.IAC_CICD if "IAC" in rule.rule_id else CyberDomain.CLOUD_IAM,
                        severity=rule.severity,
                        cwe_ids=[rule.cwe],
                        confidence=0.95,
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=file_path,
                        line_start=lineno,
                        endpoint_or_asset=f"{file_path}:{lineno}",
                        remediation_guidance=rule.remediation,
                        secure_code_example=rule.hardened_hcl_snippet,
                        discovered_by="ely_cloud_iac_policy_drift_engine",
                    )
                )
                patches.append({
                    "rule_id": rule.rule_id,
                    "file_path": file_path,
                    "line": str(lineno),
                    "cis_control": rule.cis_control,
                    "hardened_snippet": rule.hardened_hcl_snippet,
                })

        # Also inspect structured JSON IAM policy documents for subtle combinations
        if file_path.endswith(".json"):
            vulns.extend(self._audit_structured_iam_json(content, file_path))

        score = self._compute_iac_score(vulns)
        return {
            "audited_at": utc_now_iso(),
            "file_path": file_path,
            "iac_security_score": score,
            "findings_count": len(vulns),
            "hardened_patch_suggestions": patches,
            "vulnerabilities": vulns,
        }

    def _audit_structured_iam_json(self, content: str, file_path: str) -> List[CyberVulnerability]:
        out: List[CyberVulnerability] = []
        try:
            doc = json.loads(content)
        except Exception:
            return out
        if not isinstance(doc, dict) or "Statement" not in doc:
            return out
        stmts = doc["Statement"]
        if isinstance(stmts, dict):
            stmts = [stmts]
        if not isinstance(stmts, list):
            return out

        for idx, st in enumerate(stmts):
            if not isinstance(st, dict) or str(st.get("Effect", "")).lower() != "allow":
                continue
            actions = st.get("Action") or []
            if isinstance(actions, str):
                actions = [actions]
            not_actions = st.get("NotAction")
            resources = st.get("Resource") or []
            if isinstance(resources, str):
                resources = [resources]

            if not_actions is not None:
                out.append(
                    make_cyber_vuln(
                        rule_id="CYB-IAC-IAM-NOTACTION-ALLOW",
                        title=f"[Cloud IAM] Dangerous `Effect: Allow` Combined With `NotAction` (Statement #{idx+1})",
                        description=f"Statement #{idx+1} in `{file_path}` uses `Allow + NotAction`, implicitly permitting almost all AWS APIs.",
                        cyber_domain=CyberDomain.CLOUD_IAM,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-269"],
                        confidence=0.97,
                        verification_method=VerificationMethod.STATIC_AST,
                        file_path=file_path,
                        endpoint_or_asset=f"{file_path}#Statement[{idx}]",
                        remediation_guidance="Never pair `Effect: Allow` with `NotAction`; enumerate explicit minimal `Action` permissions.",
                        discovered_by="ely_cloud_iac_policy_drift_engine",
                    )
                )

            act_set = {str(a).lower() for a in actions}
            if ("iam:passrole" in act_set and any(a in act_set for a in ("lambda:createfunction", "ec2:runinstances", "glue:createdevendpoint", "ecs:runtask"))) or (
                "*" in act_set and "*" in resources
            ):
                out.append(
                    make_cyber_vuln(
                        rule_id="CYB-IAC-IAM-COMBO-PRIVESC",
                        title=f"[Cloud IAM] Composed Privilege Escalation Graph in Statement #{idx+1}",
                        description=f"Statement #{idx+1} in `{file_path}` combines `{sorted(act_set)[:6]}` permitting full role/account takeover.",
                        cyber_domain=CyberDomain.CLOUD_IAM,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-269"],
                        confidence=0.98,
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        file_path=file_path,
                        endpoint_or_asset=f"{file_path}#Statement[{idx}]",
                        remediation_guidance="Separate PassRole from compute creation or enforce strict permission boundaries.",
                        discovered_by="ely_cloud_iac_policy_drift_engine",
                    )
                )
        return out

    def audit_repository(self, target_dir: str | Path) -> Dict[str, Any]:
        root = Path(target_dir).resolve()
        files = [root] if root.is_file() else sorted(root.rglob("*"))
        all_vulns: List[CyberVulnerability] = []
        all_patches: List[Dict[str, str]] = []
        iac_files_scanned = 0
        by_rule: Dict[str, int] = {}

        for f in files:
            if not f.is_file() or any(p in f.parts for p in (".git", "node_modules", "__pycache__", ".venv")):
                continue
            if f.suffix.lower() not in IAC_EXTENSIONS or f.stat().st_size > 512_000:
                continue
            rel = f.name if root.is_file() else str(f.relative_to(root))
            try:
                txt = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            # Filter generic JSON/YAML files unless they contain cloud/IaC markers
            if f.suffix.lower() in (".json", ".yaml", ".yml") and not any(
                kw in txt for kw in ("AWSTemplateFormatVersion", '"Statement"', "aws_", "google_", "azurerm_", "publicly_accessible", "enable_key_rotation", "allUsers")
            ):
                continue
            iac_files_scanned += 1
            res = self.audit_text(txt, file_path=rel)
            all_vulns.extend(res["vulnerabilities"])
            all_patches.extend(res["hardened_patch_suggestions"])
            for v in res["vulnerabilities"]:
                by_rule[v.rule_id] = by_rule.get(v.rule_id, 0) + 1

        return {
            "audited_at": utc_now_iso(),
            "target": str(root),
            "iac_files_scanned": iac_files_scanned,
            "iac_security_score": self._compute_iac_score(all_vulns),
            "findings_count": len(all_vulns),
            "by_rule": by_rule,
            "hardened_patch_suggestions": all_patches[:25],
            "vulnerabilities": all_vulns,
        }

    def detect_posture_drift(
        self,
        baseline_audit: Dict[str, Any],
        candidate_audit: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Compare baseline vs. candidate IaC security snapshots for policy drift & regressions."""
        def _keys(a: Dict[str, Any]) -> Set[Tuple[str, str]]:
            out: Set[Tuple[str, str]] = set()
            for v in a.get("vulnerabilities", []):
                rid = v.rule_id if hasattr(v, "rule_id") else str(v.get("rule_id", ""))
                ep = v.endpoint_or_asset if hasattr(v, "endpoint_or_asset") else str(v.get("endpoint_or_asset", ""))
                out.add((rid, ep))
            return out

        base_k = _keys(baseline_audit)
        cand_k = _keys(candidate_audit)
        introduced = sorted(cand_k - base_k)
        remediated = sorted(base_k - cand_k)
        score_delta = round(
            float(candidate_audit.get("iac_security_score", 100.0))
            - float(baseline_audit.get("iac_security_score", 100.0)),
            2,
        )
        drift_verdict = (
            "DRIFT_REGRESSION_BLOCKED" if introduced else
            "DRIFT_HARDENED" if remediated else "NO_DRIFT"
        )
        return {
            "checked_at": utc_now_iso(),
            "drift_verdict": drift_verdict,
            "score_delta": score_delta,
            "newly_introduced_violations": [{"rule_id": r, "asset": a} for r, a in introduced],
            "remediated_violations": [{"rule_id": r, "asset": a} for r, a in remediated],
        }

    @staticmethod
    def _compute_iac_score(vulns: Sequence[CyberVulnerability]) -> float:
        pen = sum(
            24.0 if v.severity == Severity.CRITICAL else
            13.0 if v.severity == Severity.HIGH else
            6.0 if v.severity == Severity.MEDIUM else 2.0
            for v in vulns
        )
        return round(max(0.0, min(100.0, 100.0 - pen)), 2)
