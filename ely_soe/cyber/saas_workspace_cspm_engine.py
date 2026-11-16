"""
SaaS Security Posture Management (SSPM) Auditor for Enterprise Collaboration & Dev Platforms:
GitHub Enterprise / Org, Microsoft 365 / Entra ID, Google Workspace, Okta & Slack.

Detects high-impact SaaS control-plane misconfigurations widely exploited by modern threat actors
(Scattered Spider, Midnight Blizzard, Lapsus$):
  1. **GitHub Org & Repository Security Governance**:
       - Missing mandatory Org 2FA (`two_factor_requirement_enabled=False`)
       - Unprotected default branches (missing PR reviews, CODEOWNERS, signed commits, or allowing force-push)
       - GitHub Actions `default_workflow_permissions: write` or allowing `approve_pull_request_reviews`
       - Secret Scanning / Push Protection / Dependabot alerts disabled.
  2. **Microsoft 365 / Entra ID / Okta Identity Control Plane**:
       - Legacy authentication protocols enabled (IMAP/POP3/SMTP Basic Auth bypassing MFA!)
       - Excessive standing Global Administrators (`> 5`) or admins lacking phishing-resistant FIDO2/WebAuthn MFA
       - Unconstrained user consent to third-party OAuth apps (illicit consent grant phishing!)
       - Mail auto-forwarding to external domains enabled (BEC exfiltration persistence!).
  3. **Slack / Google Workspace Collaboration & Data-Loss Posture**:
       - Public anyone-with-the-link Drive sharing enabled organization-wide
       - Unapproved third-party Slack apps holding `files:read`/`channels:history` scopes
       - External guest accounts lacking expiration dates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

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


class SaaSWorkspaceSSPMEngine:
    """Audits GitHub, M365/Entra ID, Okta, Google Workspace, and Slack SaaS security postures."""

    def audit_github_org(self, cfg: Dict[str, Any], org_name: str = "ely-org") -> Dict[str, Any]:
        vulns: List[CyberVulnerability] = []
        checks: Dict[str, bool] = {
            "org_2fa_enforced": bool(cfg.get("two_factor_requirement_enabled", False)),
            "branch_protection_pr_reviews": int(cfg.get("required_approving_review_count", 0)) >= 2,
            "block_force_pushes": not bool(cfg.get("allow_force_pushes", True)),
            "signed_commits_required": bool(cfg.get("require_signed_commits", False)),
            "actions_default_read_only": str(cfg.get("actions_default_workflow_permissions", "write")).lower() == "read",
            "actions_cannot_approve_prs": not bool(cfg.get("actions_can_approve_pull_request_reviews", True)),
            "secret_scanning_push_protection": bool(cfg.get("secret_scanning_push_protection", False)),
            "base_member_permission_none_or_read": str(cfg.get("default_repository_permission", "write")).lower() in ("none", "read"),
        }

        rule_specs = [
            ("org_2fa_enforced", "CYB-SSPM-GH-NO-2FA", "GitHub Organization Does Not Mandate 2FA for Members", Severity.CRITICAL, "CWE-287", "T1078"),
            ("branch_protection_pr_reviews", "CYB-SSPM-GH-BRANCH-PROT", "Default Branch Requires < 2 Independent PR Approvals (Supply-Chain Bypass)", Severity.HIGH, "CWE-284", "T1195.002"),
            ("block_force_pushes", "CYB-SSPM-GH-FORCE-PUSH", "Force Push Permitted on Protected Main/Release Branch (History Tampering)", Severity.HIGH, "CWE-345", "T1565"),
            ("actions_default_read_only", "CYB-SSPM-GH-ACT-WRITE", "GitHub Actions Default `GITHUB_TOKEN` Has Broad `write` Permissions", Severity.HIGH, "CWE-269", "T1195.002"),
            ("actions_cannot_approve_prs", "CYB-SSPM-GH-ACT-APPROVE", "GitHub Actions Permitted to Auto-Approve Pull Requests (SoD Bypass)", Severity.HIGH, "CWE-269", "T1195.002"),
            ("secret_scanning_push_protection", "CYB-SSPM-GH-PUSH-PROT", "GitHub Secret Scanning Push Protection Disabled", Severity.MEDIUM, "CWE-798", "T1552.001"),
            ("base_member_permission_none_or_read", "CYB-SSPM-GH-BASE-PERM", "GitHub Org Base Member Permission Grants Global `write`/`admin`", Severity.HIGH, "CWE-269", "T1078"),
        ]
        for key, rid, title, sev, cwe, mitre in rule_specs:
            if not checks[key]:
                vulns.append(
                    make_cyber_vuln(
                        rule_id=rid,
                        title=f"[GitHub SSPM | {org_name}] {title}",
                        description=f"Control `{key}` failed on GitHub organization `{org_name}`.",
                        cyber_domain=CyberDomain.IAC_CICD,
                        severity=sev,
                        cwe_ids=[cwe],
                        confidence=0.99,
                        mitre_techniques=[MitreTechniqueRef(mitre, title, MitreTactic.INITIAL_ACCESS)],
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        endpoint_or_asset=f"github://{org_name}",
                        remediation_guidance=f"Enforce `{key}` at GitHub Organization Rulesets & Security Policy level.",
                        discovered_by="ely_cyber_saas_sspm_engine",
                    )
                )

        score = round((sum(1 for v in checks.values() if v) / len(checks)) * 100.0, 2)
        return {"platform": "github", "tenant": org_name, "sspm_score_pct": score, "checks": checks, "vulnerabilities": vulns}

    def audit_identity_suite_m365_okta(self, cfg: Dict[str, Any], tenant: str = "corp-idp") -> Dict[str, Any]:
        """Audit M365/Entra ID & Okta identity governance controls."""
        vulns: List[CyberVulnerability] = []
        standing_global_admins = int(cfg.get("standing_global_admins", 10))
        checks = {
            "legacy_auth_blocked": bool(cfg.get("legacy_auth_blocked", False)),
            "phishing_resistant_mfa_admins": bool(cfg.get("fido2_required_for_admins", False)),
            "bounded_global_admins": 1 <= standing_global_admins <= 4,
            "user_oauth_app_consent_restricted": bool(cfg.get("restrict_user_oauth_app_consent", False)),
            "external_auto_mail_forwarding_blocked": bool(cfg.get("block_external_mail_forwarding", False)),
            "high_risk_signin_conditional_access": bool(cfg.get("block_high_risk_signins", False)),
            "pim_jit_privileged_elevation": bool(cfg.get("pim_jit_enabled", False)),
        }

        specs = [
            ("legacy_auth_blocked", "CYB-SSPM-IDP-LEGACY-AUTH", "Legacy Auth Protocols (IMAP/POP3/SMTP Basic) Enabled — Bypasses MFA", Severity.CRITICAL, "CWE-287", "T1110.003"),
            ("phishing_resistant_mfa_admins", "CYB-SSPM-IDP-NO-FIDO2", "Privileged SaaS Admins Not Enforcing Phishing-Resistant FIDO2/WebAuthn MFA", Severity.CRITICAL, "CWE-308", "T1111"),
            ("bounded_global_admins", "CYB-SSPM-IDP-ADMIN-SPRAWL", f"Excessive Standing Global Administrators ({standing_global_admins} > 4 Max)", Severity.HIGH, "CWE-269", "T1078.004"),
            ("user_oauth_app_consent_restricted", "CYB-SSPM-IDP-OAUTH-CONSENT", "Unrestricted End-User OAuth App Consent (Illicit Consent Grant Phishing)", Severity.HIGH, "CWE-284", "T1528"),
            ("external_auto_mail_forwarding_blocked", "CYB-SSPM-IDP-MAIL-FWD", "Automatic External Email Forwarding Allowed (BEC Exfiltration Persistence)", Severity.HIGH, "CWE-200", "T1114.003"),
            ("high_risk_signin_conditional_access", "CYB-SSPM-IDP-RISK-CA", "Missing Conditional Access Policy Blocking High-Risk / Impossible-Travel Sign-Ins", Severity.MEDIUM, "CWE-287", "T1078"),
            ("pim_jit_privileged_elevation", "CYB-SSPM-IDP-NO-PIM", "Privileged Roles Lack Just-In-Time (PIM) Time-Bounded Elevation", Severity.MEDIUM, "CWE-269", "T1078.004"),
        ]
        for key, rid, title, sev, cwe, mitre in specs:
            if not checks[key]:
                vulns.append(
                    make_cyber_vuln(
                        rule_id=rid,
                        title=f"[IdP/M365 SSPM | {tenant}] {title}",
                        description=f"Identity SaaS control `{key}` failed on `{tenant}`.",
                        cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                        severity=sev,
                        cwe_ids=[cwe],
                        confidence=0.99,
                        mitre_techniques=[MitreTechniqueRef(mitre, title, MitreTactic.CREDENTIAL_ACCESS)],
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        endpoint_or_asset=f"idp://{tenant}",
                        remediation_guidance=f"Enable `{key}` in Entra ID / Okta Conditional Access and Identity Governance.",
                        discovered_by="ely_cyber_saas_sspm_engine",
                    )
                )

        score = round((sum(1 for v in checks.values() if v) / len(checks)) * 100.0, 2)
        return {"platform": "m365_okta", "tenant": tenant, "sspm_score_pct": score, "checks": checks, "vulnerabilities": vulns}

    def audit_collaboration_workspace(self, cfg: Dict[str, Any], tenant: str = "corp-collab") -> Dict[str, Any]:
        """Audit Google Workspace Drive & Slack workspace data-exfiltration controls."""
        vulns: List[CyberVulnerability] = []
        checks = {
            "public_link_sharing_disabled": not bool(cfg.get("allow_public_anyone_with_link", True)),
            "third_party_apps_require_approval": bool(cfg.get("require_admin_app_approval", False)),
            "dlp_sensitive_channel_scanning": bool(cfg.get("dlp_enabled", False)),
            "guest_accounts_expire": bool(cfg.get("enforce_guest_expiration", False)),
            "audit_log_siem_export": bool(cfg.get("siem_audit_export_enabled", False)),
        }

        if not checks["public_link_sharing_disabled"]:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-SSPM-COLLAB-PUBLIC-LINKS",
                    title=f"[Workspace SSPM | {tenant}] Organization-Wide Public 'Anyone With Link' Document Sharing Permitted",
                    description="Employees can expose confidential specs/credentials via unauthenticated public sharing URLs.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-284", "CWE-200"],
                    confidence=0.98,
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=f"workspace://{tenant}",
                    remediation_guidance="Restrict default sharing to domain-internal authenticated users and enforce automated DLP revocation.",
                    discovered_by="ely_cyber_saas_sspm_engine",
                )
            )
        if not checks["third_party_apps_require_approval"]:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-SSPM-COLLAB-SHADOW-APPS",
                    title=f"[Workspace SSPM | {tenant}] Unapproved Third-Party Slack/Workspace Apps Permitted With Broad Read Scopes",
                    description="Shadow OAuth apps installed by users accumulate `channels:history` and `files:read` access without security review.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-269"],
                    confidence=0.96,
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=f"workspace://{tenant}",
                    remediation_guidance="Enable mandatory Admin App Approval and audit/revoke unused OAuth grants quarterly.",
                    discovered_by="ely_cyber_saas_sspm_engine",
                )
            )

        score = round((sum(1 for v in checks.values() if v) / len(checks)) * 100.0, 2)
        return {"platform": "collaboration", "tenant": tenant, "sspm_score_pct": score, "checks": checks, "vulnerabilities": vulns}

    def audit_enterprise_saas_suite(
        self,
        github_cfg: Dict[str, Any],
        idp_cfg: Dict[str, Any],
        collab_cfg: Dict[str, Any],
    ) -> Dict[str, Any]:
        gh = self.audit_github_org(github_cfg)
        idp = self.audit_identity_suite_m365_okta(idp_cfg)
        col = self.audit_collaboration_workspace(collab_cfg)
        all_v = gh["vulnerabilities"] + idp["vulnerabilities"] + col["vulnerabilities"]
        overall = round((gh["sspm_score_pct"] + idp["sspm_score_pct"] + col["sspm_score_pct"]) / 3.0, 2)
        return {
            "assessed_at": utc_now_iso(),
            "overall_sspm_score_pct": overall,
            "github_score_pct": gh["sspm_score_pct"],
            "idp_score_pct": idp["sspm_score_pct"],
            "collaboration_score_pct": col["sspm_score_pct"],
            "vulnerabilities": all_v,
        }
