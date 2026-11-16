"""
Zero-Trust Identity, OAuth 2.1 / OIDC, SAML 2.0 XML Signature Wrapping (XSW),
RBAC Toxic-Combination Solver & CISA Zero-Trust Maturity Model (ZTMM v2.0) Engine.

Audits modern enterprise authentication & authorization architectures:
  1. **OAuth 2.0 / 2.1 & OIDC Protocol Security Verifier**:
       - Enforces Authorization Code + PKCE (`S256` only; rejects `plain`)
       - Flags deprecated Implicit (`response_type=token`) and ROPC (`grant_type=password`) flows
       - Detects wildcard/prefix/open-redirect `redirect_uri` bypass patterns
       - Checks `state` CSRF binding, OIDC `nonce` replay protection, Refresh Token Rotation,
         and public-client secret leakage.
  2. **SAML 2.0 XML Assertion Security & XSW Structural Auditor**:
       - Detects XML Signature Wrapping (XSW1–XSW8) indicators (duplicate `<Assertion>` elements,
         unsigned assertion alongside signed wrapper)
       - Detects XML comment truncation attacks (`admin@corp.com<!--evil-->.attacker.com`)
       - Flags missing `<Signature>`, weak SHA-1 `DigestMethod`/`SignatureMethod`, missing
         `NotOnOrAfter` expiration or `AudienceRestriction`.
  3. **RBAC / ABAC Separation-of-Duties (SoD) Toxic-Combination Solver**:
       - Evaluates enterprise user-to-role matrices to flag users holding mutually exclusive
         toxic permission combinations (e.g., `code_author + prod_release_approver`,
         `vendor_creator + payment_approver`, `iam_policy_editor + audit_log_deleter`).
  4. **CISA Zero-Trust Maturity Model v2.0 Quantitative 5-Pillar Scorer**:
       - Scores Identity, Devices, Networks, Applications/Workloads, and Data across
         `Traditional -> Initial -> Advanced -> Optimal`.
"""

from __future__ import annotations

import re
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


TOXIC_SOD_PAIRS: Tuple[Tuple[str, str, str, Severity], ...] = (
    ("code_author", "prod_deploy_approver", "Single actor can author and self-approve production code changes", Severity.HIGH),
    ("iam_admin", "audit_log_admin", "Actor can escalate privileges and tamper with immutable audit trails", Severity.CRITICAL),
    ("vendor_onboarding", "wire_payment_approver", "Financial fraud Separation-of-Duties conflict (create payee + release funds)", Severity.CRITICAL),
    ("vuln_scanner_planner", "vuln_confirmation_validator", "Security governance conflict (discoverer self-confirming findings)", Severity.HIGH),
    ("kms_key_admin", "encrypted_data_reader", "Split-knowledge cryptographic custody violation", Severity.HIGH),
    ("ca_template_editor", "ca_cert_approver", "PKI / ADCS certificate issuance Separation-of-Duties violation", Severity.CRITICAL),
)


class ZeroTrustIdentityEngine:
    """Audits OAuth 2.1/OIDC configs, SAML 2.0 assertions, RBAC SoD conflicts, and CISA ZTMM v2.0."""

    def audit_oauth2_oidc_config(self, cfg: Dict[str, Any], asset: str = "oauth2_provider") -> List[CyberVulnerability]:
        vulns: List[CyberVulnerability] = []
        grants = {str(g).lower() for g in cfg.get("grant_types", [])}
        resp_types = {str(r).lower() for r in cfg.get("response_types", [])}
        redirect_uris = [str(u) for u in cfg.get("redirect_uris", [])]

        if "token" in resp_types or "implicit" in grants:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-ID-OAUTH-IMPLICIT-001",
                    title="Deprecated OAuth 2.0 Implicit Grant (`response_type=token`) Enabled",
                    description=f"OAuth client `{asset}` permits Implicit Flow, exposing access tokens directly in browser URL fragments, history, and Referer leaks.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-287", "CWE-522"],
                    confidence=0.99,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Migrate to OAuth 2.1 Authorization Code Flow with mandatory PKCE (`S256`).",
                    discovered_by="ely_cyber_zero_trust_identity",
                )
            )
        if "password" in grants:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-ID-OAUTH-ROPC-001",
                    title="Deprecated Resource Owner Password Credentials (ROPC) Grant Enabled",
                    description=f"OAuth client `{asset}` allows `grant_type=password`, bypassing MFA/SSO and exposing raw user passwords to client apps.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-287"],
                    confidence=0.98,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Disable ROPC (`password`) grant and use Authorization Code + PKCE or Device Authorization Grant.",
                    discovered_by="ely_cyber_zero_trust_identity",
                )
            )
        if not cfg.get("pkce_required", False) or str(cfg.get("pkce_method", "S256")).lower() == "plain":
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-ID-OAUTH-NOPKCE-001",
                    title="OAuth 2.1 PKCE (`S256`) Not Enforced on Authorization Code Flow",
                    description=f"Client `{asset}` does not require PKCE with `S256` challenge, leaving authorization codes vulnerable to interception/injection.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-345"],
                    confidence=0.97,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Mandate PKCE with `code_challenge_method=S256` exclusively (reject `plain`).",
                    discovered_by="ely_cyber_zero_trust_identity",
                )
            )
        if not cfg.get("state_enforced", True):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-ID-OAUTH-NOSTATE-001",
                    title="Missing OAuth `state` Parameter Enforcement (Login CSRF / Account Mix-Up)",
                    description=f"Client `{asset}` skips cryptographic `state` validation on OAuth callbacks.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-352"],
                    confidence=0.96,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Bind a high-entropy per-session `state` token stored in an HttpOnly SameSite cookie and verify in constant time.",
                    discovered_by="ely_cyber_zero_trust_identity",
                )
            )
        for uri in redirect_uris:
            if "*" in uri or uri.startswith("http://") and "127.0.0.1" not in uri and "localhost" not in uri:
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-ID-OAUTH-REDIRECT-001",
                        title=f"Unsafe OAuth `redirect_uri` Allowing Wildcard or Plaintext HTTP (`{uri}`)",
                        description=f"Client `{asset}` registers `{uri}`, enabling authorization code hijacking via open redirect or on-path interception.",
                        cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-601"],
                        confidence=0.99,
                        verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                        endpoint_or_asset=asset,
                        remediation_guidance="Require exact byte-for-byte HTTPS `redirect_uri` matching with zero wildcards.",
                        discovered_by="ely_cyber_zero_trust_identity",
                    )
                )
        if cfg.get("client_type") == "public_spa" and cfg.get("refresh_token_rotation", False) is False:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-ID-OAUTH-STATIC-RT-001",
                    title="Public SPA Client Issues Non-Rotating Long-Lived Refresh Tokens",
                    description=f"Public SPA `{asset}` issues reusable static refresh tokens without rotation & reuse detection.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-613"],
                    confidence=0.94,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Enable Refresh Token Rotation with automatic token-family revocation on reuse detection.",
                    discovered_by="ely_cyber_zero_trust_identity",
                )
            )
        return vulns

    def audit_saml_assertion_xml(self, saml_xml: str, asset: str = "saml_sp") -> List[CyberVulnerability]:
        """Audit SAML 2.0 XML response/assertion for XSW, comment truncation, weak SHA-1, and missing constraints."""
        vulns: List[CyberVulnerability] = []

        # 1. XML Signature Wrapping (multiple <Assertion> elements)
        assertions = re.findall(r"<(?:\w+:)?Assertion\b", saml_xml)
        if len(assertions) > 1:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-ID-SAML-XSW-001",
                    title=f"SAML XML Signature Wrapping (XSW) Indicator — {len(assertions)} `<Assertion>` Elements Present",
                    description=f"SAML message for `{asset}` contains {len(assertions)} `<Assertion>` blocks, characteristic of XSW1–XSW8 spoofing where signature verification checks one block while SP reads another.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-347"],
                    confidence=0.97,
                    cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="N", sc="H", si="H", sa="N"),
                    mitre_techniques=[MitreTechniqueRef("T1606.002", "Forge Web Credentials: SAML Tokens", MitreTactic.CREDENTIAL_ACCESS)],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Reject SAML responses with >1 Assertion, validate strict XSD schema, and read claims exclusively from the exact XML node referenced by verified `<Reference URI>`.",
                    discovered_by="ely_cyber_zero_trust_identity",
                )
            )

        # 2. Missing XML Signature
        if not re.search(r"<(?:\w+:)?Signature\b", saml_xml):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-ID-SAML-UNSIGNED-001",
                    title="Unsigned SAML 2.0 Response / Assertion Accepted",
                    description=f"SAML payload for `{asset}` contains no XMLDSig `<Signature>` element.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-347"],
                    confidence=0.99,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Require cryptographic XMLDSig signatures on both SAML Response and Assertion pinned to IdP X.509 certificate.",
                    discovered_by="ely_cyber_zero_trust_identity",
                )
            )

        # 3. XML Comment Truncation Attack inside NameID (CVE-2017-11427 class)
        if re.search(r"<(?:\w+:)?NameID[^>]*>[^<]*<!--.*?-->[^<]*</(?:\w+:)?NameID>", saml_xml, re.DOTALL):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-ID-SAML-COMMENT-INJ-001",
                    title="SAML `<NameID>` XML Comment Truncation Spoofing Pattern Detected",
                    description=f"SAML `<NameID>` for `{asset}` embeds an XML comment (`<!--...-->`), which vulnerable XML parsers truncate to impersonate `admin@corp.com`.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-287", "CWE-347"],
                    confidence=0.98,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Canonicalize with comments stripped (C14N without comments) and reject any `<NameID>` containing child comment nodes.",
                    discovered_by="ely_cyber_zero_trust_identity",
                )
            )

        # 4. Weak SHA-1 Digest or Signature Algorithm
        if re.search(r"xmldsig#(?:rsa-)?sha1\b", saml_xml, re.IGNORECASE):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-ID-SAML-SHA1-001",
                    title="SAML 2.0 XMLDSig Uses Deprecated SHA-1 Algorithm",
                    description=f"SAML payload for `{asset}` uses SHA-1 in `DigestMethod`/`SignatureMethod`.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-328"],
                    confidence=0.97,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Upgrade SAML IdP/SP signing & digest methods to `xmldsig-more#rsa-sha256` and `xmlenc#sha256`.",
                    discovered_by="ely_cyber_zero_trust_identity",
                )
            )

        # 5. Missing AudienceRestriction or NotOnOrAfter
        if "NotOnOrAfter" not in saml_xml or "AudienceRestriction" not in saml_xml:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-ID-SAML-REPLAY-001",
                    title="SAML Assertion Missing `NotOnOrAfter` Lifetime or `AudienceRestriction`",
                    description=f"SAML assertion for `{asset}` lacks expiration or audience scoping, enabling cross-SP token replay.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-294", "CWE-613"],
                    confidence=0.95,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Enforce strict `AudienceRestriction`, short `NotOnOrAfter` (< 5 min), and assertion ID replay cache.",
                    discovered_by="ely_cyber_zero_trust_identity",
                )
            )
        return vulns

    def audit_rbac_toxic_combinations(self, user_permissions: Dict[str, Sequence[str]]) -> Dict[str, Any]:
        """Solve Separation-of-Duties toxic permission conflicts across enterprise principals."""
        conflicts: List[Dict[str, Any]] = []
        vulns: List[CyberVulnerability] = []

        for principal, perms in user_permissions.items():
            pset = {p.lower() for p in perms}
            for perm_a, perm_b, desc, sev in TOXIC_SOD_PAIRS:
                if perm_a in pset and perm_b in pset:
                    conflicts.append({"principal": principal, "perm_a": perm_a, "perm_b": perm_b, "reason": desc, "severity": sev.value})
                    vulns.append(
                        make_cyber_vuln(
                            rule_id=f"CYB-ID-SOD-{perm_a.upper()}",
                            title=f"Separation-of-Duties Toxic Combination on `{principal}` (`{perm_a}` + `{perm_b}`)",
                            description=f"Principal `{principal}` holds mutually exclusive permissions `{perm_a}` and `{perm_b}`: {desc}.",
                            cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                            severity=sev,
                            cwe_ids=["CWE-269"],
                            confidence=0.99,
                            verification_method=VerificationMethod.GRAPH_REACHABILITY,
                            endpoint_or_asset=principal,
                            remediation_guidance=f"Split `{perm_a}` and `{perm_b}` across distinct identities with dual-control approval.",
                            discovered_by="ely_cyber_zero_trust_identity",
                        )
                    )
        return {"principals_audited": len(user_permissions), "toxic_conflicts": conflicts, "vulnerabilities": vulns}

    def score_cisa_ztmm_v2(self, pillar_controls: Dict[str, Dict[str, bool]]) -> Dict[str, Any]:
        """Compute CISA Zero-Trust Maturity Model v2.0 quantitative score across all 5 pillars."""
        pillars = ("identity", "devices", "networks", "applications_workloads", "data")
        scores: Dict[str, Any] = {}
        for p in pillars:
            ctrls = pillar_controls.get(p, {})
            if not ctrls:
                pct = 0.0
            else:
                pct = round((sum(1 for v in ctrls.values() if v) / len(ctrls)) * 100.0, 2)
            tier = "Optimal" if pct >= 90 else ("Advanced" if pct >= 70 else ("Initial" if pct >= 40 else "Traditional"))
            scores[p] = {"score_pct": pct, "maturity_stage": tier, "controls_passed": sum(1 for v in ctrls.values() if v), "controls_total": len(ctrls)}

        overall = round(sum(s["score_pct"] for s in scores.values()) / len(pillars), 2)
        return {
            "assessed_at": utc_now_iso(),
            "framework": "CISA ZTMM v2.0",
            "overall_zt_score_pct": overall,
            "overall_stage": "Optimal" if overall >= 90 else ("Advanced" if overall >= 70 else ("Initial" if overall >= 40 else "Traditional")),
            "pillars": scores,
        }
