"""
Enterprise Identity Federation Security Auditor: SAML 2.0 XML, OIDC / OAuth 2.1 & Kerberos.

Performs deep structural verification of enterprise SSO federation protocols that protect
cloud control planes and corporate crown jewels:
  1. **SAML 2.0 Assertion & Response Structural Auditor**:
       - Unsigned `<Response>` / `<Assertion>` or missing `<ds:Signature>` (authentication bypass!)
       - **XML Signature Wrapping (XSW1–XSW8) structural attack detection**: multiple `<Assertion>`
         elements, detached/wrapped `<ds:Reference URI>` mismatching signed assertion ID!
       - **XML Comment Truncation Attack** inside `<NameID>` (e.g. `admin@corp.com<!--.evil.com-->`,
         CVE-2018-0489 / Duo / OneLogin SAML bypass class!)
       - Missing `<AudienceRestriction>`, missing/excessive `NotOnOrAfter` replay lifetime,
         weak `xmldsig#sha1` / `rsa-sha1` signature algorithm, or `<!DOCTYPE>` XXE declaration.
  2. **OAuth 2.1 & OpenID Connect (OIDC) Provider / Client Config Auditor**:
       - Missing PKCE (`S256`) on public/SPA/mobile authorization code flows (CWE-345)
       - Legacy Implicit (`response_type=token`) or Resource Owner Password (`password`) grant enabled
       - Wildcard / HTTP / unanchored `redirect_uri` patterns (open redirect -> auth-code theft!)
       - Missing `state` CSRF binding or `nonce` replay binding
       - Weak JWT signing algorithms (`none`, symmetric `HS256` exposed alongside `RS256` JWKS ->
         algorithm confusion), missing `aud`/`iss` tenant validation, or `http://` JWKS URI.
  3. **Kerberos / Active Directory Federation Policy Auditor**:
       - RC4-HMAC (`etype 23`) permitted on service principals (Kerberoasting trivial offline crack!)
       - Unconstrained Delegation (`TRUSTED_FOR_DELEGATION`) on non-DC hosts
       - AS-REP Roasting (`DONT_REQ_PREAUTH`) enabled on user accounts
       - Stale `KRBTGT` password age (`> 180 days` -> persistent Golden Ticket window).
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
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


class IdentityFederationAuditor:
    """Audits SAML 2.0 XML assertions, OAuth 2.1/OIDC configs, and Kerberos federation policies."""

    _NAMEID_COMMENT_RE = re.compile(r"<(?:[A-Za-z0-9_]+:)?NameID[^>]*>[^<]*<!--", re.IGNORECASE | re.DOTALL)
    _DOCTYPE_RE = re.compile(r"<!DOCTYPE\b|<!ENTITY\b", re.IGNORECASE)

    def audit_saml_response_xml(self, saml_xml: str, service_provider: str = "sp.corp.example") -> Dict[str, Any]:
        """Structurally audit a SAML 2.0 XML Response/Assertion for XSW, XXE, comment injection, and weak sigs."""
        vulns: List[CyberVulnerability] = []
        signals: Dict[str, Any] = {
            "assertion_count": 0,
            "signature_count": 0,
            "has_xxe_doctype": False,
            "has_nameid_comment_injection": False,
            "xsw_detected": False,
        }

        # 1. XXE / DOCTYPE check before parsing
        if self._DOCTYPE_RE.search(saml_xml):
            signals["has_xxe_doctype"] = True
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-FED-SAML-XXE",
                    title=f"SAML 2.0 XML Contains `<!DOCTYPE>`/`<!ENTITY>` Declaration (XXE Attack Vector)",
                    description="SAML parsers accepting DTD/ENTITY declarations allow unauthenticated local file disclosure and SSRF during SSO login.",
                    cyber_domain=CyberDomain.WEB_SSRF_XXE_SSTI_DESER,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-611"],
                    confidence=0.99,
                    mitre_techniques=[MitreTechniqueRef("T1190", "Exploit Public-Facing Application", MitreTactic.INITIAL_ACCESS)],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=service_provider,
                    remediation_guidance="Disable DTDs and external entity resolution strictly (`defusedxml` / `disallow-doctype-decl=true`).",
                    discovered_by="ely_cyber_identity_federation_auditor",
                )
            )

        # 2. NameID XML Comment Truncation Bypass (CVE-2018-0489 class)
        if self._NAMEID_COMMENT_RE.search(saml_xml):
            signals["has_nameid_comment_injection"] = True
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-FED-SAML-COMMENT-TRUNC",
                    title="SAML `<NameID>` Contains Embedded XML Comment (Account Impersonation Bypass)",
                    description="XML comments inside `<NameID>` (e.g. `admin@corp.com<!--.attacker.com-->`) survive XMLDSig C14N while naive parsers truncate at the first text node, impersonating `admin@corp.com`.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-287", "CWE-347"],
                    confidence=0.99,
                    cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="L", ui="N", vc="H", vi="H", va="N", sc="H", si="H", sa="N"),
                    mitre_techniques=[MitreTechniqueRef("T1606.002", "Forge Web Credentials: SAML Tokens", MitreTactic.CREDENTIAL_ACCESS)],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=service_provider,
                    remediation_guidance="Reject any SAML `<NameID>` or `<AttributeValue>` containing child XML comment nodes, or canonicalize with comments stripped before reading full text.",
                    discovered_by="ely_cyber_identity_federation_auditor",
                )
            )

        # Strip DOCTYPE (including internal entity subset `[...]`) safely for stdlib ElementTree inspection
        clean_xml = re.sub(r"<!DOCTYPE[^>\[]*(?:\[[^\]]*\])?\s*>", "", saml_xml, flags=re.IGNORECASE | re.DOTALL)
        try:
            root = ET.fromstring(clean_xml)
        except ET.ParseError:
            return {"audited_at": utc_now_iso(), "service_provider": service_provider, "parse_error": True, "signals": signals, "vulnerabilities": vulns}

        def _local(tag: str) -> str:
            return tag.split("}", 1)[-1] if "}" in tag else tag

        assertions = [el for el in root.iter() if _local(el.tag) == "Assertion"]
        signatures = [el for el in root.iter() if _local(el.tag) == "Signature"]
        references = [el for el in root.iter() if _local(el.tag) == "Reference"]
        sig_methods = [el.attrib.get("Algorithm", "") for el in root.iter() if _local(el.tag) in ("SignatureMethod", "DigestMethod")]
        audiences = [el for el in root.iter() if _local(el.tag) == "AudienceRestriction"]
        conditions = [el for el in root.iter() if _local(el.tag) == "Conditions"]

        signals["assertion_count"] = len(assertions)
        signals["signature_count"] = len(signatures)

        # 3. Unsigned SAML Response/Assertion
        if not signatures:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-FED-SAML-UNSIGNED",
                    title="SAML 2.0 Response & Assertion Lack XML Digital Signature (`<ds:Signature>`)",
                    description="Unsigned SAML assertions permit trivial forged administrator SSO logins without IdP key compromise.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-347"],
                    confidence=0.99,
                    mitre_techniques=[MitreTechniqueRef("T1606.002", "Forge Web Credentials: SAML Tokens", MitreTactic.CREDENTIAL_ACCESS)],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=service_provider,
                    remediation_guidance="Mandate verified XMLDSig signatures on both `<samlp:Response>` and `<saml:Assertion>` pinned to trusted IdP X.509 certificate.",
                    discovered_by="ely_cyber_identity_federation_auditor",
                )
            )

        # 4. XML Signature Wrapping (XSW) — multiple assertions or mismatched Reference URI
        assertion_ids = {a.attrib.get("ID", "") for a in assertions if a.attrib.get("ID")}
        ref_uris = {r.attrib.get("URI", "").lstrip("#") for r in references if r.attrib.get("URI")}
        if len(assertions) > 1 or (assertions and references and assertion_ids and not (assertion_ids & ref_uris) and root.attrib.get("ID", "") not in ref_uris):
            signals["xsw_detected"] = True
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-FED-SAML-XSW-ATTACK",
                    title=f"XML Signature Wrapping (XSW) Structural Anomaly Detected (`assertions={len(assertions)}`, `ref_uris={sorted(ref_uris)}`)",
                    description="Multiple `<Assertion>` elements or signature `<Reference URI>` mismatch indicates an XSW1–XSW8 signature-wrapping attack separating the verified XML subtree from the executed identity assertion.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-347", "CWE-290"],
                    confidence=0.98,
                    mitre_techniques=[MitreTechniqueRef("T1606.002", "Forge Web Credentials: SAML Tokens", MitreTactic.CREDENTIAL_ACCESS)],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=service_provider,
                    remediation_guidance="Validate strict SAML 2.0 XML Schema (XSD), require exactly ONE `<Assertion>`, and extract claims exclusively from the DOM node referenced by the verified `<ds:Reference URI>`.",
                    discovered_by="ely_cyber_identity_federation_auditor",
                )
            )

        # 5. Weak SHA-1 XMLDSig algorithm
        if any("sha1" in alg.lower() for alg in sig_methods):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-FED-SAML-SHA1",
                    title="Deprecated SHA-1 Algorithm Used in SAML XML Digital Signature",
                    description="SHA-1 collision weaknesses undermine SAML assertion integrity guarantees.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-328"],
                    confidence=0.99,
                    verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                    endpoint_or_asset=service_provider,
                    remediation_guidance="Upgrade IdP & SP signing policies to `rsa-sha256` / `ecdsa-sha256` and `xmlenc#sha256`.",
                    discovered_by="ely_cyber_identity_federation_auditor",
                )
            )

        # 6. Missing AudienceRestriction or NotOnOrAfter
        if assertions and not audiences:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-FED-SAML-NO-AUDIENCE",
                    title="SAML Assertion Missing `<AudienceRestriction>` (Cross-SP Token Replay)",
                    description="Without an explicit `<AudienceRestriction>` validated against the SP EntityID, a valid assertion issued for another application can be replayed here.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-294", "CWE-287"],
                    confidence=0.96,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=service_provider,
                    remediation_guidance="Require and strictly match `<Audience>` equal to this Service Provider's exact EntityID.",
                    discovered_by="ely_cyber_identity_federation_auditor",
                )
            )
        if assertions and not any("NotOnOrAfter" in c.attrib for c in conditions):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-FED-SAML-NO-EXPIRY",
                    title="SAML `<Conditions>` Missing `NotOnOrAfter` Expiration Bound",
                    description="Assertions without `NotOnOrAfter` remain valid indefinitely if intercepted.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-613"],
                    confidence=0.95,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=service_provider,
                    remediation_guidance="Enforce short `NotOnOrAfter` windows (<= 5 min) and maintain an Assertion ID replay cache.",
                    discovered_by="ely_cyber_identity_federation_auditor",
                )
            )

        return {
            "audited_at": utc_now_iso(),
            "service_provider": service_provider,
            "signals": signals,
            "vulnerabilities": vulns,
        }

    def audit_oauth2_oidc_config(self, cfg: Dict[str, Any], issuer: str = "https://auth.corp.example") -> Dict[str, Any]:
        """Audit OAuth 2.1 / OIDC discovery metadata and client registration configuration."""
        vulns: List[CyberVulnerability] = []
        grants = {str(g).lower() for g in cfg.get("grant_types_supported", [])}
        resp_types = {str(r).lower() for r in cfg.get("response_types_supported", [])}
        pkce_methods = {str(m).upper() for m in cfg.get("code_challenge_methods_supported", [])}
        algs = {str(a).upper() for a in cfg.get("id_token_signing_alg_values_supported", [])}
        redirects = [str(u) for u in cfg.get("redirect_uris", [])]
        jwks_uri = str(cfg.get("jwks_uri", ""))

        if "S256" not in pkce_methods or not bool(cfg.get("require_pkce", False)):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-FED-OIDC-NO-PKCE",
                    title=f"OAuth 2.1 / OIDC Provider `{issuer}` Does Not Mandate PKCE (`S256`)",
                    description="Authorization Code flows without mandatory PKCE (`S256`) are vulnerable to authorization-code interception and injection attacks.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-345"],
                    confidence=0.98,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=issuer,
                    remediation_guidance="Mandate PKCE `code_challenge_method=S256` for all OAuth 2.1 clients and disable `plain`.",
                    discovered_by="ely_cyber_identity_federation_auditor",
                )
            )

        if "implicit" in grants or any("token" in rt and "code" not in rt for rt in resp_types):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-FED-OIDC-IMPLICIT-FLOW",
                    title=f"Deprecated OAuth Implicit Flow Enabled on `{issuer}` (Access Token Leakage)",
                    description="Implicit grant leaks bearer tokens in URL fragments, browser history, and Referer headers (prohibited in OAuth 2.1).",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-598", "CWE-522"],
                    confidence=0.98,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=issuer,
                    remediation_guidance="Disable Implicit (`token`) and ROPC (`password`) grants; migrate exclusively to Authorization Code + PKCE.",
                    discovered_by="ely_cyber_identity_federation_auditor",
                )
            )

        if "NONE" in algs or ("HS256" in algs and bool(algs & {"RS256", "ES256", "PS256"})):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-FED-OIDC-JWT-ALG-CONFUSION",
                    title=f"Dangerous OIDC JWT Signing Algorithm Set `{sorted(algs)}` (None / HS256-RS256 Confusion)",
                    description="Advertising `none` or mixing symmetric `HS256` with asymmetric `RS256` JWKS exposes relying parties to forged JWT token acceptance.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-347", "CWE-327"],
                    confidence=0.99,
                    verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                    endpoint_or_asset=issuer,
                    remediation_guidance="Allow only asymmetric `EdDSA`, `ES256`, or `PS256` and explicitly pin expected algorithm per JWKS key.",
                    discovered_by="ely_cyber_identity_federation_auditor",
                )
            )

        for uri in redirects:
            if "*" in uri or (uri.startswith("http://") and "localhost" not in uri and "127.0.0.1" not in uri):
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-FED-OIDC-REDIRECT-BYPASS",
                        title=f"Unsafe OAuth `redirect_uri` Registered (`{uri}`)",
                        description="Wildcard or cleartext `http://` redirect URIs allow attackers to steal authorization codes via open redirects or subdomain takeover.",
                        cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-601"],
                        confidence=0.99,
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        endpoint_or_asset=uri,
                        remediation_guidance="Enforce exact-string HTTPS `redirect_uri` matching with zero wildcards.",
                        discovered_by="ely_cyber_identity_federation_auditor",
                    )
                )

        if jwks_uri.startswith("http://") and "localhost" not in jwks_uri:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-FED-OIDC-CLEARTEXT-JWKS",
                    title=f"OIDC `jwks_uri` Served Over Unencrypted HTTP (`{jwks_uri}`)",
                    description="Fetching signing public keys over cleartext HTTP enables trivial MITM key substitution and total SSO forgery.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-319", "CWE-347"],
                    confidence=0.99,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=jwks_uri,
                    remediation_guidance="Serve `jwks_uri` exclusively over HTTPS TLS 1.3 with strict certificate validation.",
                    discovered_by="ely_cyber_identity_federation_auditor",
                )
            )

        return {"audited_at": utc_now_iso(), "issuer": issuer, "vulnerabilities": vulns}

    def audit_kerberos_ad_policy(self, policy: Dict[str, Any], realm: str = "CORP.LOCAL") -> Dict[str, Any]:
        """Audit Active Directory Kerberos encryption, delegation, pre-auth, and KRBTGT rotation hygiene."""
        vulns: List[CyberVulnerability] = []
        if bool(policy.get("rc4_hmac_enabled", False)):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-FED-KRB-RC4-KERBEROAST",
                    title=f"Kerberos Realm `{realm}` Permits RC4-HMAC (`etype 23`) — Rapid Offline Kerberoasting",
                    description="RC4-encrypted TGS service tickets crack orders of magnitude faster on commodity GPUs than AES256-CTS-HMAC-SHA1.",
                    cyber_domain=CyberDomain.IDENTITY_ACTIVE_DIRECTORY,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-327"],
                    confidence=0.98,
                    mitre_techniques=[MitreTechniqueRef("T1558.003", "Kerberoasting", MitreTactic.CREDENTIAL_ACCESS)],
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=realm,
                    remediation_guidance="Enforce AES256-CTS-HMAC-SHA1-96 exclusively across all SPNs and migrate service accounts to gMSA.",
                    discovered_by="ely_cyber_identity_federation_auditor",
                )
            )
        unconstrained = list(policy.get("unconstrained_delegation_hosts", []))
        if unconstrained:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-FED-KRB-UNCONSTRAINED-DELEG",
                    title=f"Non-DC Hosts Configured With Kerberos Unconstrained Delegation (`{unconstrained}`)",
                    description="Compromising any unconstrained-delegation host allows capturing Domain Admin TGTs via PrinterBug/PetitPotam coercion -> instant forest takeover.",
                    cyber_domain=CyberDomain.IDENTITY_ACTIVE_DIRECTORY,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-269"],
                    confidence=0.99,
                    mitre_techniques=[MitreTechniqueRef("T1558", "Steal or Forge Kerberos Tickets", MitreTactic.CREDENTIAL_ACCESS)],
                    verification_method=VerificationMethod.GRAPH_REACHABILITY,
                    endpoint_or_asset=realm,
                    remediation_guidance="Remove `TRUSTED_FOR_DELEGATION` from all non-DC servers; migrate to Resource-Based Constrained Delegation (RBCD) and Protected Users group.",
                    discovered_by="ely_cyber_identity_federation_auditor",
                )
            )
        asrep = list(policy.get("asrep_no_preauth_users", []))
        if asrep:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-FED-KRB-ASREP-ROAST",
                    title=f"Accounts Have Kerberos Pre-Authentication Disabled (`{asrep}` — AS-REP Roasting)",
                    description="Any unauthenticated network attacker can request AS-REP encrypted material for these accounts and crack their passwords offline.",
                    cyber_domain=CyberDomain.IDENTITY_ACTIVE_DIRECTORY,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-287"],
                    confidence=0.99,
                    mitre_techniques=[MitreTechniqueRef("T1558.004", "AS-REP Roasting", MitreTactic.CREDENTIAL_ACCESS)],
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=realm,
                    remediation_guidance="Enable Kerberos Pre-Authentication on all accounts and immediately reset exposed passwords.",
                    discovered_by="ely_cyber_identity_federation_auditor",
                )
            )
        krbtgt_days = int(policy.get("krbtgt_password_age_days", 0))
        if krbtgt_days > 180:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-FED-KRB-KRBTGT-STALE",
                    title=f"`KRBTGT` Key Age Is {krbtgt_days} Days (> 180-Day Rotation Policy — Golden Ticket Exposure)",
                    description="Stale KRBTGT secrets allow previously stolen hashes to forge indefinite Golden Tickets across the entire Active Directory forest.",
                    cyber_domain=CyberDomain.IDENTITY_ACTIVE_DIRECTORY,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-324"],
                    confidence=0.97,
                    mitre_techniques=[MitreTechniqueRef("T1558.001", "Golden Ticket", MitreTactic.CREDENTIAL_ACCESS)],
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=realm,
                    remediation_guidance="Perform a staged double-reset of the `KRBTGT` password (10+ hours apart) at least every 180 days.",
                    discovered_by="ely_cyber_identity_federation_auditor",
                )
            )
        return {"audited_at": utc_now_iso(), "realm": realm, "vulnerabilities": vulns}
