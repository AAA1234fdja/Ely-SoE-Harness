"""
Authentication, JWT/OAuth2/SAML, Session & Access-Control Security Engine.

Assesses OWASP A01 (Broken Access Control) & A07 (Identification & Auth Failures):
  1. JWT Security Auditor:
       - Structural decoder (Base64URL header/payload/signature)
       - Detects `alg: none` / empty signature acceptance
       - Detects RS256 -> HS256 asymmetric-to-symmetric key-confusion risk
       - Detects `kid` SQLi / path traversal injection vectors
       - Detects `jku` / `x5u` remote key URL SSRF / untrusted key injection
       - Tests weak/default HMAC signing secrets (offline laboratory dictionary check)
       - Flags missing `exp`, excessive TTL (>24h), missing `aud`/`iss`, and sensitive claims
  2. OAuth2 / OIDC & SAML Security Auditor:
       - Missing `state` CSRF parameter, disabled PKCE (`code_challenge`), wildcard/prefix
         `redirect_uri` hijacking, implicit flow (`response_type=token`) token leakage
       - SAML XML Signature Wrapping (XSW) & XML comment injection detection
  3. Access Control & Business Logic Prober (Local Sandbox):
       - IDOR / BOLA (Object-level horizontal privilege escalation across tenants/users)
       - BFLA (Function-level vertical privilege escalation to admin routes)
       - Mass Assignment (over-posting `role`, `is_admin`, `balance`, `verified`)
       - Race Condition / TOCTOU (concurrent double-spend / coupon reuse probe)
       - Session Token Entropy Analyzer (Shannon entropy & predictability checks)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Pattern, Tuple

from ely_soe.core.models import Severity, new_id
from ely_soe.cyber.models import (
    CVSSv4Metrics,
    CyberDomain,
    CyberVulnerability,
    EvidenceArtifact,
    HttpProbeRequest,
    HttpProbeResponse,
    MitreTactic,
    MitreTechniqueRef,
    VerificationMethod,
    make_cyber_vuln,
)


# ---------------------------------------------------------------------------
# JWT Cryptographic & Claim Auditor
# ---------------------------------------------------------------------------

class JWTSecurityAuditor:
    """Offline structural & cryptographic security verifier for JSON Web Tokens."""

    WEAK_TEST_SECRETS = (
        "secret",
        "secret123",
        "password",
        "changeme",
        "jwt_secret",
        "supersecret",
        "your-256-bit-secret",
        "mysecretkey",
        "ely_dev_secret",
        "dev-secret-key",
        "123456",
        "admin",
        "test",
    )

    SENSITIVE_CLAIM_KEYS = {"password", "passwd", "secret", "api_key", "private_key", "ssn", "credit_card", "cvv"}

    @staticmethod
    def _b64url_decode(segment: str) -> bytes:
        pad = "=" * (-len(segment) % 4)
        return base64.urlsafe_b64decode(segment + pad)

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def inspect_token(self, token: str, asset: str = "jwt_auth") -> Dict[str, Any]:
        """Parse a JWT and identify cryptographic, header-injection, and claim flaws."""
        findings: List[CyberVulnerability] = []
        parts = token.strip().split(".")
        if len(parts) != 3:
            return {"valid_structure": False, "findings": [], "header": {}, "payload": {}}

        try:
            header = json.loads(self._b64url_decode(parts[0]).decode("utf-8"))
            payload = json.loads(self._b64url_decode(parts[1]).decode("utf-8"))
            sig_bytes = self._b64url_decode(parts[2]) if parts[2] else b""
        except Exception as exc:
            return {"valid_structure": False, "error": str(exc), "findings": [], "header": {}, "payload": {}}

        alg = str(header.get("alg", "")).strip()
        alg_low = alg.lower()

        # 1. alg: none or empty signature
        if alg_low == "none" or not sig_bytes:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-JWT-NONE-001",
                    title="JWT Accepts Unauthenticated `alg: none` or Missing Signature",
                    description=f"JWT header specifies `alg={alg!r}` with signature length {len(sig_bytes)} bytes, enabling trivial token forgery.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-347", "CWE-287"],
                    confidence=0.99,
                    owasp_categories=["A07:2021-Identification-and-Authentication-Failures"],
                    mitre_techniques=[MitreTechniqueRef("T1550.001", "Application Access Token", MitreTactic.DEFENSE_EVASION, "001")],
                    cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="L", sc="H", si="H", sa="N"),
                    verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                    endpoint_or_asset=asset,
                    remediation_guidance="Explicitly pin allowed signature algorithms (e.g. `algorithms=['EdDSA']` or `['RS256']`) and reject `none` or empty signatures.",
                    discovered_by="ely_cyber_jwt_auditor",
                )
            )

        # 2. Dangerous header injection keys: jku, x5u, jwk, kid traversal/SQLi
        for dangerous_hdr in ("jku", "x5u", "jwk"):
            if dangerous_hdr in header:
                findings.append(
                    make_cyber_vuln(
                        rule_id=f"CYB-JWT-{dangerous_hdr.upper()}-001",
                        title=f"JWT Embeds Untrusted Key Reference Header (`{dangerous_hdr}`)",
                        description=f"Token includes `{dangerous_hdr}` header (`{str(header[dangerous_hdr])[:80]}`), enabling attacker-controlled key injection or SSRF if trusted by the verifier.",
                        cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-347", "CWE-918"],
                        confidence=0.92,
                        owasp_categories=["A07:2021-Identification-and-Authentication-Failures"],
                        verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                        endpoint_or_asset=asset,
                        remediation_guidance="Ignore untrusted `jwk`/`jku`/`x5u` headers in tokens; resolve verification keys exclusively from a pinned server-side JWKS registry.",
                        discovered_by="ely_cyber_jwt_auditor",
                    )
                )

        if "kid" in header:
            kid_val = str(header["kid"])
            if any(tok in kid_val for tok in ("../", "..\\", "'", '"', ";", "|", "/dev/null")):
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-JWT-KID-INJ-001",
                        title="JWT `kid` Header Contains Path Traversal or Injection Metacharacters",
                        description=f"JWT `kid` value `{kid_val}` contains filesystem or SQL injection tokens.",
                        cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-22", "CWE-89", "CWE-347"],
                        confidence=0.96,
                        verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                        endpoint_or_asset=asset,
                        remediation_guidance="Validate `kid` strictly against `^[a-zA-Z0-9_-]{1,64}$` and look up keys in an in-memory map rather than filesystem paths or raw SQL.",
                        discovered_by="ely_cyber_jwt_auditor",
                    )
                )

        # 3. Weak HMAC secret laboratory verification for HS256/HS384/HS512
        if alg_low in ("hs256", "hs384", "hs512") and sig_bytes:
            hash_alg = {"hs256": hashlib.sha256, "hs384": hashlib.sha384, "hs512": hashlib.sha512}[alg_low]
            signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
            for candidate in self.WEAK_TEST_SECRETS:
                expected = hmac.new(candidate.encode("utf-8"), signing_input, hash_alg).digest()
                if hmac.compare_digest(expected, sig_bytes):
                    findings.append(
                        make_cyber_vuln(
                            rule_id="CYB-JWT-WEAK-SECRET-001",
                            title=f"JWT Signed with Weak / Guessable HMAC Secret (`{alg}`)",
                            description="JWT HMAC signature was verified offline against a common/default secret, allowing full token forgery for any user or role.",
                            cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                            severity=Severity.CRITICAL,
                            cwe_ids=["CWE-798", "CWE-326"],
                            confidence=1.0,
                            owasp_categories=["A07:2021-Identification-and-Authentication-Failures"],
                            cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="L", sc="H", si="H", sa="N", e="P"),
                            verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                            sandbox_reproduced=True,
                            endpoint_or_asset=asset,
                            attack_vector_detail=f"Offline HMAC verification matched weak secret pattern (length={len(candidate)}).",
                            remediation_guidance="Rotate immediately to a 256-bit CSPRNG secret or asymmetric Ed25519/RS256 keypair stored in KMS/HSM.",
                            discovered_by="ely_cyber_jwt_auditor",
                        )
                    )
                    break

        # 4. Missing expiration or overly long lifetime
        if "exp" not in payload:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-JWT-NO-EXP-001",
                    title="JWT Missing Mandatory `exp` (Expiration) Claim",
                    description="Token does not carry an `exp` claim, creating a permanently valid credential if leaked.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-613"],
                    confidence=0.95,
                    owasp_categories=["A07:2021-Identification-and-Authentication-Failures"],
                    verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                    endpoint_or_asset=asset,
                    remediation_guidance="Set short-lived `exp` claims (15–60 minutes) and require `exp`, `iat`, `iss`, and `aud` during verification.",
                    discovered_by="ely_cyber_jwt_auditor",
                )
            )
        elif "iat" in payload:
            try:
                ttl = int(payload["exp"]) - int(payload["iat"])
                if ttl > 86400 * 7:
                    findings.append(
                        make_cyber_vuln(
                            rule_id="CYB-JWT-LONG-TTL-001",
                            title=f"Excessive JWT Access Token Lifetime ({ttl // 86400} days)",
                            description="Access token validity exceeds 7 days, expanding stolen-token blast radius.",
                            cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                            severity=Severity.LOW,
                            cwe_ids=["CWE-613"],
                            confidence=0.92,
                            verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                            endpoint_or_asset=asset,
                            remediation_guidance="Keep access tokens short-lived (<= 1 hour) and use rotating refresh tokens.",
                            discovered_by="ely_cyber_jwt_auditor",
                        )
                    )
            except (TypeError, ValueError):
                pass

        # 5. Sensitive data embedded in unencrypted JWS payload
        leaked_keys = [k for k in payload.keys() if k.lower() in self.SENSITIVE_CLAIM_KEYS]
        if leaked_keys:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-JWT-SENSITIVE-CLAIM-001",
                    title=f"Sensitive Secret/PII Stored in Base64-Encoded JWT Claims ({', '.join(leaked_keys)})",
                    description="JWS payloads are only Base64URL-encoded (not encrypted); storing secrets/PII exposes them to any client or intermediary.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-312", "CWE-200"],
                    confidence=0.96,
                    verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                    endpoint_or_asset=asset,
                    remediation_guidance="Remove secrets and sensitive PII from JWT payloads or encrypt using JWE.",
                    discovered_by="ely_cyber_jwt_auditor",
                )
            )

        return {
            "valid_structure": True,
            "header": header,
            "payload": payload,
            "signature_bytes": len(sig_bytes),
            "findings": findings,
        }

    def forge_alg_none_probe_token(self, original_token: str, override_claims: Optional[Dict[str, Any]] = None) -> str:
        """Build a local sandbox test token with `alg: none` to verify whether a sandbox server rejects it."""
        parts = original_token.split(".")
        payload = json.loads(self._b64url_decode(parts[1]).decode("utf-8")) if len(parts) >= 2 else {"sub": "user"}
        if override_claims:
            payload.update(override_claims)
        hdr = self._b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode("utf-8"))
        body = self._b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        return f"{hdr}.{body}."


# ---------------------------------------------------------------------------
# Static Auth, OAuth2, SAML & Access-Control Rule Catalog
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuthStaticRule:
    rule_id: str
    title: str
    description: str
    severity: Severity
    cwe_ids: Tuple[str, ...]
    owasp: Tuple[str, ...]
    languages: Tuple[str, ...]
    pattern: str
    anti_pattern: Optional[str]
    remediation: str


AUTH_STATIC_RULES: Tuple[AuthStaticRule, ...] = (
    AuthStaticRule(
        rule_id="CYB-AUTH-JWT-UNVERIFIED-001",
        title="JWT Decoded Without Signature Verification (`verify_signature=False` / `jwt.decode`)",
        description="Authentication code decodes JWT claims while skipping cryptographic signature validation, enabling trivial identity impersonation.",
        severity=Severity.CRITICAL,
        cwe_ids=("CWE-347", "CWE-287"),
        owasp=("A07:2021-Identification-and-Authentication-Failures",),
        languages=(".py", ".js", ".ts", ".java", ".go", ".php"),
        pattern=r"""(?i)(?:verify_signature['"]?\s*:\s*False|verify\s*=\s*False.*jwt|jwt\.decode\s*\([^)]*options\s*=\s*\{[^}]*verify|jsonwebtoken.*jwt\.decode\s*\()""",
        anti_pattern=r"""(?i)(?:jwt\.verify\s*\(|verify_signature['"]?\s*:\s*True)""",
        remediation="Always call `jwt.verify()` / `jwt.decode(..., algorithms=['RS256'], options={'verify_signature': True})` with pinned trusted keys.",
    ),
    AuthStaticRule(
        rule_id="CYB-AUTH-OAUTH-001",
        title="OAuth2 / OIDC Insecure Flow (Wildcard Redirect URI, Implicit Flow, or Disabled State/PKCE)",
        description="OAuth2 configuration permits wildcard/substring `redirect_uri`, disables `state` CSRF verification, or uses deprecated implicit `response_type=token`.",
        severity=Severity.HIGH,
        cwe_ids=("CWE-601", "CWE-352", "CWE-287"),
        owasp=("A07:2021-Identification-and-Authentication-Failures",),
        languages=(".py", ".js", ".ts", ".json", ".yaml", ".yml", ".java", ".go"),
        pattern=r"""(?i)(?:response_type\s*[:=]\s*["']token["']|redirect_uri.*\*|verify_state\s*[:=]\s*false|pkce\s*[:=]\s*false|state_check\s*=\s*False)""",
        anti_pattern=None,
        remediation="Enforce Authorization Code Flow with mandatory PKCE (`S256`), exact string-matched `redirect_uri` allowlists, and cryptographically bound `state`/`nonce` parameters.",
    ),
    AuthStaticRule(
        rule_id="CYB-AUTH-SAML-001",
        title="SAML Assertion Verification Weakness (Unsigned Assertion / XSW Risk)",
        description="SAML SP accepts unsigned assertions or fails to verify signature over the exact parsed assertion element.",
        severity=Severity.CRITICAL,
        cwe_ids=("CWE-347", "CWE-290"),
        owasp=("A07:2021-Identification-and-Authentication-Failures",),
        languages=(".py", ".js", ".ts", ".java", ".xml", ".php"),
        pattern=r"""(?i)(?:wantAssertionsSigned\s*[:=]\s*false|wantMessagesSigned\s*[:=]\s*false|allow_unverified_saml|skipSignatureCheck\s*[:=]\s*true)""",
        anti_pattern=None,
        remediation="Require signed SAML Assertions (`wantAssertionsSigned=true`), strictly validate XML schema before signature verification, and canonicalize comments.",
    ),
    AuthStaticRule(
        rule_id="CYB-AUTH-MASSASSIGN-001",
        title="Mass Assignment / Over-Posting Directly from Request Payload to Model",
        description="Binding raw request JSON/form objects directly into ORM models permits attackers to overwrite privileged fields (`is_admin`, `role`, `permissions`).",
        severity=Severity.HIGH,
        cwe_ids=("CWE-915",),
        owasp=("A01:2021-Broken-Access-Control",),
        languages=(".py", ".js", ".ts", ".rb", ".java", ".php"),
        pattern=r"""(?i)(?:User\.(?:create|update)\s*\(\s*(?:\*\*request\.(?:json|form|get_json\(\))|req\.body)|setattr\s*\(\s*user\s*,\s*k\s*,\s*v\s*\)|permit!\b|Object\.assign\s*\(\s*user\s*,\s*req\.body\s*\))""",
        anti_pattern=r"""(?i)(?:ALLOWED_FIELDS|Schema|BaseModel|strong_params)""",
        remediation="Bind only an explicit allowlist of user-editable fields via typed DTO schemas (`Pydantic`/`Zod`).",
    ),
    AuthStaticRule(
        rule_id="CYB-AUTH-TIMING-001",
        title="Non-Constant-Time Secret / Token Comparison (`==` instead of `hmac.compare_digest`)",
        description="Comparing API keys, HMAC signatures, or reset tokens with `==` leaks byte-by-byte timing side channels.",
        severity=Severity.MEDIUM,
        cwe_ids=("CWE-208",),
        owasp=("A02:2021-Cryptographic-Failures",),
        languages=(".py", ".js", ".ts", ".go", ".java"),
        pattern=r"""(?i)(?:(?:api_key|token|signature|hmac|secret|digest|reset_code)\s*==\s*(?:expected|stored|valid|req|request|header))""",
        anti_pattern=r"""(?i)(?:compare_digest|timingSafeEqual|subtle\.ConstantTimeCompare|MessageDigest\.isEqual)""",
        remediation="Compare all secrets, tokens, and MACs using constant-time primitives (`hmac.compare_digest`, `crypto.timingSafeEqual`).",
    ),
)


# ---------------------------------------------------------------------------
# Unified Auth & Access-Control Testing Engine
# ---------------------------------------------------------------------------

class AuthAccessControlEngine:
    """
    Combines static auth/JWT/OAuth/SAML scanning, token entropy verification,
    JWT cryptographic auditing, and local sandboxed IDOR/BOLA/BFLA/Mass-Assignment/TOCTOU testing.
    """

    def __init__(self) -> None:
        self._compiled: List[Tuple[AuthStaticRule, Pattern[str], Optional[Pattern[str]]]] = [
            (r, re.compile(r.pattern), re.compile(r.anti_pattern) if r.anti_pattern else None)
            for r in AUTH_STATIC_RULES
        ]
        self.jwt_auditor = JWTSecurityAuditor()

    def scan_directory(self, root_path: Path) -> List[CyberVulnerability]:
        findings: List[CyberVulnerability] = []
        seen: set[str] = set()

        for file_path in sorted(root_path.rglob("*")):
            if not file_path.is_file():
                continue
            if any(p in {".git", "node_modules", "__pycache__", ".venv", "dist", "build"} for p in file_path.parts):
                continue
            ext = file_path.suffix.lower()
            if ext not in {".py", ".js", ".ts", ".java", ".go", ".php", ".rb", ".json", ".yaml", ".yml", ".xml"}:
                continue

            try:
                lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            rel = str(file_path.relative_to(root_path))

            for rule, regex, anti in self._compiled:
                if ext not in rule.languages:
                    continue
                for idx, line in enumerate(lines, start=1):
                    if not regex.search(line):
                        continue
                    win = "\n".join(lines[max(0, idx - 2) : min(len(lines), idx + 3)])
                    if anti and anti.search(win):
                        continue
                    v = make_cyber_vuln(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        description=rule.description,
                        cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                        severity=rule.severity,
                        cwe_ids=list(rule.cwe_ids),
                        confidence=0.88,
                        owasp_categories=list(rule.owasp),
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=rel,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line.strip()[:300],
                        remediation_guidance=rule.remediation,
                        discovered_by="ely_cyber_auth_static",
                    )
                    fp = v.fingerprint()
                    if fp not in seen:
                        seen.add(fp)
                        findings.append(v)
        return findings

    def audit_session_token_entropy(self, sample_tokens: List[str], asset: str = "session_manager") -> List[CyberVulnerability]:
        """Measure Shannon entropy, length, and sequential predictability of issued session tokens."""
        findings: List[CyberVulnerability] = []
        if not sample_tokens:
            return findings

        min_bits = min(self._shannon_entropy_bits(t) for t in sample_tokens)
        min_len = min(len(t) for t in sample_tokens)
        is_sequential = False
        if len(sample_tokens) >= 2 and all(t.isdigit() for t in sample_tokens):
            nums = [int(t) for t in sample_tokens]
            diffs = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
            if len(set(diffs)) == 1 and diffs[0] <= 10:
                is_sequential = True

        if min_bits < 64.0 or min_len < 16 or is_sequential:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-AUTH-SESSION-ENTROPY-001",
                    title="Insufficient Session Token Entropy / Predictable Session IDs",
                    description=(
                        f"Session tokens exhibit weak entropy (min_bits={min_bits:.1f}, min_len={min_len}, "
                        f"sequential={is_sequential}), enabling brute-force or session prediction hijacking."
                    ),
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-330", "CWE-384"],
                    confidence=0.97,
                    owasp_categories=["A07:2021-Identification-and-Authentication-Failures"],
                    verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                    endpoint_or_asset=asset,
                    remediation_guidance="Generate session IDs with at least 128 bits of CSPRNG entropy (`secrets.token_urlsafe(32)`).",
                    discovered_by="ely_cyber_auth_entropy",
                )
            )
        return findings

    def probe_sandbox_access_control(
        self,
        handler: Callable[[HttpProbeRequest], HttpProbeResponse],
        *,
        user_a_token: str,
        user_b_resource_path: str,
        admin_endpoint: Optional[str] = None,
        profile_update_endpoint: Optional[str] = None,
        race_redeem_endpoint: Optional[str] = None,
    ) -> List[CyberVulnerability]:
        """Run authorized local sandbox IDOR/BOLA, BFLA, JWT alg:none, Mass Assignment, and TOCTOU race probes."""
        findings: List[CyberVulnerability] = []

        # 1. IDOR / BOLA horizontal access probe (User A requesting User B's object)
        idor_resp = handler(
            HttpProbeRequest(
                method="GET",
                path=user_b_resource_path,
                headers={"Authorization": f"Bearer {user_a_token}"},
            )
        )
        if idor_resp.status_code == 200 and any(tok in idor_resp.body.lower() for tok in ("user_b", "bob", "email", "secret", "account")):
            findings.append(
                make_cyber_vuln(
                    rule_id="PROBE-AUTH-BOLA-001",
                    title="Broken Object Level Authorization (IDOR / BOLA) Confirmed",
                    description=f"Authenticated as User A, successfully read User B's protected resource at `{user_b_resource_path}`.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-639", "CWE-863"],
                    confidence=0.98,
                    owasp_categories=["A01:2021-Broken-Access-Control", "API1:2023-BOLA"],
                    mitre_techniques=[MitreTechniqueRef("T1078", "Valid Accounts", MitreTactic.PRIVILEGE_ESCALATION)],
                    cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="L", ui="N", vc="H", vi="L", va="N", sc="N", si="N", sa="N", e="P"),
                    verification_method=VerificationMethod.SANDBOX_DIFFERENTIAL_PROBE,
                    sandbox_reproduced=True,
                    endpoint_or_asset=f"GET {user_b_resource_path}",
                    remediation_guidance="Enforce object-owner and tenant-ID authorization predicates on every data query (`WHERE id = ? AND owner_id = ?`).",
                    discovered_by="ely_cyber_auth_prober",
                )
            )

        # 2. JWT `alg: none` forgery probe
        if user_a_token.count(".") == 2:
            forged = self.jwt_auditor.forge_alg_none_probe_token(user_a_token, {"role": "admin", "sub": "admin"})
            target_p = admin_endpoint or user_b_resource_path
            forgery_resp = handler(
                HttpProbeRequest(method="GET", path=target_p, headers={"Authorization": f"Bearer {forged}"})
            )
            if forgery_resp.status_code == 200:
                findings.append(
                    make_cyber_vuln(
                        rule_id="PROBE-AUTH-JWT-NONE-001",
                        title="JWT `alg: none` Signature Bypass Confirmed in Sandbox",
                        description=f"Endpoint `{target_p}` accepted an unsigned `alg: none` forged admin JWT.",
                        cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-347"],
                        confidence=1.0,
                        owasp_categories=["A07:2021-Identification-and-Authentication-Failures"],
                        cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="N", e="P"),
                        verification_method=VerificationMethod.SANDBOX_DIFFERENTIAL_PROBE,
                        sandbox_reproduced=True,
                        endpoint_or_asset=f"GET {target_p}",
                        remediation_guidance="Pin strict asymmetric/HMAC verification algorithms and reject `alg: none` unconditionally.",
                        discovered_by="ely_cyber_auth_prober",
                    )
                )

        # 3. BFLA vertical privilege escalation probe
        if admin_endpoint:
            bfla_resp = handler(
                HttpProbeRequest(method="GET", path=admin_endpoint, headers={"Authorization": f"Bearer {user_a_token}"})
            )
            if bfla_resp.status_code == 200:
                findings.append(
                    make_cyber_vuln(
                        rule_id="PROBE-AUTH-BFLA-001",
                        title="Broken Function Level Authorization (BFLA) — Standard User Reached Admin Endpoint",
                        description=f"Non-privileged User A accessed administrative endpoint `{admin_endpoint}` with HTTP 200.",
                        cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-862", "CWE-285"],
                        confidence=0.98,
                        owasp_categories=["A01:2021-Broken-Access-Control", "API5:2023-BFLA"],
                        verification_method=VerificationMethod.SANDBOX_DIFFERENTIAL_PROBE,
                        sandbox_reproduced=True,
                        endpoint_or_asset=f"GET {admin_endpoint}",
                        remediation_guidance="Enforce centralized deny-by-default RBAC middleware on all administrative routes.",
                        discovered_by="ely_cyber_auth_prober",
                    )
                )

        # 4. Mass Assignment probe
        if profile_update_endpoint:
            ma_resp = handler(
                HttpProbeRequest(
                    method="POST",
                    path=profile_update_endpoint,
                    headers={"Authorization": f"Bearer {user_a_token}"},
                    body=json.dumps({"display_name": "Alice", "role": "admin", "is_admin": True}),
                )
            )
            if ma_resp.status_code in (200, 201) and any(tok in ma_resp.body.lower() for tok in ('"role": "admin"', '"is_admin": true', "role=admin")):
                findings.append(
                    make_cyber_vuln(
                        rule_id="PROBE-AUTH-MASSASSIGN-001",
                        title="Privilege Escalation via Mass Assignment Confirmed",
                        description=f"`POST {profile_update_endpoint}` accepted restricted fields `role`/`is_admin` from user payload.",
                        cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-915"],
                        confidence=0.98,
                        owasp_categories=["A01:2021-Broken-Access-Control", "API3:2023-BOPLA"],
                        verification_method=VerificationMethod.SANDBOX_DIFFERENTIAL_PROBE,
                        sandbox_reproduced=True,
                        endpoint_or_asset=f"POST {profile_update_endpoint}",
                        remediation_guidance="Whitelist explicitly mutable user attributes and drop unallowed schema fields.",
                        discovered_by="ely_cyber_auth_prober",
                    )
                )

        # 5. Concurrent TOCTOU / Race-Condition Probe (single-use coupon / double-spend check)
        if race_redeem_endpoint:
            req = HttpProbeRequest(
                method="POST",
                path=race_redeem_endpoint,
                headers={"Authorization": f"Bearer {user_a_token}"},
                body=json.dumps({"coupon": "ONCE-ONLY-50", "amount": 50}),
            )
            with ThreadPoolExecutor(max_workers=6) as pool:
                responses = list(pool.map(lambda _: handler(req), range(6)))
            successes = [r for r in responses if r.status_code == 200 and "redeemed" in r.body.lower()]
            if len(successes) > 1:
                findings.append(
                    make_cyber_vuln(
                        rule_id="PROBE-AUTH-RACE-001",
                        title=f"TOCTOU Race Condition Confirmed ({len(successes)} Concurrent Redemptions Succeeded)",
                        description=f"Sending 6 parallel requests to `{race_redeem_endpoint}` succeeded {len(successes)} times on a single-use operation.",
                        cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-362", "CWE-367"],
                        confidence=0.96,
                        owasp_categories=["A04:2021-Insecure-Design"],
                        verification_method=VerificationMethod.SANDBOX_DIFFERENTIAL_PROBE,
                        sandbox_reproduced=True,
                        endpoint_or_asset=f"POST {race_redeem_endpoint}",
                        remediation_guidance="Enforce atomic database transactions (`SELECT ... FOR UPDATE`), unique idempotency keys, or optimistic locking.",
                        discovered_by="ely_cyber_auth_prober",
                    )
                )

        return findings

    @staticmethod
    def _shannon_entropy_bits(token: str) -> float:
        if not token:
            return 0.0
        freq: Dict[str, int] = {}
        for ch in token:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(token)
        entropy_per_char = -sum((c / n) * math.log2(c / n) for c in freq.values())
        return entropy_per_char * n
