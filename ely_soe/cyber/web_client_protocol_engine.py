"""
Client-Side, HTTP Protocol & Modern Web Transport Security Engine.

Assesses generalized client-side & HTTP transport vulnerability classes via
multi-language static analysis, HTTP wire-frame protocol state verification,
and authorized local sandboxed probing:
  - Cross-Site Scripting (Reflected XSS, Stored XSS, DOM XSS, mXSS, Unsafe React/Vue/Angular sinks)
  - Content-Security-Policy (CSP) Weakness & Bypass Auditing (`unsafe-inline`, `unsafe-eval`, wildcard CDN)
  - Cross-Site Request Forgery (CSRF) & Cookie Attribute Auditing (`HttpOnly`, `Secure`, `SameSite`)
  - Cross-Origin Resource Sharing (CORS) Origin Reflection & `null` Origin + Credentials Abuse
  - Prototype Pollution (`__proto__`, `constructor.prototype`, unsafe deep merge)
  - Open Redirect & Host Header Injection (Password Reset Poisoning)
  - HTTP Request Smuggling (CL.TE, TE.CL, TE.TE obfuscated Transfer-Encoding, H2.CL pseudo-header mismatch)
  - Web Cache Poisoning (unkeyed `X-Forwarded-Host` / `X-Original-URL` / `X-Host` reflection)
  - WebSocket Cross-Site WebSocket Hijacking (CSWSH — missing `Origin` validation)
"""

from __future__ import annotations

import re
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
# Static Client-Side & HTTP Protocol Rules
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ClientProtocolRule:
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
    secure_example: str


CLIENT_PROTOCOL_RULES: Tuple[ClientProtocolRule, ...] = (
    ClientProtocolRule(
        rule_id="CYB-WEB-XSS-001",
        title="DOM-Based Cross-Site Scripting Sink (`innerHTML` / `dangerouslySetInnerHTML` / `v-html`)",
        description="Direct assignment of unescaped data to HTML DOM execution sinks permits arbitrary JavaScript execution in the victim browser origin.",
        severity=Severity.HIGH,
        cwe_ids=("CWE-79",),
        owasp=("A03:2021-Injection",),
        languages=(".js", ".ts", ".jsx", ".tsx", ".html", ".vue"),
        pattern=r"""(?i)(?:\.innerHTML\s*=|\.outerHTML\s*=|document\.write(?:ln)?\s*\(|dangerouslySetInnerHTML\s*=\s*\{\{|v-html\s*=|bypassSecurityTrustHtml\s*\()""",
        anti_pattern=r"""(?i)(?:DOMPurify\.sanitize|sanitizeHtml|escapeHtml|textContent)""",
        remediation="Render untrusted text via `textContent` or framework auto-escaping; sanitize unavoidable rich HTML strictly with DOMPurify.",
        secure_example="element.textContent = userProvidedTitle;",
    ),
    ClientProtocolRule(
        rule_id="CYB-WEB-XSS-002",
        title="Server-Side Template Auto-Escape Disabled (`|safe`, `autoescape=False`, `mark_safe`)",
        description="Disabling template HTML escaping or marking dynamic data as safe introduces Reflected/Stored XSS.",
        severity=Severity.HIGH,
        cwe_ids=("CWE-79",),
        owasp=("A03:2021-Injection",),
        languages=(".py", ".html", ".jinja", ".j2", ".erb", ".twig"),
        pattern=r"""(?i)(?:autoescape\s*=\s*False|mark_safe\s*\(|\|\s*safe\b|Markup\s*\(\s*f["']|html_safe\b)""",
        anti_pattern=r"""(?i)(?:bleach\.clean|nh3\.clean|escape\s*\()""",
        remediation="Keep template auto-escaping enabled globally and never pass untrusted input into `mark_safe` or `|safe`.",
        secure_example="env = Environment(autoescape=select_autoescape(['html', 'xml']))",
    ),
    ClientProtocolRule(
        rule_id="CYB-WEB-CORS-001",
        title="Permissive CORS Policy with Credentials (`Origin` Reflection or Wildcard)",
        description="Combining `Access-Control-Allow-Credentials: true` with reflected `Origin` headers or wildcard `*` allows cross-origin session/data theft.",
        severity=Severity.HIGH,
        cwe_ids=("CWE-942", "CWE-346"),
        owasp=("A05:2021-Security-Misconfiguration",),
        languages=(".py", ".js", ".ts", ".java", ".go", ".php", ".rb"),
        pattern=r"""(?i)(?:Access-Control-Allow-Origin['"]?\s*[,:=]\s*(?:req\.headers\.origin|request\.headers\.get\(['"]Origin['"]\)|\*\s*['"])|supports_credentials\s*=\s*True.*origins\s*=\s*['"]\*['"]|credentials\s*:\s*true.*origin\s*:\s*(?:true|['"]\*['"]))""",
        anti_pattern=r"""(?i)(?:ALLOWED_ORIGINS|origin\s+in\s+TRUSTED_ORIGINS)""",
        remediation="Validate `Origin` strictly against an exact allowlist of trusted HTTPS origins and never combine wildcards with `Access-Control-Allow-Credentials: true`.",
        secure_example="if origin in ALLOWED_ORIGINS: resp.headers['Access-Control-Allow-Origin'] = origin",
    ),
    ClientProtocolRule(
        rule_id="CYB-WEB-PROTO-001",
        title="JavaScript Prototype Pollution via Recursive Object Merge / Dynamic Bracket Assignment",
        description="Unsanitized recursive object merges or bracket writes (`target[key] = val`) allow attackers to inject `__proto__`, `constructor`, or `prototype` properties.",
        severity=Severity.HIGH,
        cwe_ids=("CWE-1321",),
        owasp=("A08:2021-Software-and-Data-Integrity-Failures",),
        languages=(".js", ".ts", ".jsx", ".tsx"),
        pattern=r"""(?i)(?:for\s*\(\s*(?:let|const|var)\s+\w+\s+in\s+\w+\s*\).*?\[\s*\w+\s*\]\s*=|_\.merge\s*\(|lodash\.merge\s*\(|Object\.assign\s*\([^,]+,\s*JSON\.parse\s*\()""",
        anti_pattern=r"""(?i)(?:__proto__|constructor|Object\.create\s*\(\s*null\s*\)|hasOwnProperty)""",
        remediation="Reject `__proto__`, `constructor`, and `prototype` keys during merges and use `Object.create(null)` or `Map` for untrusted key-value dictionaries.",
        secure_example="if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;",
    ),
    ClientProtocolRule(
        rule_id="CYB-WEB-CSRF-001",
        title="CSRF Protection Disabled or Missing on State-Changing Endpoint",
        description="Explicitly exempting state-changing routes from CSRF checks (`@csrf_exempt`, `csrf: false`, `WTF_CSRF_ENABLED = False`) enables forged cross-site actions.",
        severity=Severity.MEDIUM,
        cwe_ids=("CWE-352",),
        owasp=("A01:2021-Broken-Access-Control",),
        languages=(".py", ".js", ".ts", ".java", ".php", ".rb"),
        pattern=r"""(?i)(?:@csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False|\.csrf\(\)\.disable\(\)|skip_before_action\s*:verify_authenticity_token|csrf\s*:\s*false)""",
        anti_pattern=r"""(?i)(?:bearer_token_only|stateless_jwt_no_cookies)""",
        remediation="Enforce synchronizer CSRF tokens or double-submit cookies combined with `SameSite=Lax`/`Strict` on all cookie-authenticated state transitions.",
        secure_example="response.set_cookie('session', token, httponly=True, secure=True, samesite='Strict')",
    ),
    ClientProtocolRule(
        rule_id="CYB-WEB-REDIR-001",
        title="Unvalidated Open Redirect via Request Parameter",
        description="Redirecting directly to a user-supplied URL (`next`, `redirect`, `return_to`, `url`) facilitates phishing and OAuth token interception.",
        severity=Severity.MEDIUM,
        cwe_ids=("CWE-601",),
        owasp=("A01:2021-Broken-Access-Control",),
        languages=(".py", ".js", ".ts", ".java", ".php", ".go", ".rb"),
        pattern=r"""(?i)(?:redirect\s*\(\s*(?:request\.args|request\.GET|req\.query|params)\[|res\.redirect\s*\(\s*req\.query|sendRedirect\s*\(\s*request\.getParameter)""",
        anti_pattern=r"""(?i)(?:url_has_allowed_host|is_safe_redirect|ALLOWED_REDIRECT_HOSTS)""",
        remediation="Permit only relative paths starting with a single `/` (not `//`) or validate parsed hostnames against a strict allowlist.",
        secure_example="if not target.startswith('/') or target.startswith('//'): target = '/dashboard'",
    ),
    ClientProtocolRule(
        rule_id="CYB-WEB-WS-001",
        title="Cross-Site WebSocket Hijacking (CSWSH) — Missing Origin Validation",
        description="WebSocket upgrade handler accepts connections without verifying the `Origin` header, allowing malicious sites to hijack authenticated WebSocket sessions.",
        severity=Severity.HIGH,
        cwe_ids=("CWE-346", "CWE-1385"),
        owasp=("A01:2021-Broken-Access-Control",),
        languages=(".go", ".js", ".ts", ".py", ".java"),
        pattern=r"""(?i)(?:CheckOrigin\s*:\s*func\s*\([^)]*\)\s*bool\s*\{\s*return\s+true\s*\}|verifyClient\s*:\s*\(\)\s*=>\s*true|allowed_origins\s*=\s*["']\*["'].*websocket)""",
        anti_pattern=None,
        remediation="Verify the HTTP `Origin` header against an exact trusted origin allowlist during the WebSocket handshake and require CSRF/bearer authentication.",
        secure_example="CheckOrigin: func(r *http.Request) bool { return r.Header.Get(\"Origin\") == \"https://app.example.com\" }",
    ),
    ClientProtocolRule(
        rule_id="CYB-WEB-COOKIE-001",
        title="Insecure Session Cookie Flags (`HttpOnly=False`, `Secure=False`, `SameSite=None`)",
        description="Session cookies issued without `HttpOnly`, `Secure`, and restrictive `SameSite` flags are vulnerable to XSS exfiltration, network sniffing, and CSRF.",
        severity=Severity.MEDIUM,
        cwe_ids=("CWE-614", "CWE-1004", "CWE-1275"),
        owasp=("A05:2021-Security-Misconfiguration",),
        languages=(".py", ".js", ".ts", ".java", ".php", ".go", ".rb"),
        pattern=r"""(?i)(?:set_cookie|res\.cookie|SESSION_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False|httpOnly\s*:\s*false|secure\s*:\s*false)""",
        anti_pattern=r"""(?i)(?:httponly\s*=\s*True.*secure\s*=\s*True|httpOnly\s*:\s*true.*secure\s*:\s*true)""",
        remediation="Set `HttpOnly=True`, `Secure=True`, and `SameSite=Strict` (or `Lax`) on all session and authentication cookies.",
        secure_example="resp.set_cookie('sid', sid, httponly=True, secure=True, samesite='Lax')",
    ),
)


# ---------------------------------------------------------------------------
# CSP Policy & Security Header Analyzer
# ---------------------------------------------------------------------------

class HttpSecurityHeaderAuditor:
    """Deep auditor for HTTP security headers, CSP bypass vectors, and cookie flags."""

    RISKY_CSP_JSONP_HOSTS = (
        "*.googleapis.com",
        "ajax.googleapis.com",
        "*.cloudflare.com",
        "cdnjs.cloudflare.com",
        "cdn.jsdelivr.net",
        "unpkg.com",
        "*.gstatic.com",
    )

    def audit_response_headers(self, endpoint: str, headers: Dict[str, str]) -> List[CyberVulnerability]:
        lower_map = {k.lower(): v for k, v in headers.items()}
        findings: List[CyberVulnerability] = []

        # 1. Content-Security-Policy analysis
        csp = lower_map.get("content-security-policy", "")
        if not csp:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-HDR-CSP-MISSING",
                    title="Missing Content-Security-Policy (CSP) Header",
                    description=f"Endpoint `{endpoint}` does not emit a `Content-Security-Policy` header, leaving the browser without defense-in-depth against XSS.",
                    cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-693", "CWE-79"],
                    owasp_categories=["A05:2021-Security-Misconfiguration"],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=endpoint,
                    remediation_guidance="Deploy a strict nonce-based CSP (`default-src 'none'; script-src 'nonce-<random>' 'strict-dynamic'; object-src 'none'; base-uri 'none'`).",
                    discovered_by="ely_cyber_header_auditor",
                )
            )
        else:
            findings.extend(self._audit_csp_directives(endpoint, csp))

        # 2. HSTS check
        hsts = lower_map.get("strict-transport-security", "")
        if not hsts or "max-age=0" in hsts.lower():
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-HDR-HSTS-MISSING",
                    title="Missing or Weak HTTP Strict-Transport-Security (HSTS)",
                    description=f"Endpoint `{endpoint}` omits HSTS, enabling SSL-stripping downgrade attacks.",
                    cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                    severity=Severity.LOW,
                    cwe_ids=["CWE-319", "CWE-523"],
                    owasp_categories=["A02:2021-Cryptographic-Failures"],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=endpoint,
                    remediation_guidance="Set `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.",
                    discovered_by="ely_cyber_header_auditor",
                )
            )

        # 3. Clickjacking protection
        xfo = lower_map.get("x-frame-options", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()
        if not xfo and not has_frame_ancestors:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-HDR-CLICKJACK-001",
                    title="Missing Clickjacking Protection (`frame-ancestors` / `X-Frame-Options`)",
                    description=f"Endpoint `{endpoint}` can be framed by arbitrary third-party origins.",
                    cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                    severity=Severity.LOW,
                    cwe_ids=["CWE-1021"],
                    owasp_categories=["A05:2021-Security-Misconfiguration"],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=endpoint,
                    remediation_guidance="Set CSP `frame-ancestors 'none'` (or `'self'`) and `X-Frame-Options: DENY`.",
                    discovered_by="ely_cyber_header_auditor",
                )
            )

        # 4. X-Content-Type-Options
        if lower_map.get("x-content-type-options", "").lower() != "nosniff":
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-HDR-MIME-001",
                    title="Missing `X-Content-Type-Options: nosniff` Header",
                    description=f"Endpoint `{endpoint}` permits MIME-type sniffing which can escalate file uploads to XSS.",
                    cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                    severity=Severity.LOW,
                    cwe_ids=["CWE-16", "CWE-430"],
                    owasp_categories=["A05:2021-Security-Misconfiguration"],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=endpoint,
                    remediation_guidance="Add `X-Content-Type-Options: nosniff` to all HTTP responses.",
                    discovered_by="ely_cyber_header_auditor",
                )
            )

        # 5. Set-Cookie hardening check
        cookie_hdr = lower_map.get("set-cookie", "")
        if cookie_hdr:
            cl = cookie_hdr.lower()
            missing_flags = [f for f in ("httponly", "secure", "samesite=") if f not in cl]
            if missing_flags:
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-HDR-COOKIE-001",
                        title=f"Session Cookie Missing Security Attributes ({', '.join(missing_flags)})",
                        description=f"`Set-Cookie` on `{endpoint}` omits: {', '.join(missing_flags)}.",
                        cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                        severity=Severity.MEDIUM,
                        cwe_ids=["CWE-614", "CWE-1004"],
                        owasp_categories=["A05:2021-Security-Misconfiguration"],
                        verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                        endpoint_or_asset=endpoint,
                        remediation_guidance="Mark all session cookies with `HttpOnly; Secure; SameSite=Strict`.",
                        discovered_by="ely_cyber_header_auditor",
                    )
                )

        return findings

    def _audit_csp_directives(self, endpoint: str, csp: str) -> List[CyberVulnerability]:
        findings: List[CyberVulnerability] = []
        directives: Dict[str, List[str]] = {}
        for part in csp.split(";"):
            tokens = part.strip().split()
            if tokens:
                directives[tokens[0].lower()] = tokens[1:]

        script_src = directives.get("script-src", directives.get("default-src", []))
        issues: List[str] = []
        if "'unsafe-inline'" in script_src and "'strict-dynamic'" not in script_src:
            issues.append("`script-src` allows `'unsafe-inline'` without nonce/hash protection")
        if "'unsafe-eval'" in script_src:
            issues.append("`script-src` allows `'unsafe-eval'` enabling JS string execution")
        if "*" in script_src or "https:" in script_src or "http:" in script_src:
            issues.append("`script-src` contains wildcard/scheme-wide source allowing arbitrary script hosting")
        for host in self.RISKY_CSP_JSONP_HOSTS:
            if any(host.lstrip("*.") in tok for tok in script_src):
                issues.append(f"`script-src` whitelists JSONP/Angular gadget CDN `{host}`")
        if "object-src" not in directives and "'none'" not in directives.get("default-src", []):
            issues.append("Missing `object-src 'none'` allows plugin/Flash gadget execution")
        if "base-uri" not in directives:
            issues.append("Missing `base-uri 'none'` enables `<base href>` relative script hijacking")

        if issues:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-HDR-CSP-BYPASS",
                    title="Bypassable Content-Security-Policy (CSP) Directives",
                    description=f"CSP on `{endpoint}` contains bypassable weaknesses: " + "; ".join(issues),
                    cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-693", "CWE-79"],
                    owasp_categories=["A05:2021-Security-Misconfiguration"],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=endpoint,
                    attack_vector_detail="; ".join(issues),
                    remediation_guidance="Use nonce-based `'strict-dynamic'` CSP, remove `'unsafe-inline'`/`'unsafe-eval'` and CDN wildcards, and add `object-src 'none'; base-uri 'none'`.",
                    discovered_by="ely_cyber_header_auditor",
                )
            )
        return findings


# ---------------------------------------------------------------------------
# HTTP Request Smuggling & Cache Poisoning Protocol Desync Analyzer
# ---------------------------------------------------------------------------

class HttpDesyncAndSmugglingAnalyzer:
    """
    Analyzes raw HTTP/1.1 & HTTP/2 wire requests and proxy/backend framing pairs
    for Request Smuggling (CL.TE, TE.CL, TE.TE obfuscation, H2.CL) and Web Cache
    Poisoning (unkeyed header reflection).
    """

    OBFUSCATED_TE_PATTERNS = (
        re.compile(rb"(?i)^transfer-encoding\s*:\s*[^\r\n]*chunked[^\r\n]*$"),
        re.compile(rb"(?i)^transfer-encoding\s+:\s*chunked"),
        re.compile(rb"(?i)^transfer-encoding:\s*x?chunked"),
        re.compile(rb"(?i)^\s+transfer-encoding\s*:"),
    )

    def analyze_raw_wire_frame(self, raw_http: bytes, asset: str = "http_gateway") -> List[CyberVulnerability]:
        """Inspect raw HTTP request bytes for RFC 9112 framing ambiguity (smuggling primitives)."""
        findings: List[CyberVulnerability] = []
        head, _, body = raw_http.partition(b"\r\n\r\n")
        header_lines = head.split(b"\r\n")[1:]

        cl_values: List[str] = []
        te_lines: List[str] = []
        obfuscated_te = False

        for line in header_lines:
            low = line.lower()
            if low.startswith(b"content-length:"):
                cl_values.append(line.split(b":", 1)[1].strip().decode("latin-1", errors="replace"))
            if b"transfer-encoding" in low:
                te_lines.append(line.decode("latin-1", errors="replace"))
                if not re.match(rb"(?i)^transfer-encoding:\s*chunked\s*$", line):
                    obfuscated_te = True

        # 1. Simultaneous Content-Length + Transfer-Encoding (CL.TE / TE.CL desync)
        if cl_values and te_lines:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-HTTP-SMUGGLE-CLTE",
                    title="HTTP Request Smuggling Desync Primitive (Dual Content-Length + Transfer-Encoding)",
                    description=(
                        "HTTP request carries both `Content-Length` and `Transfer-Encoding` headers. "
                        "RFC 9112 §6.3 mandates rejecting such ambiguous messages to prevent CL.TE / TE.CL request smuggling."
                    ),
                    cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-444"],
                    confidence=0.96,
                    owasp_categories=["A05:2021-Security-Misconfiguration"],
                    mitre_techniques=[
                        MitreTechniqueRef("T1190", "Exploit Public-Facing Application", MitreTactic.INITIAL_ACCESS)
                    ],
                    cvss4=CVSSv4Metrics(av="N", ac="L", at="P", pr="N", ui="N", vc="H", vi="H", va="L", sc="H", si="H", sa="N"),
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    attack_vector_detail=f"Content-Length={cl_values} coexists with Transfer-Encoding={te_lines}",
                    remediation_guidance="Reject any HTTP/1.1 request containing both `Content-Length` and `Transfer-Encoding` with `400 Bad Request` and normalize HTTP/2-to-HTTP/1.1 downgrades.",
                    discovered_by="ely_cyber_desync_analyzer",
                )
            )

        # 2. Multiple conflicting Content-Length headers (CL.CL desync)
        if len(set(cl_values)) > 1:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-HTTP-SMUGGLE-CLCL",
                    title="Conflicting Duplicate `Content-Length` Headers (CL.CL Smuggling)",
                    description=f"Request specifies multiple conflicting `Content-Length` values: {cl_values}.",
                    cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-444"],
                    confidence=0.95,
                    owasp_categories=["A05:2021-Security-Misconfiguration"],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Strictly reject requests with duplicate or non-numeric `Content-Length` headers.",
                    discovered_by="ely_cyber_desync_analyzer",
                )
            )

        # 3. Obfuscated Transfer-Encoding (TE.TE desync)
        if obfuscated_te:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-HTTP-SMUGGLE-TETE",
                    title="Obfuscated `Transfer-Encoding` Header (TE.TE Desync Vector)",
                    description=f"Non-canonical `Transfer-Encoding` header(s) detected: {te_lines}.",
                    cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-444"],
                    confidence=0.92,
                    owasp_categories=["A05:2021-Security-Misconfiguration"],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Reject any non-standard `Transfer-Encoding` header syntax or whitespace obfuscation at the edge proxy.",
                    discovered_by="ely_cyber_desync_analyzer",
                )
            )

        # 4. Content-Length mismatch vs actual body length (indicates pipelined smuggled prefix)
        if cl_values and not te_lines:
            try:
                declared = int(cl_values[0])
                if declared < len(body) and body[declared:].lstrip().startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ")):
                    findings.append(
                        make_cyber_vuln(
                            rule_id="CYB-HTTP-SMUGGLE-PREFIX",
                            title="Embedded Pipelined Smuggled Request Prefix Beyond Content-Length",
                            description=f"Body contains {len(body)} bytes while `Content-Length` declares {declared}, with trailing HTTP request verb.",
                            cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                            severity=Severity.CRITICAL,
                            cwe_ids=["CWE-444"],
                            confidence=0.97,
                            verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                            endpoint_or_asset=asset,
                            remediation_guidance="Enforce end-to-end HTTP/2 without downgrade and strictly close connections on framing mismatch.",
                            discovered_by="ely_cyber_desync_analyzer",
                        )
                    )
            except ValueError:
                pass

        return findings


# ---------------------------------------------------------------------------
# Unified Client-Side & Protocol Security Engine
# ---------------------------------------------------------------------------

class WebClientProtocolEngine:
    """Orchestrates static client-side scans, header/CSP audits, smuggling analysis, and local sandbox probes."""

    UNKEYED_CACHE_HEADERS = (
        "X-Forwarded-Host",
        "X-Host",
        "X-Forwarded-Server",
        "X-Original-URL",
        "X-Rewrite-URL",
    )

    def __init__(self) -> None:
        self._compiled: List[Tuple[ClientProtocolRule, Pattern[str], Optional[Pattern[str]]]] = [
            (r, re.compile(r.pattern), re.compile(r.anti_pattern) if r.anti_pattern else None)
            for r in CLIENT_PROTOCOL_RULES
        ]
        self.header_auditor = HttpSecurityHeaderAuditor()
        self.desync_analyzer = HttpDesyncAndSmugglingAnalyzer()

    def scan_directory(self, root_path: Path) -> List[CyberVulnerability]:
        findings: List[CyberVulnerability] = []
        seen: set[str] = set()

        for file_path in sorted(root_path.rglob("*")):
            if not file_path.is_file():
                continue
            if any(p in {".git", "node_modules", "__pycache__", ".venv", "dist", "build"} for p in file_path.parts):
                continue
            ext = file_path.suffix.lower()
            if ext not in {".py", ".js", ".ts", ".jsx", ".tsx", ".html", ".vue", ".jinja", ".j2", ".java", ".go", ".php", ".rb", ".erb", ".twig"}:
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
                        cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                        severity=rule.severity,
                        cwe_ids=list(rule.cwe_ids),
                        confidence=0.85,
                        owasp_categories=list(rule.owasp),
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=rel,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line.strip()[:300],
                        remediation_guidance=rule.remediation,
                        secure_code_example=rule.secure_example,
                        discovered_by="ely_cyber_client_protocol_static",
                    )
                    fp = v.fingerprint()
                    if fp not in seen:
                        seen.add(fp)
                        findings.append(v)

        return findings

    def probe_sandbox_endpoint(
        self,
        handler: Callable[[HttpProbeRequest], HttpProbeResponse],
        *,
        endpoint: str,
        param_name: str = "q",
    ) -> List[CyberVulnerability]:
        """Run local sandboxed XSS, CORS, Cache Poisoning, Open Redirect, and Header probes."""
        findings: List[CyberVulnerability] = []

        # 1. Reflected XSS Probe (unescaped script/svg tag reflection)
        xss_canary = '"><svg/onload=ely_xss_canary_4412()>'
        xss_resp = handler(HttpProbeRequest(method="GET", path=endpoint, query_params={param_name: xss_canary}))
        ctype = xss_resp.header_lower("content-type", "text/html").lower()
        if "html" in ctype and xss_canary in xss_resp.body:
            findings.append(
                make_cyber_vuln(
                    rule_id="PROBE-XSS-REFLECTED-01",
                    title="Reflected Cross-Site Scripting (XSS) Confirmed in Sandbox",
                    description=f"Unescaped HTML/SVG payload reflected verbatim in `text/html` response on `{endpoint}`.",
                    cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-79"],
                    confidence=0.98,
                    owasp_categories=["A03:2021-Injection"],
                    mitre_techniques=[MitreTechniqueRef("T1189", "Drive-by Compromise", MitreTactic.INITIAL_ACCESS)],
                    cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="P", vc="L", vi="L", va="N", sc="H", si="H", sa="N", e="P"),
                    verification_method=VerificationMethod.SANDBOX_DIFFERENTIAL_PROBE,
                    sandbox_reproduced=True,
                    endpoint_or_asset=f"GET {endpoint}?{param_name}",
                    attack_vector_detail=f"Payload `{xss_canary}` echoed unencoded in HTML response.",
                    remediation_guidance="Contextually HTML-encode all untrusted output (`html.escape`) and enforce nonce-based CSP.",
                    discovered_by="ely_cyber_client_protocol_prober",
                )
            )

        # 2. CORS Origin Reflection + Credentials Probe
        evil_origin = "https://attacker.invalid"
        cors_resp = handler(HttpProbeRequest(method="GET", path=endpoint, headers={"Origin": evil_origin}))
        acao = cors_resp.header_lower("access-control-allow-origin")
        acac = cors_resp.header_lower("access-control-allow-credentials").lower()
        if (acao == evil_origin or acao == "null") and acac == "true":
            findings.append(
                make_cyber_vuln(
                    rule_id="PROBE-CORS-REFLECT-01",
                    title="Arbitrary CORS Origin Reflection with Credentials Confirmed",
                    description=f"`{endpoint}` reflects untrusted Origin `{evil_origin}` with `Access-Control-Allow-Credentials: true`.",
                    cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-942"],
                    confidence=0.98,
                    owasp_categories=["A05:2021-Security-Misconfiguration"],
                    verification_method=VerificationMethod.SANDBOX_DIFFERENTIAL_PROBE,
                    sandbox_reproduced=True,
                    endpoint_or_asset=f"GET {endpoint}",
                    remediation_guidance="Match `Origin` strictly against a fixed server-side allowlist and omit `Allow-Credentials` for untrusted origins.",
                    discovered_by="ely_cyber_client_protocol_prober",
                )
            )

        # 3. Unkeyed Web Cache Poisoning / Host Header Injection Probe
        poison_host = "poison-canary.invalid"
        for hdr in self.UNKEYED_CACHE_HEADERS:
            cp_resp = handler(HttpProbeRequest(method="GET", path=endpoint, headers={hdr: poison_host}))
            if poison_host in cp_resp.body or poison_host in cp_resp.header_lower("location"):
                findings.append(
                    make_cyber_vuln(
                        rule_id="PROBE-CACHE-POISON-01",
                        title=f"Web Cache Poisoning / Host Header Reflection via `{hdr}`",
                        description=f"Unkeyed header `{hdr}: {poison_host}` is reflected into response body or redirect URL on `{endpoint}`.",
                        cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-444", "CWE-644"],
                        confidence=0.95,
                        owasp_categories=["A05:2021-Security-Misconfiguration"],
                        verification_method=VerificationMethod.SANDBOX_DIFFERENTIAL_PROBE,
                        sandbox_reproduced=True,
                        endpoint_or_asset=f"GET {endpoint} ({hdr})",
                        remediation_guidance="Ignore untrusted proxy override headers unless strictly validated from trusted edge IPs and include them in cache keys.",
                        discovered_by="ely_cyber_client_protocol_prober",
                    )
                )
                break

        # 4. Open Redirect Probe
        redir_resp = handler(
            HttpProbeRequest(method="GET", path=endpoint, query_params={"next": "https://evil-redirect.invalid/phish"})
        )
        loc = redir_resp.header_lower("location")
        if redir_resp.status_code in (301, 302, 303, 307, 308) and "evil-redirect.invalid" in loc:
            findings.append(
                make_cyber_vuln(
                    rule_id="PROBE-OPEN-REDIR-01",
                    title="Open Redirect Confirmed via `next` Parameter",
                    description=f"`{endpoint}` redirects to arbitrary external domain `{loc}`.",
                    cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-601"],
                    confidence=0.97,
                    owasp_categories=["A01:2021-Broken-Access-Control"],
                    verification_method=VerificationMethod.SANDBOX_DIFFERENTIAL_PROBE,
                    sandbox_reproduced=True,
                    endpoint_or_asset=f"GET {endpoint}?next=...",
                    remediation_guidance="Restrict redirects to relative same-origin paths or an explicit host allowlist.",
                    discovered_by="ely_cyber_client_protocol_prober",
                )
            )

        # 5. Security Headers & CSP audit on baseline response
        base_resp = handler(HttpProbeRequest(method="GET", path=endpoint))
        findings.extend(self.header_auditor.audit_response_headers(endpoint, base_resp.headers))

        return findings
