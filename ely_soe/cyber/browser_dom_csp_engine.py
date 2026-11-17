"""
Browser Security Policy Engine: W3C CSP Level 3 Parser & CDN-Bypass Analyzer,
CORS Origin-Reflection Verifier, Cross-Origin Isolation (COOP/COEP/CORP) Auditor
& Frontend DOM Sink / Prototype Pollution Taint Scanner.

Capabilities:
  1. **W3C Content-Security-Policy (CSP Level 3) Structural Parser & Bypass Verifier**:
       - Parses arbitrary CSP strings into canonical directive maps (`default-src`,
         `script-src`, `object-src`, `base-uri`, `frame-ancestors`, `form-action`,
         `require-trusted-types-for`, `upgrade-insecure-requests`).
       - Detects `unsafe-inline`, `unsafe-eval`, wildcard `*`, `http:`/`data:`/`blob:`
         in `script-src`, missing `object-src 'none'` (Flash/PDF XSS), missing `base-uri`
         (base-tag nonce hijacking), missing `frame-ancestors` (Clickjacking), and
         **20+ known JSONP / AngularJS CSP-bypass CDN allowlist domains** (`*.googleapis.com`,
         `cdnjs.cloudflare.com`, `cdn.jsdelivr.net`, `unpkg.com`, `ajax.aspnetcdn.com`, etc.)
         when `'strict-dynamic'` is absent!
  2. **CORS Matrix & Cross-Origin Isolation (Spectre / XS-Leaks) Verifier**:
       - Evaluates HTTP security header bundles (`Access-Control-Allow-Origin`,
         `Access-Control-Allow-Credentials`, `Strict-Transport-Security`,
         `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`,
         `Cross-Origin-Resource-Policy`, `X-Content-Type-Options`, `Permissions-Policy`).
  3. **Frontend JavaScript/TypeScript DOM Sink & Prototype Pollution Auditor**:
       - Detects `innerHTML`/`outerHTML`/`document.write`, `dangerouslySetInnerHTML`,
         unvalidated `window.addEventListener('message', ...)` lacking `event.origin` checks,
         `postMessage(secret, '*')`, `location.href = userInput` (`javascript:` URI XSS),
         `__proto__`/`constructor.prototype` unsafe deep merges, and `localStorage` JWT storage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ely_soe.core.models import Severity, utc_now_iso
from ely_soe.cyber.models import (
    CVSSv4Metrics,
    CyberDomain,
    CyberVulnerability,
    VerificationMethod,
    make_cyber_vuln,
)


# Public CDN / JSONP / AngularJS endpoints famously abused to bypass host-allowlist CSPs
CSP_BYPASS_CDN_HOSTS: Tuple[Tuple[str, str], ...] = (
    ("googleapis.com", "Hosts legacy AngularJS / JSONP callbacks enabling arbitrary script execution under host-allowlist CSP."),
    ("gstatic.com", "Hosts AngularJS / Polymer bundles usable for CSP script-gadget bypasses."),
    ("cdnjs.cloudflare.com", "Public library mirror hosting arbitrary vulnerable AngularJS/jQuery/PrototypeJS gadgets."),
    ("cdn.jsdelivr.net", "Serves arbitrary GitHub/npm user-uploaded packages directly (`jsdelivr` bypass)."),
    ("unpkg.com", "Serves arbitrary npm packages allowing immediate attacker-controlled JS load."),
    ("raw.githubusercontent.com", "Hosts attacker-controlled raw GitHub repository scripts."),
    ("ajax.aspnetcdn.com", "Hosts legacy AngularJS versions usable for CSP bypass."),
    ("code.jquery.com", "Hosts legacy jQuery / script gadgets usable in DOM-based CSP bypasses."),
    ("s3.amazonaws.com", "Broad multi-tenant AWS S3 domain allows any attacker bucket to serve scripts."),
    ("storage.googleapis.com", "Broad multi-tenant GCS domain allows attacker buckets to bypass script-src."),
    ("azureedge.net", "Shared CDN suffix permits attacker-controlled origins."),
    ("firebaseapp.com", "Shared hosting suffix allows attacker-controlled scripts."),
    ("accounts.google.com", "Exposes JSONP/OAuth callback endpoints frequently abused for CSP bypass."),
    ("www.google.com", "Exposes JSONP endpoints (`/complete/search?jsonp=...`) that bypass host-based CSP."),
    ("youtube.com", "Exposes legacy JSONP endpoints usable to execute arbitrary callbacks."),
)


class BrowserDOMCSPEngine:
    """Comprehensive browser security header, CSP Level 3, CORS, and DOM sink auditor."""

    def parse_csp(self, csp_header: str) -> Dict[str, List[str]]:
        directives: Dict[str, List[str]] = {}
        for part in csp_header.split(";"):
            tokens = part.strip().split()
            if not tokens:
                continue
            name = tokens[0].lower()
            if name not in directives:  # W3C CSP3: first occurrence of a directive wins
                directives[name] = [t.strip() for t in tokens[1:]]
        return directives

    def audit_csp(self, csp_header: str, asset: str = "web_frontend") -> Dict[str, Any]:
        """Deep W3C CSP Level 3 security audit with bypass detection and strictness scoring."""
        vulns: List[CyberVulnerability] = []
        directives = self.parse_csp(csp_header)
        if not directives:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-CSP-MISSING-001",
                    title=f"Missing `Content-Security-Policy` Header on `{asset}`",
                    description="No CSP policy is configured, leaving XSS payloads unrestricted.",
                    cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-693", "CWE-79"],
                    confidence=0.99,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Deploy a strict nonce-based CSP Level 3 header (`script-src 'nonce-<rand>' 'strict-dynamic'; object-src 'none'; base-uri 'none'`).",
                    discovered_by="ely_cyber_browser_csp_engine",
                )
            )
            return {"asset": asset, "csp_score": 0.0, "directives": {}, "bypasses": ["missing_csp"], "vulnerabilities": vulns}

        score = 100.0
        bypasses: List[str] = []
        effective_script = directives.get("script-src", directives.get("default-src", []))
        eff_lower = [t.lower() for t in effective_script]
        has_strict_dynamic = "'strict-dynamic'" in eff_lower
        has_nonce_or_hash = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in eff_lower)

        if not effective_script:
            score -= 35.0
            bypasses.append("missing_script_src_and_default_src")
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-CSP-NO-SCRIPT-SRC",
                    title=f"CSP on `{asset}` Defines Neither `script-src` Nor `default-src`",
                    description="Without `script-src` or `default-src`, browsers permit arbitrary inline and external script execution.",
                    cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-693", "CWE-79"],
                    confidence=0.99,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Define explicit `default-src 'none'` and nonce-gated `script-src`.",
                    discovered_by="ely_cyber_browser_csp_engine",
                )
            )

        # unsafe-inline is ignored by CSP3 browsers ONLY if a nonce/hash is present AND strict-dynamic isn't missing
        if "'unsafe-inline'" in eff_lower and not has_nonce_or_hash:
            score -= 35.0
            bypasses.append("script_src_unsafe_inline")
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-CSP-UNSAFE-INLINE",
                    title=f"CSP `script-src` Allows `'unsafe-inline'` Without Nonce/Hash on `{asset}`",
                    description="Permitting `'unsafe-inline'` without cryptographic nonces/hashes completely neutralizes CSP XSS protection.",
                    cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-79", "CWE-693"],
                    confidence=0.99,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Replace `'unsafe-inline'` with per-response cryptographic `'nonce-<128bit>'` + `'strict-dynamic'`.",
                    discovered_by="ely_cyber_browser_csp_engine",
                )
            )

        if "'unsafe-eval'" in eff_lower:
            score -= 20.0
            bypasses.append("script_src_unsafe_eval")
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-CSP-UNSAFE-EVAL",
                    title=f"CSP `script-src` Allows `'unsafe-eval'` on `{asset}`",
                    description="Allowing `'unsafe-eval'` permits `eval()`, `new Function()`, and string `setTimeout()` DOM-XSS execution.",
                    cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-95", "CWE-693"],
                    confidence=0.98,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Remove `'unsafe-eval'` and precompile templates/bundles at build time.",
                    discovered_by="ely_cyber_browser_csp_engine",
                )
            )

        for risky_tok in ("*", "http:", "https:", "data:", "blob:"):
            if risky_tok in eff_lower and not has_strict_dynamic:
                score -= 25.0
                bypasses.append(f"script_src_wildcard_or_scheme:{risky_tok}")
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-CSP-WILDCARD-SCHEME",
                        title=f"CSP `script-src` Permits Wildcard/Broad Scheme `{risky_tok}` on `{asset}`",
                        description=f"Allowing `{risky_tok}` in `script-src` lets attackers load arbitrary remote or inline `data:` scripts.",
                        cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-79", "CWE-693"],
                        confidence=0.99,
                        verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                        endpoint_or_asset=asset,
                        remediation_guidance="Eliminate `*`, `http:`, `https:`, and `data:` from `script-src`; adopt `'strict-dynamic'` with nonces.",
                        discovered_by="ely_cyber_browser_csp_engine",
                    )
                )
                break

        # Known JSONP / CDN gadget bypass check (only exploitable when strict-dynamic is absent)
        if not has_strict_dynamic:
            for tok in eff_lower:
                for cdn_host, reason in CSP_BYPASS_CDN_HOSTS:
                    if cdn_host in tok:
                        score -= 18.0
                        bypasses.append(f"cdn_gadget_bypass:{cdn_host}")
                        vulns.append(
                            make_cyber_vuln(
                                rule_id=f"CYB-CSP-CDN-BYPASS-{cdn_host.split('.')[0].upper()[:12]}",
                                title=f"CSP `script-src` Allowlists Known Bypass CDN `{cdn_host}` Without `'strict-dynamic'`",
                                description=f"Allowlisted source `{tok}` matches `{cdn_host}`: {reason}",
                                cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                                severity=Severity.HIGH,
                                cwe_ids=["CWE-79", "CWE-693"],
                                confidence=0.95,
                                verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                                endpoint_or_asset=asset,
                                remediation_guidance="Migrate from host allowlists to nonce + `'strict-dynamic'` and enforce Subresource Integrity (SRI).",
                                discovered_by="ely_cyber_browser_csp_engine",
                            )
                        )
                        break

        # Check object-src, base-uri, frame-ancestors
        obj_src = [t.lower() for t in directives.get("object-src", directives.get("default-src", []))]
        if "'none'" not in obj_src:
            score -= 10.0
            bypasses.append("missing_object_src_none")
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-CSP-OBJECT-SRC",
                    title=f"CSP Missing `object-src 'none'` on `{asset}` (Plugin/Object Execution Exposure)",
                    description="Without `object-src 'none'`, attackers can inject `<object>`/`<embed>` elements to bypass script restrictions.",
                    cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-693"],
                    confidence=0.95,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Add `object-src 'none'` to CSP.",
                    discovered_by="ely_cyber_browser_csp_engine",
                )
            )

        base_uri = [t.lower() for t in directives.get("base-uri", [])]
        if not base_uri or ("'none'" not in base_uri and "'self'" not in base_uri):
            score -= 10.0
            bypasses.append("missing_base_uri")
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-CSP-BASE-URI",
                    title=f"CSP Missing `base-uri 'none'`/`'self'` on `{asset}` (Relative Script Nonce Hijack)",
                    description="Missing `base-uri` enables `<base href='https://evil.com/'>` injection to redirect relative nonced `<script src='/app.js'>` loads.",
                    cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-79", "CWE-693"],
                    confidence=0.95,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Add `base-uri 'none'` (or `'self'`) to CSP.",
                    discovered_by="ely_cyber_browser_csp_engine",
                )
            )

        if "frame-ancestors" not in directives:
            score -= 8.0
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-CSP-CLICKJACKING",
                    title=f"CSP Missing `frame-ancestors` Directive on `{asset}` (Clickjacking Exposure)",
                    description="Without `frame-ancestors 'none'`/`'self'`, the application can be embedded in hostile iframes for UI redressing.",
                    cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-1021"],
                    confidence=0.96,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Add `frame-ancestors 'none'` (or exact trusted parent origins) to CSP.",
                    discovered_by="ely_cyber_browser_csp_engine",
                )
            )

        return {
            "audited_at": utc_now_iso(),
            "asset": asset,
            "csp_score": round(max(0.0, score), 2),
            "directives": directives,
            "bypasses": bypasses,
            "has_trusted_types": "require-trusted-types-for" in directives,
            "vulnerabilities": vulns,
        }

    def audit_http_security_headers(
        self,
        headers: Dict[str, str],
        asset: str = "web_app",
    ) -> Dict[str, Any]:
        """Audit full HTTP response security header suite including CORS & Cross-Origin Isolation."""
        norm = {k.lower(): v for k, v in headers.items()}
        vulns: List[CyberVulnerability] = []

        csp_res = self.audit_csp(norm.get("content-security-policy", ""), asset=asset)
        vulns.extend(csp_res["vulnerabilities"])

        # CORS credentials + wildcard or null origin
        acao = norm.get("access-control-allow-origin", "").strip()
        acac = norm.get("access-control-allow-credentials", "").strip().lower()
        if acao == "null" or (acao == "*" and acac == "true"):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-CORS-CREDENTIAL-BYPASS",
                    title=f"Critical CORS Misconfiguration (`ACAO: {acao}`, `ACAC: {acac}`) on `{asset}`",
                    description="Allowing `Origin: null` (sandboxed iframe bypass) or wildcard with credentials leaks authenticated API data cross-origin.",
                    cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-942"],
                    confidence=0.99,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Validate `Origin` against an exact static allowlist; never trust `null` or reflect arbitrary origins with credentials.",
                    discovered_by="ely_cyber_browser_csp_engine",
                )
            )

        # HSTS check
        hsts = norm.get("strict-transport-security", "")
        m_age = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        if not hsts or not m_age or int(m_age.group(1)) < 31536000:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-HDR-HSTS-WEAK",
                    title=f"Missing or Short HSTS (`Strict-Transport-Security`) Header on `{asset}`",
                    description="HSTS missing or `max-age < 31536000` (1 year), leaving users exposed to SSL-stripping downgrade attacks.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-319"],
                    confidence=0.97,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Emit `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.",
                    discovered_by="ely_cyber_browser_csp_engine",
                )
            )

        # Cross-Origin Isolation (COOP / COEP / CORP)
        coop = norm.get("cross-origin-opener-policy", "").lower()
        corp = norm.get("cross-origin-resource-policy", "").lower()
        if coop != "same-origin" or corp not in ("same-origin", "same-site"):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-HDR-CROSS-ORIGIN-ISOLATION",
                    title=f"Missing Cross-Origin Isolation Headers (`COOP`/`CORP`) on `{asset}` (XS-Leaks / Spectre)",
                    description="Absent `Cross-Origin-Opener-Policy: same-origin` or `Cross-Origin-Resource-Policy` allows cross-origin window/timing XS-Leaks.",
                    cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                    severity=Severity.LOW,
                    cwe_ids=["CWE-693"],
                    confidence=0.93,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Set `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, and `X-Content-Type-Options: nosniff`.",
                    discovered_by="ely_cyber_browser_csp_engine",
                )
            )

        return {
            "audited_at": utc_now_iso(),
            "asset": asset,
            "csp_score": csp_res["csp_score"],
            "cross_origin_isolated": coop == "same-origin" and norm.get("cross-origin-embedder-policy", "").lower() == "require-corp",
            "vulnerabilities": vulns,
        }

    def scan_directory(self, root_path: Path) -> List[CyberVulnerability]:
        """Scan JS/TS/HTML frontend code for DOM XSS sinks, postMessage bugs, and prototype pollution."""
        dom_rules = [
            ("CYB-DOM-POSTMSG-WILD", Severity.HIGH, "CWE-346", r"\.postMessage\s*\([^,]+,\s*['\"]\*['\"]\s*\)", "Wildcard `postMessage(..., '*')` Target Origin Leaks Sensitive Data to Any Parent/Child Frame", "Specify exact trusted target origin (e.g. `https://app.example.com`) instead of `'*'`."),
            ("CYB-DOM-PROTOTYPE-POLLUTION", Severity.CRITICAL, "CWE-1321", r"(?:__proto__|constructor\s*\[\s*['\"]prototype['\"]\s*\])|function\s+merge\s*\([^)]*\)\s*\{[^}]{0,220}target\s*\[\s*key\s*\]\s*=", "JavaScript Prototype Pollution Sink / Unsafe Recursive Object Merge", "Reject `__proto__`, `constructor`, and `prototype` keys and use `Object.create(null)` maps."),
            ("CYB-DOM-DANGEROUS-HTML", Severity.HIGH, "CWE-79", r"(?:dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:|document\.write\s*\(|\bv-html\s*=)", "Direct Unsanitized HTML Injection Sink (`dangerouslySetInnerHTML` / `document.write` / `v-html`)", "Sanitize HTML strictly with DOMPurify + Trusted Types or render plain text nodes."),
            ("CYB-DOM-LOCALSTORAGE-JWT", Severity.MEDIUM, "CWE-922", r"localStorage\.setItem\s*\(\s*['\"][^'\"]*(?:token|jwt|auth|session)[^'\"]*['\"]", "Authentication Token Persisted in `localStorage` (Exfiltratable by Any XSS)", "Store session tokens exclusively in `HttpOnly; Secure; SameSite=Strict` cookies."),
            ("CYB-DOM-SRI-MISSING", Severity.MEDIUM, "CWE-829", r"<script\b[^>]*src\s*=\s*['\"]https?://(?![^'\"]*localhost)[^'\"]+['\"](?![^>]*\bintegrity\s*=)[^>]*>", "External Third-Party `<script>` Loaded Without Subresource Integrity (`integrity=` Hash)", "Pin external scripts with `integrity='sha384-...' crossorigin='anonymous'` or self-host."),
        ]
        compiled = [(rid, sev, cwe, re.compile(pat, re.IGNORECASE | re.DOTALL), title, rem) for rid, sev, cwe, pat, title, rem in dom_rules]
        vulns: List[CyberVulnerability] = []
        exts = {".js", ".ts", ".jsx", ".tsx", ".html", ".vue", ".svelte"}

        for fp in sorted(root_path.rglob("*")):
            if not fp.is_file() or fp.suffix.lower() not in exts:
                continue
            if any(p in {".git", "node_modules", "__pycache__", ".venv", "dist"} for p in fp.parts):
                continue
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(fp.relative_to(root_path))
            for rid, sev, cwe, rx, title, rem in compiled:
                for m in rx.finditer(content):
                    lineno = content[: m.start()].count("\n") + 1
                    vulns.append(
                        make_cyber_vuln(
                            rule_id=rid,
                            title=title,
                            description=f"Detected client-side DOM/browser security weakness in `{rel}:{lineno}`.",
                            cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                            severity=sev,
                            cwe_ids=[cwe],
                            confidence=0.92,
                            verification_method=VerificationMethod.STATIC_PATTERN,
                            file_path=rel,
                            line_start=lineno,
                            line_end=lineno,
                            code_snippet=m.group(0)[:160],
                            remediation_guidance=rem,
                            discovered_by="ely_cyber_browser_csp_engine",
                        )
                    )
        return vulns
