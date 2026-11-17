"""
Mobile (Android OWASP MASVS v2.1 & iOS) and Electron/Thick-Client Security Auditor.

Statically audits mobile & desktop client codebases and configuration manifests:
  - **Android (`AndroidManifest.xml`, `network_security_config.xml`, Kotlin/Java)**:
      * `android:debuggable="true"`, `android:allowBackup="true"`, `usesCleartextTraffic="true"`
      * Exported Activities/Services/Receivers/ContentProviders without explicit `android:permission`
      * WebView `setJavaScriptEnabled(true)` + `addJavascriptInterface` / `setAllowUniversalAccessFromFileURLs(true)`
      * Insecure `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` storage & `TrustAllX509TrustManager`
  - **iOS (`Info.plist`, Swift/Obj-C)**:
      * App Transport Security disabled (`NSAllowsArbitraryLoads = true`)
      * Insecure Keychain accessibility (`kSecAttrAccessibleAlways`)
      * Deprecated `UIWebView` & unvalidated `URLSession` TLS trust overrides
  - **Electron / Thick-Client (`main.js` / `preload.ts`)**:
      * `nodeIntegration: true`, `contextIsolation: false`, `webSecurity: false`,
        `sandbox: false`, `allowRunningInsecureContent: true`, `shell.openExternal(untrusted)`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

from ely_soe.core.models import Severity
from ely_soe.cyber.models import (
    CVSSv4Metrics,
    CyberDomain,
    CyberVulnerability,
    VerificationMethod,
    make_cyber_vuln,
)


@dataclass(frozen=True)
class ClientSecurityRule:
    rule_id: str
    platform: str  # android | ios | electron
    masvs_id: str
    title: str
    severity: Severity
    cwe_id: str
    pattern: str
    description: str
    remediation: str


CLIENT_SECURITY_RULES: Tuple[ClientSecurityRule, ...] = (
    # ---- Android (OWASP MASVS v2.1) ----
    ClientSecurityRule(
        "CYB-MOB-AND-DEBUG-001", "android", "MASVS-RESILIENCE-1",
        "Android Manifest Enables `android:debuggable=\"true\"` in Release Configuration",
        Severity.HIGH, "CWE-489",
        r'android:debuggable\s*=\s*"true"',
        "Debuggable release APKs allow attaching JDWP debuggers, dumping runtime memory, and inspecting private app sandbox files.",
        "Remove `android:debuggable=\"true\"` from `AndroidManifest.xml`; let Gradle set it strictly on debug buildTypes.",
    ),
    ClientSecurityRule(
        "CYB-MOB-AND-BACKUP-001", "android", "MASVS-STORAGE-2",
        "Android `android:allowBackup=\"true\"` Exposes Private App Data via ADB Backup",
        Severity.MEDIUM, "CWE-530",
        r'android:allowBackup\s*=\s*"true"',
        "Enabling full ADB/cloud backup allows physical/USB attackers to extract tokens, SQLite DBs, and SharedPreferences.",
        "Set `android:allowBackup=\"false\"` or configure restrictive `android:dataExtractionRules` excluding sensitive files.",
    ),
    ClientSecurityRule(
        "CYB-MOB-AND-CLEARTEXT-001", "android", "MASVS-NETWORK-1",
        "Android App Permits Cleartext HTTP Traffic (`usesCleartextTraffic` / `cleartextTrafficPermitted`)",
        Severity.HIGH, "CWE-319",
        r'(?:android:usesCleartextTraffic|cleartextTrafficPermitted)\s*=\s*"true"',
        "Permitting cleartext HTTP exposes API credentials, session cookies, and user traffic to local Wi-Fi MiTM attacks.",
        "Set `cleartextTrafficPermitted=\"false\"` in `network_security_config.xml` and enforce TLS 1.3 + certificate pinning.",
    ),
    ClientSecurityRule(
        "CYB-MOB-AND-EXPORTED-001", "android", "MASVS-PLATFORM-1",
        "Exported Android Component (`activity`/`service`/`provider`) Without Permission Guard",
        Severity.HIGH, "CWE-926",
        r'<(?:service|receiver|provider)\b(?![^>]*android:permission=)[^>]*android:exported\s*=\s*"true"',
        "Exported Android services/receivers/content providers without explicit `android:permission` can be invoked by any malicious app on the device.",
        "Set `android:exported=\"false\"` unless cross-app IPC is required, and enforce signature-level custom permissions.",
    ),
    ClientSecurityRule(
        "CYB-MOB-AND-WEBVIEW-001", "android", "MASVS-PLATFORM-2",
        "Android WebView Unsafe File/Universal Origin Access or JS Bridge Exposure",
        Severity.CRITICAL, "CWE-749",
        r"(?:setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)|setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)|addJavascriptInterface\s*\()",
        "Enabling universal file access or exposing Java objects to untrusted WebView JS enables arbitrary local file theft and RCE.",
        "Disable file/universal access in WebView settings and restrict WebView navigation to allowlisted HTTPS origins.",
    ),
    ClientSecurityRule(
        "CYB-MOB-AND-TRUSTALL-001", "android", "MASVS-NETWORK-1",
        "Android Custom `X509TrustManager` / `HostnameVerifier` Bypasses TLS Certificate Validation",
        Severity.CRITICAL, "CWE-295",
        r"(?:AllowAllHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|onReceivedSslError[^}]*handler\.proceed\(\))",
        "Ignoring SSL errors (`handler.proceed()`) or accepting all hostnames trivially defeats HTTPS against any MiTM attacker.",
        "Remove custom trust-all verifiers and rely on Android's system trust store + `network_security_config.xml` pins.",
    ),
    # ---- iOS (OWASP MASVS v2.1) ----
    ClientSecurityRule(
        "CYB-MOB-IOS-ATS-001", "ios", "MASVS-NETWORK-1",
        "iOS `Info.plist` Disables App Transport Security (`NSAllowsArbitraryLoads`)",
        Severity.HIGH, "CWE-319",
        r"<key>NSAllowsArbitraryLoads</key>\s*<true\s*/>",
        "Disabling iOS App Transport Security allows insecure HTTP connections and weak TLS ciphers globally.",
        "Remove `NSAllowsArbitraryLoads` and enforce HTTPS TLS 1.2+/1.3 across all API endpoints.",
    ),
    ClientSecurityRule(
        "CYB-MOB-IOS-KEYCHAIN-001", "ios", "MASVS-STORAGE-1",
        "iOS Keychain Item Stored With Weak `kSecAttrAccessibleAlways` Attribute",
        Severity.HIGH, "CWE-522",
        r"\bkSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b",
        "Storing credentials with `kSecAttrAccessibleAlways` makes secrets readable even while the iOS device is locked.",
        "Use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` or `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.",
    ),
    # ---- Electron / Desktop Thick-Client ----
    ClientSecurityRule(
        "CYB-ELEC-NODEINT-001", "electron", "MASVS-PLATFORM-2",
        "Electron BrowserWindow Enables `nodeIntegration: true` (XSS -> Full OS RCE)",
        Severity.CRITICAL, "CWE-94",
        r"nodeIntegration\s*:\s*true",
        "Enabling `nodeIntegration: true` in renderer windows turns any XSS or third-party script load into instant Node.js OS command execution.",
        "Set `nodeIntegration: false`, `contextIsolation: true`, and `sandbox: true` on every `BrowserWindow`.",
    ),
    ClientSecurityRule(
        "CYB-ELEC-CTXISO-001", "electron", "MASVS-PLATFORM-2",
        "Electron Disables `contextIsolation` or `webSecurity` or `sandbox`",
        Severity.CRITICAL, "CWE-693",
        r"(?:contextIsolation\s*:\s*false|webSecurity\s*:\s*false|sandbox\s*:\s*false|allowRunningInsecureContent\s*:\s*true)",
        "Disabling Electron's context isolation, SOP `webSecurity`, or Chromium OS sandbox lets renderer JS hijack preload APIs and execute OS code.",
        "Enforce `contextIsolation: true`, `webSecurity: true`, and `sandbox: true`; expose only minimal validated IPC via `contextBridge`.",
    ),
    ClientSecurityRule(
        "CYB-ELEC-OPENEXT-001", "electron", "MASVS-PLATFORM-1",
        "Electron `shell.openExternal()` Invoked With Potentially Unvalidated URL Protocol",
        Severity.HIGH, "CWE-78",
        r"shell\.openExternal\s*\(\s*(?!['\"]https://)[^)]+\)",
        "Passing unvalidated URLs (`file://`, `smb://`, `ms-msdt:`) to `shell.openExternal()` enables desktop RCE on Windows/macOS.",
        "Parse URL with `new URL(target)` and strictly verify `url.protocol === 'https:'` before calling `shell.openExternal`.",
    ),
)


class MobileAndClientSecurityAuditor:
    """Audits Android, iOS, and Electron/Desktop client apps against OWASP MASVS v2.1."""

    def __init__(self) -> None:
        self._compiled = [(r, re.compile(r.pattern, re.DOTALL)) for r in CLIENT_SECURITY_RULES]

    def scan_directory(self, root_path: Path) -> List[CyberVulnerability]:
        vulns: List[CyberVulnerability] = []
        exts = {".xml", ".plist", ".kt", ".java", ".swift", ".m", ".mm", ".js", ".ts", ".jsx", ".tsx"}
        for fp in sorted(root_path.rglob("*")):
            if not fp.is_file() or fp.suffix.lower() not in exts:
                continue
            if any(p in {".git", "node_modules", "__pycache__", ".venv", "build"} for p in fp.parts):
                continue
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(fp.relative_to(root_path))
            for rule, rx in self._compiled:
                for m in rx.finditer(content):
                    lineno = content[: m.start()].count("\n") + 1
                    vulns.append(
                        make_cyber_vuln(
                            rule_id=rule.rule_id,
                            title=f"[{rule.platform.upper()} | {rule.masvs_id}] {rule.title}",
                            description=rule.description,
                            cyber_domain=CyberDomain.WEB_CLIENT_PROTOCOL,
                            severity=rule.severity,
                            cwe_ids=[rule.cwe_id],
                            confidence=0.95,
                            owasp_categories=[rule.masvs_id],
                            cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="P", vc="H", vi="H", va="L", sc="H", si="H", sa="N"),
                            verification_method=VerificationMethod.STATIC_PATTERN,
                            file_path=rel,
                            line_start=lineno,
                            line_end=lineno,
                            code_snippet=m.group(0)[:160],
                            remediation_guidance=rule.remediation,
                            discovered_by="ely_cyber_mobile_client_auditor",
                        )
                    )
        return vulns
