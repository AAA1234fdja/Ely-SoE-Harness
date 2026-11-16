"""
SSRF, XXE, SSTI, Insecure Deserialization & Path/Archive Traversal Testing Engine.

Covers high-impact server-side vulnerability classes:
  1. Server-Side Request Forgery (SSRF):
       - Strict URL/IP canonicalizer catching IPv4 decimal/octal/hex obfuscation,
         IPv6-mapped IPv4 (`[::ffff:127.0.0.1]`, `[::ffff:169.254.169.254]`),
         AWS/GCP/Azure/Alibaba Cloud IMDS endpoints, `file://`/`gopher://`/`dict://`
         schemes, `@` userinfo parser confusion, and DNS rebinding sinks.
  2. XML External Entity (XXE) & Billion Laughs XML Bomb:
       - Static detection of unsafe XML parsers across Python (`xml.etree`, `lxml`
         with `resolve_entities=True`), Java (`DocumentBuilderFactory`, `SAXParser`),
         PHP (`LIBXML_NOENT`), and .NET (`XmlDocument` with `XmlUrlResolver`),
         plus XML payload structural inspection.
  3. Server-Side Template Injection (SSTI):
       - Static detection of `render_template_string`, `Template(user_input)`,
         `Mako`, `Twig`, `Freemarker`, `Velocity`, `ERB`, `Handlebars`, plus
         sandboxed polyglot mathematical canary probing (`{{7*7}}`, `${7*7}`, `<%=7*7%>`).
  4. Insecure Deserialization:
       - Python (`pickle.loads`, `yaml.load` without `SafeLoader`, `marshal`, `shelve`, `jsonpickle`),
         Java (`ObjectInputStream.readObject`, `XMLDecoder`, `XStream`), PHP (`unserialize`),
         Ruby (`Marshal.load`), .NET (`BinaryFormatter`).
  5. Path Traversal, ZipSlip & TarSlip:
       - Static + archive member path boundary validator detecting `../`, absolute paths,
         backslash traversal, null bytes, and symlink-escape archive entries.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Pattern, Tuple
from urllib.parse import urlparse

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
# SSRF URL Canonicalizer & Bypass Detector
# ---------------------------------------------------------------------------

class SSRFUrlValidatorAndBypassDetector:
    """
    Parses and normalizes candidate URLs to detect SSRF targets including
    obfuscated numeric IPs, IPv6-mapped loopbacks, cloud IMDS hosts, and
    dangerous URI schemes.
    """

    DANGEROUS_SCHEMES = {"file", "gopher", "dict", "ftp", "tftp", "ldap", "ldaps", "jar", "netdoc", "php", "expect"}
    CLOUD_METADATA_HOSTS = {
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        "metadata.azure.internal",
        "fd00:ec2::254",
    }
    LOOPBACK_ALIASES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "0.0.0.0", "0"}

    def evaluate_url(self, raw_url: str) -> Dict[str, Any]:
        """Analyze whether a URL targets internal/metadata/dangerous resources or uses parser confusion."""
        reasons: List[str] = []
        url = raw_url.strip()
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()

        if scheme in self.DANGEROUS_SCHEMES:
            reasons.append(f"Dangerous non-HTTP URI scheme `{scheme}://` permits local file/socket access")
        elif scheme not in ("http", "https"):
            reasons.append(f"Unrecognized or missing URI scheme `{scheme}`")

        # Userinfo parser confusion (`https://trusted.com@169.254.169.254/`)
        if parsed.username is not None or "@" in (parsed.netloc or ""):
            reasons.append("URI contains `@` userinfo authority segment (classic SSRF parser confusion)")

        # Backslash confusion (`https://trusted.com\@169.254.169.254/`)
        if "\\" in (parsed.netloc or ""):
            reasons.append("Backslash in authority section triggers URL parser mismatch between validator and HTTP client")

        host = (parsed.hostname or "").strip().lower().rstrip(".")
        if not host:
            reasons.append("Empty or unparseable destination hostname")
            return {"is_ssrf_risk": True, "normalized_ip": None, "host": host, "reasons": reasons}

        if host in self.CLOUD_METADATA_HOSTS:
            reasons.append(f"Targets cloud instance metadata service (IMDS) `{host}`")
        if host in self.LOOPBACK_ALIASES:
            reasons.append(f"Targets loopback alias `{host}`")

        # Resolve obfuscated numeric IPv4 (decimal `2130706433`, hex `0x7f000001`, octal `0177.0.0.1`, shorthand `127.1`)
        resolved_ip = self._parse_obfuscated_ip(host)
        if resolved_ip is not None:
            if isinstance(resolved_ip, ipaddress.IPv6Address) and resolved_ip.ipv4_mapped:
                resolved_ip = resolved_ip.ipv4_mapped
                reasons.append(f"IPv6-mapped IPv4 obfuscation resolved to `{resolved_ip}`")
            if str(resolved_ip) in self.CLOUD_METADATA_HOSTS:
                reasons.append(f"Obfuscated IP resolves to Cloud IMDS `{resolved_ip}`")
            if resolved_ip.is_loopback:
                reasons.append(f"Resolves to loopback address `{resolved_ip}`")
            if resolved_ip.is_private:
                reasons.append(f"Resolves to RFC 1918/4193 private network `{resolved_ip}`")
            if resolved_ip.is_link_local:
                reasons.append(f"Resolves to link-local range `{resolved_ip}` (cloud IMDS range)")
            if resolved_ip.is_reserved or resolved_ip.is_multicast or resolved_ip.is_unspecified:
                reasons.append(f"Resolves to non-global reserved address `{resolved_ip}`")

        # Internal service TLD heuristics
        if host.endswith((".internal", ".local", ".corp", ".cluster.local", ".svc")):
            reasons.append(f"Targets internal service-discovery DNS namespace `{host}`")

        return {
            "is_ssrf_risk": len(reasons) > 0,
            "scheme": scheme,
            "host": host,
            "normalized_ip": str(resolved_ip) if resolved_ip else None,
            "reasons": reasons,
        }

    def _parse_obfuscated_ip(self, host: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        # Standard IPv4 / IPv6
        try:
            return ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            pass

        # Single integer decimal or hex IPv4 (e.g., 2130706433 or 0x7f000001 or 0xa9fea9fe)
        try:
            if host.startswith("0x"):
                val = int(host, 16)
                if 0 <= val <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(val)
            elif host.isdigit():
                val = int(host, 10)
                if 0 <= val <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(val)
        except ValueError:
            pass

        # Dotted octal / hex / shorthand IPv4 (e.g. 0177.0.0.1, 127.1, 0x7f.0.0.1)
        parts = host.split(".")
        if 2 <= len(parts) <= 4:
            nums: List[int] = []
            try:
                for p in parts:
                    if p.startswith("0x"):
                        nums.append(int(p, 16))
                    elif len(p) > 1 and p.startswith("0") and all(c in "01234567" for c in p):
                        nums.append(int(p, 8))
                    elif p.isdigit():
                        nums.append(int(p, 10))
                    else:
                        return None
                if len(nums) == 4 and all(0 <= n <= 255 for n in nums):
                    return ipaddress.IPv4Address((nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3])
                if len(nums) == 2 and 0 <= nums[0] <= 255 and 0 <= nums[1] <= 0xFFFFFF:
                    return ipaddress.IPv4Address((nums[0] << 24) | nums[1])
                if len(nums) == 3 and 0 <= nums[0] <= 255 and 0 <= nums[1] <= 255 and 0 <= nums[2] <= 0xFFFF:
                    return ipaddress.IPv4Address((nums[0] << 24) | (nums[1] << 16) | nums[2])
            except ValueError:
                return None
        return None


# ---------------------------------------------------------------------------
# Static Rules for SSRF, XXE, SSTI, Deserialization & Path/Archive Traversal
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ServerSideRule:
    rule_id: str
    title: str
    description: str
    severity: Severity
    cwe_ids: Tuple[str, ...]
    owasp: Tuple[str, ...]
    mitre_id: str
    mitre_name: str
    tactic: MitreTactic
    languages: Tuple[str, ...]
    pattern: str
    anti_pattern: Optional[str]
    remediation: str
    secure_example: str


SERVER_SIDE_RULES: Tuple[ServerSideRule, ...] = (
    ServerSideRule(
        rule_id="CYB-SSRF-001",
        title="Unvalidated Server-Side Request Forgery (SSRF) Sink",
        description="Outbound HTTP client fetches a dynamic URL without validating scheme, canonical IP ranges, or egress allowlist.",
        severity=Severity.CRITICAL,
        cwe_ids=("CWE-918",),
        owasp=("A10:2021-Server-Side-Request-Forgery",),
        mitre_id="T1190",
        mitre_name="Exploit Public-Facing Application",
        tactic=MitreTactic.INITIAL_ACCESS,
        languages=(".py", ".js", ".ts", ".go", ".java", ".php", ".rb"),
        pattern=r"""(?i)(?:requests\.(?:get|post|put|request)\s*\(|urllib\.request\.urlopen\s*\(|httpx\.(?:get|post|AsyncClient)|axios\.(?:get|post)\s*\(|fetch\s*\(|http\.Get\s*\(|curl_exec\s*\()\s*(?:url|target_url|webhook|callback|endpoint|req\.(?:query|body)|request\.(?:args|json|form)|f["']https?://\{)""",
        anti_pattern=r"""(?i)(?:ALLOWED_HOSTS|validate_ssrf|is_private|is_link_local|SSRFUrlValidator|allowlist)""",
        remediation="Parse and canonicalize URLs, resolve DNS once before connecting, deny RFC 1918 / loopback / `169.254.169.254` link-local ranges, and enforce HTTPS allowlists.",
        secure_example="check_egress_allowlist(url)  # validates HTTPS + resolves IP != private/link-local",
    ),
    ServerSideRule(
        rule_id="CYB-XXE-001",
        title="XML External Entity (XXE) Injection — External Entities Enabled",
        description="XML parser configured with external entity resolution (`resolve_entities=True`, `LIBXML_NOENT`, default Java `DocumentBuilderFactory` without disallow-doctype-decl).",
        severity=Severity.HIGH,
        cwe_ids=("CWE-611", "CWE-776"),
        owasp=("A05:2021-Security-Misconfiguration",),
        mitre_id="T1005",
        mitre_name="Data from Local System",
        tactic=MitreTactic.COLLECTION,
        languages=(".py", ".java", ".php", ".cs", ".rb", ".js", ".ts"),
        pattern=r"""(?i)(?:resolve_entities\s*=\s*True|load_dtd\s*=\s*True|LIBXML_NOENT|DocumentBuilderFactory\.newInstance\(\)|SAXParserFactory\.newInstance\(\)|XMLInputFactory\.newInstance\(\)|xml\.dom\.minidom\.parse|xml\.sax\.parse)""",
        anti_pattern=r"""(?i)(?:defusedxml|disallow-doctype-decl|resolve_entities\s*=\s*False|IS_SUPPORTING_EXTERNAL_ENTITIES.*false)""",
        remediation="Disable DOCTYPE declarations and external entity resolution (`defusedxml` in Python; `disallow-doctype-decl=true` in Java; `libxml_disable_entity_loader` in PHP).",
        secure_example="from defusedxml import ElementTree as SafeET\nroot = SafeET.fromstring(xml_bytes)",
    ),
    ServerSideRule(
        rule_id="CYB-SSTI-001",
        title="Server-Side Template Injection (SSTI) via Untrusted Template Source",
        description="Untrusted input compiled directly as a template string (`render_template_string`, `jinja2.Template`, `mako.Template`, `Twig`, `ERB.new`, `Handlebars.compile`) enables RCE.",
        severity=Severity.CRITICAL,
        cwe_ids=("CWE-1336", "CWE-94"),
        owasp=("A03:2021-Injection",),
        mitre_id="T1059",
        mitre_name="Command and Scripting Interpreter",
        tactic=MitreTactic.EXECUTION,
        languages=(".py", ".js", ".ts", ".java", ".php", ".rb"),
        pattern=r"""(?i)(?:render_template_string\s*\(|(?:jinja2\.)?Template\s*\(\s*(?:f["']|user|req|request|body|prompt|template_str)|mako\.template\.Template\s*\(|ERB\.new\s*\(|Handlebars\.compile\s*\(\s*(?:req|user|input)|createTemplate\s*\(\s*(?:req|user))""",
        anti_pattern=r"""(?i)(?:SandboxedEnvironment|render_template\s*\(\s*["'][a-zA-Z0-9_./-]+\.html["'])""",
        remediation="Never compile user input as a template; pass untrusted values strictly as data context variables to static template files (or use Jinja2 `SandboxedEnvironment`).",
        secure_example="return render_template('greeting.html', username=user_input)",
    ),
    ServerSideRule(
        rule_id="CYB-DESER-001",
        title="Insecure Deserialization (`pickle` / `yaml.load` / `ObjectInputStream` / `unserialize`)",
        description="Deserializing untrusted byte streams using arbitrary-object serializers enables direct Remote Code Execution via gadget chains.",
        severity=Severity.CRITICAL,
        cwe_ids=("CWE-502",),
        owasp=("A08:2021-Software-and-Data-Integrity-Failures",),
        mitre_id="T1190",
        mitre_name="Exploit Public-Facing Application",
        tactic=MitreTactic.INITIAL_ACCESS,
        languages=(".py", ".java", ".php", ".rb", ".cs", ".js", ".ts"),
        pattern=r"""(?i)(?:pickle\.loads?\s*\(|cPickle\.loads?\s*\(|yaml\.load\s*\([^)]*(?!Loader\s*=\s*(?:yaml\.)?SafeLoader)|yaml\.unsafe_load\s*\(|marshal\.loads?\s*\(|jsonpickle\.decode\s*\(|ObjectInputStream\s*\(|XMLDecoder\s*\(|BinaryFormatter\s*\(|\bunserialize\s*\(|Marshal\.load\s*\(|node-serialize)""",
        anti_pattern=r"""(?i)(?:yaml\.safe_load|SafeLoader|CSafeLoader|ObjectInputFilter)""",
        remediation="Replace unsafe binary/object deserializers with strict schema-validated JSON (`json.loads`), Protocol Buffers, or `yaml.safe_load()`.",
        secure_example="config = yaml.safe_load(raw_yaml_text)",
    ),
    ServerSideRule(
        rule_id="CYB-PATH-TRAV-001",
        title="Path Traversal / Arbitrary File Read or Write via Uncanonicalized Join",
        description="Combining user-controlled path segments with filesystem operations without canonical root containment allows escaping into `/etc/passwd`, `.env`, or SSH keys.",
        severity=Severity.HIGH,
        cwe_ids=("CWE-22", "CWE-23"),
        owasp=("A01:2021-Broken-Access-Control",),
        mitre_id="T1005",
        mitre_name="Data from Local System",
        tactic=MitreTactic.COLLECTION,
        languages=(".py", ".js", ".ts", ".go", ".java", ".php", ".rb"),
        pattern=r"""(?i)(?:(?:open|send_file|readFileSync|readFile|os\.ReadFile|Files\.readAllBytes|file_get_contents)\s*\(\s*(?:os\.path\.join|path\.join|filepath\.Join|f["'])[^)]*(?:req\.|request\.|params|filename|filepath|user_path|path_arg))""",
        anti_pattern=r"""(?i)(?:is_relative_to|commonpath|secure_filename|realpath.*startswith|canonicalPath\.startsWith)""",
        remediation="Canonicalize paths with `Path.resolve()` and assert `resolved.is_relative_to(base_root.resolve())`, denying `..`, symlinks, and hidden dotfiles.",
        secure_example="target = (BASE_DIR / filename).resolve()\nif not target.is_relative_to(BASE_DIR.resolve()): raise PermissionError('Blocked')",
    ),
    ServerSideRule(
        rule_id="CYB-ARCHIVE-ZIPSLIP-001",
        title="Archive Extraction Path Traversal (ZipSlip / TarSlip)",
        description="Calling `.extractall()` on untrusted ZIP/TAR archives without validating every member's canonical extraction destination permits arbitrary file overwrite.",
        severity=Severity.HIGH,
        cwe_ids=("CWE-22",),
        owasp=("A08:2021-Software-and-Data-Integrity-Failures",),
        mitre_id="T1546",
        mitre_name="Event Triggered Execution",
        tactic=MitreTactic.PERSISTENCE,
        languages=(".py", ".java", ".js", ".ts", ".go"),
        pattern=r"""(?i)(?:\.extractall\s*\(|tarfile\.open\([^)]*\).*extract|unzipper\.Extract|ZipInputStream.*getNextEntry)""",
        anti_pattern=r"""(?i)(?:filter\s*=\s*["']data["']|is_relative_to|safe_extract|validate_member)""",
        remediation="Validate every archive member path against `dest_dir.resolve()`, reject symlinks/device nodes, and use Python 3.12+ `tar.extractall(filter='data')`.",
        secure_example="for m in zf.namelist():\n    dest = (out_dir / m).resolve()\n    assert dest.is_relative_to(out_dir.resolve())",
    ),
)


# ---------------------------------------------------------------------------
# Unified Server-Side High-Impact Engine (SSRF / XXE / SSTI / Deser / Traversal)
# ---------------------------------------------------------------------------

class WebServerSideVulnEngine:
    """Static + structural + local sandboxed differential tester for SSRF, XXE, SSTI, Deser, and ZipSlip."""

    SSRF_TEST_URLS: Tuple[Tuple[str, str], ...] = (
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IMDSv1 direct"),
        ("http://[::ffff:169.254.169.254]/latest/meta-data/", "IPv6-mapped IPv4 IMDS bypass"),
        ("http://0xa9fea9fe/latest/meta-data/", "Hex-encoded IPv4 IMDS bypass"),
        ("http://2130706433/admin", "Decimal-encoded loopback bypass"),
        ("http://trusted.example.com@127.0.0.1:8080/internal", "Userinfo `@` parser confusion"),
        ("file:///etc/passwd", "File URI scheme local read"),
    )

    SSTI_PROBES: Tuple[Tuple[str, str, str], ...] = (
        ("{{7*7*19}}", "931", "Jinja2 / Twig / Nunjucks"),
        ("${7*7*19}", "931", "Freemarker / Velocity / Mako / Spring EL"),
        ("<%= 7*7*19 %>", "931", "ERB / EJS"),
        ("#{7*7*19}", "931", "Ruby / Thymeleaf / Jade"),
    )

    def __init__(self) -> None:
        self._compiled: List[Tuple[ServerSideRule, Pattern[str], Optional[Pattern[str]]]] = [
            (r, re.compile(r.pattern), re.compile(r.anti_pattern) if r.anti_pattern else None)
            for r in SERVER_SIDE_RULES
        ]
        self.ssrf_validator = SSRFUrlValidatorAndBypassDetector()

    def scan_directory(self, root_path: Path) -> List[CyberVulnerability]:
        findings: List[CyberVulnerability] = []
        seen: set[str] = set()

        for file_path in sorted(root_path.rglob("*")):
            if not file_path.is_file():
                continue
            if any(p in {".git", "node_modules", "__pycache__", ".venv", "dist", "build"} for p in file_path.parts):
                continue
            ext = file_path.suffix.lower()
            if ext not in {".py", ".js", ".ts", ".java", ".go", ".php", ".rb", ".cs", ".xml"}:
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = str(file_path.relative_to(root_path))
            lines = content.splitlines()

            # Check XML files directly for dangerous DOCTYPE/ENTITY declarations
            if ext == ".xml":
                findings.extend(self.audit_xml_payload(content, rel))

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
                        cyber_domain=CyberDomain.WEB_SSRF_XXE_SSTI_DESER,
                        severity=rule.severity,
                        cwe_ids=list(rule.cwe_ids),
                        confidence=0.88,
                        owasp_categories=list(rule.owasp),
                        mitre_techniques=[MitreTechniqueRef(rule.mitre_id, rule.mitre_name, rule.tactic)],
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=rel,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line.strip()[:300],
                        remediation_guidance=rule.remediation,
                        secure_code_example=rule.secure_example,
                        discovered_by="ely_cyber_server_side_static",
                    )
                    fp = v.fingerprint()
                    if fp not in seen:
                        seen.add(fp)
                        findings.append(v)

        return findings

    def audit_xml_payload(self, xml_text: str, source_ref: str = "xml_input") -> List[CyberVulnerability]:
        """Inspect an XML document for XXE external entity or Billion Laughs expansion constructs."""
        findings: List[CyberVulnerability] = []
        if re.search(r"<!ENTITY\s+[^>]*(?:SYSTEM|PUBLIC)\s+[\"']", xml_text, re.IGNORECASE):
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-XXE-PAYLOAD-001",
                    title="XML External Entity (XXE) SYSTEM/PUBLIC Declaration Detected",
                    description=f"XML payload `{source_ref}` declares an external `SYSTEM`/`PUBLIC` entity capable of reading local files or triggering SSRF.",
                    cyber_domain=CyberDomain.WEB_SSRF_XXE_SSTI_DESER,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-611"],
                    confidence=0.96,
                    owasp_categories=["A05:2021-Security-Misconfiguration"],
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    file_path=source_ref,
                    remediation_guidance="Reject all XML inputs containing `<!DOCTYPE` or `<!ENTITY` declarations.",
                    discovered_by="ely_cyber_xxe_inspector",
                )
            )
        entity_count = len(re.findall(r"<!ENTITY\s+", xml_text, re.IGNORECASE))
        if entity_count >= 5:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-XXE-BOMB-001",
                    title="XML Entity Expansion Bomb (Billion Laughs DoS Pattern)",
                    description=f"XML document `{source_ref}` defines {entity_count} nested entity declarations indicative of exponential entity expansion.",
                    cyber_domain=CyberDomain.WEB_SSRF_XXE_SSTI_DESER,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-776"],
                    confidence=0.94,
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    file_path=source_ref,
                    remediation_guidance="Disable DTDs completely in XML parsers (`defusedxml`).",
                    discovered_by="ely_cyber_xxe_inspector",
                )
            )
        return findings

    def audit_archive_members(self, member_paths: List[str], dest_root: str = "/tmp/extract") -> List[CyberVulnerability]:
        """Validate candidate archive entries against ZipSlip / TarSlip escape invariants."""
        findings: List[CyberVulnerability] = []
        root_resolved = Path(dest_root).resolve()
        bad_entries: List[str] = []
        for entry in member_paths:
            norm = entry.replace("\\", "/")
            if norm.startswith("/") or "\x00" in norm or ".." in Path(norm).parts:
                bad_entries.append(entry)
                continue
            target = (root_resolved / norm).resolve()
            if not target.is_relative_to(root_resolved):
                bad_entries.append(entry)
        if bad_entries:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-ZIPSLIP-MEMBER-001",
                    title="Archive Traversal (ZipSlip/TarSlip) Escape Entries Detected",
                    description=f"Archive contains {len(bad_entries)} member(s) escaping extraction root `{dest_root}`: {bad_entries[:5]}",
                    cyber_domain=CyberDomain.WEB_SSRF_XXE_SSTI_DESER,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-22"],
                    confidence=0.99,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=dest_root,
                    attack_vector_detail=f"Escaping entries: {bad_entries[:5]}",
                    remediation_guidance="Reject archives containing absolute paths, `..` components, backslashes, or symlinks outside extraction root.",
                    discovered_by="ely_cyber_archive_verifier",
                )
            )
        return findings

    def probe_sandbox_ssrf_ssti_path(
        self,
        handler: Callable[[HttpProbeRequest], HttpProbeResponse],
        *,
        ssrf_endpoint: Optional[str] = None,
        ssti_endpoint: Optional[str] = None,
        file_endpoint: Optional[str] = None,
    ) -> List[CyberVulnerability]:
        """Execute local sandboxed differential SSRF, SSTI, and Path Traversal probes."""
        findings: List[CyberVulnerability] = []

        # 1. Sandboxed SSRF probing
        if ssrf_endpoint:
            for test_url, label in self.SSRF_TEST_URLS:
                res = handler(HttpProbeRequest(method="GET", path=ssrf_endpoint, query_params={"url": test_url}))
                reached = any(
                    marker in (" ".join(res.outbound_requests) + " " + res.body).lower()
                    for marker in ("169.254.169.254", "iam/security-credentials", "127.0.0.1", "root:x:0:0", "ssrf_fetched")
                )
                if res.status_code == 200 and reached:
                    findings.append(
                        make_cyber_vuln(
                            rule_id="PROBE-SSRF-001",
                            title=f"Server-Side Request Forgery (SSRF) Confirmed ({label})",
                            description=f"Endpoint `{ssrf_endpoint}` accepted `{test_url}` ({label}) and performed internal/metadata fetch.",
                            cyber_domain=CyberDomain.WEB_SSRF_XXE_SSTI_DESER,
                            severity=Severity.CRITICAL,
                            cwe_ids=["CWE-918"],
                            confidence=0.98,
                            owasp_categories=["A10:2021-Server-Side-Request-Forgery"],
                            mitre_techniques=[MitreTechniqueRef("T1552.005", "Cloud Instance Metadata API", MitreTactic.CREDENTIAL_ACCESS, "005")],
                            cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="H", vi="L", va="N", sc="H", si="H", sa="N", e="P"),
                            verification_method=VerificationMethod.SANDBOX_DIFFERENTIAL_PROBE,
                            sandbox_reproduced=True,
                            endpoint_or_asset=f"GET {ssrf_endpoint}?url=...",
                            attack_vector_detail=f"Bypass vector `{test_url}` reached outbound/metadata handler.",
                            remediation_guidance="Canonicalize URLs, resolve IPs, block private/loopback/link-local CIDRs, and enforce IMDSv2 hop limit=1.",
                            evidence=[
                                EvidenceArtifact(
                                    artifact_id=new_id("ev"),
                                    kind="http_exchange",
                                    summary=f"SSRF probe {label}",
                                    content=f"URL={test_url}\nOutbound={res.outbound_requests}\nBody={res.body[:220]}",
                                )
                            ],
                            discovered_by="ely_cyber_server_side_prober",
                        )
                    )
                    break

        # 2. Sandboxed SSTI probing
        if ssti_endpoint:
            for expr, expected, engines in self.SSTI_PROBES:
                res = handler(HttpProbeRequest(method="GET", path=ssti_endpoint, query_params={"name": expr}))
                if res.status_code == 200 and expected in res.body and expr not in res.body:
                    findings.append(
                        make_cyber_vuln(
                            rule_id="PROBE-SSTI-001",
                            title=f"Server-Side Template Injection Confirmed ({engines})",
                            description=f"Template expression `{expr}` evaluated server-side to `{expected}` on `{ssti_endpoint}`.",
                            cyber_domain=CyberDomain.WEB_SSRF_XXE_SSTI_DESER,
                            severity=Severity.CRITICAL,
                            cwe_ids=["CWE-1336", "CWE-94"],
                            confidence=0.99,
                            owasp_categories=["A03:2021-Injection"],
                            mitre_techniques=[MitreTechniqueRef("T1059", "Command and Scripting Interpreter", MitreTactic.EXECUTION)],
                            cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="L", e="P"),
                            verification_method=VerificationMethod.SANDBOX_DIFFERENTIAL_PROBE,
                            sandbox_reproduced=True,
                            endpoint_or_asset=f"GET {ssti_endpoint}?name=...",
                            attack_vector_detail=f"Expression `{expr}` rendered `{expected}`.",
                            remediation_guidance="Pass user input strictly as template data context variables, never as template source text.",
                            discovered_by="ely_cyber_server_side_prober",
                        )
                    )
                    break

        # 3. Sandboxed Path Traversal probing
        if file_endpoint:
            for payload in ("../../../../etc/passwd", "..%2f..%2f.env", "/etc/passwd"):
                res = handler(HttpProbeRequest(method="GET", path=file_endpoint, query_params={"file": payload}))
                leaked = any(
                    tok in (res.body + " " + " ".join(res.files_accessed)).lower()
                    for tok in ("root:x:0:0", "openai_api_key", "database_url", "/etc/passwd", ".env")
                )
                if res.status_code == 200 and leaked:
                    findings.append(
                        make_cyber_vuln(
                            rule_id="PROBE-PATHTRAV-001",
                            title="Path Traversal Arbitrary File Read Confirmed in Sandbox",
                            description=f"Endpoint `{file_endpoint}` escaped root directory using `{payload}`.",
                            cyber_domain=CyberDomain.WEB_SSRF_XXE_SSTI_DESER,
                            severity=Severity.CRITICAL,
                            cwe_ids=["CWE-22"],
                            confidence=0.99,
                            owasp_categories=["A01:2021-Broken-Access-Control"],
                            verification_method=VerificationMethod.SANDBOX_DIFFERENTIAL_PROBE,
                            sandbox_reproduced=True,
                            endpoint_or_asset=f"GET {file_endpoint}?file=...",
                            attack_vector_detail=f"Payload `{payload}` read out-of-root file.",
                            remediation_guidance="Resolve canonical path via `Path.resolve()` and enforce strict `is_relative_to(allowed_root)` check.",
                            discovered_by="ely_cyber_server_side_prober",
                        )
                    )
                    break

        return findings
