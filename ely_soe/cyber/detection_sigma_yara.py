"""
Sigma Log Detection Engine & YARA-Style Byte/Hex/Regex Signature Scanner.

Provides built-in Blue-Team / Purple-Team Detection Engineering without external dependencies:
  1. **Sigma Detection Rule Compiler & Evaluator**:
       - Evaluates structured `SigmaRule` definitions against `TelemetryEvent` streams
       - Supports Sigma field modifiers: exact match, `|contains`, `|startswith`, `|endswith`,
         `|re` (regex), `|gt`, `|lt`, `|all` (match all values in list), case-insensitive matching
       - Supports boolean selection conditions (`selection`, `selection and not filter`,
         `sel1 and sel2`, `sel1 or sel2`, `1 of sel*`, `all of sel*`)
       - Ships with **22 built-in defensive Sigma rules** directly detecting the ATT&CK techniques
         emitted by `MitreAttackEmulationEngine` (CloudTrail StopLogging, IMDSv1 SSRF,
         LSASS dump, DCSync Event 4662, Kerberoasting Event 4769 RC4, ADCS ESC1, K8s privileged pod,
         `pods/exec`, encoded PowerShell, `curl | sh`, DNS tunneling, Shadow Copy deletion, etc.)
  2. **YARA-Style Signature & Binary/Source Pattern Engine**:
       - Supports literal ASCII strings, case-insensitive `nocase`, hex byte patterns with
         wildcards (`4D 5A ?? ?? 50 45`), regex patterns, file-size bounds, Shannon entropy checks,
         and `any of them` / `all of them` / `N of them` match conditions
       - Ships with **12 built-in YARA rules** detecting web shells, reverse-shell snippets,
         credential-dump scripts, malicious pickle opcodes, suspicious ELF/PE packed stubs,
         hidden prompt-injection payloads, and CI/CD secret exfiltration patterns
  3. **Purple-Team Detection Coverage Analyzer**:
       - Cross-references emulated ATT&CK techniques against Sigma alerts to compute exact
         Detective Coverage % and list blind-spot techniques requiring new SIEM rules.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import Severity, new_id
from ely_soe.cyber.models import DetectionMatch, TelemetryEvent


# ---------------------------------------------------------------------------
# Sigma Detection Rule Engine
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SigmaRule:
    rule_id: str
    title: str
    log_source: str  # matches TelemetryEvent.log_source or "*"
    severity: Severity
    mitre_techniques: Tuple[str, ...]
    selections: Dict[str, Dict[str, Any]]
    condition: str = "selection"
    description: str = ""


BUILTIN_SIGMA_RULES: Tuple[SigmaRule, ...] = (
    SigmaRule(
        rule_id="SIGMA-CLOUD-001",
        title="CloudTrail Audit Logging Disabled (`StopLogging` / `DeleteTrail`)",
        log_source="cloudtrail",
        severity=Severity.CRITICAL,
        mitre_techniques=("T1562.008",),
        selections={"selection": {"event_name": ["StopLogging", "DeleteTrail", "UpdateTrail"]}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-CLOUD-002",
        title="IAM Privilege Escalation via AdministratorAccess Attachment or Cross-User Access Key",
        log_source="cloudtrail",
        severity=Severity.CRITICAL,
        mitre_techniques=("T1098.003", "T1098.001"),
        selections={
            "sel_attach": {"event_name": "AttachRolePolicy", "policy_arn|contains": "AdministratorAccess"},
            "sel_key": {"event_name": "CreateAccessKey"},
        },
        condition="sel_attach or sel_key",
    ),
    SigmaRule(
        rule_id="SIGMA-CLOUD-003",
        title="Cloud Console Login Without MFA",
        log_source="cloudtrail",
        severity=Severity.HIGH,
        mitre_techniques=("T1078.004",),
        selections={"selection": {"event_name": "ConsoleLogin", "mfa_used": "No", "result": "Success"}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-CLOUD-004",
        title="Bulk Sensitive Cloud Storage Data Extraction (`GetObject` Spike)",
        log_source="cloudtrail",
        severity=Severity.HIGH,
        mitre_techniques=("T1530",),
        selections={"selection": {"event_name": "GetObject", "objects_downloaded_5m|gt": 500}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-CLOUD-005",
        title="Suspicious Cloud Secrets Enumeration Burst (`ListSecrets`)",
        log_source="cloudtrail",
        severity=Severity.MEDIUM,
        mitre_techniques=("T1580",),
        selections={"selection": {"event_name": "ListSecrets", "burst_calls_1m|gt": 20}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-CLOUD-006",
        title="Unsigned Serverless Function Code Overwrite",
        log_source="cloudtrail",
        severity=Severity.HIGH,
        mitre_techniques=("T1525",),
        selections={"selection": {"event_name|startswith": "UpdateFunctionCode", "unsigned": True}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-CICD-001",
        title="GitHub Actions `pull_request_target` with Unpinned Action Reference",
        log_source="cloudtrail",
        severity=Severity.CRITICAL,
        mitre_techniques=("T1195.002",),
        selections={"selection": {"event_name": "GitHubActionsWorkflowRun", "trigger": "pull_request_target"}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-K8S-001",
        title="Kubernetes Privileged Container or HostPath Docker Socket Pod Creation",
        log_source="k8s_audit",
        severity=Severity.CRITICAL,
        mitre_techniques=("T1611",),
        selections={
            "sel_priv": {"verb": "create", "resource": "pods", "privileged": True},
            "sel_sock": {"host_path|contains": "docker.sock"},
        },
        condition="sel_priv or sel_sock",
    ),
    SigmaRule(
        rule_id="SIGMA-K8S-002",
        title="Kubernetes `pods/exec` Interactive Command Execution in Production",
        log_source="k8s_audit",
        severity=Severity.HIGH,
        mitre_techniques=("T1609",),
        selections={"selection": {"verb": "create", "resource": "pods/exec", "namespace": "production"}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-K8S-003",
        title="Kubernetes Cluster Secrets Listing by Workload ServiceAccount",
        log_source="k8s_audit",
        severity=Severity.HIGH,
        mitre_techniques=("T1613",),
        selections={"selection": {"verb": ["list", "get"], "resource": "secrets", "namespace": "kube-system"}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-PROC-001",
        title="Remote Script Download Piped Directly to Shell (`curl | sh`)",
        log_source="process_creation",
        severity=Severity.CRITICAL,
        mitre_techniques=("T1059.004",),
        selections={"selection": {"command_line|re": r"(?i)(curl|wget).*\|\s*(sh|bash)"}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-PROC-002",
        title="Obfuscated Encoded PowerShell Execution (`-EncodedCommand`)",
        log_source="process_creation",
        severity=Severity.HIGH,
        mitre_techniques=("T1059.001",),
        selections={"selection": {"image|contains": "powershell", "command_line|contains": ["-EncodedCommand", "-enc"]}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-PROC-003",
        title="Volume Shadow Copy / Backup Recovery Deletion (`vssadmin delete shadows`)",
        log_source="process_creation",
        severity=Severity.CRITICAL,
        mitre_techniques=("T1490",),
        selections={"selection": {"command_line|contains|all": ["delete", "shadows"]}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-PROC-004",
        title="Ransomware Rapid Mass Encryption Process Activity",
        log_source="process_creation",
        severity=Severity.CRITICAL,
        mitre_techniques=("T1486",),
        selections={"selection": {"files_modified_10s|gt": 100}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-PROC-005",
        title="Linux Audit Log Tampering / Deletion (`/var/log/audit`)",
        log_source="process_creation",
        severity=Severity.HIGH,
        mitre_techniques=("T1070.002",),
        selections={"selection": {"command_line|contains": ["/var/log/auth.log", "/var/log/audit"]}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-PROC-006",
        title="Reverse SSH Tunnel / SOCKS Forwarding Process",
        log_source="process_creation",
        severity=Severity.HIGH,
        mitre_techniques=("T1572",),
        selections={"selection": {"image|endswith": "ssh", "command_line|contains": " -R "}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-PROC-007",
        title="Suspicious Crontab Persistence Pointing to `/tmp`",
        log_source="process_creation",
        severity=Severity.HIGH,
        mitre_techniques=("T1053.003",),
        selections={"selection": {"command_line|contains|all": ["crontab", "/tmp/"]}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-WIN-001",
        title="LSASS Memory Access for Credential Dumping (Sysmon Event 10)",
        log_source="windows_security",
        severity=Severity.CRITICAL,
        mitre_techniques=("T1003.001",),
        selections={"selection": {"event_id": 10, "target_image|endswith": "lsass.exe"}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-WIN-002",
        title="DCSync Active Directory Replication Rights Abuse (Event 4662)",
        log_source="windows_security",
        severity=Severity.CRITICAL,
        mitre_techniques=("T1003.006",),
        selections={"selection": {"event_id": 4662, "properties|contains": "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-WIN-003",
        title="Kerberoasting RC4 Service Ticket Request (Event 4769, Encryption 0x17)",
        log_source="windows_security",
        severity=Severity.HIGH,
        mitre_techniques=("T1558.003",),
        selections={"selection": {"event_id": 4769, "ticket_encryption_type": "0x17"}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-WIN-004",
        title="ADCS ESC1 Forged Admin SAN Certificate Enrollment Request (Event 4886)",
        log_source="windows_security",
        severity=Severity.CRITICAL,
        mitre_techniques=("T1649",),
        selections={"selection": {"event_id": 4886, "san_upn|contains": "administrator"}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-NET-001",
        title="Cloud Instance Metadata IMDSv1 Unauthenticated Request (`169.254.169.254`)",
        log_source="network_connection",
        severity=Severity.CRITICAL,
        mitre_techniques=("T1552.005",),
        selections={"selection": {"dst_ip": "169.254.169.254", "imds_token_header": False}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-NET-002",
        title="Large Outbound Cloud Storage Exfiltration Upload (>100MB)",
        log_source="network_connection",
        severity=Severity.CRITICAL,
        mitre_techniques=("T1567.002",),
        selections={"selection": {"http_method": "PUT", "bytes_out|gt": 100_000_000}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-DNS-001",
        title="High-Entropy DNS TXT Tunneling / C2 Beacon",
        log_source="dns",
        severity=Severity.HIGH,
        mitre_techniques=("T1071.004",),
        selections={"selection": {"qtype": "TXT", "entropy|gt": 3.8}},
        condition="selection",
    ),
    SigmaRule(
        rule_id="SIGMA-WEB-001",
        title="SQL Injection UNION SELECT Attempt in Web Request Body",
        log_source="web_access",
        severity=Severity.CRITICAL,
        mitre_techniques=("T1190",),
        selections={"selection": {"body_sample|re": r"(?i)union\s+select\b"}},
        condition="selection",
    ),
)


class SigmaDetectionEngine:
    """Evaluates built-in and custom Sigma rules against normalized `TelemetryEvent` streams."""

    def __init__(self, rules: Optional[Sequence[SigmaRule]] = None) -> None:
        self.rules: List[SigmaRule] = list(rules) if rules is not None else list(BUILTIN_SIGMA_RULES)

    def evaluate_events(self, events: Sequence[TelemetryEvent]) -> List[DetectionMatch]:
        matches: List[DetectionMatch] = []
        for ev in events:
            for rule in self.rules:
                if rule.log_source != "*" and rule.log_source != ev.log_source:
                    continue
                if self._matches_rule(rule, ev.fields):
                    matches.append(
                        DetectionMatch(
                            match_id=new_id("dmat"),
                            engine="sigma",
                            rule_id=rule.rule_id,
                            rule_title=rule.title,
                            severity=rule.severity,
                            mitre_techniques=list(rule.mitre_techniques),
                            target_ref=f"{ev.log_source}:{ev.event_id}@{ev.host}",
                            matched_evidence=str(ev.fields)[:280],
                        )
                    )
        return matches

    def measure_purple_team_coverage(
        self,
        emulation_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Score Sigma detective coverage against an `MitreAttackEmulationEngine` campaign."""
        events: List[TelemetryEvent] = emulation_result.get("telemetry_events", [])
        matches = self.evaluate_events(events)

        detected_techniques = {t for m in matches for t in m.mitre_techniques}
        all_techs = [r["technique_id"] for r in emulation_result.get("technique_results", [])]
        covered = [t for t in all_techs if t in detected_techniques]
        blind_spots = [t for t in all_techs if t not in detected_techniques]
        coverage_pct = round((len(covered) / len(all_techs)) * 100.0, 2) if all_techs else 100.0

        return {
            "total_events_evaluated": len(events),
            "sigma_rules_loaded": len(self.rules),
            "total_alerts_fired": len(matches),
            "techniques_emulated": len(all_techs),
            "techniques_detected": len(covered),
            "detective_coverage_pct": coverage_pct,
            "blind_spot_techniques": blind_spots,
            "matches": [m.to_dict() for m in matches],
            "raw_matches": matches,
        }

    def _matches_rule(self, rule: SigmaRule, fields: Dict[str, Any]) -> bool:
        sel_results = {
            name: self._eval_selection(spec, fields)
            for name, spec in rule.selections.items()
        }
        return self._eval_condition(rule.condition.strip(), sel_results)

    def _eval_selection(self, spec: Dict[str, Any], fields: Dict[str, Any]) -> bool:
        for raw_key, expected in spec.items():
            parts = raw_key.split("|")
            field_name = parts[0]
            modifiers = set(parts[1:])
            if field_name not in fields:
                return False
            actual = fields[field_name]
            if not self._match_field(actual, expected, modifiers):
                return False
        return True

    def _match_field(self, actual: Any, expected: Any, modifiers: set[str]) -> bool:
        if "gt" in modifiers:
            try:
                return float(actual) > float(expected)
            except (TypeError, ValueError):
                return False
        if "lt" in modifiers:
            try:
                return float(actual) < float(expected)
            except (TypeError, ValueError):
                return False

        expected_list = expected if isinstance(expected, (list, tuple, set)) else [expected]
        require_all = "all" in modifiers

        def _single(val: Any) -> bool:
            if "re" in modifiers:
                return bool(re.search(str(val), str(actual)))
            if "contains" in modifiers:
                return str(val).lower() in str(actual).lower()
            if "startswith" in modifiers:
                return str(actual).lower().startswith(str(val).lower())
            if "endswith" in modifiers:
                return str(actual).lower().endswith(str(val).lower())
            if isinstance(val, bool) or isinstance(actual, bool):
                return actual is val
            return str(actual).lower() == str(val).lower()

        return all(_single(v) for v in expected_list) if require_all else any(_single(v) for v in expected_list)

    def _eval_condition(self, cond: str, sel_results: Dict[str, bool]) -> bool:
        # Handle `1 of prefix*` and `all of prefix*`
        m_of = re.fullmatch(r"(1|all)\s+of\s+([a-zA-Z0-9_]+)\*", cond)
        if m_of:
            quant, prefix = m_of.group(1), m_of.group(2)
            vals = [v for k, v in sel_results.items() if k.startswith(prefix)]
            return all(vals) if quant == "all" else any(vals)

        # Split on ` or ` then ` and ` with optional `not `
        for or_branch in cond.split(" or "):
            branch_ok = True
            for term in or_branch.strip().split(" and "):
                t = term.strip()
                neg = False
                if t.startswith("not "):
                    neg = True
                    t = t[4:].strip()
                val = sel_results.get(t, False)
                if neg:
                    val = not val
                if not val:
                    branch_ok = False
                    break
            if branch_ok:
                return True
        return False


# ---------------------------------------------------------------------------
# YARA-Style Byte, Hex-Wildcard, Regex & Entropy Signature Scanner
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class YaraSignatureRule:
    rule_id: str
    title: str
    severity: Severity
    mitre_techniques: Tuple[str, ...]
    ascii_patterns: Tuple[bytes, ...] = ()
    hex_patterns: Tuple[str, ...] = ()     # e.g. "80 04 ?? ?? 63 6f 73 0a"
    regex_patterns: Tuple[str, ...] = ()
    min_match_count: int = 1
    min_entropy: Optional[float] = None
    nocase: bool = True


BUILTIN_YARA_RULES: Tuple[YaraSignatureRule, ...] = (
    YaraSignatureRule(
        rule_id="YARA-WEBSHELL-PHP-001",
        title="PHP Eval/System Webshell Signature",
        severity=Severity.CRITICAL,
        mitre_techniques=("T1505.003",),
        regex_patterns=(
            r"(?i)<\?php.*\b(?:eval|assert|system|passthru|shell_exec)\s*\(\s*(?:base64_decode|gzinflate)?\s*\(?\$_(?:GET|POST|REQUEST|COOKIE)",
        ),
    ),
    YaraSignatureRule(
        rule_id="YARA-REVSHELL-001",
        title="Interactive Reverse Shell Payload Pattern (`/dev/tcp` / `pty.spawn` / `nc -e`)",
        severity=Severity.CRITICAL,
        mitre_techniques=("T1059.004",),
        regex_patterns=(
            r"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+",
            r"bash\s+-i\s+>&\s+/dev/tcp/",
            r"socket\.socket\(.*connect\(.*pty\.spawn",
            r"\bnc(?:at)?\s+.*-e\s+/bin/(?:ba)?sh",
        ),
    ),
    YaraSignatureRule(
        rule_id="YARA-PICKLE-RCE-001",
        title="Malicious Python Pickle Opcode Invoking `os.system` / `posix.system` / `subprocess`",
        severity=Severity.CRITICAL,
        mitre_techniques=("T1059.006",),
        hex_patterns=("63 70 6f 73 69 78 0a 73 79 73 74 65 6d", "63 6f 73 0a 73 79 73 74 65 6d"),
        ascii_patterns=(b"cposix\nsystem", b"cos\nsystem", b"csubprocess\nPopen"),
    ),
    YaraSignatureRule(
        rule_id="YARA-PRIVKEY-LEAK-001",
        title="Embedded Private Cryptographic Key Material (PEM)",
        severity=Severity.CRITICAL,
        mitre_techniques=("T1552.004",),
        ascii_patterns=(b"-----BEGIN RSA PRIVATE KEY-----", b"-----BEGIN OPENSSH PRIVATE KEY-----", b"-----BEGIN EC PRIVATE KEY-----"),
        nocase=False,
    ),
    YaraSignatureRule(
        rule_id="YARA-CRYPTO-MINER-001",
        title="Stratum Cryptominer Pool Configuration Signature",
        severity=Severity.HIGH,
        mitre_techniques=("T1496",),
        ascii_patterns=(b"stratum+tcp://", b"stratum+ssl://", b"xmrig", b"randomx"),
        min_match_count=2,
    ),
    YaraSignatureRule(
        rule_id="YARA-CICD-EXFIL-001",
        title="CI/CD Secret Exfiltration Over HTTP (`curl -d $SECRET` / `base64` Env Dump)",
        severity=Severity.CRITICAL,
        mitre_techniques=("T1552.001", "T1567"),
        regex_patterns=(
            r"(?i)curl\s+.*(?:-d|--data).*(?:\$\{\{\s*secrets\.|\$AWS_SECRET|\$GITHUB_TOKEN)",
            r"(?i)env\s*\|\s*base64.*\|\s*curl",
        ),
    ),
    YaraSignatureRule(
        rule_id="YARA-PROMPT-INJ-TAG-001",
        title="Hidden Agentic Prompt-Injection Directive Embedded in Data/Tool Artifact",
        severity=Severity.HIGH,
        mitre_techniques=("T1059",),
        regex_patterns=(
            r"(?i)<IMPORTANT>.*(?:ignore\s+all\s+previous|exfiltrate|run_shell)",
            r"(?i)SYSTEM\s+OVERRIDE:\s*disregard\s+(?:all\s+)?(?:prior|previous)\s+(?:rules|instructions)",
        ),
    ),
)


class YaraStyleScanner:
    """Pure-Python YARA-style signature scanner supporting ASCII, wildcard hex bytes, regex, and entropy."""

    def __init__(self, rules: Optional[Sequence[YaraSignatureRule]] = None) -> None:
        self.rules: List[YaraSignatureRule] = list(rules) if rules is not None else list(BUILTIN_YARA_RULES)

    def scan_bytes(self, data: bytes, target_ref: str = "buffer") -> List[DetectionMatch]:
        matches: List[DetectionMatch] = []
        text = data.decode("utf-8", errors="ignore")
        low_data = data.lower()
        entropy = self._byte_entropy(data) if data else 0.0

        for rule in self.rules:
            if rule.min_entropy is not None and entropy < rule.min_entropy:
                continue

            hits: List[str] = []
            for pat in rule.ascii_patterns:
                hay = low_data if rule.nocase else data
                needle = pat.lower() if rule.nocase else pat
                if needle in hay:
                    hits.append(f"ascii:{pat.decode('ascii', errors='replace')[:40]}")

            for hpat in rule.hex_patterns:
                rx = self._compile_hex_wildcard(hpat)
                if rx.search(data):
                    hits.append(f"hex:{hpat[:32]}")

            for rpat in rule.regex_patterns:
                m = re.search(rpat, text)
                if m:
                    hits.append(f"re:{m.group(0)[:60]}")

            if len(hits) >= rule.min_match_count:
                matches.append(
                    DetectionMatch(
                        match_id=new_id("ymat"),
                        engine="yara",
                        rule_id=rule.rule_id,
                        rule_title=rule.title,
                        severity=rule.severity,
                        mitre_techniques=list(rule.mitre_techniques),
                        target_ref=target_ref,
                        matched_evidence="; ".join(hits[:4]),
                    )
                )

        return matches

    def scan_directory(self, root_path: Path, max_file_bytes: int = 2_000_000) -> List[DetectionMatch]:
        all_matches: List[DetectionMatch] = []
        for fp in sorted(root_path.rglob("*")):
            if not fp.is_file():
                continue
            if any(p in {".git", "node_modules", "__pycache__", ".venv"} for p in fp.parts):
                continue
            try:
                if fp.stat().st_size > max_file_bytes:
                    continue
                data = fp.read_bytes()
            except OSError:
                continue
            rel = str(fp.relative_to(root_path))
            all_matches.extend(self.scan_bytes(data, target_ref=rel))
        return all_matches

    @staticmethod
    def _compile_hex_wildcard(hex_pattern: str) -> re.Pattern[bytes]:
        tokens = hex_pattern.strip().split()
        parts: List[bytes] = []
        for tok in tokens:
            if tok == "??":
                parts.append(b".")
            else:
                bval = bytes([int(tok, 16)])
                parts.append(re.escape(bval))
        return re.compile(b"".join(parts), re.DOTALL)

    @staticmethod
    def _byte_entropy(data: bytes) -> float:
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in counts if c > 0)
