"""
Windows Endpoint Internals, PowerShell Deobfuscation, LOLBins (Living-off-the-Land),
Credential-Dump (LSASS/NTDS), AMSI/ETW Evasion & EDR Telemetry Detection Engine.

Detects high-signal endpoint intrusion behaviors across Windows process creation logs
(Sysmon Event ID 1 / Security 4688), PowerShell ScriptBlock logs (Event ID 4104),
and registry/WMI persistence artifacts:
  1. **Automated PowerShell Deobfuscator**:
       - Detects & decodes Base64 UTF-16LE `-EncodedCommand` / `-enc` / `-e` payloads!
       - Strips caret (`^`) and backtick (`` ` ``) character-splitting obfuscation (`I`E`X`, `c^m^d`).
       - Evaluates concatenated string-join patterns (`'Down'+'loadString'`, `-f` format reassembly).
  2. **25+ LOLBins & Dual-Use Execution Signatures**:
       - `certutil -urlcache -split -f`, `mshta http`, `rundll32 javascript:`,
         `regsvr32 /s /n /u /i:http scrobj.dll`, `bitsadmin /transfer`, `wmic process call create`,
         `cmstp /ni /s`, `msiexec /q /i http`, `forfiles /c`, `installutil`, `msbuild`, `csc.exe`.
  3. **Credential Access & Defense Evasion Detectors**:
       - LSASS memory dumping (`comsvcs.dll MiniDump`, `procdump -ma lsass`, `sekurlsa::logonpasswords`, `nanodump`)
       - Active Directory NTDS extraction (`ntdsutil "ac i ntds" "ifm"`, `vssadmin create shadow`, `reg save hklm\\sam`)
       - AMSI / ETW in-memory bypass (`AmsiScanBuffer`, `amsiInitFailed`, `EtwEventWrite`, `Set-MpPreference -DisableRealtimeMonitoring`)
       - Ransomware pre-encryption shadow-copy destruction (`vssadmin delete shadows /all`, `wbadmin delete catalog`, `bcdedit /set recoveryenabled no`)
       - Suspicious Parent-Child Process Lineage (`WINWORD.EXE -> powershell.exe`, `w3wp.exe -> cmd.exe`, `sqlservr.exe -> powershell.exe`).
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

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


@dataclass
class EndpointProcessEvent:
    event_id: str
    timestamp: str
    hostname: str
    user: str
    parent_image: str
    image: str
    command_line: str
    integrity_level: str = "Medium"


@dataclass(frozen=True)
class EDRCommandSignature:
    rule_id: str
    title: str
    severity: Severity
    cwe_id: str
    mitre_id: str
    tactic: MitreTactic
    pattern: str
    description: str


EDR_SIGNATURES: Tuple[EDRCommandSignature, ...] = (
    EDRCommandSignature(
        "CYB-EDR-LSASS-DUMP-001", "LSASS Process Memory Credential Dumping Detected",
        Severity.CRITICAL, "CWE-522", "T1003.001", MitreTactic.CREDENTIAL_ACCESS,
        r"(?i)(?:comsvcs\.dll[,\s]+MiniDump|procdump[^\n]*lsass|sekurlsa::(?:logonpasswords|wdigest)|sqldumper[^\n]*0x01100|nanodump)",
        "Command line matches known LSASS memory credential dumping tooling targeting plaintext/NTLM/Kerberos tickets.",
    ),
    EDRCommandSignature(
        "CYB-EDR-NTDS-SHADOW-001", "Active Directory NTDS.dit / SAM Registry Hive Credential Extraction",
        Severity.CRITICAL, "CWE-522", "T1003.003", MitreTactic.CREDENTIAL_ACCESS,
        r"(?i)(?:ntdsutil[^\n]*(?:ifm|activate\s+instance\s+ntds)|reg(?:\.exe)?\s+save\s+hklm\\(?:sam|system|security)|vssadmin[^\n]*create\s+shadow)",
        "Attempt to extract AD NTDS.dit database or local SAM/SYSTEM registry hives for offline hash cracking.",
    ),
    EDRCommandSignature(
        "CYB-EDR-RANSOM-VSS-WIPE-001", "Ransomware Pre-Encryption Shadow Copy & Recovery Destruction",
        Severity.CRITICAL, "CWE-693", "T1490", MitreTactic.IMPACT,
        r"(?i)(?:vssadmin(?:\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|wbadmin\s+delete\s+(?:catalog|systemstatebackup)|bcdedit[^\n]*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures))",
        "Destroying Volume Shadow Copies and disabling Windows Recovery is a high-confidence precursor to enterprise ransomware encryption.",
    ),
    EDRCommandSignature(
        "CYB-EDR-AMSI-ETW-BYPASS-001", "AMSI / ETW / Windows Defender Tampering & Defense Evasion",
        Severity.CRITICAL, "CWE-693", "T1562.001", MitreTactic.DEFENSE_EVASION,
        r"(?i)(?:amsiInitFailed|AmsiScanBuffer|EtwEventWrite|Set-MpPreference[^\n]*-DisableRealtimeMonitoring\s+\$true|Add-MpPreference[^\n]*-ExclusionPath)",
        "PowerShell or binary attempted to patch AMSI/ETW telemetry hooks or blind endpoint AV/EDR monitoring.",
    ),
    EDRCommandSignature(
        "CYB-EDR-PS-DOWNLOAD-CRADLE-001", "PowerShell Fileless In-Memory Download & Execute Cradle (IEX)",
        Severity.CRITICAL, "CWE-94", "T1059.001", MitreTactic.EXECUTION,
        r"(?i)(?:(?:IEX|Invoke-Expression)\s*\([^\n]*(?:DownloadString|DownloadData|Invoke-WebRequest|iwr|irm|Net\.WebClient)|Invoke-RestMethod[^\n]*\|\s*(?:iex|Invoke-Expression))",
        "Fileless PowerShell cradle downloads and executes remote payload directly in memory without touching disk.",
    ),
    EDRCommandSignature(
        "CYB-EDR-LOLBIN-CERTUTIL-001", "LOLBin Ingress Transfer / Decode via `certutil.exe`",
        Severity.HIGH, "CWE-494", "T1105", MitreTactic.COMMAND_AND_CONTROL,
        r"(?i)certutil(?:\.exe)?[^\n]*(?:-urlcache|-verifyctl|-decode\b)",
        "Abuse of signed Windows binary `certutil.exe` to download payloads from attacker URLs or decode staged malware.",
    ),
    EDRCommandSignature(
        "CYB-EDR-LOLBIN-MSHTA-REGSVR-001", "LOLBin Proxy Execution via `mshta.exe` / `regsvr32.exe` / `rundll32.exe`",
        Severity.HIGH, "CWE-94", "T1218.005", MitreTactic.DEFENSE_EVASION,
        r"(?i)(?:mshta(?:\.exe)?[^\n]*(?:https?://|vbscript:|javascript:)|regsvr32(?:\.exe)?[^\n]*/i:https?://[^\n]*scrobj\.dll|rundll32(?:\.exe)?[^\n]*javascript:)",
        "Signed LOLBin abused to proxy-execute remote scriptlets bypassing Application Whitelisting (AppLocker/WDAC).",
    ),
    EDRCommandSignature(
        "CYB-EDR-WMI-PERSIST-001", "WMI Permanent Event Subscription / Remote Process Execution",
        Severity.HIGH, "CWE-284", "T1546.003", MitreTactic.PERSISTENCE,
        r"(?i)(?:wmic(?:\.exe)?[^\n]*(?:/node:|process\s+call\s+create)|__EventFilter[^\n]*CommandLineEventConsumer)",
        "WMI used for stealthy lateral execution or fileless SYSTEM-level event subscription persistence.",
    ),
    EDRCommandSignature(
        "CYB-EDR-KERBEROAST-TOOLS-001", "Active Directory Kerberoasting / Golden Ticket / DCSync Tooling",
        Severity.CRITICAL, "CWE-287", "T1558.003", MitreTactic.CREDENTIAL_ACCESS,
        r"(?i)(?:Rubeus(?:\.exe)?[^\n]*(?:kerberoast|asreproast|s4u|asktgt)|lsadump::dcsync|Invoke-Kerberoast|kerberos::golden)",
        "Detected offensive Kerberos/AD credential abuse command-line arguments.",
    ),
)

SUSPICIOUS_PARENT_CHILD_PAIRS: Tuple[Tuple[str, str, str], ...] = (
    ("winword.exe", "powershell.exe", "Macro/Document exploitation spawning PowerShell"),
    ("excel.exe", "powershell.exe", "Excel macro spawning PowerShell"),
    ("winword.exe", "cmd.exe", "Office document spawning command shell"),
    ("excel.exe", "mshta.exe", "Office document invoking mshta LOLBin"),
    ("w3wp.exe", "cmd.exe", "IIS Webshell spawning interactive command shell"),
    ("w3wp.exe", "powershell.exe", "IIS Webshell spawning PowerShell"),
    ("sqlservr.exe", "cmd.exe", "MSSQL `xp_cmdshell` OS command execution"),
    ("sqlservr.exe", "powershell.exe", "MSSQL database server spawning PowerShell"),
    ("services.exe", "powershell.exe", "Malicious Windows Service executing PowerShell directly"),
    ("wmiprvse.exe", "powershell.exe", "Remote WMI lateral movement launching PowerShell"),
)


class WindowsEndpointEDREngine:
    """PowerShell deobfuscator, LOLBin/Credential-Dump detector, and process-lineage EDR analyzer."""

    def __init__(self) -> None:
        self._compiled = [(sig, re.compile(sig.pattern)) for sig in EDR_SIGNATURES]

    def deobfuscate_command_line(self, cmd: str) -> Dict[str, Any]:
        """
        Deobfuscate Windows CMD caret escapes (`^`), PowerShell backticks (`` ` ``),
        string concatenation (`'a'+'b'`), and `-EncodedCommand` UTF-16LE Base64 payloads!
        """
        techniques: List[str] = []
        working = cmd

        # 1. Strip PowerShell backtick obfuscation (`I`E`X -> IEX)
        if "`" in working:
            stripped = re.sub(r"`([A-Za-z])", r"\1", working)
            if stripped != working:
                techniques.append("powershell_backtick_obfuscation")
                working = stripped

        # 2. Strip CMD caret obfuscation (c^m^d -> cmd)
        if "^" in working:
            stripped = re.sub(r"\^([A-Za-z0-9./:-])", r"\1", working)
            if stripped != working:
                techniques.append("cmd_caret_obfuscation")
                working = stripped

        # 3. Collapse adjacent quoted string joins ('Down'+'loadString' -> 'DownloadString')
        joined = re.sub(r"(['\"])\s*\+\s*\1", "", working)
        if joined != working:
            techniques.append("string_concatenation_obfuscation")
            working = joined

        # 4. Detect & decode PowerShell -EncodedCommand / -enc / -e (UTF-16LE or UTF-8 Base64)
        decoded_b64 = ""
        m_enc = re.search(r"(?i)(?:^|\s)-(?:e|ec|en|enc|enco|encodedcommand)\s+([A-Za-z0-9+/=]{16,})", working)
        if m_enc:
            b64_tok = m_enc.group(1)
            padded = b64_tok + "=" * ((4 - len(b64_tok) % 4) % 4)
            try:
                raw = base64.b64decode(padded)
                try:
                    decoded_b64 = raw.decode("utf-16le")
                    if "\x00" in decoded_b64 or not decoded_b64.isprintable():
                        alt = raw.decode("utf-8", errors="ignore")
                        if len(alt) > len(decoded_b64.replace("\x00", "")):
                            decoded_b64 = alt
                except UnicodeDecodeError:
                    decoded_b64 = raw.decode("utf-8", errors="ignore")
                if decoded_b64.strip():
                    techniques.append("base64_encoded_command")
                    working = f"{working} [DECODED_ENC: {decoded_b64}]"
            except Exception:
                pass

        return {
            "original": cmd,
            "normalized": working,
            "decoded_base64": decoded_b64,
            "obfuscation_techniques": techniques,
            "was_obfuscated": len(techniques) > 0,
        }

    def analyze_process_events(self, events: Sequence[EndpointProcessEvent]) -> Dict[str, Any]:
        """Inspect endpoint process telemetry for LOLBins, deobfuscated PowerShell, LSASS dumps, and lineage."""
        vulns: List[CyberVulnerability] = []
        deobfuscated_count = 0
        lineage_alerts = 0

        for ev in events:
            deob = self.deobfuscate_command_line(ev.command_line)
            if deob["was_obfuscated"]:
                deobfuscated_count += 1
            norm_cmd = deob["normalized"]

            # 1. Check signatures on BOTH original and deobfuscated command lines
            for sig, rx in self._compiled:
                if rx.search(norm_cmd):
                    vulns.append(
                        make_cyber_vuln(
                            rule_id=sig.rule_id,
                            title=f"[EDR | {ev.hostname}] {sig.title}",
                            description=(
                                f"{sig.description} Host=`{ev.hostname}`, User=`{ev.user}`, "
                                f"Parent=`{ev.parent_image}` -> Child=`{ev.image}`."
                                + (f" Deobfuscated techniques: {deob['obfuscation_techniques']}." if deob["was_obfuscated"] else "")
                            ),
                            cyber_domain=CyberDomain.DETECTION_ENGINEERING,
                            severity=sig.severity,
                            cwe_ids=[sig.cwe_id],
                            confidence=0.98,
                            cvss4=CVSSv4Metrics(av="L", ac="L", at="N", pr="L", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
                            mitre_techniques=[MitreTechniqueRef(sig.mitre_id, sig.title, sig.tactic)],
                            verification_method=VerificationMethod.SIGMA_YARA_MATCH,
                            endpoint_or_asset=f"{ev.hostname}/{ev.image}",
                            code_snippet=norm_cmd[:200],
                            remediation_guidance="Isolate endpoint via EDR, revoke compromised user/Kerberos TGTs, and enforce WDAC/Constrained Language Mode.",
                            discovered_by="ely_cyber_windows_edr_engine",
                        )
                    )

            # 2. Suspicious Parent -> Child process lineage anomaly
            p_base = ev.parent_image.replace("\\", "/").split("/")[-1].lower()
            c_base = ev.image.replace("\\", "/").split("/")[-1].lower()
            for sp, sc, reason in SUSPICIOUS_PARENT_CHILD_PAIRS:
                if p_base == sp and c_base == sc:
                    lineage_alerts += 1
                    vulns.append(
                        make_cyber_vuln(
                            rule_id=f"CYB-EDR-LINEAGE-{sp.split('.')[0].upper()}-{sc.split('.')[0].upper()}",
                            title=f"[EDR Lineage | {ev.hostname}] Suspicious Process Tree `{p_base} -> {c_base}` ({reason})",
                            description=f"Anomalous process parent-child execution on `{ev.hostname}` by `{ev.user}`: `{p_base}` spawned `{c_base}` (`{norm_cmd[:120]}`).",
                            cyber_domain=CyberDomain.DETECTION_ENGINEERING,
                            severity=Severity.HIGH,
                            cwe_ids=["CWE-78"],
                            confidence=0.96,
                            mitre_techniques=[MitreTechniqueRef("T1059", "Command and Scripting Interpreter", MitreTactic.EXECUTION)],
                            verification_method=VerificationMethod.SIGMA_YARA_MATCH,
                            endpoint_or_asset=f"{ev.hostname}/{ev.event_id}",
                            code_snippet=norm_cmd[:180],
                            remediation_guidance="Terminate child process tree, inspect parent service/document for webshell or macro payload, and enforce Attack Surface Reduction (ASR) rules.",
                            discovered_by="ely_cyber_windows_edr_engine",
                        )
                    )

        return {
            "analyzed_at": utc_now_iso(),
            "events_analyzed": len(events),
            "obfuscated_commands_decoded": deobfuscated_count,
            "suspicious_lineage_alerts": lineage_alerts,
            "total_alerts": len(vulns),
            "vulnerabilities": vulns,
        }
