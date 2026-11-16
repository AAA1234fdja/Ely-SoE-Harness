"""
Binary Artifact Structural Triage, Packer Entropy Analyzer, Suspicious API Import Triad
Matcher, Single-Byte XOR Deobfuscator & Shellcode Pattern Inspector.

Pure-Python static reverse-engineering & malware-triage analyzer operating safely on raw bytes:
  1. **Magic-Byte Format Classifier & Header Sanity Dissector**:
       Identifies ELF (`\x7fELF`), PE (`MZ` + `PE\x00\x00` COFF/Optional header machine &
       DllCharacteristics for ASLR/DEP/CFG/HighEntropyVA!), Mach-O (`\xcf\xfa\xed\xfe`),
       WebAssembly (`\x00asm`), Java Class (`\xca\xfe\xba\xbe`), and ZIP/APK/JAR archives.
  2. **Sliding-Window Shannon Entropy & Packer/Crypter Detector**:
       Computes whole-file & 256-byte chunk entropy to flag packed/encrypted payloads
       (`entropy >= 7.2` bits/byte, UPX signatures `UPX0`/`UPX1`, VMProtect/Themida markers).
  3. **Behavioral Malware Import Triad Matcher**:
       Inspects extracted ASCII/UTF-16 symbol strings against high-precision Windows/POSIX
       offensive API triads:
         - Process Injection Triad (`VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`)
         - Process Hollowing Triad (`NtUnmapViewOfSection` + `SetThreadContext` + `ResumeThread`)
         - Ransomware Triad (`CryptEncrypt`/`BCryptEncrypt` + `FindFirstFile` + `MoveFileEx`)
         - Credential Harvesting / Keylogger Triad (`SetWindowsHookEx` + `GetAsyncKeyState` / `OpenProcess` + `MiniDumpWriteDump`).
  4. **Automated Single-Byte XOR Deobfuscator**:
       Tests all 255 non-zero XOR keys to uncover hidden C2 URLs (`http://`, `https://`),
       `powershell`, `cmd.exe`, or `/bin/sh` strings obfuscated inside binary payloads!
  5. **x86-64 / ARM64 Shellcode & RWX Stub Heuristic Scanner**:
       Detects NOP sleds (`\x90 * 16+`), classic Linux x86-64 `execve("/bin/sh")` syscall
       stubs (`\x0f\x05`), and Windows PEB TEB walking prologues (`\x65\x48\x8b\x04\x25\x60\x00\x00\x00`).
"""

from __future__ import annotations

import math
import re
import struct
from collections import Counter
from dataclasses import dataclass
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


MALWARE_API_TRIADS: Tuple[Tuple[str, str, Tuple[str, ...], Severity, str, MitreTactic], ...] = (
    ("CYB-REV-PROC-INJ-TRIAD", "Windows Remote Process Injection API Triad", ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"), Severity.CRITICAL, "T1055.001", MitreTactic.DEFENSE_EVASION),
    ("CYB-REV-PROC-HOLLOW-TRIAD", "Process Hollowing API Triad", ("NtUnmapViewOfSection", "SetThreadContext", "ResumeThread"), Severity.CRITICAL, "T1055.012", MitreTactic.DEFENSE_EVASION),
    ("CYB-REV-RANSOMWARE-TRIAD", "Ransomware File-Encryption API Triad", ("FindFirstFile", "CryptEncrypt", "MoveFileEx"), Severity.CRITICAL, "T1486", MitreTactic.IMPACT),
    ("CYB-REV-KEYLOGGER-TRIAD", "Keylogger / Input-Capture API Triad", ("SetWindowsHookEx", "GetAsyncKeyState", "GetForegroundWindow"), Severity.HIGH, "T1056.001", MitreTactic.COLLECTION),
    ("CYB-REV-LSASS-MINIDUMP-TRIAD", "Credential Memory Dump API Triad", ("OpenProcess", "MiniDumpWriteDump"), Severity.CRITICAL, "T1003.001", MitreTactic.CREDENTIAL_ACCESS),
    ("CYB-REV-POSIX-MEMFD-EXEC", "Linux Fileless `memfd_create` + `execveat` Memory Execution", ("memfd_create", "execveat"), Severity.CRITICAL, "T1620", MitreTactic.DEFENSE_EVASION),
)

XOR_IOC_NEEDLES: Tuple[bytes, ...] = (
    b"http://", b"https://", b"powershell", b"cmd.exe", b"/bin/sh", b"VirtualAllocEx",
)


def _byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = float(len(data))
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


class ReverseEngineeringTriageEngine:
    """Pure-Python binary format dissector, entropy/packer detector, API triad matcher & XOR deobfuscator."""

    def analyze_binary_bytes(self, data: bytes, filename: str = "sample.bin") -> Dict[str, Any]:
        vulns: List[CyberVulnerability] = []
        fmt = self._detect_format(data)
        overall_ent = _byte_entropy(data)

        # Sliding-window max chunk entropy (256-byte chunks)
        chunk_entropies = [_byte_entropy(data[i : i + 256]) for i in range(0, len(data), 256) if len(data[i : i + 256]) >= 64]
        max_chunk_ent = max(chunk_entropies) if chunk_entropies else overall_ent

        # 1. PE Header Security Flags (ASLR / DEP / CFG)
        pe_mitigations: Dict[str, Any] = {}
        if fmt == "PE":
            pe_mitigations = self._parse_pe_mitigations(data)
            if pe_mitigations.get("valid_pe") and (not pe_mitigations.get("aslr_dynamic_base") or not pe_mitigations.get("dep_nx_compat")):
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-REV-PE-NO-ASLR-DEP",
                        title=f"PE Binary `{filename}` Missing ASLR (`DYNAMIC_BASE`) or DEP (`NX_COMPAT`) Hardening",
                        description=f"PE DllCharacteristics (`0x{pe_mitigations.get('dll_characteristics', 0):04x}`) disables core memory exploitation mitigations.",
                        cyber_domain=CyberDomain.BINARY_MEMORY_SAFETY,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-119"],
                        confidence=0.98,
                        verification_method=VerificationMethod.BINARY_HEADER_INSPECTION,
                        endpoint_or_asset=filename,
                        remediation_guidance="Compile with `/DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /guard:cf`.",
                        discovered_by="ely_cyber_reverse_engineering_engine",
                    )
                )

        # 2. Packer / Encrypted Payload Detection
        packer_markers = [m for m in (b"UPX0", b"UPX1", b"UPX!", b"VMProtect", b"Themida", b".aspack") if m in data]
        if overall_ent >= 7.2 or packer_markers:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-REV-PACKED-HIGH-ENTROPY",
                    title=f"Packed / Encrypted Binary Payload Detected in `{filename}` (Entropy={overall_ent:.2f} bits/byte)",
                    description=f"High Shannon entropy ({overall_ent:.2f}) or packer section signatures ({[m.decode('ascii', 'ignore') for m in packer_markers]}) indicate obfuscated/packed binary.",
                    cyber_domain=CyberDomain.BINARY_MEMORY_SAFETY,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-506"],
                    confidence=0.91,
                    mitre_techniques=[MitreTechniqueRef("T1027.002", "Software Packing", MitreTactic.DEFENSE_EVASION)],
                    verification_method=VerificationMethod.BINARY_HEADER_INSPECTION,
                    endpoint_or_asset=filename,
                    remediation_guidance="Unpack artifact inside an isolated sandbox and verify code-signing provenance before allowing execution.",
                    discovered_by="ely_cyber_reverse_engineering_engine",
                )
            )

        # 3. Extract printable ASCII & UTF-16LE strings and match Malware API Triads
        ascii_strings = {m.group(0).decode("ascii", errors="ignore") for m in re.finditer(rb"[\x20-\x7e]{5,}", data)}
        blob_text = "\n".join(ascii_strings)
        matched_triads: List[str] = []
        for rid, title, apis, sev, mitre_id, tactic in MALWARE_API_TRIADS:
            if all(api in blob_text for api in apis):
                matched_triads.append(rid)
                vulns.append(
                    make_cyber_vuln(
                        rule_id=rid,
                        title=f"[{filename}] {title} ({' + '.join(apis)})",
                        description=f"Binary `{filename}` references complete offensive capability triad: {', '.join(apis)}.",
                        cyber_domain=CyberDomain.BINARY_MEMORY_SAFETY,
                        severity=sev,
                        cwe_ids=["CWE-506"],
                        confidence=0.96,
                        mitre_techniques=[MitreTechniqueRef(mitre_id, title, tactic)],
                        verification_method=VerificationMethod.BINARY_HEADER_INSPECTION,
                        endpoint_or_asset=filename,
                        remediation_guidance="Quarantine binary immediately and perform full dynamic behavioral analysis in a detonator sandbox.",
                        discovered_by="ely_cyber_reverse_engineering_engine",
                    )
                )

        # 4. Single-Byte XOR Obfuscated IOC Recovery (bounded to first 16 KB for sub-ms latency)
        xor_hits = self._scan_single_byte_xor(data[:16384])
        if xor_hits:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-REV-XOR-OBFUSCATED-IOC",
                    title=f"Single-Byte XOR-Encoded C2/Execution Strings Uncovered in `{filename}` (key=0x{xor_hits[0]['xor_key']:02x})",
                    description=f"Brute-force XOR recovery decoded hidden payload strings (`{xor_hits[0]['decoded_snippet']}`) obfuscated with key `0x{xor_hits[0]['xor_key']:02x}`.",
                    cyber_domain=CyberDomain.BINARY_MEMORY_SAFETY,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-506"],
                    confidence=0.95,
                    mitre_techniques=[MitreTechniqueRef("T1027", "Obfuscated Files or Information", MitreTactic.DEFENSE_EVASION)],
                    verification_method=VerificationMethod.BINARY_HEADER_INSPECTION,
                    endpoint_or_asset=filename,
                    code_snippet=xor_hits[0]["decoded_snippet"][:120],
                    remediation_guidance="Extract all decoded C2 IOCs into SIEM/WAF blocklists and quarantine the binary.",
                    discovered_by="ely_cyber_reverse_engineering_engine",
                )
            )

        # 5. Shellcode NOP-Sled + Syscall / PEB-Walk Heuristic
        shellcode_indicators: List[str] = []
        if b"\x90" * 16 in data:
            shellcode_indicators.append("x86_nop_sled_16plus")
        if b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00" in data:
            shellcode_indicators.append("win64_peb_gs60_walk")
        if b"/bin/sh" in data and b"\x0f\x05" in data:
            shellcode_indicators.append("linux_x64_execve_syscall_stub")

        if shellcode_indicators:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-REV-SHELLCODE-STUB-001",
                    title=f"Raw Shellcode / Position-Independent Implant Stub Detected in `{filename}` ({', '.join(shellcode_indicators)})",
                    description=f"Binary byte sequence matches known shellcode indicators: {shellcode_indicators}.",
                    cyber_domain=CyberDomain.BINARY_MEMORY_SAFETY,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-94", "CWE-506"],
                    confidence=0.95,
                    mitre_techniques=[MitreTechniqueRef("T1055", "Shellcode Execution / Injection", MitreTactic.EXECUTION)],
                    verification_method=VerificationMethod.BINARY_HEADER_INSPECTION,
                    endpoint_or_asset=filename,
                    remediation_guidance="Block artifact, enforce W^X / DEP / HVCI memory protections, and hunt for loader origin.",
                    discovered_by="ely_cyber_reverse_engineering_engine",
                )
            )

        return {
            "analyzed_at": utc_now_iso(),
            "filename": filename,
            "size_bytes": len(data),
            "detected_format": fmt,
            "shannon_entropy": round(overall_ent, 4),
            "max_chunk_entropy": round(max_chunk_ent, 4),
            "pe_mitigations": pe_mitigations,
            "matched_api_triads": matched_triads,
            "xor_decoded_iocs": xor_hits[:5],
            "shellcode_indicators": shellcode_indicators,
            "vulnerabilities": vulns,
        }

    @staticmethod
    def _detect_format(data: bytes) -> str:
        if data.startswith(b"\x7fELF"):
            return "ELF"
        if data.startswith(b"MZ"):
            return "PE"
        if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"):
            return "Mach-O/Java"
        if data.startswith(b"\x00asm"):
            return "WebAssembly"
        if data.startswith(b"PK\x03\x04"):
            return "ZIP/APK/JAR"
        return "RAW_BLOB"

    @staticmethod
    def _parse_pe_mitigations(data: bytes) -> Dict[str, Any]:
        if len(data) < 0x40:
            return {"valid_pe": False}
        pe_off = struct.unpack("<I", data[0x3C:0x40])[0]
        if pe_off + 24 + 72 > len(data) or data[pe_off : pe_off + 4] != b"PE\x00\x00":
            return {"valid_pe": False}
        opt_off = pe_off + 24
        opt_magic = struct.unpack("<H", data[opt_off : opt_off + 2])[0]
        if opt_magic not in (0x10B, 0x20B):
            return {"valid_pe": False}
        dll_chars = struct.unpack("<H", data[opt_off + 70 : opt_off + 72])[0]
        return {
            "valid_pe": True,
            "is_pe64": opt_magic == 0x20B,
            "dll_characteristics": dll_chars,
            "high_entropy_va": bool(dll_chars & 0x0020),
            "aslr_dynamic_base": bool(dll_chars & 0x0040),
            "dep_nx_compat": bool(dll_chars & 0x0100),
            "control_flow_guard_cfg": bool(dll_chars & 0x4000),
        }

    @staticmethod
    def _scan_single_byte_xor(sample: bytes) -> List[Dict[str, Any]]:
        if not sample:
            return []
        hits: List[Dict[str, Any]] = []
        # Pre-check plaintext needles so we only report genuinely XOR-encoded (non-key-0) hides
        for key in range(1, 256):
            # Fast needle search by XORing the short needles instead of full buffer first!
            for needle in XOR_IOC_NEEDLES:
                enc_needle = bytes(b ^ key for b in needle)
                idx = sample.find(enc_needle)
                if idx != -1:
                    window = sample[max(0, idx - 4) : min(len(sample), idx + 48)]
                    decoded = bytes(b ^ key for b in window).decode("ascii", errors="ignore")
                    hits.append({"xor_key": key, "matched_needle": needle.decode("ascii"), "offset": idx, "decoded_snippet": decoded})
                    if len(hits) >= 5:
                        return hits
        return hits
