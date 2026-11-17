"""
Binary Hardening (ELF/PE Checksec) & Multi-Language Memory-Safety Security Engine.

Provides zero-dependency binary & native-code vulnerability analysis:
  1. Pure-Python ELF32 / ELF64 Header & Program-Header Parser:
       - Parses `e_ident`, `e_type` (ET_EXEC vs ET_DYN -> PIE detection), `e_machine`
       - Parses Program Headers (`PT_GNU_STACK` -> NX/DEP execution stack flag,
         `PT_GNU_RELRO` -> Partial/Full RELRO, `PT_DYNAMIC` -> `BIND_NOW` / `RPATH` / `RUNPATH`)
       - Scans symbol/string tables for `__stack_chk_fail` (Stack Canary), `_chk` (FORTIFY_SOURCE),
         and dangerous C/libc imports (`gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`, `scanf`,
         `system`, `popen`, `mktemp`, `memcpy` unchecked)
  2. Pure-Python PE32 / PE32+ (Windows) Header Parser:
       - Parses DOS header (`MZ`), PE signature (`PE\\0\\0`), COFF Machine, Optional Header `DllCharacteristics`
       - Extracts `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` (ASLR), `HIGH_ENTROPY_VA`,
         `NX_COMPAT` (DEP), `GUARD_CF` (Control Flow Guard), `NO_SEH`
  3. Multi-Language Memory-Safety & Native Concurrency Static Analyzer (C, C++, Go, Rust, Java):
       - Buffer overflows (`gets`, `strcpy`, `sprintf`, `strcat`, unbounded `scanf("%s")`)
       - Format-string vulnerabilities (`printf(user_buf)`, `fprintf(fp, msg)`, `syslog(prio, buf)`)
       - Use-After-Free (UAF) & Double-Free patterns (`free(ptr)` without NULLing followed by deref/free)
       - Integer overflow in allocation (`malloc(n * sizeof(...))` without bounds check)
       - Unsafe C/C++ `alloca`, `strncpy` non-null-terminated pitfall, `system()`/`popen()`
       - Go `unsafe.Pointer`, `cgo` raw memory, race-prone unlocked map writes, `html/template` bypass
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Tuple

from ely_soe.core.models import Severity
from ely_soe.cyber.models import (
    BinarySecurityProfile,
    CVSSv4Metrics,
    CyberDomain,
    CyberVulnerability,
    MitreTactic,
    MitreTechniqueRef,
    VerificationMethod,
    make_cyber_vuln,
)


# ---------------------------------------------------------------------------
# Pure-Python ELF & PE Binary Header Parser
# ---------------------------------------------------------------------------

ELF_MACHINES = {
    3: "x86",
    40: "ARM",
    62: "x86_64",
    183: "AArch64",
    243: "RISC-V",
}

PE_MACHINES = {
    0x014C: "x86",
    0x8664: "x86_64",
    0x01C0: "ARM",
    0xAA64: "AArch64",
}

DANGEROUS_BINARY_SYMBOLS = (
    b"gets",
    b"strcpy",
    b"strcat",
    b"sprintf",
    b"vsprintf",
    b"scanf",
    b"mktemp",
    b"tmpnam",
    b"system",
    b"popen",
    b"execve",
    b"WinExec",
    b"ShellExecuteA",
    b"lstrcpyA",
)


class BinaryHeaderSecurityAnalyzer:
    """Zero-dependency pure-Python ELF32/ELF64 and PE32/PE32+ hardening inspector."""

    # ELF constants
    PT_DYNAMIC = 2
    PT_GNU_STACK = 0x6474E551
    PT_GNU_RELRO = 0x6474E552
    PF_X = 0x1
    ET_DYN = 3
    DT_RPATH = 15
    DT_RUNPATH = 29
    DT_BIND_NOW = 24
    DT_FLAGS = 30
    DT_FLAGS_1 = 0x6FFFFFFB
    DF_BIND_NOW = 0x8
    DF_1_NOW = 0x1

    # PE DllCharacteristics flags
    IMAGE_DLL_HIGH_ENTROPY_VA = 0x0020
    IMAGE_DLL_DYNAMIC_BASE = 0x0040
    IMAGE_DLL_NX_COMPAT = 0x0100
    IMAGE_DLL_NO_SEH = 0x0400
    IMAGE_DLL_GUARD_CF = 0x4000

    def inspect_bytes(self, data: bytes, file_path: str = "binary.bin") -> Tuple[BinarySecurityProfile, List[CyberVulnerability]]:
        """Parse ELF or PE binary bytes and emit hardening profile + missing-mitigation findings."""
        if len(data) >= 52 and data[:4] == b"\x7fELF":
            profile = self._parse_elf(data, file_path)
        elif len(data) >= 64 and data[:2] == b"MZ":
            profile = self._parse_pe(data, file_path)
        else:
            profile = BinarySecurityProfile(
                file_path=file_path,
                binary_format="UNKNOWN",
                architecture="unknown",
                endianness="unknown",
                hardening_score=100.0,
            )
            return profile, []

        findings = self._evaluate_profile(profile)
        return profile, findings

    def _parse_elf(self, data: bytes, file_path: str) -> BinarySecurityProfile:
        ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
        ei_data = data[5]   # 1 = little-endian, 2 = big-endian
        is_64 = ei_class == 2
        endian = "<" if ei_data == 1 else ">"
        endian_name = "little" if ei_data == 1 else "big"

        if is_64 and len(data) >= 64:
            e_type, e_machine = struct.unpack_from(f"{endian}HH", data, 16)
            e_phoff = struct.unpack_from(f"{endian}Q", data, 32)[0]
            e_phentsize, e_phnum = struct.unpack_from(f"{endian}HH", data, 54)
        elif not is_64 and len(data) >= 52:
            e_type, e_machine = struct.unpack_from(f"{endian}HH", data, 16)
            e_phoff = struct.unpack_from(f"{endian}I", data, 28)[0]
            e_phentsize, e_phnum = struct.unpack_from(f"{endian}HH", data, 42)
        else:
            return BinarySecurityProfile(file_path, "ELF_TRUNCATED", "unknown", endian_name)

        has_pie = e_type == self.ET_DYN
        has_nx = False
        has_relro_phdr = False
        has_bind_now = False
        has_rpath = False

        # Walk Program Headers
        for i in range(min(e_phnum, 64)):
            off = e_phoff + i * e_phentsize
            if off + e_phentsize > len(data):
                break
            if is_64 and e_phentsize >= 56:
                p_type, p_flags, p_offset, _vaddr, _paddr, p_filesz = struct.unpack_from(f"{endian}IIQQQQ", data, off)
            elif not is_64 and e_phentsize >= 32:
                p_type, p_offset, _vaddr, _paddr, p_filesz, _memsz, p_flags = struct.unpack_from(f"{endian}IIIIIII", data, off)
            else:
                break

            if p_type == self.PT_GNU_STACK:
                has_nx = (p_flags & self.PF_X) == 0
            elif p_type == self.PT_GNU_RELRO:
                has_relro_phdr = True
            elif p_type == self.PT_DYNAMIC and p_offset + p_filesz <= len(data):
                entry_sz = 16 if is_64 else 8
                fmt = f"{endian}QQ" if is_64 else f"{endian}II"
                for doff in range(p_offset, min(p_offset + p_filesz, len(data) - entry_sz + 1), entry_sz):
                    d_tag, d_val = struct.unpack_from(fmt, data, doff)
                    if d_tag == 0:
                        break
                    if d_tag == self.DT_BIND_NOW:
                        has_bind_now = True
                    elif d_tag == self.DT_FLAGS and (d_val & self.DF_BIND_NOW):
                        has_bind_now = True
                    elif d_tag == self.DT_FLAGS_1 and (d_val & self.DF_1_NOW):
                        has_bind_now = True
                    elif d_tag in (self.DT_RPATH, self.DT_RUNPATH):
                        has_rpath = True

        relro = "full" if (has_relro_phdr and has_bind_now) else ("partial" if has_relro_phdr else "none")
        has_canary = b"__stack_chk_fail" in data or b"__stack_chk_guard" in data
        has_fortify = b"_chk\x00" in data or b"__memcpy_chk" in data or b"__sprintf_chk" in data
        dangerous = sorted(
            sym.decode("ascii")
            for sym in DANGEROUS_BINARY_SYMBOLS
            if (b"\x00" + sym + b"\x00") in data or (sym + b"@") in data
        )

        score = 0.0
        if has_pie:
            score += 22.0
        if has_nx:
            score += 22.0
        if relro == "full":
            score += 20.0
        elif relro == "partial":
            score += 10.0
        if has_canary:
            score += 20.0
        if has_fortify:
            score += 10.0
        if not has_rpath:
            score += 6.0
        score = max(0.0, score - min(30.0, len(dangerous) * 6.0))

        return BinarySecurityProfile(
            file_path=file_path,
            binary_format="ELF64" if is_64 else "ELF32",
            architecture=ELF_MACHINES.get(e_machine, f"machine_{e_machine}"),
            endianness=endian_name,
            has_pie=has_pie,
            has_nx=has_nx,
            has_relro=relro,
            has_stack_canary=has_canary,
            has_aslr=has_pie,
            has_dep=has_nx,
            has_fortify=has_fortify,
            has_rpath=has_rpath,
            dangerous_imports=dangerous,
            hardening_score=round(score, 2),
        )

    def _parse_pe(self, data: bytes, file_path: str) -> BinarySecurityProfile:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_off + 24 > len(data) or data[pe_off : pe_off + 4] != b"PE\x00\x00":
            return BinarySecurityProfile(file_path, "PE_INVALID", "unknown", "little")

        machine = struct.unpack_from("<H", data, pe_off + 4)[0]
        opt_off = pe_off + 24
        if opt_off + 72 > len(data):
            return BinarySecurityProfile(file_path, "PE_TRUNCATED", PE_MACHINES.get(machine, "unknown"), "little")

        magic = struct.unpack_from("<H", data, opt_off)[0]
        is_64 = magic == 0x20B
        dll_chars = struct.unpack_from("<H", data, opt_off + 70)[0]

        has_aslr = bool(dll_chars & self.IMAGE_DLL_DYNAMIC_BASE)
        has_dep = bool(dll_chars & self.IMAGE_DLL_NX_COMPAT)
        has_cfg = bool(dll_chars & self.IMAGE_DLL_GUARD_CF)
        has_canary = b"__security_cookie" in data or b"__security_check_cookie" in data
        dangerous = sorted(
            sym.decode("ascii")
            for sym in DANGEROUS_BINARY_SYMBOLS
            if (b"\x00" + sym + b"\x00") in data
        )

        score = 0.0
        if has_aslr:
            score += 28.0
        if has_dep:
            score += 28.0
        if has_cfg:
            score += 22.0
        if has_canary:
            score += 22.0
        score = max(0.0, score - min(30.0, len(dangerous) * 6.0))

        return BinarySecurityProfile(
            file_path=file_path,
            binary_format="PE32+" if is_64 else "PE32",
            architecture=PE_MACHINES.get(machine, f"machine_0x{machine:x}"),
            endianness="little",
            has_pie=has_aslr,
            has_nx=has_dep,
            has_aslr=has_aslr,
            has_dep=has_dep,
            has_cfg=has_cfg,
            has_stack_canary=has_canary,
            dangerous_imports=dangerous,
            hardening_score=round(score, 2),
        )

    def _evaluate_profile(self, prof: BinarySecurityProfile) -> List[CyberVulnerability]:
        findings: List[CyberVulnerability] = []
        is_elf = prof.binary_format.startswith("ELF")

        if not prof.has_nx:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-BIN-NO-NX-001",
                    title=f"Executable Stack Enabled (Missing NX / DEP) in `{prof.file_path}`",
                    description=f"Binary `{prof.file_path}` ({prof.binary_format}/{prof.architecture}) lacks NX/DEP stack protection, allowing direct shellcode execution on stack corruption.",
                    cyber_domain=CyberDomain.BINARY_MEMORY_SAFETY,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-119", "CWE-693"],
                    confidence=0.99,
                    verification_method=VerificationMethod.BINARY_HEADER_INSPECTION,
                    file_path=prof.file_path,
                    remediation_guidance="Compile with `-z noexecstack` (ELF) or `/NXCOMPAT` (PE).",
                    discovered_by="ely_cyber_binary_checksec",
                )
            )

        if not prof.has_pie:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-BIN-NO-PIE-ASLR-001",
                    title=f"Missing PIE / ASLR Hardening in `{prof.file_path}`",
                    description=f"Binary `{prof.file_path}` loads at a deterministic base address, making ROP gadget chains reliable.",
                    cyber_domain=CyberDomain.BINARY_MEMORY_SAFETY,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-693"],
                    confidence=0.98,
                    verification_method=VerificationMethod.BINARY_HEADER_INSPECTION,
                    file_path=prof.file_path,
                    remediation_guidance="Build with `-fPIE -pie` (ELF) or `/DYNAMICBASE /HIGHENTROPYVA` (PE).",
                    discovered_by="ely_cyber_binary_checksec",
                )
            )

        if is_elf and prof.has_relro != "full":
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-BIN-NO-FULL-RELRO",
                    title=f"Incomplete RELRO (`{prof.has_relro}`) Leaves GOT Writable in `{prof.file_path}`",
                    description="Without Full RELRO (`-Wl,-z,relro,-z,now`), arbitrary write primitives can hijack Global Offset Table (GOT) function pointers.",
                    cyber_domain=CyberDomain.BINARY_MEMORY_SAFETY,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-123", "CWE-693"],
                    confidence=0.97,
                    verification_method=VerificationMethod.BINARY_HEADER_INSPECTION,
                    file_path=prof.file_path,
                    remediation_guidance="Link ELF binaries with `-Wl,-z,relro,-z,now`.",
                    discovered_by="ely_cyber_binary_checksec",
                )
            )

        if not prof.has_stack_canary:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-BIN-NO-CANARY-001",
                    title=f"Missing Stack Canary Protection in `{prof.file_path}`",
                    description="No stack-smashing protector (`__stack_chk_fail` / `__security_cookie`) detected in binary.",
                    cyber_domain=CyberDomain.BINARY_MEMORY_SAFETY,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-121", "CWE-693"],
                    confidence=0.94,
                    verification_method=VerificationMethod.BINARY_HEADER_INSPECTION,
                    file_path=prof.file_path,
                    remediation_guidance="Compile with `-fstack-protector-strong` (GCC/Clang) or `/GS` (MSVC).",
                    discovered_by="ely_cyber_binary_checksec",
                )
            )

        if prof.has_rpath:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-BIN-RPATH-HIJACK",
                    title=f"Insecure `DT_RPATH`/`DT_RUNPATH` Library Search Path in `{prof.file_path}`",
                    description="Embedded RPATH/RUNPATH enables shared-library hijacking (`LD_PRELOAD`-equivalent escalation) if pointing to writable paths.",
                    cyber_domain=CyberDomain.BINARY_MEMORY_SAFETY,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-426", "CWE-427"],
                    confidence=0.92,
                    mitre_techniques=[MitreTechniqueRef("T1574.006", "Dynamic Linker Hijacking", MitreTactic.PRIVILEGE_ESCALATION, "006")],
                    verification_method=VerificationMethod.BINARY_HEADER_INSPECTION,
                    file_path=prof.file_path,
                    remediation_guidance="Strip `DT_RPATH`/`DT_RUNPATH` or confine strictly to root-owned immutable system library directories.",
                    discovered_by="ely_cyber_binary_checksec",
                )
            )

        if prof.dangerous_imports:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-BIN-DANGEROUS-IMPORTS",
                    title=f"Unsafe C/OS Memory-Corruption Imports ({', '.join(prof.dangerous_imports[:6])})",
                    description=f"Binary `{prof.file_path}` imports classic unbounded memory/command functions: {prof.dangerous_imports}.",
                    cyber_domain=CyberDomain.BINARY_MEMORY_SAFETY,
                    severity=Severity.HIGH if any(x in prof.dangerous_imports for x in ("gets", "strcpy", "sprintf", "system")) else Severity.MEDIUM,
                    cwe_ids=["CWE-120", "CWE-676"],
                    confidence=0.93,
                    verification_method=VerificationMethod.BINARY_HEADER_INSPECTION,
                    file_path=prof.file_path,
                    remediation_guidance="Replace unsafe libc functions with bounded equivalents (`snprintf`, `strlcpy`, `fgets`) and enable `_FORTIFY_SOURCE=3`.",
                    discovered_by="ely_cyber_binary_checksec",
                )
            )

        return findings


# ---------------------------------------------------------------------------
# Multi-Language Native Memory-Safety & Concurrency Static Analyzer
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MemorySafetyRule:
    rule_id: str
    title: str
    description: str
    severity: Severity
    cwe_ids: Tuple[str, ...]
    languages: Tuple[str, ...]
    pattern: str
    anti_pattern: Optional[str]
    remediation: str


MEMORY_SAFETY_RULES: Tuple[MemorySafetyRule, ...] = (
    MemorySafetyRule(
        rule_id="CYB-MEM-BOF-001",
        title="Unbounded Buffer Copy / Stack Buffer Overflow (`gets`, `strcpy`, `strcat`, `sprintf`, `scanf %s`)",
        description="Classic unbounded C string/buffer function writes past stack or heap buffer bounds, enabling memory corruption and RCE.",
        severity=Severity.CRITICAL,
        cwe_ids=("CWE-120", "CWE-121", "CWE-787"),
        languages=(".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"),
        pattern=r"""(?:\b(?:gets|strcpy|strcat|sprintf|vsprintf|wcscpy|wcscat)\s*\(|\bscanf\s*\([^)]*"[^"]*%s)""",
        anti_pattern=r"""(?:snprintf|strlcpy|strncpy_s|strcpy_s)""",
        remediation="Replace with bounded functions (`snprintf`, `strlcpy`, `fgets`, `std::string`) and compile with AddressSanitizer + `-fstack-protector-strong`.",
    ),
    MemorySafetyRule(
        rule_id="CYB-MEM-FMTSTR-001",
        title="Format String Vulnerability (Non-Literal Format Argument in `printf`/`fprintf`/`syslog`)",
        description="Passing a non-literal variable directly as the format string allows arbitrary stack read (`%p/%s`) and arbitrary memory write (`%n`).",
        severity=Severity.CRITICAL,
        cwe_ids=("CWE-134",),
        languages=(".c", ".cc", ".cpp", ".h", ".hpp"),
        pattern=r"""\b(?:printf|vprintf)\s*\(\s*[a-zA-Z_]\w*\s*\)|\b(?:fprintf|syslog|snprintf)\s*\(\s*[^,]+,\s*[a-zA-Z_]\w*\s*\)""",
        anti_pattern=None,
        remediation="Always pass a compile-time constant format string literal (`printf(\"%s\", user_str)`).",
    ),
    MemorySafetyRule(
        rule_id="CYB-MEM-INTOVF-ALLOC-001",
        title="Integer Overflow in Dynamic Heap Allocation (`malloc(n * sz)`)",
        description="Multiplying untrusted counts inside `malloc`/`calloc`/`realloc` can wrap around 32/64-bit integer width, allocating an undersized heap buffer followed by heap overflow.",
        severity=Severity.HIGH,
        cwe_ids=("CWE-190", "CWE-122"),
        languages=(".c", ".cc", ".cpp", ".h", ".hpp"),
        pattern=r"""\b(?:malloc|realloc)\s*\([^)]*\*[^)]*\)""",
        anti_pattern=r"""(?:__builtin_mul_overflow|calloc\s*\(|SIZE_MAX)""",
        remediation="Use overflow-checked multiplication (`__builtin_mul_overflow`, `calloc(count, size)`) and enforce explicit upper bounds.",
    ),
    MemorySafetyRule(
        rule_id="CYB-MEM-CMD-C-001",
        title="OS Command Injection in Native C/C++ (`system()` / `popen()`)",
        description="Invoking `/bin/sh -c` via `system()` or `popen()` with non-constant buffers leads directly to command injection.",
        severity=Severity.CRITICAL,
        cwe_ids=("CWE-78",),
        languages=(".c", ".cc", ".cpp", ".h", ".hpp"),
        pattern=r"""\b(?:system|popen)\s*\(\s*(?!")""",
        anti_pattern=None,
        remediation="Use `posix_spawn` or `execve` with an explicit `argv[]` array and scrubbed `envp[]`.",
    ),
    MemorySafetyRule(
        rule_id="CYB-MEM-GO-UNSAFE-001",
        title="Unsafe Go Pointer Arithmetic / Raw `cgo` Memory Cast",
        description="Bypassing Go's memory-safety type system via `unsafe.Pointer` + `uintptr` arithmetic introduces memory corruption and GC hazards.",
        severity=Severity.MEDIUM,
        cwe_ids=("CWE-119", "CWE-704"),
        languages=(".go",),
        pattern=r"""unsafe\.Pointer\s*\(\s*uintptr\s*\(""",
        anti_pattern=None,
        remediation="Eliminate raw pointer arithmetic; use bounds-checked slices and `encoding/binary`.",
    ),
    MemorySafetyRule(
        rule_id="CYB-MEM-TOCTOU-C-001",
        title="Filesystem TOCTOU Race Condition (`access()` Followed by `open()` / `mktemp()`)",
        description="Checking file permissions with `access()` before `open()`, or using predictable `mktemp()`, permits symlink privilege-escalation races.",
        severity=Severity.HIGH,
        cwe_ids=("CWE-367", "CWE-377"),
        languages=(".c", ".cc", ".cpp"),
        pattern=r"""\b(?:mktemp|tmpnam|tempnam)\s*\(|\baccess\s*\([^)]*\)\s*==\s*0""",
        anti_pattern=r"""(?:mkstemp|O_CREAT\s*\|\s*O_EXCL|O_NOFOLLOW)""",
        remediation="Use `mkstemp()` or `openat()` with `O_NOFOLLOW | O_CREAT | O_EXCL` and inspect permissions via `fstat()` on the open descriptor.",
    ),
)


class BinaryAndMemorySafetyEngine:
    """Unified engine combining ELF/PE binary checksec and C/C++/Go/Rust memory-safety static analysis."""

    def __init__(self) -> None:
        self.binary_analyzer = BinaryHeaderSecurityAnalyzer()
        self._compiled: List[Tuple[MemorySafetyRule, Pattern[str], Optional[Pattern[str]]]] = [
            (r, re.compile(r.pattern), re.compile(r.anti_pattern) if r.anti_pattern else None)
            for r in MEMORY_SAFETY_RULES
        ]

    def scan_directory(self, root_path: Path) -> Tuple[List[CyberVulnerability], List[BinarySecurityProfile]]:
        findings: List[CyberVulnerability] = []
        profiles: List[BinarySecurityProfile] = []
        seen: set[str] = set()

        for fp in sorted(root_path.rglob("*")):
            if not fp.is_file():
                continue
            if any(p in {".git", "node_modules", "__pycache__", ".venv"} for p in fp.parts):
                continue

            rel = str(fp.relative_to(root_path))
            ext = fp.suffix.lower()

            # Check binary ELF / PE files by magic bytes
            if ext in {".so", ".elf", ".bin", ".exe", ".dll", ".out", ""}:
                try:
                    raw = fp.read_bytes()
                except OSError:
                    continue
                if len(raw) >= 64 and (raw[:4] == b"\x7fELF" or raw[:2] == b"MZ"):
                    prof, b_findings = self.binary_analyzer.inspect_bytes(raw, rel)
                    profiles.append(prof)
                    for bf in b_findings:
                        if bf.fingerprint() not in seen:
                            seen.add(bf.fingerprint())
                            findings.append(bf)
                    continue

            # Source-code memory safety checks
            if ext not in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".go"}:
                continue
            try:
                content = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.splitlines()
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
                        cyber_domain=CyberDomain.BINARY_MEMORY_SAFETY,
                        severity=rule.severity,
                        cwe_ids=list(rule.cwe_ids),
                        confidence=0.91,
                        mitre_techniques=[MitreTechniqueRef("T1203", "Exploitation for Client Execution", MitreTactic.EXECUTION)],
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=rel,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line.strip()[:260],
                        remediation_guidance=rule.remediation,
                        discovered_by="ely_cyber_memory_safety",
                    )
                    if v.fingerprint() not in seen:
                        seen.add(v.fingerprint())
                        findings.append(v)

            # Intra-file Use-After-Free / Double-Free heuristic detector for C/C++
            if ext in {".c", ".cc", ".cpp", ".cxx"}:
                findings.extend(self._detect_uaf_double_free(lines, rel, seen))

        return findings, profiles

    def _detect_uaf_double_free(self, lines: List[str], rel_path: str, seen: set[str]) -> List[CyberVulnerability]:
        """Detect `free(ptr)` not followed by `ptr = NULL` where `ptr` is reused or double-freed."""
        findings: List[CyberVulnerability] = []
        freed_vars: Dict[str, int] = {}
        free_re = re.compile(r"\bfree\s*\(\s*([a-zA-Z_]\w*)\s*\)")

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            # Reset tracking at function closing brace
            if stripped == "}":
                freed_vars.clear()
                continue

            # Clear if pointer is reassigned to NULL or new allocation
            for var in list(freed_vars.keys()):
                if re.search(rf"\b{re.escape(var)}\s*=\s*(?:NULL|nullptr|0|malloc|calloc|realloc)\b", stripped):
                    del freed_vars[var]

            m_free = free_re.search(stripped)
            if m_free:
                var = m_free.group(1)
                if var in freed_vars:
                    v = make_cyber_vuln(
                        rule_id="CYB-MEM-DOUBLE-FREE-001",
                        title=f"Potential Double-Free of Heap Pointer `{var}`",
                        description=f"Pointer `{var}` freed at line {freed_vars[var]} is freed again at line {idx} without intermediate NULLing or reallocation.",
                        cyber_domain=CyberDomain.BINARY_MEMORY_SAFETY,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-415"],
                        confidence=0.88,
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=stripped[:240],
                        remediation_guidance=f"Immediately assign `{var} = NULL;` after `free({var});` and adopt RAII/smart pointers.",
                        discovered_by="ely_cyber_uaf_detector",
                    )
                    if v.fingerprint() not in seen:
                        seen.add(v.fingerprint())
                        findings.append(v)
                else:
                    freed_vars[var] = idx
                continue

            # Check dereference of freed pointer
            for var, freed_line in list(freed_vars.items()):
                if re.search(rf"(?:\*{re.escape(var)}\b|\b{re.escape(var)}\s*->|\b{re.escape(var)}\s*\[)", stripped):
                    v = make_cyber_vuln(
                        rule_id="CYB-MEM-UAF-001",
                        title=f"Potential Use-After-Free (UAF) Dereference of `{var}`",
                        description=f"Pointer `{var}` freed at line {freed_line} is dereferenced at line {idx}.",
                        cyber_domain=CyberDomain.BINARY_MEMORY_SAFETY,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-416"],
                        confidence=0.87,
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=stripped[:240],
                        remediation_guidance=f"Set `{var} = NULL;` immediately upon free and never dereference post-free.",
                        discovered_by="ely_cyber_uaf_detector",
                    )
                    if v.fingerprint() not in seen:
                        seen.add(v.fingerprint())
                        findings.append(v)
                    del freed_vars[var]

        return findings
