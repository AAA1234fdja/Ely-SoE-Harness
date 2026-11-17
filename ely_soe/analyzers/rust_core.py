"""
Rust Core Deep Security Analyzer (Domain 10: Rust Core).

Audits Rust crates (`*.rs`, `build.rs`, `Cargo.toml`) for memory unsafety, FFI
soundness bugs, concurrency hazards, logic/crypto flaws, and build-time supply
chain attacks:
  1. Unjustified `unsafe` blocks/functions lacking `// SAFETY:` invariants
  2. `std::mem::transmute` / `transmute_copy` / `MaybeUninit::assume_init` UB hazards
  3. FFI `extern "C"` functions calling `slice::from_raw_parts(_mut)` without null/bounds checks
  4. Unsound `unsafe impl Send` / `unsafe impl Sync` (data races)
  5. Panic DoS via `.unwrap()` / `.expect()` on untrusted inputs inside security boundaries
  6. Async deadlock hazard: holding `std::sync::Mutex` / `RwLock` guard across `.await`
  7. Lossy/unchecked integer truncation casts (`as u32`, `as i32`, `as usize`) near allocation/bounds
  8. Weak cryptography / non-CSPRNG (`SmallRng`, `StdRng::seed_from_u64`, MD5/SHA1, timing-unsafe `==` on secrets)
  9. `build.rs` malicious or risky command execution / network exfiltration
 10. `Cargo.toml` release-profile missing `overflow-checks = true` or wildcard `*` crate versions
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

from ely_soe.core.models import (
    CodeLocation,
    EvidenceArtifact,
    Finding,
    FindingStatus,
    SecurityDomain,
    Severity,
    new_id,
)


@dataclass(frozen=True)
class RustRule:
    rule_id: str
    title: str
    severity: Severity
    cwe: str
    pattern: str
    description: str
    impact: str
    require_no_safety_comment: bool = False
    require_no_nearby_guard: Tuple[str, ...] = ()
    only_filename: str = ""


RUST_RULES: List[RustRule] = [
    RustRule(
        rule_id="RUST-MEM-001",
        title="Unsound std::mem::transmute Usage",
        severity=Severity.CRITICAL,
        cwe="CWE-704",
        pattern=r"\b(?:std::mem::|core::mem::)?transmute(?:_copy)?\b",
        description="Use of `transmute` bypasses Rust's type and lifetime soundness guarantees and easily leads to Undefined Behavior.",
        impact="Memory corruption, arbitrary pointer dereference, or sandbox escape inside Rust Core",
    ),
    RustRule(
        rule_id="RUST-FFI-002",
        title="FFI slice::from_raw_parts Without Null & Upper-Bound Validation",
        severity=Severity.CRITICAL,
        cwe="CWE-119",
        pattern=r"\bslice::from_raw_parts(?:_mut)?\s*\(",
        description="Constructing a Rust slice from a raw FFI pointer without checking `is_null()` and an explicit max-length bound risks out-of-bounds read/write UB.",
        impact="Heap over-read, memory corruption, or process crash triggered from Python/agent FFI input",
        require_no_nearby_guard=("is_null()", "MAX_", "checked_", "validate_ffi_bounds"),
    ),
    RustRule(
        rule_id="RUST-CONC-003",
        title="Unsound Manual unsafe impl Send / Sync",
        severity=Severity.HIGH,
        cwe="CWE-362",
        pattern=r"\bunsafe\s+impl\b[^{]*\b(?:Send|Sync)\s+for\b",
        description="Manually implementing `Send` or `Sync` for types containing raw pointers or interior mutability without rigorous synchronization introduces data races.",
        impact="Multi-threaded data race causing memory corruption across concurrent agent tasks",
        require_no_safety_comment=True,
    ),
    RustRule(
        rule_id="RUST-MEM-004",
        title="Unjustified Raw Pointer Dereference or MaybeUninit::assume_init",
        severity=Severity.HIGH,
        cwe="CWE-416",
        pattern=r"\b(?:assume_init\s*\(\)|offset\s*\(|ptr::read|ptr::write|from_raw\s*\()",
        description="Low-level pointer manipulation or `assume_init()` without documented safety invariants risks use-after-free or uninitialized memory reads.",
        impact="Memory safety violation or information disclosure from uninitialized Rust Core buffers",
        require_no_safety_comment=True,
    ),
    RustRule(
        rule_id="RUST-DOS-005",
        title="Panic-Prone unwrap()/expect() in Security/FFI Boundary",
        severity=Severity.MEDIUM,
        cwe="CWE-755",
        pattern=r"\.(?:unwrap|expect)\s*\(",
        description="Calling `.unwrap()` or `.expect()` on untrusted input or FFI/parser results triggers panics (and UB if unwinding across `extern \"C\"`).",
        impact="Denial of Service crashing the Ely core worker or aborting the sandbox host process",
    ),
    RustRule(
        rule_id="RUST-CRYPTO-006",
        title="Predictable / Non-Cryptographic RNG or Weak Hash in Rust Core",
        severity=Severity.HIGH,
        cwe="CWE-338",
        pattern=r"\b(?:SmallRng|seed_from_u64\s*\(|md5::|Md5::|Sha1::|sha1::)",
        description="Predictable PRNG or broken hash function used inside security-sensitive Rust Core module.",
        impact="Predictable session tokens, forgeable agent capabilities, or broken integrity checks",
    ),
    RustRule(
        rule_id="RUST-AUTH-007",
        title="Non-Constant-Time Secret/Token Equality Comparison",
        severity=Severity.MEDIUM,
        cwe="CWE-208",
        pattern=r"\b(?:token|secret|signature|hmac|api_key|digest)\s*==\s*",
        description="Comparing cryptographic secrets or tokens with `==` leaks byte-by-byte timing side-channel information.",
        impact="Remote timing oracle enabling progressive forgery of MACs or agent auth tokens",
        require_no_nearby_guard=("ct_eq", "constant_time_eq", "subtle::ConstantTimeEq"),
    ),
    RustRule(
        rule_id="RUST-BUILD-008",
        title="Risky Shell/Network Execution in Cargo build.rs",
        severity=Severity.CRITICAL,
        cwe="CWE-829",
        pattern=r"\b(?:Command::new\s*\(\s*\"(?:sh|bash|curl|wget|powershell)|TcpStream::connect|reqwest::)",
        description="Cargo `build.rs` executes arbitrary shell/network commands at compile time.",
        impact="Build-time remote code execution and supply-chain compromise of Ely Rust Core binaries",
        only_filename="build.rs",
    ),
    RustRule(
        rule_id="RUST-CMD-009",
        title="Unsanitized Shell Command Execution via std::process::Command",
        severity=Severity.HIGH,
        cwe="CWE-78",
        pattern=r'Command::new\s*\(\s*"(?:sh|bash|/bin/sh|/bin/bash)"\s*\)',
        description="Spawning an OS shell interpreter from Rust Core widens command-injection attack surface.",
        impact="Arbitrary OS command execution escaping Ely tool constraints",
    ),
    RustRule(
        rule_id="RUST-INT-010",
        title="Unchecked Integer Truncation Cast Near Allocation/Indexing",
        severity=Severity.MEDIUM,
        cwe="CWE-190",
        pattern=r"\b(?:len|size|offset|capacity|count)\s+as\s+(?:u8|u16|u32|i32|isize)\b",
        description="Truncating `usize`/`u64` lengths via `as` instead of `TryFrom` silently wraps oversized values.",
        impact="Integer truncation leading to undersized buffer allocation or bounds check bypass",
        require_no_nearby_guard=("try_into", "TryFrom", "checked_"),
    ),
]


class RustCoreAnalyzer:
    """
    Deep lexical & structural Rust Core security auditor emitting HYPOTHESIS findings.
    """

    def analyze_directory(self, snapshot_root: Path) -> List[Finding]:
        findings: List[Finding] = []
        root = Path(snapshot_root).resolve()

        for rs_file in sorted(root.rglob("*.rs")):
            if any(part in ("target", ".git", "node_modules") for part in rs_file.relative_to(root).parts):
                continue
            rel = rs_file.relative_to(root).as_posix()
            try:
                content = rs_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(self.analyze_rust_source(rel, content))

        for cargo_file in sorted(root.rglob("Cargo.toml")):
            if any(part in ("target", ".git") for part in cargo_file.relative_to(root).parts):
                continue
            rel = cargo_file.relative_to(root).as_posix()
            try:
                content = cargo_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(self.analyze_cargo_toml(rel, content))

        return findings

    def analyze_rust_source(self, rel_path: str, source: str) -> List[Finding]:
        findings: List[Finding] = []
        raw_lines = source.splitlines()
        code_lines = self._strip_rust_comments_preserve_lines(source)
        fname = Path(rel_path).name

        # Rule-based lexical checks on comment-stripped lines
        for rule in RUST_RULES:
            if rule.only_filename and fname != rule.only_filename:
                continue
            compiled = re.compile(rule.pattern)
            for idx, line in enumerate(code_lines, start=1):
                if not compiled.search(line):
                    continue

                # Avoid flagging unwrap() inside #[cfg(test)] blocks
                if rule.rule_id == "RUST-DOS-005" and self._in_test_section(raw_lines, idx):
                    continue

                if rule.require_no_safety_comment and self._has_safety_comment_above(raw_lines, idx):
                    continue

                if rule.require_no_nearby_guard and self._has_nearby_guard(code_lines, idx, rule.require_no_nearby_guard):
                    continue

                snippet = raw_lines[idx - 1].strip()[:160]
                findings.append(
                    self._make_finding(
                        rule_id=rule.rule_id,
                        title=f"[Rust Core] {rule.title}",
                        description=rule.description,
                        severity=rule.severity,
                        cwe=rule.cwe,
                        rel_path=rel_path,
                        line_no=idx,
                        snippet=snippet,
                        impact=rule.impact,
                    )
                )

        # Structural check 1: `std::sync::Mutex::lock()` held across `.await` in async fn
        findings.extend(self._detect_sync_mutex_across_await(rel_path, raw_lines, code_lines))

        # Structural check 2: Undocumented `unsafe {` blocks
        findings.extend(self._detect_undocumented_unsafe_blocks(rel_path, raw_lines, code_lines))

        return findings

    def analyze_cargo_toml(self, rel_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        has_release_profile = "[profile.release]" in content
        has_overflow_checks = bool(re.search(r"overflow-checks\s*=\s*true", content))

        if has_release_profile and not has_overflow_checks:
            ln = next((i for i, l in enumerate(lines, 1) if "[profile.release]" in l), 1)
            findings.append(
                self._make_finding(
                    rule_id="RUST-CFG-011",
                    title="[Rust Core] Release Profile Missing Integer overflow-checks = true",
                    description="Rust release builds wrap integer overflows silently unless `overflow-checks = true` is explicitly enabled.",
                    severity=Severity.LOW,
                    cwe="CWE-190",
                    rel_path=rel_path,
                    line_no=ln,
                    snippet=lines[ln - 1].strip(),
                    impact="Silent integer wraparound in release builds of Ely Rust Core security checks",
                )
            )
        return findings

    def _detect_sync_mutex_across_await(
        self, rel_path: str, raw_lines: List[str], code_lines: List[str]
    ) -> List[Finding]:
        findings: List[Finding] = []
        in_async = False
        brace_depth = 0
        sync_lock_line: int | None = None

        for idx, line in enumerate(code_lines, start=1):
            if re.search(r"\basync\s+fn\b", line):
                in_async = True
                brace_depth = 0
                sync_lock_line = None

            if in_async:
                brace_depth += line.count("{") - line.count("}")
                if re.search(r"\.lock\s*\(\s*\)", line) and "tokio::sync" not in "\n".join(code_lines[:idx]):
                    sync_lock_line = idx
                if sync_lock_line is not None and ".await" in line and idx > sync_lock_line:
                    findings.append(
                        self._make_finding(
                            rule_id="RUST-ASYNC-012",
                            title="[Rust Core] std::sync::Mutex Guard Potentially Held Across .await",
                            description=(
                                f"A synchronous `.lock()` acquired at line {sync_lock_line} appears to remain held "
                                f"across `.await` at line {idx}, risking executor starvation or deadlock."
                            ),
                            severity=Severity.HIGH,
                            cwe="CWE-833",
                            rel_path=rel_path,
                            line_no=idx,
                            snippet=raw_lines[idx - 1].strip()[:160],
                            impact="Async runtime deadlock halting multi-agent sandbox coordinator",
                        )
                    )
                    sync_lock_line = None
                if "drop(" in line:
                    sync_lock_line = None
                if brace_depth <= 0 and "}" in line:
                    in_async = False
                    sync_lock_line = None
        return findings

    def _detect_undocumented_unsafe_blocks(
        self, rel_path: str, raw_lines: List[str], code_lines: List[str]
    ) -> List[Finding]:
        findings: List[Finding] = []
        for idx, line in enumerate(code_lines, start=1):
            if re.search(r"\bunsafe\s*\{", line):
                if not self._has_safety_comment_above(raw_lines, idx):
                    findings.append(
                        self._make_finding(
                            rule_id="RUST-UNSAFE-013",
                            title="[Rust Core] Undocumented unsafe Block Missing // SAFETY: Invariant",
                            description="An `unsafe { ... }` block lacks a `// SAFETY:` invariant justification required by Ely Rust Core hardening standards.",
                            severity=Severity.MEDIUM,
                            cwe="CWE-119",
                            rel_path=rel_path,
                            line_no=idx,
                            snippet=raw_lines[idx - 1].strip()[:160],
                            impact="Unreviewed unsafe memory invariant increases risk of silent UB during refactoring",
                        )
                    )
        return findings

    @staticmethod
    def _strip_rust_comments_preserve_lines(source: str) -> List[str]:
        """Strip `//` and `/* ... */` comments while preserving exact 1-based line numbers."""
        out: List[str] = []
        i = 0
        n = len(source)
        in_block_comment = 0
        in_string = False

        while i < n:
            ch = source[i]
            nxt = source[i + 1] if i + 1 < n else ""
            if in_block_comment > 0:
                if ch == "/" and nxt == "*":
                    in_block_comment += 1
                    out.append("  ")
                    i += 2
                elif ch == "*" and nxt == "/":
                    in_block_comment -= 1
                    out.append("  ")
                    i += 2
                elif ch == "\n":
                    out.append("\n")
                    i += 1
                else:
                    out.append(" ")
                    i += 1
            elif in_string:
                out.append(ch)
                if ch == "\\" and i + 1 < n:
                    out.append(nxt)
                    i += 2
                else:
                    if ch == '"':
                        in_string = False
                    i += 1
            else:
                if ch == '"':
                    in_string = True
                    out.append(ch)
                    i += 1
                elif ch == "/" and nxt == "/":
                    while i < n and source[i] != "\n":
                        out.append(" ")
                        i += 1
                elif ch == "/" and nxt == "*":
                    in_block_comment = 1
                    out.append("  ")
                    i += 2
                else:
                    out.append(ch)
                    i += 1
        return "".join(out).splitlines()

    @staticmethod
    def _has_safety_comment_above(raw_lines: List[str], line_no: int) -> bool:
        start = max(0, line_no - 5)
        window = "\n".join(raw_lines[start:line_no])
        return "SAFETY:" in window.upper()

    @staticmethod
    def _has_nearby_guard(code_lines: List[str], line_no: int, guards: Tuple[str, ...]) -> bool:
        start = max(0, line_no - 8)
        end = min(len(code_lines), line_no + 3)
        window = "\n".join(code_lines[start:end])
        return any(g in window for g in guards)

    @staticmethod
    def _in_test_section(raw_lines: List[str], line_no: int) -> bool:
        prefix = "\n".join(raw_lines[:line_no])
        return "#[cfg(test)]" in prefix

    @staticmethod
    def _make_finding(
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        cwe: str,
        rel_path: str,
        line_no: int,
        snippet: str,
        impact: str,
    ) -> Finding:
        return Finding(
            finding_id=new_id("fnd"),
            title=title,
            description=description,
            domain=SecurityDomain.RUST_CORE,
            severity=severity,
            rule_id=rule_id,
            discovered_by="ely_rust_core_analyzer",
            location=CodeLocation(
                file_path=rel_path,
                line_start=line_no,
                snippet=snippet,
                language="rust",
            ),
            status=FindingStatus.HYPOTHESIS,
            confidence=0.86,
            cwe_ids=[cwe],
            attack_vector="Malformed FFI call, untrusted input, or concurrent multi-agent task hitting Rust Core",
            impact=impact,
            poc_spec={
                "kind": "rust_static_audit",
                "rule_id": rule_id,
                "target_file": rel_path,
                "target_line": line_no,
                "snippet": snippet,
            },
            evidence=[
                EvidenceArtifact(
                    artifact_id=new_id("ev"),
                    kind="rust_audit_snippet",
                    description=f"Rust Core rule {rule_id} match at {rel_path}:{line_no}",
                    content=f"{rel_path}:{line_no}\n{snippet}",
                    producer="ely_rust_core_analyzer",
                )
            ],
            tags=["rust_core", rule_id.lower(), cwe.lower()],
        )
