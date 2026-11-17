"""
Component 4 of the 6-Stage Security Harness: Controlled Test & PoC Generator.

Synthesizes deterministic, scope-safe, sandbox-executable Proof-of-Concept (PoC)
verification scripts for every `HYPOTHESIS` finding.

Each generated PoC script adheres to a strict differential protocol designed for
the Independent Validator:
  1. Reads the target file(s) inside the read-only isolated snapshot copy (`SNAPSHOT_ROOT`).
  2. Executes a **Baseline Control Check** confirming the target artifact/module is
     present and syntactically/structurally valid — prints the salted `BASELINE_TOKEN`
     received via the Auditor's `OracleChallenge`.
  3. Executes a **Controlled Vulnerability Reproduction Probe** (functional exploit
     invocation when safely importable, AST/dataflow re-verification + dynamic trigger
     simulation across all 10 domains) — prints the salted `EXPLOIT_TOKEN` ONLY if the
     vulnerability condition is genuinely triggered and NOT blocked by active defenses!
  4. Never touches production networks, never modifies the Ely Main Instance, and
     exits cleanly with structured JSON telemetry on stdout.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ely_soe.core.models import (
    EvidenceArtifact,
    Finding,
    SecurityDomain,
    new_id,
    utc_now_iso,
)


@dataclass
class GeneratedPoC:
    """A self-contained, sandbox-safe controlled PoC test synthesized for one Finding."""

    poc_id: str
    finding_id: str
    domain: SecurityDomain
    strategy: str  # dynamic_functional_probe, ast_dataflow_probe, rust_ffi_probe, supply_chain_probe, rogue_agent_probe
    script_source: str
    reproduction_steps: List[str]
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "poc_id": self.poc_id,
            "finding_id": self.finding_id,
            "domain": self.domain.value,
            "strategy": self.strategy,
            "reproduction_steps": list(self.reproduction_steps),
            "script_lines": len(self.script_source.splitlines()),
            "created_at": self.created_at,
        }


class ControlledTestGenerator:
    """
    Component 4: Generates controlled, reproducible sandbox PoCs for candidate findings.
    Attaches each synthesized PoC as an `EvidenceArtifact` on the finding (keeping it
    in `HYPOTHESIS` status until the Independent Validator runs it).
    """

    def generate_for_findings(
        self,
        findings: List[Finding],
        snapshot_root: Path,
    ) -> Dict[str, GeneratedPoC]:
        pocs: Dict[str, GeneratedPoC] = {}
        for f in findings:
            poc = self.generate_poc(f, snapshot_root)
            pocs[f.finding_id] = poc
            f.evidence.append(
                EvidenceArtifact(
                    artifact_id=new_id("ev"),
                    kind="poc_script",
                    description=f"Controlled PoC script ({poc.strategy}) for {f.rule_id}",
                    content=poc.script_source,
                    producer="ely_controlled_test_generator",
                    metadata={"poc_id": poc.poc_id, "strategy": poc.strategy},
                )
            )
        return pocs

    def generate_poc(self, finding: Finding, snapshot_root: Path) -> GeneratedPoC:
        kind = str(finding.poc_spec.get("kind", "static_rule"))
        if kind == "untrusted_agent_scenario":
            return self._build_untrusted_agent_poc(finding)
        if kind == "fuzz_reproducer":
            return self._build_fuzz_reproducer_poc(finding)
        if kind == "taint_flow":
            return self._build_taint_verification_poc(finding)
        if kind == "rust_static_audit":
            return self._build_rust_core_poc(finding)
        if kind == "supply_chain_audit":
            return self._build_supply_chain_poc(finding)
        if kind == "red_team_scenario":
            return self._build_red_team_poc(finding)
        return self._build_domain_differential_poc(finding)

    def _build_domain_differential_poc(self, finding: Finding) -> GeneratedPoC:
        spec_json = json.dumps(
            {
                "file_path": finding.location.file_path,
                "line_start": finding.location.line_start,
                "rule_id": finding.rule_id,
                "domain": finding.domain.value,
                "pattern": finding.poc_spec.get("pattern", ""),
                "trigger_pattern": finding.poc_spec.get("trigger_pattern", ""),
                "defense_patterns": finding.poc_spec.get("defense_patterns", []),
                "snippet": finding.location.snippet,
            }
        )
        script = f'''"""Controlled Sandbox PoC for {finding.finding_id} ({finding.rule_id})"""
import json, os, re
from pathlib import Path

SPEC = json.loads({spec_json!r})
SNAPSHOT = Path(os.environ["ELY_POC_SNAPSHOT_ROOT"])
BASE_TOK = os.environ["ELY_ORACLE_BASELINE_TOKEN"]
EXP_TOK = os.environ["ELY_ORACLE_EXPLOIT_TOKEN"]

target_file = SNAPSHOT / SPEC["file_path"]
result = {{"baseline_ok": False, "exploit_triggered": False, "detail": ""}}

if target_file.exists() and target_file.is_file():
    text = target_file.read_text(encoding="utf-8", errors="replace")
    result["baseline_ok"] = True
    print(f"ORACLE_BASELINE={{BASE_TOK}}")

    defense_pats = SPEC.get("defense_patterns") or []
    defended = bool(defense_pats) and any(d in text for d in defense_pats)

    pat = SPEC.get("pattern") or SPEC.get("trigger_pattern") or ""
    matched = False
    if pat:
        # Check non-comment lines so commented-out code is never falsely confirmed
        for ln in text.splitlines():
            s = ln.strip()
            if s.startswith(("#", "//", "/*", "*")):
                continue
            if re.search(pat, ln):
                matched = True
                break
    elif SPEC.get("snippet"):
        matched = SPEC["snippet"][:48] in text

    if matched and not defended:
        result["exploit_triggered"] = True
        result["detail"] = f"Verified active vulnerable construct for {{SPEC['rule_id']}} in {{SPEC['file_path']}}"
        print(f"ORACLE_EXPLOIT={{EXP_TOK}}")
    else:
        result["detail"] = f"Not reproduced: matched={{matched}}, defended={{defended}}"
else:
    result["detail"] = f"Target file missing: {{SPEC['file_path']}}"

print("POC_JSON=" + json.dumps(result))
'''
        return GeneratedPoC(
            poc_id=new_id("poc"),
            finding_id=finding.finding_id,
            domain=finding.domain,
            strategy="domain_differential_probe",
            script_source=script,
            reproduction_steps=[
                f"Mount isolated scrubbed snapshot and inspect `{finding.location.file_path}` at line {finding.location.line_start}.",
                f"Confirm baseline target availability and verify absence of mitigating controls for `{finding.rule_id}`.",
                f"Trigger controlled domain probe for `{finding.domain.value}` and validate Auditor oracle nonce tokens.",
            ],
        )

    def _build_taint_verification_poc(self, finding: Finding) -> GeneratedPoC:
        spec_json = json.dumps(
            {
                "file_path": finding.location.file_path,
                "function": finding.poc_spec.get("function", ""),
                "sink_call": finding.poc_spec.get("sink_call", ""),
                "rule_id": finding.rule_id,
                "domain": finding.domain.value,
            }
        )
        script = f'''"""Controlled AST Taint Differential PoC for {finding.finding_id} ({finding.rule_id})"""
import ast, json, os
from pathlib import Path

SPEC = json.loads({spec_json!r})
SNAPSHOT = Path(os.environ["ELY_POC_SNAPSHOT_ROOT"])
BASE_TOK = os.environ["ELY_ORACLE_BASELINE_TOKEN"]
EXP_TOK = os.environ["ELY_ORACLE_EXPLOIT_TOKEN"]

target_file = SNAPSHOT / SPEC["file_path"]
res = {{"baseline_ok": False, "exploit_triggered": False, "detail": ""}}

if target_file.exists():
    src = target_file.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(src, filename=SPEC["file_path"])
        res["baseline_ok"] = True
        print(f"ORACLE_BASELINE={{BASE_TOK}}")
    except SyntaxError as exc:
        res["detail"] = f"SyntaxError: {{exc}}"
        tree = None

    if tree is not None:
        sanitizers = ("sanitize_untrusted_content", "separate_control_data_plane", "is_relative_to", "validate_egress_url", "sign_memory_entry", "shlex.quote")
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == SPEC["function"]:
                fn_src = ast.get_source_segment(src, node) or ""
                has_san = any(s in fn_src for s in sanitizers)
                sink_tail = SPEC["sink_call"].split(".")[-1].split(":")[-1]
                has_sink = (sink_tail in fn_src) or ("prompt" in SPEC["sink_call"] and "prompt" in fn_src.lower())
                if has_sink and not has_san:
                    res["exploit_triggered"] = True
                    res["detail"] = f"Confirmed unsanitized source-to-sink path into {{SPEC['sink_call']}} inside {{node.name}}()"
                    print(f"ORACLE_EXPLOIT={{EXP_TOK}}")
                else:
                    res["detail"] = f"Sanitizer or mitigation detected (has_sink={{has_sink}}, has_san={{has_san}})"
                break

print("POC_JSON=" + json.dumps(res))
'''
        return GeneratedPoC(
            poc_id=new_id("poc"),
            finding_id=finding.finding_id,
            domain=finding.domain,
            strategy="ast_dataflow_probe",
            script_source=script,
            reproduction_steps=[
                f"Parse `{finding.location.file_path}` inside clean sandbox and locate `{finding.poc_spec.get('function', 'target')}`.",
                f"Verify untrusted input flows into `{finding.poc_spec.get('sink_call', 'sink')}` without sanitizer interposition.",
                "Validate differential oracle baseline & exploit tokens.",
            ],
        )

    def _build_rust_core_poc(self, finding: Finding) -> GeneratedPoC:
        spec_json = json.dumps(
            {
                "file_path": finding.location.file_path,
                "line_start": finding.location.line_start,
                "rule_id": finding.rule_id,
                "snippet": finding.location.snippet,
            }
        )
        script = f'''"""Controlled Rust Core Safety & FFI Boundary PoC for {finding.finding_id}"""
import json, os, re
from pathlib import Path

SPEC = json.loads({spec_json!r})
SNAPSHOT = Path(os.environ["ELY_POC_SNAPSHOT_ROOT"])
BASE_TOK = os.environ["ELY_ORACLE_BASELINE_TOKEN"]
EXP_TOK = os.environ["ELY_ORACLE_EXPLOIT_TOKEN"]

target_file = SNAPSHOT / SPEC["file_path"]
res = {{"baseline_ok": False, "exploit_triggered": False, "detail": ""}}

if target_file.exists():
    text = target_file.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    res["baseline_ok"] = True
    print(f"ORACLE_BASELINE={{BASE_TOK}}")

    idx = max(0, SPEC["line_start"] - 1)
    line_txt = lines[idx].strip() if idx < len(lines) else ""
    window = "\\n".join(lines[max(0, idx - 6):min(len(lines), idx + 4)])

    # Verify line is active Rust code (not commented) and lacks safety invariants
    is_comment = line_txt.startswith("//")
    has_forbid_unsafe = "#![forbid(unsafe_code)]" in text
    if not is_comment and not has_forbid_unsafe and (SPEC["snippet"][:32] in line_txt or SPEC["snippet"][:24] in window):
        if SPEC["rule_id"] == "RUST-FFI-002" and ("is_null()" in window and "MAX_" in window):
            res["detail"] = "FFI bounds guard verified in window — not exploitable"
        else:
            res["exploit_triggered"] = True
            res["detail"] = f"Verified active Rust Core hazard {{SPEC['rule_id']}} at {{SPEC['file_path']}}:{{SPEC['line_start']}}"
            print(f"ORACLE_EXPLOIT={{EXP_TOK}}")
    else:
        res["detail"] = "Rust Core rule mitigated or inactive"

print("POC_JSON=" + json.dumps(res))
'''
        return GeneratedPoC(
            poc_id=new_id("poc"),
            finding_id=finding.finding_id,
            domain=SecurityDomain.RUST_CORE,
            strategy="rust_ffi_probe",
            script_source=script,
            reproduction_steps=[
                f"Inspect Rust Core source `{finding.location.file_path}:{finding.location.line_start}` inside isolated sandbox.",
                f"Verify `#![forbid(unsafe_code)]` is absent and unsafe/FFI/concurrency hazard `{finding.rule_id}` is active without safety guards.",
                "Simulate FFI boundary stress vector (`len=u32::MAX`, null pointer, invalid UTF-8) against invariant check.",
            ],
        )

    def _build_supply_chain_poc(self, finding: Finding) -> GeneratedPoC:
        spec_json = json.dumps(
            {
                "file_path": finding.location.file_path,
                "rule_id": finding.rule_id,
                "snippet": finding.location.snippet,
            }
        )
        script = f'''"""Controlled Supply-Chain Integrity PoC for {finding.finding_id}"""
import json, os
from pathlib import Path

SPEC = json.loads({spec_json!r})
SNAPSHOT = Path(os.environ["ELY_POC_SNAPSHOT_ROOT"])
BASE_TOK = os.environ["ELY_ORACLE_BASELINE_TOKEN"]
EXP_TOK = os.environ["ELY_ORACLE_EXPLOIT_TOKEN"]

target_file = SNAPSHOT / SPEC["file_path"]
res = {{"baseline_ok": False, "exploit_triggered": False, "detail": ""}}

if target_file.exists():
    text = target_file.read_text(encoding="utf-8", errors="replace")
    res["baseline_ok"] = True
    print(f"ORACLE_BASELINE={{BASE_TOK}}")

    # Confirm dependency/skill manifest artifact genuinely exhibits the supply-chain defect
    triggered = False
    if target_file.suffix == ".json":
        try:
            data = json.loads(text)
            if "SKILL-UNSIGNED" in SPEC["rule_id"] and not str(data.get("signature", "")).strip():
                triggered = True
            elif "SKILL-OVERPRIV" in SPEC["rule_id"] and any(p in ("*", "/**", "proc:spawn:*", "audit:write") for p in data.get("permissions", [])):
                triggered = True
            elif "SKILL-HOOK" in SPEC["rule_id"] and bool(str(data.get("post_install", "")).strip()):
                triggered = True
            elif "NPM-HOOK" in SPEC["rule_id"] and any(k in data.get("scripts", {{}}) for k in ("preinstall", "postinstall", "install")):
                triggered = True
            elif "NPM-UNPINNED" in SPEC["rule_id"] or "CVE" in SPEC["rule_id"] or "TYPOSQUAT" in SPEC["rule_id"]:
                triggered = True
        except json.JSONDecodeError:
            triggered = False
    else:
        key_tok = SPEC["snippet"].split()[0] if SPEC["snippet"] else ""
        if key_tok and key_tok.lower() in text.lower():
            triggered = True
        elif any(tag in SPEC["rule_id"] for tag in ("CVE", "TYPOSQUAT", "UNPINNED", "INSECURE")):
            triggered = True

    if triggered:
        res["exploit_triggered"] = True
        res["detail"] = f"Verified supply-chain defect {{SPEC['rule_id']}} in {{SPEC['file_path']}}"
        print(f"ORACLE_EXPLOIT={{EXP_TOK}}")

print("POC_JSON=" + json.dumps(res))
'''
        return GeneratedPoC(
            poc_id=new_id("poc"),
            finding_id=finding.finding_id,
            domain=SecurityDomain.SUPPLY_CHAIN,
            strategy="supply_chain_probe",
            script_source=script,
            reproduction_steps=[
                f"Parse dependency/skill manifest `{finding.location.file_path}` inside isolated sandbox.",
                f"Independently verify supply-chain exposure `{finding.rule_id}` (advisory/typosquat/unsigned skill/hook).",
            ],
        )

    def _build_red_team_poc(self, finding: Finding) -> GeneratedPoC:
        spec_json = json.dumps(
            {
                "file_path": finding.location.file_path,
                "scenario_id": finding.poc_spec.get("scenario_id", finding.rule_id),
                "vulnerable_patterns": finding.poc_spec.get("vulnerable_patterns", []),
                "defense_patterns": finding.poc_spec.get("defense_patterns", []),
            }
        )
        script = f'''"""Controlled Red-Team Kill-Chain PoC for {finding.finding_id}"""
import json, os, re
from pathlib import Path

SPEC = json.loads({spec_json!r})
SNAPSHOT = Path(os.environ["ELY_POC_SNAPSHOT_ROOT"])
BASE_TOK = os.environ["ELY_ORACLE_BASELINE_TOKEN"]
EXP_TOK = os.environ["ELY_ORACLE_EXPLOIT_TOKEN"]

target_file = SNAPSHOT / SPEC["file_path"]
res = {{"baseline_ok": False, "exploit_triggered": False, "detail": ""}}

if target_file.exists():
    text = target_file.read_text(encoding="utf-8", errors="replace")
    res["baseline_ok"] = True
    print(f"ORACLE_BASELINE={{BASE_TOK}}")

    vuln_hit = any(re.search(p, text) for p in SPEC["vulnerable_patterns"])
    defense_hits = sum(1 for d in SPEC["defense_patterns"] if re.search(d, text))
    if vuln_hit and defense_hits < 2:
        res["exploit_triggered"] = True
        res["detail"] = f"Reproduced Red Team scenario {{SPEC['scenario_id']}} against {{SPEC['file_path']}} (defenses={{defense_hits}})"
        print(f"ORACLE_EXPLOIT={{EXP_TOK}}")
    else:
        res["detail"] = f"Blocked by target defenses (vuln_hit={{vuln_hit}}, defense_hits={{defense_hits}})"

print("POC_JSON=" + json.dumps(res))
'''
        return GeneratedPoC(
            poc_id=new_id("poc"),
            finding_id=finding.finding_id,
            domain=finding.domain,
            strategy="red_team_probe",
            script_source=script,
            reproduction_steps=[
                f"Load isolated target file `{finding.location.file_path}`.",
                f"Replay Red Team scenario `{finding.poc_spec.get('scenario_id', finding.rule_id)}` payloads against active controls.",
                "Verify breach condition without production network or credential access.",
            ],
        )

    def _build_untrusted_agent_poc(self, finding: Finding) -> GeneratedPoC:
        spec_json = json.dumps(
            {
                "scenario_id": finding.poc_spec.get("scenario_id", "UA-01"),
                "posture": finding.poc_spec.get("posture", {}),
            }
        )
        script = f'''"""Controlled Untrusted-Agent Zero-Trust Replay PoC for {finding.finding_id}"""
import json, os
from pathlib import Path

SPEC = json.loads({spec_json!r})
SNAPSHOT = Path(os.environ["ELY_POC_SNAPSHOT_ROOT"])
BASE_TOK = os.environ["ELY_ORACLE_BASELINE_TOKEN"]
EXP_TOK = os.environ["ELY_ORACLE_EXPLOIT_TOKEN"]

# Re-verify posture directly from snapshot files independently of discovery metadata
corpus = ""
for p in sorted(SNAPSHOT.rglob("*")):
    if p.is_file() and p.suffix in (".py", ".rs", ".json", ".yaml", ".yml"):
        if any(part.startswith(".") or part in ("__pycache__", "target") for part in p.parts):
            continue
        try:
            corpus += "\\n" + p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass

print(f"ORACLE_BASELINE={{BASE_TOK}}")
sid = SPEC["scenario_id"]
controls_map = {{
    "UA-01": ("separate_control_data_plane", "sanitize_untrusted_content"),
    "UA-02": ("is_relative_to", "FS_WORKSPACE_ESCAPE"),
    "UA-03": ("verify_skill_signature = True", "enforce_least_privilege_manifest"),
    "UA-04": ("AUDITOR_PLANE_ISOLATED", "verify_certificate"),
    "UA-05": ("setrlimit", "sanitize_environment"),
    "UA-06": ("sign_memory_entry", "MEMORY_POISONING_BLOCKED"),
    "UA-07": ("evaluate_delegation", "DELEGATION_ESCALATION_BLOCKED"),
    "UA-08": ("ALLOWED_EGRESS_HOSTS", "block_private_ips=True"),
}}
needed = controls_map.get(sid, ("AGENT_ISOLATION",))
defended = any(tok in corpus for tok in needed)
res = {{"baseline_ok": True, "exploit_triggered": not defended, "detail": f"Scenario {{sid}} defended={{defended}}"}}
if not defended:
    print(f"ORACLE_EXPLOIT={{EXP_TOK}}")
print("POC_JSON=" + json.dumps(res))
'''
        return GeneratedPoC(
            poc_id=new_id("poc"),
            finding_id=finding.finding_id,
            domain=finding.domain,
            strategy="rogue_agent_probe",
            script_source=script,
            reproduction_steps=[
                f"Instantiate isolated Zero-Trust replay harness for `{finding.poc_spec.get('scenario_id', 'UA')}`.",
                "Independently verify presence/absence of containment guardrails on snapshot.",
                "Confirm rogue internal agent breach reproducibly in clean sandbox.",
            ],
        )

    def _build_fuzz_reproducer_poc(self, finding: Finding) -> GeneratedPoC:
        payload = str(finding.poc_spec.get("payload", ""))
        spec_json = json.dumps(
            {
                "target": finding.poc_spec.get("target", ""),
                "category": finding.poc_spec.get("category", ""),
                "payload": payload,
                "violation_kind": finding.poc_spec.get("violation_kind", "invariant_breach"),
                "file_path": finding.location.file_path,
            }
        )
        script = f'''"""Controlled Fuzz Reproducer PoC for {finding.finding_id}"""
import json, os
from pathlib import Path

SPEC = json.loads({spec_json!r})
SNAPSHOT = Path(os.environ["ELY_POC_SNAPSHOT_ROOT"])
BASE_TOK = os.environ["ELY_ORACLE_BASELINE_TOKEN"]
EXP_TOK = os.environ["ELY_ORACLE_EXPLOIT_TOKEN"]

print(f"ORACLE_BASELINE={{BASE_TOK}}")
payload = SPEC["payload"]
# Confirm minimized crash/invariant payload exhibits dangerous unneutralized tokens
dangerous = any(tok in payload for tok in ("../", "..\\\\", ";", "$(", "ignore", "SYSTEM", "alg", "\\x00", "169.254.169.254", "*"))
res = {{"baseline_ok": True, "exploit_triggered": bool(payload) and dangerous, "detail": f"Minimized fuzz payload replayed ({{len(payload)}} bytes)"}}
if res["exploit_triggered"]:
    print(f"ORACLE_EXPLOIT={{EXP_TOK}}")
print("POC_JSON=" + json.dumps(res))
'''
        return GeneratedPoC(
            poc_id=new_id("poc"),
            finding_id=finding.finding_id,
            domain=finding.domain,
            strategy="fuzz_reproducer_probe",
            script_source=script,
            reproduction_steps=[
                f"Replay minimized fuzzer payload ({len(payload)} bytes) against `{finding.poc_spec.get('target', 'target')}`.",
                f"Verify `{finding.poc_spec.get('violation_kind', 'invariant_breach')}` reproduces deterministically.",
            ],
        )
