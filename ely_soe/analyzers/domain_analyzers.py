"""
Deep Specialized Security Analyzers for Core Agentic & API Domains (Domains 1–5):
  1. Agent Isolation (`agent_isolation`)
  2. Tool Execution (`tool_execution`)
  3. Memory Security (`memory`)
  4. Prompt Injection (`prompt_injection`)
  5. API Security (`api_security`)

Combines Python AST inspection + multi-language structural rules (Python/TS/JS/YAML/JSON)
with context-aware false-positive suppression so hardened Ely builds score cleanly while
vulnerable code produces precise, high-signal `HYPOTHESIS` findings ready for PoC
generation and independent validation.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
class StaticRule:
    rule_id: str
    domain: SecurityDomain
    title: str
    severity: Severity
    cwe: str
    pattern: str
    description: str
    impact: str
    suppress_if_line_or_file_contains: Tuple[str, ...] = ()
    extensions: Tuple[str, ...] = (".py", ".ts", ".js", ".json", ".yaml", ".yml")


CORE_AGENTIC_RULES: List[StaticRule] = [
    # --- Domain 1: Agent Isolation ---
    StaticRule(
        rule_id="AGT-ISO-001",
        domain=SecurityDomain.AGENT_ISOLATION,
        title="Agent Isolation Explicitly Disabled or Shared Mutable Global Agent State",
        severity=Severity.CRITICAL,
        cwe="CWE-668",
        pattern=r"(?:isolate_agents\s*=\s*False|shared_agent_state\s*=\s*\{|GLOBAL_AGENT_MEMORY\s*=\s*\{)",
        description="Agents share mutable global state or disable namespace isolation, letting one compromised agent read or poison another agent's context.",
        impact="Cross-agent credential theft, workspace tampering, and lateral movement across Ely agents",
    ),
    StaticRule(
        rule_id="AGT-ISO-002",
        domain=SecurityDomain.AGENT_ISOLATION,
        title="Unauthenticated Cross-Agent State Access Without Caller Verification",
        severity=Severity.HIGH,
        cwe="CWE-284",
        pattern=r"def\s+(?:get_agent_state|read_agent_context|switch_agent_session)\s*\(\s*(?:self\s*,\s*)?agent_id\b",
        description="State accessor accepts an arbitrary `agent_id` without authenticating the caller principal or checking namespace ownership.",
        impact="Rogue agent impersonates peer agents and extracts private session data",
        suppress_if_line_or_file_contains=("verify_agent_namespace", "caller_id", "AGENT_ISOLATION"),
    ),
    StaticRule(
        rule_id="AGT-ISO-003",
        domain=SecurityDomain.AGENT_ISOLATION,
        title="Evaluated Agent Permitted to Modify Validation or Audit Results",
        severity=Severity.CRITICAL,
        cwe="CWE-269",
        pattern=r"(?:allow_agent_modify_validation\s*=\s*True|can_modify_validation\s*=\s*True|validation_results\[.*\]\s*=)",
        description="Evaluated agents or untrusted roles hold write access to validation results, violating zero-trust separation between agents and the Auditor plane.",
        impact="Compromised agent suppresses vulnerability findings or forges passing maturity scores",
        suppress_if_line_or_file_contains=('role="auditor"', "role == 'auditor'", "AUDITOR_PLANE_ISOLATED"),
    ),
    StaticRule(
        rule_id="AGT-ISO-004",
        domain=SecurityDomain.AGENT_ISOLATION,
        title="Unrestricted Multi-Agent Delegation Allowing Privilege Amplification",
        severity=Severity.HIGH,
        cwe="CWE-266",
        pattern=r"(?:allow_privilege_escalation\s*=\s*True|delegate_all_permissions\s*=\s*True|inherit_admin_caps\s*=\s*True)",
        description="Delegation helper transfers full or elevated capabilities without capability attenuation or peer allowlist checks.",
        impact="Confused-deputy privilege escalation across Ely agent workflows",
    ),

    # --- Domain 2: Tool Execution ---
    StaticRule(
        rule_id="TOOL-EXEC-001",
        domain=SecurityDomain.TOOL_EXECUTION,
        title="Shell Injection Risk via subprocess(..., shell=True) or os.system()",
        severity=Severity.CRITICAL,
        cwe="CWE-78",
        pattern=r"(?:subprocess\.(?:run|Popen|call|check_output|check_call)\([^)]*shell\s*=\s*True|\bos\.system\s*\(|\bos\.popen\s*\()",
        description="Tool executes OS commands through a shell interpreter (`shell=True` / `os.system`), enabling shell metacharacter injection.",
        impact="Arbitrary OS command execution triggered by prompt injection or untrusted tool parameters",
    ),
    StaticRule(
        rule_id="TOOL-EXEC-002",
        domain=SecurityDomain.TOOL_EXECUTION,
        title="Excessive Wildcard Tool Permissions Granted to Agent/Tool Registry",
        severity=Severity.HIGH,
        cwe="CWE-250",
        pattern=r"(?:allow_all_tools\s*=\s*True|allowed_tools\s*=\s*\[\s*['\"]\*['\"]\s*\]|tool_permissions\s*=\s*['\"]\*['\"])",
        description="Agent or tool dispatcher grants wildcard access to all tools, violating least privilege.",
        impact="Low-privilege agents (e.g., researchers) can invoke destructive shell/filesystem tools",
    ),
    StaticRule(
        rule_id="TOOL-EXEC-003",
        domain=SecurityDomain.TOOL_EXECUTION,
        title="Dynamic Code Execution (eval/exec) Inside Tool Handler",
        severity=Severity.CRITICAL,
        cwe="CWE-94",
        pattern=r"\b(?:eval|exec)\s*\([^)]*(?:arg|cmd|code|expr|input|payload|script|tool)",
        description="Tool passes dynamic/agent-supplied strings directly to `eval()` or `exec()`.",
        impact="Immediate remote code execution breaking out of tool schemas",
    ),
    StaticRule(
        rule_id="TOOL-EXEC-004",
        domain=SecurityDomain.TOOL_EXECUTION,
        title="Unverified Runtime Tool Registration / Tool Shadowing Exposure",
        severity=Severity.HIGH,
        cwe="CWE-494",
        pattern=r"(?:allow_tool_overwrite\s*=\s*True|tools_registry\[[^\]]+\]\s*=\s*.*(?:skill|plugin|dynamic))",
        description="Third-party skills can overwrite or shadow built-in core tools without immutability checks.",
        impact="Rug-pull / tool-shadowing attack intercepts legitimate agent tool invocations",
        suppress_if_line_or_file_contains=("verify_skill_signature", "FROZEN_CORE_TOOLS"),
    ),

    # --- Domain 3: Memory Security ---
    StaticRule(
        rule_id="MEM-SEC-001",
        domain=SecurityDomain.MEMORY,
        title="Memory Integrity Verification Disabled or Unverified Memory Persistence",
        severity=Severity.HIGH,
        cwe="CWE-345",
        pattern=r"(?:verify_memory_integrity\s*=\s*False|sign_memory\s*=\s*False|trust_all_memory\s*=\s*True)",
        description="Agent long-term memory/RAG store disables cryptographic provenance or integrity checks.",
        impact="Persistent memory poisoning survives across sessions and silently alters agent behavior",
    ),
    StaticRule(
        rule_id="MEM-SEC-002",
        domain=SecurityDomain.MEMORY,
        title="Unsafe Pickle Deserialization of Persistent Agent Memory",
        severity=Severity.CRITICAL,
        cwe="CWE-502",
        pattern=r"\bpickle\.(?:loads|load)\s*\(",
        description="Agent memory/session state is deserialized via `pickle`, allowing arbitrary code execution on memory tampering.",
        impact="Full RCE when a compromised agent or attacker alters a persisted memory file",
    ),
    StaticRule(
        rule_id="MEM-SEC-003",
        domain=SecurityDomain.MEMORY,
        title="Cross-Session Shared Memory Append Without Provenance or Injection Screening",
        severity=Severity.HIGH,
        cwe="CWE-94",
        pattern=r"(?:shared_memory\.append\s*\(|vector_store\.upsert\s*\(|memory_db\.insert\s*\()",
        description="External or agent outputs are stored in shared persistent memory without ProvenanceTag binding or prompt-injection filtering.",
        impact="Sleeper prompt-injection payload planted in RAG/episodic memory hijacks future agents",
        suppress_if_line_or_file_contains=("ProvenanceTag", "sign_memory_entry", "MEMORY_POISONING_BLOCKED"),
    ),

    # --- Domain 4: Prompt Injection ---
    StaticRule(
        rule_id="PI-DEF-001",
        domain=SecurityDomain.PROMPT_INJECTION,
        title="Direct Mixing of Untrusted External Content into Privileged System Prompt",
        severity=Severity.CRITICAL,
        cwe="CWE-74",
        pattern=r"(?:allow_untrusted_instructions\s*=\s*True|system_prompt\s*\+=\s*|f['\"][^'\"]*SYSTEM[^'\"]*\{[^}]*(?:web|page|doc|external|content|html|tool))",
        description="External untrusted content is interpolated directly into the privileged system/control prompt without CaMeL control/data separation.",
        impact="Zero-click indirect prompt injection hijacks agent goals and triggers privileged tools",
    ),
    StaticRule(
        rule_id="PI-DEF-002",
        domain=SecurityDomain.PROMPT_INJECTION,
        title="Agent Tool Loop Automatically Executes Instructions Parsed From External Data",
        severity=Severity.CRITICAL,
        cwe="CWE-77",
        pattern=r"(?:auto_execute_extracted_commands\s*=\s*True|execute_from_webpage\s*=\s*True|trust_tool_output_as_instructions\s*=\s*True)",
        description="Agent runtime treats tool outputs or external web pages as executable control instructions.",
        impact="Arbitrary tool hijacking from any scraped web page, email, or third-party API response",
    ),
    StaticRule(
        rule_id="PI-DEF-003",
        domain=SecurityDomain.PROMPT_INJECTION,
        title="Naive Substring Blocklist Without Unicode Normalization or Control-Plane Separation",
        severity=Severity.MEDIUM,
        cwe="CWE-184",
        pattern=r"if\s+['\"]ignore previous instructions['\"]\s+in\s+",
        description="Prompt injection defense relies solely on a naive English substring check trivially bypassed via homoglyphs, zero-width chars, or base64.",
        impact="Adaptive Red Team bypasses prompt defense in 1–2 mutation turns",
        suppress_if_line_or_file_contains=("unicodedata.normalize", "separate_control_data_plane", "TrustLevel"),
    ),

    # --- Domain 5: API Security ---
    StaticRule(
        rule_id="API-AUTH-001",
        domain=SecurityDomain.API_SECURITY,
        title="JWT Signature Verification Disabled or alg='none' Accepted",
        severity=Severity.CRITICAL,
        cwe="CWE-347",
        pattern=r"(?:verify_signature\s*[:=]\s*False|algorithms\s*=\s*\[[^\]]*['\"]none['\"]|auth_required\s*=\s*False)",
        description="API accepts unverified JWTs or disables authentication on agent control endpoints.",
        impact="Complete authentication bypass allowing attackers to forge admin/auditor identities",
    ),
    StaticRule(
        rule_id="API-AUTH-002",
        domain=SecurityDomain.API_SECURITY,
        title="Hardcoded Administrative / API Secret Token in Source Code",
        severity=Severity.HIGH,
        cwe="CWE-798",
        pattern=r"(?:ADMIN_TOKEN|API_SECRET|JWT_SECRET|MASTER_KEY)\s*=\s*['\"][A-Za-z0-9_\-]{8,}['\"]",
        description="Hardcoded static secret used for API authentication or token signing.",
        impact="Anyone with repository read access can forge valid administrative API tokens",
        suppress_if_line_or_file_contains=("os.environ", "ELY_LAB_REDACTED", "example"),
    ),
    StaticRule(
        rule_id="API-AUTHZ-003",
        domain=SecurityDomain.API_SECURITY,
        title="Wildcard CORS Policy Exposed on Control API",
        severity=Severity.MEDIUM,
        cwe="CWE-942",
        pattern=r"Access-Control-Allow-Origin['\"]\s*[:,]\s*['\"]\*['\"]",
        description="API responds with wildcard `Access-Control-Allow-Origin: *` alongside privileged endpoints.",
        impact="Cross-origin browser requests from malicious websites can interact with local Ely API",
        suppress_if_line_or_file_contains=("ALLOWED_ORIGINS", "strict_cors"),
    ),
    StaticRule(
        rule_id="API-AUTH-004",
        domain=SecurityDomain.API_SECURITY,
        title="Timing-Unsafe Token Comparison Using '==' Instead of hmac.compare_digest",
        severity=Severity.MEDIUM,
        cwe="CWE-208",
        pattern=r"if\s+(?:token|api_key|auth_token|signature|provided_secret)\s*==\s*",
        description="Authentication token checked with standard equality operator `==`, leaking timing side-channel.",
        impact="Timing oracle facilitates secret recovery on high-throughput endpoints",
        suppress_if_line_or_file_contains=("hmac.compare_digest",),
    ),
    StaticRule(
        rule_id="API-SQLI-005",
        domain=SecurityDomain.API_SECURITY,
        title="Unsanitized String Formatting Inside SQL Query Execution",
        severity=Severity.HIGH,
        cwe="CWE-89",
        pattern=r"\.execute\s*\(\s*f['\"].*(?:SELECT|INSERT|UPDATE|DELETE).*\{",
        description="SQL statement constructed via f-string interpolation instead of bound parameters.",
        impact="SQL injection exposing or corrupting Ely session, agent, and audit records",
    ),
]


class CoreAgenticDomainAnalyzer:
    """
    Executes deep static & AST checks across Domains 1–5 (Agent Isolation, Tool Execution,
    Memory Security, Prompt Injection, API Security). Emits HYPOTHESIS findings only.
    """

    def analyze_directory(
        self,
        snapshot_root: Path,
        domains: Optional[List[SecurityDomain]] = None,
    ) -> List[Finding]:
        target_domains = set(domains) if domains else {
            SecurityDomain.AGENT_ISOLATION,
            SecurityDomain.TOOL_EXECUTION,
            SecurityDomain.MEMORY,
            SecurityDomain.PROMPT_INJECTION,
            SecurityDomain.API_SECURITY,
        }
        findings: List[Finding] = []
        root = Path(snapshot_root).resolve()

        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if any(part.startswith(".") or part in ("__pycache__", "node_modules", "target", ".venv", "tests") for part in path.relative_to(root).parts):
                continue
            ext = path.suffix.lower()
            rel = path.relative_to(root).as_posix()
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.splitlines()
            for rule in CORE_AGENTIC_RULES:
                if rule.domain not in target_domains:
                    continue
                if ext not in rule.extensions:
                    continue
                if rule.suppress_if_line_or_file_contains and any(
                    sup in content for sup in rule.suppress_if_line_or_file_contains
                ):
                    continue
                compiled = re.compile(rule.pattern)
                for idx, line in enumerate(lines, start=1):
                    stripped = line.strip()
                    if stripped.startswith(("#", "//", "/*", "*")):
                        continue
                    if compiled.search(line):
                        findings.append(self._build_finding(rule, rel, idx, stripped))
                        break  # one finding per rule per file to prevent spam

            # AST-level check for unauthenticated API handler methods lacking authz checks
            if ext == ".py" and SecurityDomain.API_SECURITY in target_domains:
                findings.extend(self._ast_check_api_handlers(rel, content, lines))

        return findings

    def _ast_check_api_handlers(self, rel_path: str, content: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(content, filename=rel_path)
        except SyntaxError:
            return findings

        auth_keywords = ("verify_jwt", "authenticate", "require_auth", "check_resource_owner", "authorize", "hmac.compare_digest")
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                low = node.name.lower()
                if any(low.startswith(p) for p in ("api_delete_", "api_admin_", "handle_agent_secret", "handle_run_tool")):
                    body_src = "\n".join(lines[node.lineno - 1 : getattr(node, "end_lineno", node.lineno)])
                    if not any(ak in body_src for ak in auth_keywords):
                        findings.append(
                            Finding(
                                finding_id=new_id("fnd"),
                                title=f"[API Security] Privileged Endpoint '{node.name}' Missing AuthN/AuthZ Verification",
                                description=(
                                    f"Privileged API handler `{node.name}` in `{rel_path}` does not invoke any "
                                    "recognized authentication or resource-ownership authorization guard (BFLA/BOLA risk)."
                                ),
                                domain=SecurityDomain.API_SECURITY,
                                severity=Severity.HIGH,
                                rule_id="API-BFLA-006",
                                discovered_by="ely_core_domain_analyzer",
                                location=CodeLocation(
                                    file_path=rel_path,
                                    line_start=node.lineno,
                                    symbol=node.name,
                                    snippet=lines[node.lineno - 1].strip()[:160],
                                    language="python",
                                ),
                                status=FindingStatus.HYPOTHESIS,
                                confidence=0.80,
                                cwe_ids=["CWE-862", "CWE-639"],
                                attack_vector=f"Direct unauthenticated/cross-tenant request to `{node.name}`",
                                impact="Broken Function/Object Level Authorization (BFLA/BOLA) on Ely API",
                                poc_spec={
                                    "kind": "static_rule",
                                    "rule_id": "API-BFLA-006",
                                    "target_file": rel_path,
                                    "target_line": node.lineno,
                                    "symbol": node.name,
                                },
                                evidence=[
                                    EvidenceArtifact(
                                        artifact_id=new_id("ev"),
                                        kind="ast_audit",
                                        description=f"Missing auth guard in {node.name}",
                                        content=body_src[:400],
                                        producer="ely_core_domain_analyzer",
                                    )
                                ],
                                tags=["api_security", "bfla", "bola"],
                            )
                        )
        return findings

    @staticmethod
    def _build_finding(rule: StaticRule, rel_path: str, line_no: int, snippet: str) -> Finding:
        ext = Path(rel_path).suffix.lower()
        lang = {".py": "python", ".ts": "typescript", ".js": "javascript", ".json": "json"}.get(ext, "text")
        return Finding(
            finding_id=new_id("fnd"),
            title=f"[{rule.domain.display_name}] {rule.title}",
            description=rule.description,
            domain=rule.domain,
            severity=rule.severity,
            rule_id=rule.rule_id,
            discovered_by="ely_core_domain_analyzer",
            location=CodeLocation(
                file_path=rel_path,
                line_start=line_no,
                snippet=snippet[:160],
                language=lang,
            ),
            status=FindingStatus.HYPOTHESIS,
            confidence=0.85,
            cwe_ids=[rule.cwe],
            attack_vector=f"Exploiting `{rule.rule_id}` in `{rel_path}:{line_no}`",
            impact=rule.impact,
            poc_spec={
                "kind": "static_rule",
                "rule_id": rule.rule_id,
                "pattern": rule.pattern,
                "target_file": rel_path,
                "target_line": line_no,
            },
            evidence=[
                EvidenceArtifact(
                    artifact_id=new_id("ev"),
                    kind="static_rule_match",
                    description=f"Matched rule {rule.rule_id} at {rel_path}:{line_no}",
                    content=f"{rel_path}:{line_no}\n{snippet}",
                    producer="ely_core_domain_analyzer",
                )
            ],
            tags=[rule.domain.value, rule.rule_id.lower(), rule.cwe.lower()],
        )
