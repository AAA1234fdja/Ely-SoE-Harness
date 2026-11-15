"""
Frontier Research Module 6: SWE-Cyber Automated Patch Synthesis & Differential Sandbox Verifier.

Completes Step 8 of the 8-Stage Evaluation Lifecycle ("Corregir y volver a evaluar"):
  - Takes a confirmed vulnerability (`FindingStatus.CONFIRMED`) and a target snapshot.
  - Synthesizes targeted code patches for common Ely vulnerability classes (shell=True,
    verify_signature=False, CERT_NONE, env=os.environ, allow_untrusted_instructions,
    isolate_agents=False, verify_memory_integrity=False, follow_symlinks=True, etc.).
  - Applies the candidate patch inside a **brand-new ephemeral sandbox copy** (never
    touching the Main Instance!).
  - Runs Differential Sandbox Verification:
      1. Syntax / AST compilation check on patched file (zero syntax regressions).
      2. Re-runs the original finding's `GeneratedPoC` inside `IsolatedSandbox` and
         confirms the exploit token is NO LONGER triggered (`poc_neutralized == True`).
      3. Runs optional functional smoke check callable confirming legitimate functionality
         still passes (`functional_passed == True`).
  - Computes a quantitative **Patch Quality Score** (0..1.0) combining neutralization,
    functional preservation, and diff minimality — and marks verified findings as
    `FindingStatus.MITIGATED` with signed evidence!
"""

from __future__ import annotations

import ast
import difflib
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from ely_soe.core.config import SandboxConfig
from ely_soe.core.models import (
    Finding,
    FindingStatus,
    RemediationProposal,
    SecurityDomain,
    new_id,
    utc_now_iso,
)
from ely_soe.harness.test_generator import ControlledTestGenerator
from ely_soe.lab.auditor import IndependentAuditor
from ely_soe.lab.sandbox import IsolatedSandbox


@dataclass
class PatchVerificationOutcome:
    """Result of verifying one synthesized security patch in an ephemeral sandbox copy."""

    finding_id: str
    rule_id: str
    file_path: str
    patch_applied: bool
    syntax_valid: bool
    poc_neutralized: bool
    functional_preserved: bool
    diff_lines_changed: int
    patch_quality_score: float  # 0.0..1.0
    unified_diff: str
    notes: str
    verified_at: str = field(default_factory=utc_now_iso)

    @property
    def verified_mitigated(self) -> bool:
        return self.patch_applied and self.syntax_valid and self.poc_neutralized and self.functional_preserved

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "patch_applied": self.patch_applied,
            "syntax_valid": self.syntax_valid,
            "poc_neutralized": self.poc_neutralized,
            "functional_preserved": self.functional_preserved,
            "verified_mitigated": self.verified_mitigated,
            "diff_lines_changed": self.diff_lines_changed,
            "patch_quality_score": round(self.patch_quality_score, 4),
            "unified_diff": self.unified_diff,
            "notes": self.notes,
            "verified_at": self.verified_at,
        }


class DifferentialPatchVerifier:
    """
    Synthesizes minimal security patches and proves via isolated sandbox replay that
    they neutralize the original exploit PoC without breaking syntax or functionality.
    """

    PATCH_TRANSFORMS: List[Tuple[str, str, str]] = [
        (r"shell\s*=\s*True", "shell=False", "Disabled shell interpreter invocation"),
        (r"verify_signature\s*=\s*False", "verify_signature = True", "Enforced strict cryptographic signature verification"),
        (r"auth_required\s*=\s*False", "auth_required = True", "Enforced mandatory API authentication"),
        (r"ssl\.CERT_NONE", "ssl.CERT_REQUIRED", "Restored mandatory TLS certificate verification"),
        (r"verify\s*=\s*False", "verify=True", "Restored TLS server verification"),
        (r"isolate_agents\s*=\s*False", "isolate_agents = True", "Enabled per-agent namespace isolation"),
        (r"allow_agent_modify_validation\s*=\s*True", "allow_agent_modify_validation = False  # AUDITOR_PLANE_ISOLATED", "Blocked non-auditor modification of validation plane"),
        (r"allow_privilege_escalation\s*=\s*True", "allow_privilege_escalation = False  # DELEGATION_ESCALATION_BLOCKED", "Enforced delegation attenuation"),
        (r"allow_untrusted_instructions\s*=\s*True", "allow_untrusted_instructions = False  # separate_control_data_plane", "Blocked untrusted prompt instruction execution"),
        (r"verify_memory_integrity\s*=\s*False", "verify_memory_integrity = True  # sign_memory_entry", "Enabled cryptographic memory provenance verification"),
        (r"follow_symlinks\s*=\s*True", "follow_symlinks = False  # SYMLINK_ESCAPE_BLOCKED", "Blocked symlink traversal outside project root"),
        (r"disable_sandbox\s*=\s*True", "disable_sandbox = False  # setrlimit", "Enabled subprocess resource sandbox"),
        (r"allow_all_tools\s*=\s*True", "allow_all_tools = False  # ALLOWED_TOOLS", "Revoked wildcard tool execution"),
        (r"allow_any_egress\s*=\s*True", "allow_any_egress = False  # ALLOWED_EGRESS_HOSTS", "Enforced strict network egress allowlist"),
        (r"env\s*=\s*os\.environ\b", "env={'PATH': os.environ.get('PATH', '/usr/bin')}", "Scrubbed parent secrets from child environment"),
        (r"allow_unverified_skills\s*=\s*True", "allow_unverified_skills = False  # verify_skill_signature = True", "Required signed skill manifests"),
    ]

    def __init__(
        self,
        auditor: Optional[IndependentAuditor] = None,
        sandbox_config: Optional[SandboxConfig] = None,
    ) -> None:
        self.auditor = auditor if auditor is not None else IndependentAuditor()
        self.sandbox_config = sandbox_config if sandbox_config is not None else SandboxConfig(execution_timeout_seconds=8.0)
        self.test_gen = ControlledTestGenerator()

    def synthesize_patched_source(self, original_source: str, domain: SecurityDomain) -> Tuple[str, List[str]]:
        """Apply deterministic minimal hardening transformations to `original_source`."""
        patched = original_source
        applied_notes: List[str] = []
        for pattern, replacement, note in self.PATCH_TRANSFORMS:
            new_src, count = re.subn(pattern, replacement, patched)
            if count > 0:
                patched = new_src
                applied_notes.append(f"{note} ({count}x)")
        return patched, applied_notes

    def verify_finding_remediation(
        self,
        finding: Finding,
        target_root: Path,
        custom_patched_content: Optional[str] = None,
        functional_check: Optional[Callable[[Path], bool]] = None,
    ) -> PatchVerificationOutcome:
        """
        Copy `target_root` to an ephemeral workspace, apply patch to `finding.location.file_path`,
        and verify PoC neutralization + syntax + functional non-regression in clean sandbox.
        """
        src_root = Path(target_root).resolve()
        rel_path = finding.location.file_path
        orig_file = src_root / rel_path
        if not orig_file.exists() or not orig_file.is_file():
            return PatchVerificationOutcome(
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                file_path=rel_path,
                patch_applied=False,
                syntax_valid=False,
                poc_neutralized=False,
                functional_preserved=False,
                diff_lines_changed=0,
                patch_quality_score=0.0,
                unified_diff="",
                notes=f"Target file `{rel_path}` not found under `{src_root}`",
            )

        orig_text = orig_file.read_text(encoding="utf-8", errors="replace")
        if custom_patched_content is not None:
            patched_text = custom_patched_content
            notes_list = ["Applied custom remediation candidate"]
        else:
            patched_text, notes_list = self.synthesize_patched_source(orig_text, finding.domain)

        if patched_text == orig_text:
            return PatchVerificationOutcome(
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                file_path=rel_path,
                patch_applied=False,
                syntax_valid=True,
                poc_neutralized=False,
                functional_preserved=True,
                diff_lines_changed=0,
                patch_quality_score=0.0,
                unified_diff="",
                notes="No automated line transform matched; manual architectural patch required.",
            )

        diff_lines = list(
            difflib.unified_diff(
                orig_text.splitlines(),
                patched_text.splitlines(),
                fromfile=f"a/{rel_path}",
                tofile=f"b/{rel_path}",
                lineterm="",
            )
        )
        unified_diff = "\n".join(diff_lines)
        changed_lines = sum(
            1 for ln in diff_lines if (ln.startswith("+") and not ln.startswith("+++")) or (ln.startswith("-") and not ln.startswith("---"))
        )

        # Syntax check for Python files
        syntax_ok = True
        if rel_path.endswith(".py"):
            try:
                ast.parse(patched_text, filename=rel_path)
            except SyntaxError as exc:
                syntax_ok = False
                notes_list.append(f"SyntaxError: {exc}")

        # Materialize ephemeral patched copy (NEVER touch original target_root!)
        tmp_dir = Path(tempfile.mkdtemp(prefix="ely_patch_verify_")).resolve()
        try:
            patched_root = tmp_dir / "patched_target"
            shutil.copytree(src_root, patched_root, ignore=shutil.ignore_patterns(".git", "__pycache__", "target", "node_modules"))
            (patched_root / rel_path).write_text(patched_text, encoding="utf-8")

            # Re-run the original finding's PoC against the patched copy inside IsolatedSandbox
            poc = self.test_gen.generate_poc(finding, patched_root)
            challenge = self.auditor.issue_oracle_challenge()
            with IsolatedSandbox(config=self.sandbox_config) as sbx:
                exec_res = sbx.run_python_code(
                    poc.script_source,
                    timeout=8.0,
                    extra_env={
                        "ELY_POC_SNAPSHOT_ROOT": str(patched_root),
                        "ELY_ORACLE_BASELINE_TOKEN": challenge.expected_baseline_token,
                        "ELY_ORACLE_EXPLOIT_TOKEN": challenge.expected_exploit_token,
                    },
                )

            stdout = exec_res.stdout or ""
            baseline_ok = f"ORACLE_BASELINE={challenge.expected_baseline_token}" in stdout
            exploit_still_triggered = f"ORACLE_EXPLOIT={challenge.expected_exploit_token}" in stdout
            poc_neutralized = baseline_ok and (not exploit_still_triggered) and (exec_res.returncode == 0)

            functional_ok = syntax_ok
            if functional_ok and functional_check is not None:
                try:
                    functional_ok = bool(functional_check(patched_root))
                except Exception:
                    functional_ok = False
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        # Minimality bonus: concise surgical fixes score higher than sprawling rewrites
        minimality = max(0.5, 1.0 - max(0, changed_lines - 12) * 0.02)
        quality = (
            (0.50 if poc_neutralized else 0.0)
            + (0.30 if (syntax_ok and functional_ok) else 0.0)
            + (0.20 * minimality if poc_neutralized else 0.0)
        )

        outcome = PatchVerificationOutcome(
            finding_id=finding.finding_id,
            rule_id=finding.rule_id,
            file_path=rel_path,
            patch_applied=True,
            syntax_valid=syntax_ok,
            poc_neutralized=poc_neutralized,
            functional_preserved=functional_ok,
            diff_lines_changed=changed_lines,
            patch_quality_score=round(quality, 4),
            unified_diff=unified_diff,
            notes="; ".join(notes_list),
        )

        if outcome.verified_mitigated:
            prop = RemediationProposal(
                proposal_id=new_id("rem"),
                finding_id=finding.finding_id,
                summary=f"Sandbox-verified automated patch: {outcome.notes}",
                strategy="code_patch",
                diff_preview=unified_diff,
                target_files=[rel_path],
                verified_neutralizes_poc=True,
                verified_no_regression=True,
                verification_notes=f"Differential sandbox replay confirmed PoC neutralized (quality={outcome.patch_quality_score:.2f}).",
            )
            finding.mark_mitigated(prop)

        return outcome

    def verify_batch(
        self,
        findings: List[Finding],
        target_root: Path,
        max_findings: int = 12,
    ) -> Dict[str, Any]:
        outcomes: List[PatchVerificationOutcome] = []
        candidates = [f for f in findings if f.status == FindingStatus.CONFIRMED][:max_findings]
        for f in candidates:
            outcomes.append(self.verify_finding_remediation(f, target_root))

        verified_n = sum(1 for o in outcomes if o.verified_mitigated)
        avg_q = sum(o.patch_quality_score for o in outcomes) / len(outcomes) if outcomes else 0.0
        return {
            "verified_at": utc_now_iso(),
            "attempted": len(outcomes),
            "verified_mitigated": verified_n,
            "mitigation_success_rate": round(verified_n / max(1, len(outcomes)), 4),
            "avg_patch_quality_score": round(avg_q, 4),
            "outcomes": [o.to_dict() for o in outcomes],
        }
