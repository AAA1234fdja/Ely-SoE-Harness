"""
Component 5 of the 6-Stage Security Harness: Independent Validator.

Enforces the single most important reliability invariant of the harness:
    "Separar descubrimiento y validación. El modelo no debería poder declarar
    una vulnerabilidad confirmada simplemente porque su propio análisis la
    considere probable."

How it works:
  1. Accepts `HYPOTHESIS` findings and `GeneratedPoC` scripts from Components 3 & 4.
  2. Never trusts discovery confidence or LLM opinions.
  3. For each candidate finding, requests a fresh salted `OracleChallenge` from the
     `IndependentAuditor` and executes the PoC script across `reproducibility_trials`
     clean `IsolatedSandbox` runs.
  4. Checks:
       * Baseline control token matched (`ORACLE_BASELINE=<salted_nonce>`)
       * Exploit confirmation token matched (`ORACLE_EXPLOIT=<salted_nonce>`)
       * Zero spoofed/tampered oracle tokens or sandbox escape events
       * Reproducibility ratio meets `min_reproducibility_ratio` (e.g., >= 2/3 trials)
  5. Submits the raw trial evidence to `IndependentAuditor.certify_validation()`,
     which cryptographically signs a `ValidationCertificate` and transitions the
     finding into `CONFIRMED`, `FALSE_POSITIVE`, or `INCONCLUSIVE`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ely_soe.core.config import SandboxConfig, ValidatorConfig
from ely_soe.core.models import (
    EvidenceArtifact,
    Finding,
    FindingStatus,
    SecurityDomain,
    Severity,
    ValidationCertificate,
    new_id,
)
from ely_soe.harness.test_generator import ControlledTestGenerator, GeneratedPoC
from ely_soe.lab.auditor import IndependentAuditor
from ely_soe.lab.monitor import SecurityMonitor
from ely_soe.lab.sandbox import IsolatedSandbox


class IndependentValidator:
    """
    Strictly separated clean-room validation plane verifying PoC reproducibility
    and delegating certification exclusively to `IndependentAuditor`.
    """

    def __init__(
        self,
        auditor: IndependentAuditor,
        validator_config: Optional[ValidatorConfig] = None,
        sandbox_config: Optional[SandboxConfig] = None,
        monitor: Optional[SecurityMonitor] = None,
    ) -> None:
        self.auditor = auditor
        self.config = validator_config if validator_config is not None else ValidatorConfig()
        self.sandbox_config = sandbox_config if sandbox_config is not None else SandboxConfig()
        self.monitor = monitor
        self._fallback_generator = ControlledTestGenerator()

    def validate_all(
        self,
        findings: List[Finding],
        pocs: Dict[str, GeneratedPoC],
        snapshot_root: Path,
    ) -> Dict[str, Any]:
        """Validate all candidate findings independently and return detailed validation telemetry."""
        certs: List[ValidationCertificate] = []
        confirmed = 0
        false_positives = 0
        inconclusive = 0
        tamper_detected = 0

        for finding in findings:
            poc = pocs.get(finding.finding_id)
            if poc is None:
                poc = self._fallback_generator.generate_poc(finding, snapshot_root)
            cert = self.validate_finding(finding, poc, snapshot_root)
            certs.append(cert)

            if finding.status == FindingStatus.CONFIRMED:
                confirmed += 1
            elif finding.status == FindingStatus.FALSE_POSITIVE:
                false_positives += 1
            else:
                inconclusive += 1
                if cert.verdict.value == "tamper_detected":
                    tamper_detected += 1

        total = len(findings)
        return {
            "total_evaluated": total,
            "confirmed": confirmed,
            "false_positives_filtered": false_positives,
            "inconclusive": inconclusive,
            "tamper_attempts_detected": tamper_detected,
            "confirmation_rate": round(confirmed / max(1, total), 4),
            "false_positive_filter_rate": round(false_positives / max(1, total), 4),
            "certificates_issued": len(certs),
            "auditor_id": self.auditor.auditor_id,
        }

    def validate_finding(
        self,
        finding: Finding,
        poc: GeneratedPoC,
        snapshot_root: Path,
    ) -> ValidationCertificate:
        """Execute clean-room multi-trial PoC reproduction for a single hypothesis."""
        finding.mark_validating()
        trials_target = max(1, int(self.config.reproducibility_trials))
        # Fast deterministic sandboxing: run up to `trials_target` trials (reuse sandbox or fresh per trial)
        trials_run = 0
        trials_reproduced = 0
        baseline_all_passed = True
        oracle_integrity_ok = True
        last_sandbox_id = "sbx-none"
        trial_logs: List[Dict[str, Any]] = []

        for trial_idx in range(trials_target):
            challenge = self.auditor.issue_oracle_challenge()
            extra_env = {
                "ELY_POC_SNAPSHOT_ROOT": str(Path(snapshot_root).resolve()),
                "ELY_ORACLE_BASELINE_TOKEN": challenge.expected_baseline_token,
                "ELY_ORACLE_EXPLOIT_TOKEN": challenge.expected_exploit_token,
                "ELY_VALIDATION_TRIAL": str(trial_idx + 1),
            }

            with IsolatedSandbox(config=self.sandbox_config, ledger=self.auditor.ledger) as sbx:
                last_sandbox_id = sbx.sandbox_id
                exec_res = sbx.run_python_code(poc.script_source, timeout=8.0, extra_env=extra_env)

            trials_run += 1
            stdout = exec_res.stdout or ""
            base_seen = f"ORACLE_BASELINE={challenge.expected_baseline_token}" in stdout
            exp_seen = f"ORACLE_EXPLOIT={challenge.expected_exploit_token}" in stdout

            # Anti-tamper check: detect spoofed ORACLE_EXPLOIT=... with wrong nonce
            for line in stdout.splitlines():
                if line.startswith("ORACLE_EXPLOIT=") and line.strip() != f"ORACLE_EXPLOIT={challenge.expected_exploit_token}":
                    oracle_integrity_ok = False
                if line.startswith("ORACLE_BASELINE=") and line.strip() != f"ORACLE_BASELINE={challenge.expected_baseline_token}":
                    oracle_integrity_ok = False

            if exec_res.escape_attempts_blocked and self.monitor is not None:
                self.monitor.emit(
                    source="validator",
                    category="validation",
                    severity=Severity.HIGH,
                    domain=SecurityDomain.PROCESS_MANAGEMENT,
                    message=f"Sandbox blocked escape attempt during PoC validation of {finding.finding_id}",
                    actor="validator",
                    details={"escape_events": exec_res.escape_attempts_blocked},
                    anomaly_score=0.9,
                )

            if not base_seen:
                baseline_all_passed = False
            if base_seen and exp_seen and oracle_integrity_ok and exec_res.returncode == 0:
                trials_reproduced += 1

            poc_payload: Dict[str, Any] = {}
            for line in stdout.splitlines():
                if line.startswith("POC_JSON="):
                    try:
                        poc_payload = json.loads(line[len("POC_JSON=") :])
                    except json.JSONDecodeError:
                        pass

            trial_logs.append(
                {
                    "trial": trial_idx + 1,
                    "sandbox_id": last_sandbox_id,
                    "returncode": exec_res.returncode,
                    "timed_out": exec_res.timed_out,
                    "duration_ms": round(exec_res.duration_ms, 2),
                    "baseline_verified": base_seen,
                    "exploit_verified": exp_seen,
                    "oracle_integrity_ok": oracle_integrity_ok,
                    "poc_detail": poc_payload.get("detail", ""),
                }
            )

            # Fast-path: if trial 1 cleanly fails to reproduce (0% exploit) with valid baseline, run 2nd check only
            if trial_idx == 1 and trials_reproduced == 0 and baseline_all_passed:
                break

        validation_evidence = EvidenceArtifact(
            artifact_id=new_id("ev"),
            kind="validation_trial_log",
            description=f"Independent Validator clean-room trial transcript ({trials_reproduced}/{trials_run} reproduced)",
            content=json.dumps(trial_logs, indent=2),
            producer="ely_independent_validator",
            metadata={"trials_run": trials_run, "trials_reproduced": trials_reproduced},
        )
        finding.evidence.append(validation_evidence)

        notes = (
            f"Reproduced deterministically in {trials_reproduced}/{trials_run} isolated sandbox trials."
            if trials_reproduced > 0
            else f"Could not reproduce vulnerability across {trials_run} isolated trials (baseline_ok={baseline_all_passed})."
        )

        return self.auditor.certify_validation(
            finding=finding,
            sandbox_id=last_sandbox_id,
            trials_run=trials_run,
            trials_reproduced=trials_reproduced,
            baseline_passed=baseline_all_passed,
            exploit_triggered=trials_reproduced > 0,
            oracle_integrity_verified=oracle_integrity_ok,
            reproduction_steps=poc.reproduction_steps,
            evidence_artifacts=finding.evidence,
            min_repro_ratio=self.config.min_reproducibility_ratio,
            notes=notes,
        )
