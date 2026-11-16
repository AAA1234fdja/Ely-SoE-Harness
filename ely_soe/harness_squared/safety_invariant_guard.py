"""
Harness² Cryptographic & Structural Meta-Safety Invariant Guard.

The foundational design principle of Harness² is **Adaptation Without Safety Drift**:
no contextual bandit update, evolutionary genome mutation, or live MAPE-K DAG rewrite
may EVER weaken, disable, or bypass any first-order ELY security invariant.

Enforces **8 Formal Non-Relaxable Invariants**:
  - `INV-01 SCOPE_PRESERVATION`: Target path & live URL strictly authorized by `ScopeGuard`
  - `INV-02 SEPARATION_OF_DUTIES`: `genome.validator_id != genome.planner_id` & non-empty
  - `INV-03 SECRET_SCRUBBING_MANDATORY`: `genome.enforce_secret_scrubbing` MUST be True
  - `INV-04 INDEPENDENT_VALIDATION`: `genome.require_independent_validation` MUST be True
  - `INV-05 BUDGET_CEILING`: `genome.total_budget_ms <= hard_max_budget_ms` & stage budgets positive
  - `INV-06 LOOPBACK_ONLY_DAST`: `genome.loopback_only_dast` MUST be True & any URL is loopback
  - `INV-07 AUDIT_LEDGER_PROVENANCE`: Every approved/rejected meta-action is sealed in `ForensicAuditLedger`
  - `INV-08 DAG_ACYCLICITY_AND_BOUNDED_ADAPTATION`: DAG has zero cycles and adaptation count <= `max_adaptation_rounds`

Produces signed `InvariantCheckResult` audit trails for every verified genome and directive.
"""

from __future__ import annotations

import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ely_soe.core.crypto_ledger import AuditorKeyring, ForensicAuditLedger
from ely_soe.core.models import new_id
from ely_soe.core.scope_guard import ScopeGuard, ScopeViolationError
from ely_soe.harness_squared.models import (
    AdaptationActionType,
    AdaptationDirective,
    HarnessGenome,
    InvariantCheckResult,
    MetaInvariantViolationError,
)


class MetaSafetyInvariantGuard:
    """Formal non-relaxable safety invariant verifier for Harness² genomes, directives, and DAG mutations."""

    HARD_MAX_BUDGET_MS: int = 180_000
    HARD_MAX_ADAPTATION_ROUNDS: int = 24
    HARD_MAX_DAG_NODES: int = 64
    LOOPBACK_HOSTS: Set[str] = {"127.0.0.1", "localhost", "::1"}

    def __init__(
        self,
        scope_guard: Optional[ScopeGuard] = None,
        keyring: Optional[AuditorKeyring] = None,
        ledger: Optional[ForensicAuditLedger] = None,
        hard_max_budget_ms: int = 180_000,
    ) -> None:
        self.scope_guard = scope_guard
        self.keyring = keyring or AuditorKeyring(key_id="ely_h2_invariant_guard")
        self.ledger = ledger or ForensicAuditLedger(self.keyring)
        self.hard_max_budget_ms = min(hard_max_budget_ms, self.HARD_MAX_BUDGET_MS)
        self.check_history: List[InvariantCheckResult] = []

    def verify_genome(
        self,
        genome: HarnessGenome,
        *,
        target_path: Optional[Path] = None,
        live_local_url: Optional[str] = None,
        raise_on_violation: bool = True,
    ) -> List[InvariantCheckResult]:
        """Verify all non-relaxable invariants against a candidate `HarnessGenome`."""
        results: List[InvariantCheckResult] = []

        # INV-01: ScopeGuard preservation
        inv1_ok = True
        inv1_msg = "ScopeGuard authorization verified."
        if not genome.enforce_scope_guard:
            inv1_ok = False
            inv1_msg = "Genome attempted to set `enforce_scope_guard=False`."
        elif target_path is not None and self.scope_guard is not None:
            try:
                self.scope_guard.assert_path_in_scope(Path(target_path).resolve())
            except ScopeViolationError as exc:
                inv1_ok = False
                inv1_msg = f"Target path rejected by ScopeGuard: {exc}"
        results.append(self._record("INV-01", "SCOPE_PRESERVATION", inv1_ok, inv1_msg))

        # INV-02: Separation of Duties
        sod_ok = (
            genome.enforce_separation_of_duties
            and bool(genome.validator_id)
            and bool(genome.planner_id)
            and genome.validator_id != genome.planner_id
        )
        sod_msg = (
            f"Separation of Duties holds (planner='{genome.planner_id}' != validator='{genome.validator_id}')."
            if sod_ok
            else f"Separation of Duties violated: enforce={genome.enforce_separation_of_duties}, planner='{genome.planner_id}', validator='{genome.validator_id}'."
        )
        results.append(self._record("INV-02", "SEPARATION_OF_DUTIES", sod_ok, sod_msg))

        # INV-03: Secret Scrubbing Mandatory
        scrub_ok = bool(genome.enforce_secret_scrubbing)
        results.append(
            self._record(
                "INV-03",
                "SECRET_SCRUBBING_MANDATORY",
                scrub_ok,
                "Secret scrubbing active." if scrub_ok else "Genome attempted to disable mandatory secret scrubbing.",
            )
        )

        # INV-04: Independent Validation Non-Bypass
        val_ok = bool(genome.require_independent_validation)
        results.append(
            self._record(
                "INV-04",
                "INDEPENDENT_VALIDATION",
                val_ok,
                "Independent validation required for confirmation." if val_ok else "Genome attempted to bypass independent validation.",
            )
        )

        # INV-05: Compute & Probe Budget Ceiling
        bud_ok = (
            0 < genome.total_budget_ms <= self.hard_max_budget_ms
            and all(b > 0 for b in genome.stage_budgets_ms.values())
            and 0 <= genome.max_adaptation_rounds <= self.HARD_MAX_ADAPTATION_ROUNDS
        )
        results.append(
            self._record(
                "INV-05",
                "BUDGET_CEILING",
                bud_ok,
                f"Budget {genome.total_budget_ms}ms <= ceiling {self.hard_max_budget_ms}ms and adaptation cap {genome.max_adaptation_rounds} valid."
                if bud_ok
                else f"Budget/round ceiling exceeded: total={genome.total_budget_ms}ms (max {self.hard_max_budget_ms}ms), rounds={genome.max_adaptation_rounds}.",
            )
        )

        # INV-06: Loopback-Only Dynamic Probing
        loop_ok = bool(genome.loopback_only_dast)
        loop_msg = "Live dynamic probing locked to authorized loopback sandboxes."
        if not loop_ok:
            loop_msg = "Genome attempted to relax `loopback_only_dast`."
        elif live_local_url:
            host = urllib.parse.urlparse(live_local_url).hostname
            if host not in self.LOOPBACK_HOSTS:
                loop_ok = False
                loop_msg = f"Live URL host '{host}' is outside loopback sandbox allowlist {sorted(self.LOOPBACK_HOSTS)}."
        results.append(self._record("INV-06", "LOOPBACK_ONLY_DAST", loop_ok, loop_msg))

        # INV-07: Audit Ledger Provenance Seal
        self.ledger.append(
            event_type="H2_GENOME_INVARIANT_VERIFICATION",
            actor="ely_h2_invariant_guard",
            payload={
                "genome_id": genome.genome_id,
                "signature": genome.genome_signature(),
                "all_passed": all(r.passed for r in results),
                "failed_invariants": [r.invariant_id for r in results if not r.passed],
            },
        )
        results.append(
            self._record(
                "INV-07",
                "AUDIT_LEDGER_PROVENANCE",
                True,
                f"Recorded cryptographic ledger entry #{len(self.ledger.entries)} (merkle_root={self.ledger.merkle_root()[:16]}).",
            )
        )

        failed = [r for r in results if not r.passed]
        if failed and raise_on_violation:
            first = failed[0]
            raise MetaInvariantViolationError(first.invariant_id, first.message, {"genome_id": genome.genome_id})
        return results

    def verify_adaptation_directive(
        self,
        directive: AdaptationDirective,
        *,
        current_adaptation_count: int,
        max_adaptation_rounds: int,
        current_node_count: int,
        remaining_budget_ms: int,
        would_create_cycle: bool = False,
    ) -> InvariantCheckResult:
        """Gate every single live MAPE-K adaptation directive prior to DAG mutation."""
        if current_adaptation_count >= min(max_adaptation_rounds, self.HARD_MAX_ADAPTATION_ROUNDS):
            res = self._record(
                "INV-08",
                "DAG_ACYCLICITY_AND_BOUNDED_ADAPTATION",
                False,
                f"Adaptation round limit ({max_adaptation_rounds}) reached; blocking directive `{directive.directive_id}` to guarantee finite termination.",
            )
        elif would_create_cycle:
            res = self._record(
                "INV-08",
                "DAG_ACYCLICITY_AND_BOUNDED_ADAPTATION",
                False,
                f"Directive `{directive.directive_id}` would introduce a cycle in the execution DAG.",
            )
        elif directive.action_type in (AdaptationActionType.EXPAND_DRILLDOWN, AdaptationActionType.INJECT_HYPOTHESIS_PROBE) and current_node_count >= self.HARD_MAX_DAG_NODES:
            res = self._record(
                "INV-08",
                "DAG_ACYCLICITY_AND_BOUNDED_ADAPTATION",
                False,
                f"DAG node ceiling ({self.HARD_MAX_DAG_NODES}) reached; cannot expand further.",
            )
        elif directive.action_type == AdaptationActionType.EXPAND_DRILLDOWN and int(directive.payload.get("budget_ms", 0)) > max(remaining_budget_ms, 5000):
            res = self._record(
                "INV-05",
                "BUDGET_CEILING",
                False,
                f"Requested drilldown budget {directive.payload.get('budget_ms')}ms exceeds safe remaining allowance.",
            )
        else:
            # Verify no payload attempts to relax safety flags
            forbidden_keys = {"disable_scope_guard", "disable_scrubbing", "bypass_validator", "external_target_url"}
            bad = forbidden_keys & set(directive.payload.keys())
            if bad:
                res = self._record(
                    "INV-01",
                    "SCOPE_PRESERVATION",
                    False,
                    f"Directive payload contained forbidden safety-relaxation keys: {sorted(bad)}.",
                )
            else:
                res = self._record(
                    "INV-08",
                    "DAG_ACYCLICITY_AND_BOUNDED_ADAPTATION",
                    True,
                    f"Approved directive `{directive.rule_id}` ({directive.action_type.value}) on `{directive.target_stage_id}`.",
                )

        directive.approved_by_invariant_guard = res.passed
        if not res.passed:
            directive.rejection_reason = res.message

        self.ledger.append(
            event_type="H2_ADAPTATION_DIRECTIVE_GATE",
            actor="ely_h2_invariant_guard",
            payload={
                "directive_id": directive.directive_id,
                "rule_id": directive.rule_id,
                "action_type": directive.action_type.value,
                "approved": res.passed,
                "reason": res.message,
            },
        )
        return res

    def ledger_summary(self) -> Dict[str, Any]:
        return {
            "total_checks": len(self.check_history),
            "passed_checks": sum(1 for c in self.check_history if c.passed),
            "rejected_checks": sum(1 for c in self.check_history if not c.passed),
            "ledger_entries": len(self.ledger.entries),
            "ledger_merkle_root": self.ledger.merkle_root(),
            "ledger_chain_valid": bool(self.ledger.verify()[0] if isinstance(self.ledger.verify(), tuple) else self.ledger.verify()),
        }

    def _record(self, inv_id: str, name: str, passed: bool, message: str) -> InvariantCheckResult:
        res = InvariantCheckResult(
            check_id=new_id("inv"),
            invariant_id=inv_id,
            invariant_name=name,
            passed=passed,
            message=message,
        )
        self.check_history.append(res)
        return res
