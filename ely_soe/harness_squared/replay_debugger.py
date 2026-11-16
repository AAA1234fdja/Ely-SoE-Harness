"""
Harness² Deterministic Time-Travel Execution Replay & Counterfactual What-If Debugger.

Reconstructs full tick-by-tick state transition timelines from `HarnessSquaredEngine`
run reports, supports exact time-travel snapshots at any tick `0..T`, and executes
offline counterfactual what-if ablations (disabling MAPE-K rules, disabling stages, or
capping latency) to detect gate-flip sensitivity!
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set

from ely_soe.core.models import utc_now_iso


@dataclass
class ReplayEventTick:
    tick: int
    event_type: str  # STAGE_EXECUTED | ADAPTATION_APPLIED | HYPOTHESIS_RESOLVED | GATE_DECIDED
    actor: str
    summary: str
    elapsed_ms_cumulative: float
    findings_cumulative: int
    criticals_cumulative: int
    safety_preserved: bool
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tick": self.tick,
            "event_type": self.event_type,
            "actor": self.actor,
            "summary": self.summary,
            "elapsed_ms_cumulative": round(self.elapsed_ms_cumulative, 2),
            "findings_cumulative": self.findings_cumulative,
            "criticals_cumulative": self.criticals_cumulative,
            "safety_preserved": self.safety_preserved,
            "metadata": dict(self.metadata),
        }


@dataclass
class CounterfactualSimulationResult:
    run_id: str
    simulated_at: str
    scenario_description: str
    disabled_rules: List[str]
    disabled_stages: List[str]
    simulated_latency_cap_ms: Optional[float]
    original_findings_estimate: int
    counterfactual_findings_estimate: int
    findings_lost: int
    original_criticals_estimate: int
    counterfactual_criticals_estimate: int
    criticals_lost: int
    original_gate_verdict: str
    counterfactual_gate_verdict: str
    gate_decision_flipped: bool
    dropped_stages: List[str]
    risk_impact_verdict: str  # CATASTROPHIC_GATE_FLIP | HIGH_RECALL_LOSS | MODERATE_LOSS | BENIGN

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "simulated_at": self.simulated_at,
            "scenario_description": self.scenario_description,
            "disabled_rules": list(self.disabled_rules),
            "disabled_stages": list(self.disabled_stages),
            "simulated_latency_cap_ms": self.simulated_latency_cap_ms,
            "original_findings_estimate": self.original_findings_estimate,
            "counterfactual_findings_estimate": self.counterfactual_findings_estimate,
            "findings_lost": self.findings_lost,
            "original_criticals_estimate": self.original_criticals_estimate,
            "counterfactual_criticals_estimate": self.counterfactual_criticals_estimate,
            "criticals_lost": self.criticals_lost,
            "original_gate_verdict": self.original_gate_verdict,
            "counterfactual_gate_verdict": self.counterfactual_gate_verdict,
            "gate_decision_flipped": self.gate_decision_flipped,
            "dropped_stages": list(self.dropped_stages),
            "risk_impact_verdict": self.risk_impact_verdict,
        }


class HarnessReplayDebugger:
    """Builds time-travel execution tapes and runs counterfactual what-if ablations."""

    def build_replay_tape(self, run_report: Dict[str, Any]) -> List[ReplayEventTick]:
        ticks: List[ReplayEventTick] = []
        stage_records = list(run_report.get("telemetry", {}).get("stage_records", []))
        directives = list(run_report.get("mapek_adaptation", {}).get("directives", []))
        hyps = list(run_report.get("hypotheses", {}).get("hypotheses", []))
        ledger_valid = bool(run_report.get("safety_invariants", {}).get("guard_ledger_summary", {}).get("ledger_chain_valid", True))

        cum_ms = 0.0
        cum_findings = 0
        cum_crits = 0

        for rec in stage_records:
            sid = str(rec.get("stage_id", ""))
            adapter = str(rec.get("adapter_name", sid))
            el = float(rec.get("elapsed_ms", 0.0))
            f_cnt = int(rec.get("findings_total", 0))
            c_cnt = int(rec.get("critical_count", 0))
            cum_ms += el
            cum_findings += f_cnt
            cum_crits += c_cnt
            ticks.append(
                ReplayEventTick(
                    tick=len(ticks),
                    event_type="STAGE_EXECUTED",
                    actor=sid,
                    summary=f"Stage `{sid}` ({adapter}) completed in {el:.2f}ms -> {f_cnt} findings ({c_cnt} critical).",
                    elapsed_ms_cumulative=cum_ms,
                    findings_cumulative=cum_findings,
                    criticals_cumulative=cum_crits,
                    safety_preserved=ledger_valid,
                    metadata={"adapter": adapter, "elapsed_ms": round(el, 2), "risk_yield": rec.get("risk_weighted_yield", 0.0)},
                )
            )

        for d in directives:
            ticks.append(
                ReplayEventTick(
                    tick=len(ticks),
                    event_type="ADAPTATION_APPLIED",
                    actor=str(d.get("rule_id", "MAPEK")),
                    summary=f"Directive `{d.get('rule_id')}` ({d.get('action_type')} -> {d.get('target_stage_id')}, applied={d.get('applied')}): {d.get('rationale', '')}",
                    elapsed_ms_cumulative=cum_ms,
                    findings_cumulative=cum_findings,
                    criticals_cumulative=cum_crits,
                    safety_preserved=bool(d.get("approved_by_invariant_guard", True)),
                    metadata={"applied": d.get("applied"), "target_stage_id": d.get("target_stage_id")},
                )
            )

        for h in hyps:
            ticks.append(
                ReplayEventTick(
                    tick=len(ticks),
                    event_type="HYPOTHESIS_RESOLVED",
                    actor=str(h.get("hypothesis_id", "hyp")),
                    summary=f"Hypothesis `{h.get('title')}` -> {h.get('status')} (P: {h.get('prior_probability', 0):.2f} -> {h.get('posterior_probability', 0):.2f})",
                    elapsed_ms_cumulative=cum_ms,
                    findings_cumulative=cum_findings,
                    criticals_cumulative=cum_crits,
                    safety_preserved=ledger_valid,
                    metadata={"status": h.get("status"), "posterior": h.get("posterior_probability")},
                )
            )

        ticks.append(
            ReplayEventTick(
                tick=len(ticks),
                event_type="GATE_DECIDED",
                actor="release_gate",
                summary=f"Final Gate = `{run_report.get('gate_verdict')}` (dedup_vulns={run_report.get('total_vulnerabilities', 0)}, posture={run_report.get('overall_cyber_posture', 0)}).",
                elapsed_ms_cumulative=float(run_report.get("duration_ms", cum_ms)),
                findings_cumulative=int(run_report.get("total_vulnerabilities", 0)),
                criticals_cumulative=int(run_report.get("severity_counts", {}).get("critical", 0)),
                safety_preserved=ledger_valid,
                metadata={"gate_verdict": run_report.get("gate_verdict")},
            )
        )
        return ticks

    def time_travel_snapshot(self, tape: Sequence[ReplayEventTick], target_tick: int) -> Dict[str, Any]:
        if not tape:
            return {"snapshot_tick": 0, "total_ticks": 0}
        idx = max(0, min(len(tape) - 1, target_tick))
        prefix = tape[: idx + 1]
        cur = prefix[-1]
        return {
            "snapshot_tick": idx,
            "total_ticks": len(tape),
            "last_event": cur.to_dict(),
            "stages_completed_so_far": [e.actor for e in prefix if e.event_type == "STAGE_EXECUTED"],
            "adaptations_triggered_so_far": [e.actor for e in prefix if e.event_type == "ADAPTATION_APPLIED"],
            "elapsed_ms_at_tick": round(cur.elapsed_ms_cumulative, 2),
            "findings_at_tick": cur.findings_cumulative,
            "criticals_at_tick": cur.criticals_cumulative,
            "safety_preserved_at_tick": all(e.safety_preserved for e in prefix),
        }

    def simulate_counterfactual(
        self,
        run_report: Dict[str, Any],
        disable_rules: Sequence[str] = (),
        disable_stages: Sequence[str] = (),
        latency_cap_ms: Optional[float] = None,
    ) -> CounterfactualSimulationResult:
        run_id = str(run_report.get("run_id", "h2-run"))
        orig_gate = str(run_report.get("gate_verdict", "BLOCKED"))
        stage_records = list(run_report.get("telemetry", {}).get("stage_records", []))
        directives = list(run_report.get("mapek_adaptation", {}).get("directives", []))

        disabled_rule_set = set(disable_rules)
        dropped: Set[str] = set(disable_stages)
        for d in directives:
            if str(d.get("rule_id", "")) in disabled_rule_set and d.get("applied"):
                if str(d.get("action_type", "")) in ("inject_stage", "inject_drilldown", "add_stage"):
                    if d.get("target_stage_id"):
                        dropped.add(str(d["target_stage_id"]))

        cum_ms = 0.0
        kept = []
        for rec in stage_records:
            sid = str(rec.get("stage_id", ""))
            el = float(rec.get("elapsed_ms", 0.0))
            if sid in dropped:
                continue
            if latency_cap_ms is not None and (cum_ms + el) > latency_cap_ms:
                dropped.add(sid)
                continue
            cum_ms += el
            kept.append(rec)

        orig_f = sum(int(r.get("findings_total", 0)) for r in stage_records)
        cf_f = sum(int(r.get("findings_total", 0)) for r in kept)
        orig_c = sum(int(r.get("critical_count", 0)) for r in stage_records)
        cf_c = sum(int(r.get("critical_count", 0)) for r in kept)

        cf_gate = "BLOCKED" if cf_c > 0 else ("CONDITIONAL" if cf_f > 0 else "APPROVED")
        flipped = cf_gate != orig_gate
        c_lost = max(0, orig_c - cf_c)
        f_lost = max(0, orig_f - cf_f)

        if flipped and orig_gate == "BLOCKED":
            verdict = "CATASTROPHIC_GATE_FLIP"
        elif c_lost > 0:
            verdict = "HIGH_RECALL_LOSS"
        elif f_lost > 0:
            verdict = "MODERATE_LOSS"
        else:
            verdict = "BENIGN"

        parts = []
        if disable_rules:
            parts.append(f"disable_rules={list(disable_rules)}")
        if disable_stages:
            parts.append(f"disable_stages={list(disable_stages)}")
        if latency_cap_ms is not None:
            parts.append(f"latency_cap_ms={latency_cap_ms}")

        return CounterfactualSimulationResult(
            run_id=run_id,
            simulated_at=utc_now_iso(),
            scenario_description="; ".join(parts) or "baseline_identity",
            disabled_rules=list(disable_rules),
            disabled_stages=list(disable_stages),
            simulated_latency_cap_ms=latency_cap_ms,
            original_findings_estimate=orig_f,
            counterfactual_findings_estimate=cf_f,
            findings_lost=f_lost,
            original_criticals_estimate=orig_c,
            counterfactual_criticals_estimate=cf_c,
            criticals_lost=c_lost,
            original_gate_verdict=orig_gate,
            counterfactual_gate_verdict=cf_gate,
            gate_decision_flipped=flipped,
            dropped_stages=sorted(dropped),
            risk_impact_verdict=verdict,
        )
