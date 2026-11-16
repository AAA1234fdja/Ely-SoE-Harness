"""
Harness² Real-Time Execution Telemetry Observer & Signal Extraction Engine.

Monitors every first-order security stage as it completes, computing:
  - Severity-weighted **Risk Yield** (`10*Critical + 5*High + 2*Medium + 0.5*Low + 3*Reproduced`)
  - **Discovery Velocity** (`risk_weighted_yield / elapsed_seconds`)
  - **Time-to-First-Critical (TTFC)** in milliseconds
  - **Marginal Saturation Index** (consecutive low-yield stages indicating wasted budget)
  - **Cross-Domain Pivot Signals** (detecting CWE clusters like SSRF -> Cloud IAM,
    Web Injection -> Live DAST + Grammar Fuzzing, Secrets -> Supply-Chain + CI/CD,
    K8s Privileged -> Seccomp/eBPF Runtime, Auth/JWT -> IDOR/BFLA Sandbox Probing,
    AI/LLM patterns -> OWASP LLM Red-Team)
  - **Budget Burn Rate** & projected overrun alerts.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Set

from ely_soe.core.models import Severity, new_id
from ely_soe.cyber.models import CyberVulnerability
from ely_soe.harness_squared.models import (
    StageTelemetryRecord,
    TelemetrySignal,
    WorkflowStageNode,
)


SEVERITY_YIELD_WEIGHTS: Dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 5.0,
    Severity.MEDIUM: 2.0,
    Severity.LOW: 0.5,
    Severity.INFO: 0.1,
}


class TelemetryObserver:
    """Real-time observer transforming stage execution outputs into structured MAPE-K `TelemetrySignal`s."""

    def __init__(self, total_budget_ms: int = 30_000) -> None:
        self.total_budget_ms = max(1, total_budget_ms)
        self.records: List[StageTelemetryRecord] = []
        self.signals: List[TelemetrySignal] = []
        self.cumulative_elapsed_ms: float = 0.0
        self.time_to_first_critical_ms: Optional[float] = None
        self.consecutive_zero_yield_stages: int = 0
        self.observed_cwes: Set[str] = set()
        self.observed_domains: Set[str] = set()

    def observe_stage(
        self,
        node: WorkflowStageNode,
        vulnerabilities: Sequence[CyberVulnerability],
        extra_metrics: Optional[Dict[str, Any]] = None,
    ) -> Tuple[StageTelemetryRecord, List[TelemetrySignal]]:
        """Record telemetry for a finished stage and emit fresh adaptation signals."""
        elapsed = max(0.5, float(node.elapsed_ms))
        self.cumulative_elapsed_ms += elapsed

        crit = sum(1 for v in vulnerabilities if v.severity == Severity.CRITICAL)
        high = sum(1 for v in vulnerabilities if v.severity == Severity.HIGH)
        med = sum(1 for v in vulnerabilities if v.severity == Severity.MEDIUM)
        low = sum(1 for v in vulnerabilities if v.severity == Severity.LOW)
        repro = sum(1 for v in vulnerabilities if v.sandbox_reproduced)
        max_cvss = max((float(v.cvss4_score or 0.0) for v in vulnerabilities), default=0.0)

        cwes = sorted({c for v in vulnerabilities for c in v.cwe_ids})
        domains = sorted({v.cyber_domain.value for v in vulnerabilities})
        self.observed_cwes.update(cwes)
        self.observed_domains.update(domains)

        if crit > 0 and self.time_to_first_critical_ms is None:
            self.time_to_first_critical_ms = round(self.cumulative_elapsed_ms, 2)

        weighted_yield = sum(SEVERITY_YIELD_WEIGHTS.get(v.severity, 0.2) for v in vulnerabilities) + (repro * 3.0)
        yield_per_sec = weighted_yield / max(0.01, elapsed / 1000.0)
        budget_util = (elapsed / max(1, node.budget_ms)) * 100.0

        if weighted_yield < 0.5:
            self.consecutive_zero_yield_stages += 1
        else:
            self.consecutive_zero_yield_stages = 0

        rec = StageTelemetryRecord(
            stage_id=node.stage_id,
            adapter_name=node.adapter_name,
            category=node.category.value,
            elapsed_ms=elapsed,
            budget_ms=node.budget_ms,
            findings_total=len(vulnerabilities),
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            reproduced_count=repro,
            max_cvss4=max_cvss,
            distinct_cwes=cwes,
            distinct_domains=domains,
            risk_weighted_yield=weighted_yield,
            yield_per_second=yield_per_sec,
            budget_utilization_pct=budget_util,
        )
        self.records.append(rec)

        new_signals = self._extract_signals(rec, vulnerabilities, extra_metrics or {})
        self.signals.extend(new_signals)
        return rec, new_signals

    def _extract_signals(
        self,
        rec: StageTelemetryRecord,
        vulns: Sequence[CyberVulnerability],
        extra: Dict[str, Any],
    ) -> List[TelemetrySignal]:
        out: List[TelemetrySignal] = []
        cwe_set = set(rec.distinct_cwes)

        # 1. Critical/High Severity Cluster
        if rec.critical_count >= 1 or rec.high_count >= 3:
            out.append(
                TelemetrySignal(
                    signal_id=new_id("sig"),
                    signal_type="high_severity_cluster",
                    source_stage_id=rec.stage_id,
                    strength=min(1.0, 0.55 + rec.critical_count * 0.15 + rec.high_count * 0.05),
                    evidence={
                        "adapter": rec.adapter_name,
                        "criticals": rec.critical_count,
                        "highs": rec.high_count,
                        "cwes": rec.distinct_cwes[:8],
                    },
                )
            )

        # 2. Cross-Domain Pivot Triggers based on observed CWE families
        if cwe_set & {"CWE-89", "CWE-78", "CWE-77", "CWE-94", "CWE-943"}:
            out.append(
                TelemetrySignal(
                    signal_id=new_id("sig"),
                    signal_type="pivot_injection_to_dast_and_fuzz",
                    source_stage_id=rec.stage_id,
                    strength=0.92,
                    evidence={"cwes": sorted(cwe_set & {"CWE-89", "CWE-78", "CWE-77", "CWE-94", "CWE-943"})},
                )
            )

        if cwe_set & {"CWE-918", "CWE-611", "CWE-502", "CWE-1336"}:
            out.append(
                TelemetrySignal(
                    signal_id=new_id("sig"),
                    signal_type="pivot_ssrf_to_cloud_iam",
                    source_stage_id=rec.stage_id,
                    strength=0.90,
                    evidence={"cwes": sorted(cwe_set & {"CWE-918", "CWE-611", "CWE-502", "CWE-1336"})},
                )
            )

        if cwe_set & {"CWE-798", "CWE-321", "CWE-312", "CWE-829"}:
            out.append(
                TelemetrySignal(
                    signal_id=new_id("sig"),
                    signal_type="pivot_secrets_to_supply_chain",
                    source_stage_id=rec.stage_id,
                    strength=0.88,
                    evidence={"cwes": sorted(cwe_set & {"CWE-798", "CWE-321", "CWE-312", "CWE-829"})},
                )
            )

        if cwe_set & {"CWE-250", "CWE-269"} and "kubernetes" in rec.adapter_name:
            out.append(
                TelemetrySignal(
                    signal_id=new_id("sig"),
                    signal_type="pivot_k8s_to_runtime_ebpf",
                    source_stage_id=rec.stage_id,
                    strength=0.91,
                    evidence={"cwes": sorted(cwe_set & {"CWE-250", "CWE-269"})},
                )
            )

        if cwe_set & {"CWE-639", "CWE-347", "CWE-287", "CWE-862", "CWE-863"}:
            out.append(
                TelemetrySignal(
                    signal_id=new_id("sig"),
                    signal_type="pivot_auth_to_identity_and_dast",
                    source_stage_id=rec.stage_id,
                    strength=0.86,
                    evidence={"cwes": sorted(cwe_set & {"CWE-639", "CWE-347", "CWE-287", "CWE-862", "CWE-863"})},
                )
            )

        if cwe_set & {"CWE-74"} or extra.get("ai_surface_detected"):
            out.append(
                TelemetrySignal(
                    signal_id=new_id("sig"),
                    signal_type="ai_surface_hit",
                    source_stage_id=rec.stage_id,
                    strength=0.87,
                    evidence={"adapter": rec.adapter_name},
                )
            )

        # 3. Unverified High/Critical Findings Requiring Escalated Independent Validation
        unverified_crit = [v for v in vulns if v.severity == Severity.CRITICAL and not v.sandbox_reproduced]
        if len(unverified_crit) >= 2:
            out.append(
                TelemetrySignal(
                    signal_id=new_id("sig"),
                    signal_type="unverified_criticals",
                    source_stage_id=rec.stage_id,
                    strength=min(1.0, 0.6 + len(unverified_crit) * 0.08),
                    evidence={"count": len(unverified_crit), "rule_ids": [v.rule_id for v in unverified_crit[:5]]},
                )
            )

        # 4. Low-Yield Saturation Signal (candidate for branch pruning)
        if self.consecutive_zero_yield_stages >= 2:
            out.append(
                TelemetrySignal(
                    signal_id=new_id("sig"),
                    signal_type="low_yield_saturation",
                    source_stage_id=rec.stage_id,
                    strength=min(1.0, 0.5 + self.consecutive_zero_yield_stages * 0.15),
                    evidence={"consecutive_zero_yield": self.consecutive_zero_yield_stages},
                )
            )

        # 5. Budget Burn Pressure Signal
        burn_pct = (self.cumulative_elapsed_ms / self.total_budget_ms) * 100.0
        if burn_pct >= 65.0:
            out.append(
                TelemetrySignal(
                    signal_id=new_id("sig"),
                    signal_type="budget_pressure",
                    source_stage_id=rec.stage_id,
                    strength=min(1.0, burn_pct / 100.0),
                    evidence={"burn_pct": round(burn_pct, 1), "elapsed_ms": round(self.cumulative_elapsed_ms, 1)},
                )
            )

        return out

    def summary(self) -> Dict[str, Any]:
        total_yield = sum(r.risk_weighted_yield for r in self.records)
        total_sec = max(0.001, self.cumulative_elapsed_ms / 1000.0)
        return {
            "stages_observed": len(self.records),
            "cumulative_elapsed_ms": round(self.cumulative_elapsed_ms, 2),
            "budget_burn_pct": round((self.cumulative_elapsed_ms / self.total_budget_ms) * 100.0, 2),
            "time_to_first_critical_ms": self.time_to_first_critical_ms,
            "total_risk_weighted_yield": round(total_yield, 2),
            "mean_risk_yield_per_second": round(total_yield / total_sec, 2),
            "signals_emitted": len(self.signals),
            "distinct_cwes_observed": sorted(self.observed_cwes),
            "stage_records": [r.to_dict() for r in self.records],
            "signals": [s.to_dict() for s in self.signals],
        }


from typing import Tuple  # noqa: E402
