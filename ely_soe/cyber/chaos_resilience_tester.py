"""
Security Chaos Engineering & Fail-Closed Resilience Verifier.

Tests whether critical security controls uphold fail-closed invariants under adverse
fault conditions (simulated deterministically inside authorized sandboxes):
  1. **AuthN/AuthZ Dependency Outage (Fail-Closed Verification)**:
     Verifies that when IdP/JWKS/OPA policy server times out or returns 503, the target
     rejects privileged access (`401/403/503`) rather than failing open (`200 OK`).
  2. **Rate-Limiter / Brute-Force Surge Resilience**:
     Verifies bounded throughput and lockout activation under burst authentication traffic.
  3. **KMS / Secret Store Degraded Mode Verification**:
     Ensures services do not fall back to hardcoded default secrets when KMS is unreachable.
  4. **Audit Ledger / Telemetry Backpressure Resilience**:
     Ensures security-critical operations fail-closed or preserve cryptographic continuity
     when log pipelines experience backpressure or disk quota exhaustion.
  5. **TLS Certificate Revocation / Clock-Skew Resilience**:
     Verifies strict rejection of expired/future-dated tokens and untrusted certificates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from ely_soe.core.models import Severity, utc_now_iso
from ely_soe.cyber.models import (
    CVSSv4Metrics,
    CyberDomain,
    CyberVulnerability,
    VerificationMethod,
    make_cyber_vuln,
)


@dataclass
class ChaosExperimentSpec:
    experiment_id: str
    title: str
    fault_type: str  # idp_timeout | opa_503 | kms_unavailable | auth_burst | clock_skew | ledger_full
    expected_fail_closed: bool = True
    severity_on_fail_open: Severity = Severity.CRITICAL
    cwe_id: str = "CWE-636"


@dataclass
class ChaosExperimentResult:
    experiment_id: str
    title: str
    fault_type: str
    passed_fail_closed: bool
    observed_status: str
    latency_ms: float
    details: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "title": self.title,
            "fault_type": self.fault_type,
            "passed_fail_closed": self.passed_fail_closed,
            "observed_status": self.observed_status,
            "latency_ms": round(self.latency_ms, 2),
            "details": self.details,
        }


DEFAULT_SECURITY_CHAOS_SUITE: Tuple[ChaosExperimentSpec, ...] = (
    ChaosExperimentSpec("CHAOS-SEC-001", "IdP / JWKS Endpoint Timeout -> AuthZ Must Fail Closed", "idp_timeout", True, Severity.CRITICAL, "CWE-636"),
    ChaosExperimentSpec("CHAOS-SEC-002", "Policy Engine (OPA/PDP) HTTP 503 -> Request Denied", "opa_503", True, Severity.CRITICAL, "CWE-636"),
    ChaosExperimentSpec("CHAOS-SEC-003", "KMS Unreachable -> No Hardcoded Fallback Key Permitted", "kms_unavailable", True, Severity.CRITICAL, "CWE-798"),
    ChaosExperimentSpec("CHAOS-SEC-004", "Credential Stuffing Burst (50 req/s) -> Lockout/429 Enforced", "auth_burst", True, Severity.HIGH, "CWE-307"),
    ChaosExperimentSpec("CHAOS-SEC-005", "Token Clock Skew (+3600s) -> Expired Session Rejected", "clock_skew", True, Severity.HIGH, "CWE-613"),
    ChaosExperimentSpec("CHAOS-SEC-006", "Audit Sink Backpressure -> Cryptographic Queue Durability", "ledger_full", True, Severity.MEDIUM, "CWE-778"),
)


class SecurityChaosResilienceTester:
    """Runs deterministic fail-closed security chaos experiments against simulated or live adapters."""

    def run_suite(
        self,
        fault_handler: Callable[[str], Dict[str, Any]],
        experiments: Sequence[ChaosExperimentSpec] = DEFAULT_SECURITY_CHAOS_SUITE,
        asset: str = "target_service",
    ) -> Dict[str, Any]:
        results: List[ChaosExperimentResult] = []
        vulns: List[CyberVulnerability] = []

        for exp in experiments:
            outcome = fault_handler(exp.fault_type)
            failed_closed = bool(outcome.get("failed_closed", False))
            status = str(outcome.get("observed_status", "unknown"))
            lat = float(outcome.get("latency_ms", 1.0))
            details = str(outcome.get("details", ""))

            results.append(
                ChaosExperimentResult(
                    experiment_id=exp.experiment_id,
                    title=exp.title,
                    fault_type=exp.fault_type,
                    passed_fail_closed=failed_closed,
                    observed_status=status,
                    latency_ms=lat,
                    details=details,
                )
            )
            if exp.expected_fail_closed and not failed_closed:
                vulns.append(
                    make_cyber_vuln(
                        rule_id=f"CYB-{exp.experiment_id}",
                        title=f"Fail-Open Security Control Under Fault `{exp.fault_type}` ({exp.title})",
                        description=f"Under injected fault `{exp.fault_type}` on `{asset}`, security control failed OPEN (`{status}`): {details}",
                        cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                        severity=exp.severity_on_fail_open,
                        cwe_ids=[exp.cwe_id],
                        confidence=0.99,
                        cvss4=CVSSv4Metrics(av="N", ac="H", at="P", pr="N", ui="N", vc="H", vi="H", va="L", sc="N", si="N", sa="N"),
                        verification_method=VerificationMethod.SANDBOX_DIFFERENTIAL_PROBE,
                        endpoint_or_asset=asset,
                        remediation_guidance="Enforce strict fail-closed error handling (CWE-636): deny access on policy/IdP/KMS failure and never fall back to static secrets.",
                        discovered_by="ely_cyber_chaos_resilience",
                    )
                )

        passed = sum(1 for r in results if r.passed_fail_closed)
        resilience_score = round((passed / max(1, len(results))) * 100.0, 2)
        return {
            "executed_at": utc_now_iso(),
            "asset": asset,
            "experiments_total": len(results),
            "experiments_passed": passed,
            "fail_closed_resilience_score": resilience_score,
            "results": [r.to_dict() for r in results],
            "vulnerabilities": vulns,
        }

    def build_simulated_handler(self, hardened: bool = True) -> Callable[[str], Dict[str, Any]]:
        """Deterministic simulator for verifying fail-closed vs fail-open service profiles."""
        def _handle(fault_type: str) -> Dict[str, Any]:
            if hardened:
                return {
                    "failed_closed": True,
                    "observed_status": "403_DENIED_FAIL_CLOSED" if fault_type != "auth_burst" else "429_RATE_LIMITED",
                    "latency_ms": 4.2,
                    "details": f"Hardened control enforced strict fail-closed invariant during `{fault_type}`.",
                }
            # Vulnerable profile fails open on IdP timeout, KMS unavailability, and auth burst
            vulnerable_faults = {"idp_timeout", "kms_unavailable", "auth_burst"}
            if fault_type in vulnerable_faults:
                return {
                    "failed_closed": False,
                    "observed_status": "200_OK_FAIL_OPEN_BYPASS",
                    "latency_ms": 12.8,
                    "details": f"Vulnerable service bypassed security check / fell back to default secret during `{fault_type}`.",
                }
            return {
                "failed_closed": True,
                "observed_status": "503_DENIED",
                "latency_ms": 6.1,
                "details": f"Service rejected request under `{fault_type}`.",
            }
        return _handle
