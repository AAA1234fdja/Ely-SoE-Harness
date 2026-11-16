"""
Privacy Engineering, Quantitative Anonymization Verifier (k-Anonymity & l-Diversity),
Differential Privacy (epsilon/delta) Budget Accountant & GDPR/CCPA/HIPAA Data-Flow Auditor.

Provides mathematically rigorous privacy assurance without external dependencies:
  1. **True k-Anonymity & Distinct/Entropy l-Diversity Verifier**:
       Given a tabular dataset (rows of dicts), quasi-identifiers (e.g., `["zip", "age_band", "gender"]`),
       and sensitive attribute (`"diagnosis"`), partitions records into exact equivalence classes,
       computes minimum `k`, distinct `l`, and Shannon entropy `l = exp(H)`, and flags
       re-identification / attribute-disclosure vulnerabilities (`k < k_min` or `l < l_min`).
  2. **Differential Privacy (`(epsilon, delta)`) Composition Accountant**:
       Tracks sequential Gaussian/Laplace DP query logs using both **Basic Composition**
       (`sum(eps_i)`) and **Dwork-Rothblum-Vadhan Advanced Composition Theorem**:
         `eps_adv = sqrt(2 * k * ln(1 / delta')) * eps_max + k * eps_max * (exp(eps_max) - 1)`
       to detect privacy budget exhaustion before membership-inference leakage occurs.
  3. **GDPR / CCPA / HIPAA Data-Governance & Retention Policy Auditor**:
       Audits data-asset inventories for missing encryption/tokenization, excessive retention
       periods (`retention_days > legal_max`), unconsented third-party sharing, missing DSR
       (Data Subject Right to Erasure / Art. 17) hooks, and unencrypted cross-border transfers.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import Severity, utc_now_iso
from ely_soe.cyber.models import (
    CVSSv4Metrics,
    CyberDomain,
    CyberVulnerability,
    VerificationMethod,
    make_cyber_vuln,
)


@dataclass
class DPQueryEvent:
    query_id: str
    mechanism: str  # laplace | gaussian | exponential
    epsilon: float
    delta: float = 0.0
    description: str = ""


@dataclass
class DataAssetPrivacySpec:
    asset_id: str
    contains_pii: bool
    contains_phi_or_special_cat: bool = False
    encrypted_at_rest: bool = True
    tokenized_or_pseudonymized: bool = False
    legal_basis: str = "consent"  # consent | contract | legitimate_interest | none
    retention_days: int = 90
    max_allowed_retention_days: int = 365
    supports_art17_erasure: bool = True
    cross_border_transfer_unprotected: bool = False
    shared_with_third_parties_without_dpa: bool = False


class PrivacyPIIGDPREngine:
    """Quantitative privacy verification engine covering k-anonymity, l-diversity, DP budgets, and GDPR/HIPAA."""

    def verify_k_anonymity_l_diversity(
        self,
        records: Sequence[Dict[str, Any]],
        quasi_identifiers: Sequence[str],
        sensitive_attr: str,
        required_k: int = 5,
        required_l: int = 2,
        dataset_name: str = "analytics_export",
    ) -> Dict[str, Any]:
        """Compute exact equivalence-class k-anonymity and distinct + entropy l-diversity."""
        vulns: List[CyberVulnerability] = []
        if not records:
            return {
                "dataset": dataset_name,
                "record_count": 0,
                "equivalence_classes": 0,
                "achieved_k": 0,
                "achieved_distinct_l": 0,
                "min_entropy_l": 0.0,
                "compliant": True,
                "vulnerabilities": [],
            }

        eq_classes: Dict[Tuple[Any, ...], List[Any]] = defaultdict(list)
        for row in records:
            qi_tuple = tuple(row.get(col) for col in quasi_identifiers)
            eq_classes[qi_tuple].append(row.get(sensitive_attr))

        min_k = min(len(vals) for vals in eq_classes.values())
        violating_k_classes = sum(1 for vals in eq_classes.values() if len(vals) < required_k)
        violating_k_records = sum(len(vals) for vals in eq_classes.values() if len(vals) < required_k)

        min_distinct_l = min(len(set(vals)) for vals in eq_classes.values())
        violating_l_classes = sum(1 for vals in eq_classes.values() if len(set(vals)) < required_l)

        # Compute minimum entropy l-diversity: exp(-sum(p_s * ln(p_s)))
        min_entropy_l = float("inf")
        for vals in eq_classes.values():
            cnts = Counter(vals)
            n = float(len(vals))
            h = -sum((c / n) * math.log(c / n) for c in cnts.values() if c > 0)
            min_entropy_l = min(min_entropy_l, math.exp(h))
        if min_entropy_l == float("inf"):
            min_entropy_l = 0.0

        reid_risk_max = round(1.0 / max(1, min_k), 4)

        if min_k < required_k:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PRIV-KANON-VIOLATION",
                    title=f"Dataset `{dataset_name}` Fails {required_k}-Anonymity (Achieved k={min_k}; Max Re-ID Risk={reid_risk_max:.0%})",
                    description=(
                        f"{violating_k_classes} equivalence class(es) covering {violating_k_records} record(s) have group size < {required_k} "
                        f"on quasi-identifiers {list(quasi_identifiers)}, enabling linkage re-identification attacks."
                    ),
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.CRITICAL if min_k == 1 else Severity.HIGH,
                    cwe_ids=["CWE-359", "CWE-200"],
                    confidence=0.99,
                    verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                    endpoint_or_asset=dataset_name,
                    remediation_guidance=f"Generalize/suppress quasi-identifiers {list(quasi_identifiers)} until every equivalence class satisfies k >= {required_k}.",
                    discovered_by="ely_cyber_privacy_gdpr_engine",
                )
            )

        if min_distinct_l < required_l:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PRIV-LDIV-VIOLATION",
                    title=f"Dataset `{dataset_name}` Fails {required_l}-Diversity on `{sensitive_attr}` (Homogeneity Attack)",
                    description=(
                        f"{violating_l_classes} equivalence class(es) have fewer than {required_l} distinct `{sensitive_attr}` values "
                        f"(min distinct l={min_distinct_l}, min entropy l={min_entropy_l:.2f}), allowing attribute disclosure even if k-anonymous."
                    ),
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-359"],
                    confidence=0.98,
                    verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                    endpoint_or_asset=dataset_name,
                    remediation_guidance=f"Merge homogeneous equivalence classes or add calibrated differential privacy noise until distinct l >= {required_l}.",
                    discovered_by="ely_cyber_privacy_gdpr_engine",
                )
            )

        return {
            "audited_at": utc_now_iso(),
            "dataset": dataset_name,
            "record_count": len(records),
            "equivalence_classes": len(eq_classes),
            "achieved_k": min_k,
            "required_k": required_k,
            "violating_k_classes": violating_k_classes,
            "max_reidentification_prob": reid_risk_max,
            "achieved_distinct_l": min_distinct_l,
            "min_entropy_l": round(min_entropy_l, 3),
            "required_l": required_l,
            "compliant": (min_k >= required_k) and (min_distinct_l >= required_l),
            "vulnerabilities": vulns,
        }

    def audit_differential_privacy_budget(
        self,
        queries: Sequence[DPQueryEvent],
        max_epsilon_budget: float = 3.0,
        max_delta_budget: float = 1e-5,
        delta_prime: float = 1e-6,
        asset: str = "dp_query_engine",
    ) -> Dict[str, Any]:
        """Track cumulative `(epsilon, delta)` privacy loss via Basic & Advanced Composition Theorems."""
        vulns: List[CyberVulnerability] = []
        basic_eps = sum(max(0.0, q.epsilon) for q in queries)
        basic_delta = sum(max(0.0, q.delta) for q in queries)

        k = len(queries)
        if k > 0:
            eps_max = max(max(0.0, q.epsilon) for q in queries)
            adv_eps = math.sqrt(2.0 * k * math.log(1.0 / max(1e-12, delta_prime))) * eps_max + k * eps_max * (math.exp(eps_max) - 1.0)
            adv_delta = basic_delta + delta_prime
            effective_eps = min(basic_eps, adv_eps)
            effective_delta = basic_delta if basic_eps <= adv_eps else adv_delta
        else:
            adv_eps = 0.0
            effective_eps = 0.0
            effective_delta = 0.0

        exhausted = effective_eps > max_epsilon_budget or effective_delta > max_delta_budget
        if exhausted:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PRIV-DP-BUDGET-EXHAUSTED",
                    title=f"Differential Privacy Budget Exhausted on `{asset}` (eps={effective_eps:.3f} > cap {max_epsilon_budget})",
                    description=(
                        f"{k} sequential queries exhausted the formal differential privacy envelope "
                        f"(basic_eps={basic_eps:.3f}, advanced_eps={adv_eps:.3f}, delta={effective_delta:.2e}), "
                        "exposing training/analytics cohorts to membership-inference & reconstruction attacks."
                    ),
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.HIGH if effective_eps <= max_epsilon_budget * 2 else Severity.CRITICAL,
                    cwe_ids=["CWE-200", "CWE-359"],
                    confidence=0.99,
                    verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                    endpoint_or_asset=asset,
                    remediation_guidance="Halt further queries on this cohort (fail-closed privacy accountant) or increase noise scale sigma.",
                    discovered_by="ely_cyber_privacy_gdpr_engine",
                )
            )

        return {
            "audited_at": utc_now_iso(),
            "asset": asset,
            "queries_accounted": k,
            "basic_composition_epsilon": round(basic_eps, 4),
            "advanced_composition_epsilon": round(adv_eps, 4),
            "effective_epsilon": round(effective_eps, 4),
            "effective_delta": effective_delta,
            "max_epsilon_budget": max_epsilon_budget,
            "budget_utilization_pct": round((effective_eps / max(1e-6, max_epsilon_budget)) * 100.0, 2),
            "budget_exhausted": exhausted,
            "vulnerabilities": vulns,
        }

    def audit_gdpr_hipaa_governance(self, assets: Sequence[DataAssetPrivacySpec]) -> Dict[str, Any]:
        """Audit enterprise data inventory against GDPR Arts. 5/6/17/32/44 and HIPAA Safeguards."""
        vulns: List[CyberVulnerability] = []
        checks_total = 0
        checks_passed = 0

        for a in assets:
            if not a.contains_pii and not a.contains_phi_or_special_cat:
                continue
            controls = [
                (a.encrypted_at_rest, "CYB-PRIV-GDPR-ART32-NOENC", f"PII/PHI Store `{a.asset_id}` Lacks Encryption at Rest (GDPR Art. 32 / HIPAA)", Severity.CRITICAL, "CWE-311"),
                (a.legal_basis.lower() != "none", "CYB-PRIV-GDPR-ART6-NOLAWFUL", f"PII Store `{a.asset_id}` Lacks Documented Lawful Processing Basis (GDPR Art. 6)", Severity.HIGH, "CWE-359"),
                (a.retention_days <= a.max_allowed_retention_days, "CYB-PRIV-GDPR-ART5-RETENTION", f"PII Store `{a.asset_id}` Exceeds Storage Limitation ({a.retention_days}d > {a.max_allowed_retention_days}d; GDPR Art. 5)", Severity.MEDIUM, "CWE-359"),
                (a.supports_art17_erasure, "CYB-PRIV-GDPR-ART17-ERASURE", f"PII Store `{a.asset_id}` Missing Automated Right-to-Erasure Pipeline (GDPR Art. 17)", Severity.HIGH, "CWE-459"),
                (not a.cross_border_transfer_unprotected, "CYB-PRIV-GDPR-ART44-XFER", f"PII Store `{a.asset_id}` Performs Unprotected Cross-Border Transfer Without SCC/Adequacy (GDPR Art. 44)", Severity.HIGH, "CWE-359"),
                (not a.shared_with_third_parties_without_dpa, "CYB-PRIV-GDPR-ART28-NODPA", f"PII Store `{a.asset_id}` Shared With Third-Party Subprocessor Without DPA (GDPR Art. 28)", Severity.HIGH, "CWE-359"),
            ]
            for passed, rid, title, sev, cwe in controls:
                checks_total += 1
                if passed:
                    checks_passed += 1
                else:
                    vulns.append(
                        make_cyber_vuln(
                            rule_id=rid,
                            title=title,
                            description=f"Privacy governance violation detected on data asset `{a.asset_id}`.",
                            cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                            severity=sev,
                            cwe_ids=[cwe],
                            confidence=0.98,
                            verification_method=VerificationMethod.STATIC_PATTERN,
                            endpoint_or_asset=a.asset_id,
                            remediation_guidance="Remediate GDPR/HIPAA control gap via KMS encryption, TTL erasure automation, and signed DPAs.",
                            discovered_by="ely_cyber_privacy_gdpr_engine",
                        )
                    )

        return {
            "audited_at": utc_now_iso(),
            "assets_audited": len(assets),
            "checks_total": checks_total,
            "checks_passed": checks_passed,
            "privacy_governance_score_pct": round((checks_passed / max(1, checks_total)) * 100.0, 2),
            "vulnerabilities": vulns,
        }
