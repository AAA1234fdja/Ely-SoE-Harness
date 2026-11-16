"""
Harness² Automated Adversarial Hypothesis Generator & Bayesian Verification Planner.

Synthesizes falsifiable cross-domain security hypotheses from partial first-order
findings as a run progresses, assigns Bayesian priors, maps each hypothesis to a
concrete verification micro-stage adapter, and updates posterior probabilities
via Bayes' rule once verification evidence arrives (`CONFIRMED` / `REFUTED` / `INCONCLUSIVE`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ely_soe.core.models import Severity, new_id, utc_now_iso
from ely_soe.cyber.models import CyberVulnerability
from ely_soe.harness_squared.models import HypothesisStatus, SecurityHypothesis


@dataclass(frozen=True)
class HypothesisTemplate:
    template_id: str
    title: str
    statement_tpl: str
    required_cwe_any: Tuple[str, ...]
    verification_adapter: str
    prior_probability: float
    likelihood_if_true: float
    likelihood_if_false: float


HYPOTHESIS_TEMPLATES: Tuple[HypothesisTemplate, ...] = (
    HypothesisTemplate(
        "HYP-SQLI-LIVE",
        "Live Exploitable Database Takeover via Dynamic SQLi",
        "Static SQLi sink ({cwes}) in `{stage}` is dynamically reachable and exploitable via boolean/error differential payloads.",
        ("CWE-89", "CWE-943"),
        "live_sandbox_dast",
        0.72, 0.94, 0.12,
    ),
    HypothesisTemplate(
        "HYP-SSRF-IAM",
        "SSRF-to-Cloud-Admin Lateral Pivot Chain",
        "SSRF / server-side exposure ({cwes}) enables IMDS credential theft and transitive AWS/GCP/Azure IAM Admin escalation.",
        ("CWE-918", "CWE-611", "CWE-502"),
        "cloud_iam_graph",
        0.68, 0.91, 0.15,
    ),
    HypothesisTemplate(
        "HYP-SECRET-SUPPLY",
        "Exposed Credentials Enable Supply-Chain / CI Artifact Poisoning",
        "Hardcoded secrets or unpinned dependencies ({cwes}) permit unauthorized CI/CD publish or third-party registry compromise.",
        ("CWE-798", "CWE-321", "CWE-829"),
        "supply_chain_sbom",
        0.70, 0.90, 0.18,
    ),
    HypothesisTemplate(
        "HYP-K8S-ESCAPE",
        "Container Privilege Misconfiguration Enables Host Kernel Escape",
        "Kubernetes/container misconfigurations ({cwes}) allow host breakout via dangerous syscalls/capabilities (eBPF/Falco verifiable).",
        ("CWE-250", "CWE-269"),
        "container_runtime_ebpf",
        0.75, 0.93, 0.14,
    ),
    HypothesisTemplate(
        "HYP-AUTH-BOLA",
        "Authentication Weakness Chains Into Cross-Tenant BOLA / Admin Takeover",
        "JWT/auth flaws ({cwes}) allow forging administrative claims or reading cross-tenant resources without authorization.",
        ("CWE-347", "CWE-639", "CWE-287", "CWE-862"),
        "live_sandbox_dast",
        0.74, 0.92, 0.16,
    ),
    HypothesisTemplate(
        "HYP-PARSER-FUZZ",
        "Input Boundary Flaws Yield Grammar-Fuzzer Crash or Invariant Bypass",
        "Injection/protocol/deserialization weaknesses ({cwes}) can be systematically stressed via grammar-aware mutation fuzzing.",
        ("CWE-20", "CWE-22", "CWE-78", "CWE-444", "CWE-1336"),
        "grammar_fuzzer",
        0.64, 0.88, 0.20,
    ),
    HypothesisTemplate(
        "HYP-AI-HIJACK",
        "AI/LLM Pipeline Susceptible to Indirect Prompt Injection & Tool Hijack",
        "Detected AI/LLM code patterns ({cwes}) lack strict CaMeL control/data isolation and may leak secrets or invoke forbidden tools.",
        ("CWE-74", "CWE-94", "CWE-502"),
        "ai_llm_redteam",
        0.66, 0.91, 0.17,
    ),
    HypothesisTemplate(
        "HYP-AD-TIER0",
        "Identity / Directory Exposure Enables Tier-0 Domain Dominance",
        "Active Directory / Kerberos / ADCS misconfigurations ({cwes}) provide a shortest-path kill chain to Domain Admins.",
        ("CWE-287", "CWE-269", "CWE-319"),
        "active_directory_graph",
        0.65, 0.92, 0.15,
    ),
)


class AdversarialHypothesisEngine:
    """Proposes falsifiable security hypotheses and updates Bayesian posteriors from verification stages."""

    def __init__(self, templates: Sequence[HypothesisTemplate] = HYPOTHESIS_TEMPLATES) -> None:
        self.templates = list(templates)
        self.hypotheses: Dict[str, SecurityHypothesis] = {}
        self._emitted_keys: Set[Tuple[str, str]] = set()

    def propose_from_findings(
        self,
        source_stage_id: str,
        vulnerabilities: Sequence[CyberVulnerability],
    ) -> List[SecurityHypothesis]:
        """Analyze newly discovered findings and synthesize novel falsifiable hypotheses."""
        if not vulnerabilities:
            return []
        cwes_found = {c for v in vulnerabilities for c in v.cwe_ids}
        newly_proposed: List[SecurityHypothesis] = []

        for tpl in self.templates:
            overlap = sorted(cwes_found & set(tpl.required_cwe_any))
            if not overlap:
                continue
            key = (tpl.template_id, tpl.verification_adapter)
            if key in self._emitted_keys:
                continue
            self._emitted_keys.add(key)

            hyp = SecurityHypothesis(
                hypothesis_id=new_id("hyp"),
                title=tpl.title,
                statement=tpl.statement_tpl.format(cwes=", ".join(overlap), stage=source_stage_id),
                source_stage_id=source_stage_id,
                triggering_cwes=overlap,
                target_verification_adapter=tpl.verification_adapter,
                prior_probability=tpl.prior_probability,
                posterior_probability=tpl.prior_probability,
                status=HypothesisStatus.PROPOSED,
                evidence_notes=[f"Proposed from {len(vulnerabilities)} findings in `{source_stage_id}` matching {overlap}."],
            )
            self.hypotheses[hyp.hypothesis_id] = hyp
            newly_proposed.append(hyp)

        return newly_proposed

    def update_from_verification(
        self,
        adapter_name: str,
        verification_vulns: Sequence[CyberVulnerability],
        extra_confirmed: bool = False,
    ) -> List[SecurityHypothesis]:
        """Apply Bayesian posterior update to all active hypotheses targeting `adapter_name`."""
        updated: List[SecurityHypothesis] = []
        positive_evidence = extra_confirmed or any(
            v.severity in (Severity.CRITICAL, Severity.HIGH) or v.sandbox_reproduced
            for v in verification_vulns
        )

        for hyp in self.hypotheses.values():
            if hyp.target_verification_adapter != adapter_name:
                continue
            if hyp.status in (HypothesisStatus.CONFIRMED, HypothesisStatus.REFUTED):
                continue

            prior = hyp.posterior_probability
            if positive_evidence:
                # Bayes update for confirming evidence: P(H|E+) = P(E+|H)P(H) / [P(E+|H)P(H) + P(E+|~H)(1-P(H))]
                p_e_h, p_e_nh = 0.92, 0.14
                post = (p_e_h * prior) / max(1e-9, (p_e_h * prior) + (p_e_nh * (1.0 - prior)))
                hyp.posterior_probability = min(0.99, post)
                hyp.status = HypothesisStatus.CONFIRMED
                hyp.evidence_notes.append(
                    f"Confirmed by `{adapter_name}` ({len(verification_vulns)} findings); posterior raised {prior:.2f} -> {hyp.posterior_probability:.2f}."
                )
            else:
                # Bayes update for refuting/clean evidence: P(H|E-)
                p_ne_h, p_ne_nh = 0.12, 0.88
                post = (p_ne_h * prior) / max(1e-9, (p_ne_h * prior) + (p_ne_nh * (1.0 - prior)))
                hyp.posterior_probability = max(0.02, post)
                hyp.status = HypothesisStatus.REFUTED if hyp.posterior_probability < 0.30 else HypothesisStatus.INCONCLUSIVE
                hyp.evidence_notes.append(
                    f"Refuted/unconfirmed by `{adapter_name}` (0 critical/high hits); posterior dropped {prior:.2f} -> {hyp.posterior_probability:.2f}."
                )
            hyp.resolved_at = utc_now_iso()
            updated.append(hyp)

        return updated

    def summary(self) -> Dict[str, Any]:
        all_h = list(self.hypotheses.values())
        return {
            "total_hypotheses": len(all_h),
            "confirmed": sum(1 for h in all_h if h.status == HypothesisStatus.CONFIRMED),
            "refuted": sum(1 for h in all_h if h.status == HypothesisStatus.REFUTED),
            "open_or_inconclusive": sum(1 for h in all_h if h.status not in (HypothesisStatus.CONFIRMED, HypothesisStatus.REFUTED)),
            "hypotheses": [h.to_dict() for h in all_h],
        }
