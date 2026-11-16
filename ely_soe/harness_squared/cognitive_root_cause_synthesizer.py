"""
Autonomous Cross-Finding Root-Cause Clustering, Architectural Anti-Pattern Diagnostician
& Secure-By-Construction Refactor Blueprint Synthesizer.

Moves organizations beyond endless "whack-a-mole" single-line patching by clustering
raw Harness² / Cyber vulnerabilities into systemic **Architectural Root Causes**:
  1. **Missing Parameterized Data-Access Layer (DAL)** — clusters SQLi / NoSQLi / LDAPi (`CWE-89`, `CWE-943`, `CWE-90`)
  2. **Missing Centralized AuthN / AuthZ & Tenant Isolation Middleware** — clusters IDOR/BOLA, broken auth, JWT flaws, privilege escalation (`CWE-284`, `CWE-287`, `CWE-347`, `CWE-639`, `CWE-862`, `CWE-863`, `CWE-269`)
  3. **Absence of Safe Subprocess / Template / Deserialization Boundary** — clusters CMDi, SSTI, Unsafe Deser, Code Injection (`CWE-78`, `CWE-94`, `CWE-95`, `CWE-502`, `CWE-1336`)
  4. **Unconstrained Egress / SSRF / XXE Network Client Boundary** — clusters SSRF, XXE, Open Redirect (`CWE-918`, `CWE-611`, `CWE-601`)
  5. **Hardcoded Secrets & Absence of KMS/Vault Secret Lifecycle** — clusters hardcoded creds, weak crypto, cleartext (`CWE-798`, `CWE-327`, `CWE-328`, `CWE-319`, `CWE-522`)
  6. **Missing IaC / K8s / CI-CD Policy-as-Code Admission Guardrails** — clusters privileged containers, public S3/IAM wildcards, PPE pipelines (`CWE-250`, `CWE-732`, `CWE-829`, `CWE-494`).

For each diagnosed systemic root cause, computes:
  - Total raw findings eliminated simultaneously (**Leverage Ratio = findings eliminated / 1 architectural refactor**)
  - Percentage of total CVSS/risk mass eliminated
  - Concrete **Secure-By-Construction Engineering Blueprint** (target architecture pattern,
    CI guardrail check to prevent permanent recurrence, and estimated engineering sprint effort).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ely_soe.core.models import utc_now_iso


@dataclass(frozen=True)
class RootCauseArchetype:
    archetype_id: str
    title: str
    cwe_cluster: Tuple[str, ...]
    anti_pattern_diagnosis: str
    secure_by_construction_blueprint: str
    preventive_ci_guardrail: str
    estimated_refactor_days: float


ROOT_CAUSE_ARCHETYPES: Tuple[RootCauseArchetype, ...] = (
    RootCauseArchetype(
        archetype_id="RC-DAL-INJECTION",
        title="Absence of Enforced Parameterized Data-Access Layer (Injection Family)",
        cwe_cluster=("CWE-89", "CWE-90", "CWE-943", "CWE-74"),
        anti_pattern_diagnosis="Application handlers interpolate untrusted strings directly into raw SQL/NoSQL/LDAP queries across multiple endpoints.",
        secure_by_construction_blueprint="Adopt a typed Repository/ORM layer enforcing prepared-statement placeholders only; ban raw string query execution via custom linter/AST hook.",
        preventive_ci_guardrail="Semgrep/ELY-AST pre-commit gate failing any non-literal `cursor.execute(...)` or raw `$where` operator.",
        estimated_refactor_days=3.0,
    ),
    RootCauseArchetype(
        archetype_id="RC-AUTHZ-MIDDLEWARE",
        title="Decentralized / Missing Deny-By-Default AuthN, AuthZ & Tenant Isolation Layer",
        cwe_cluster=("CWE-284", "CWE-287", "CWE-306", "CWE-347", "CWE-639", "CWE-862", "CWE-863", "CWE-269", "CWE-915"),
        anti_pattern_diagnosis="Routes implement ad-hoc authorization checks (or omit them), creating BOLA/IDOR, broken function-level auth, JWT bypass, and mass-assignment exposure.",
        secure_by_construction_blueprint="Enforce centralized deny-by-default Policy Enforcement Point (PEP) middleware with declarative RBAC/ABAC tenant scoping and strict Pydantic/schema DTO allowlists.",
        preventive_ci_guardrail="Automated route-inventory test asserting every non-public endpoint carries an explicit AuthZ policy decorator + cross-tenant BOLA integration suite.",
        estimated_refactor_days=5.0,
    ),
    RootCauseArchetype(
        archetype_id="RC-UNSAFE-EXEC-DESER",
        title="Unrestricted Code Execution, Shell Invocation & Unsafe Deserialization Boundaries",
        cwe_cluster=("CWE-78", "CWE-94", "CWE-95", "CWE-502", "CWE-1336", "CWE-22"),
        anti_pattern_diagnosis="Services invoke shell interpreters (`shell=True`), `eval`/`exec`, `pickle`/`yaml.load`, or raw filesystem joins on untrusted inputs.",
        secure_by_construction_blueprint="Replace shell calls with native stdlib/SDK APIs (`argv[]` list exec only), replace pickle/unsafe YAML with signed JSON/Protobuf schemas, and jail file access via canonical `Path.resolve().is_relative_to(BASE)`.",
        preventive_ci_guardrail="Block `shell=True`, `pickle.loads`, `yaml.load` (without SafeLoader), `eval`, and `exec` unconditionally in CI.",
        estimated_refactor_days=3.5,
    ),
    RootCauseArchetype(
        archetype_id="RC-EGRESS-SSRF-XML",
        title="Unfiltered Outbound Network Client & XML Parser Surface (SSRF / XXE)",
        cwe_cluster=("CWE-918", "CWE-611", "CWE-601"),
        anti_pattern_diagnosis="Outbound HTTP clients connect directly to user-supplied URLs without DNS-rebinding/RFC1918/IMDS egress firewalling, and XML parsers allow DTD/external entities.",
        secure_by_construction_blueprint="Mandate a single hardened `SafeHTTPClient` wrapper (validating resolved IP != private/link-local/169.254.169.254, disabling redirects) + centralized `defusedxml` parser + IMDSv2 hop-limit=1.",
        preventive_ci_guardrail="Forbid direct `requests`/`urllib` calls outside `SafeHTTPClient` and enforce VPC egress proxy allowlist.",
        estimated_refactor_days=2.5,
    ),
    RootCauseArchetype(
        archetype_id="RC-SECRETS-CRYPTO-HYGIENE",
        title="Absence of Managed KMS/Vault Secret Lifecycle & Modern Crypto Primitives",
        cwe_cluster=("CWE-798", "CWE-522", "CWE-327", "CWE-328", "CWE-319", "CWE-330", "CWE-295", "CWE-200"),
        anti_pattern_diagnosis="Credentials reside in source/configs, legacy MD5/SHA1/RC4/TLS1.0 primitives persist, or TLS verification is disabled.",
        secure_by_construction_blueprint="Migrate all secrets to short-lived OIDC/Vault dynamic leases, standardize on AEAD (`AES-256-GCM`/`ChaCha20-Poly1305`) + Argon2id + TLS 1.3 + hybrid PQC readiness (`ML-KEM-768`).",
        preventive_ci_guardrail="Enable GitHub Push Protection + ELY DLP pre-receive hook + automated TLS/CBOM compliance gate.",
        estimated_refactor_days=4.0,
    ),
    RootCauseArchetype(
        archetype_id="RC-INFRA-SUPPLY-CHAIN-GUARDRAILS",
        title="Missing IaC, Container Admission & CI/CD Supply-Chain Policy Guardrails",
        cwe_cluster=("CWE-250", "CWE-732", "CWE-829", "CWE-494", "CWE-1104", "CWE-345", "CWE-120", "CWE-416"),
        anti_pattern_diagnosis="Containers run privileged/root, cloud buckets/IAM roles use wildcards, and CI/CD pipelines execute unpinned actions or untrusted PR code.",
        secure_by_construction_blueprint="Enforce Kubernetes Pod Security Admission `restricted`, OPA/Kyverno IaC gates, 40-char SHA-pinned CI actions, OIDC federation, and SLSA Level 3 Cosign signed provenance.",
        preventive_ci_guardrail="Mandatory ELY IaC + CI/CD PPE + SBOM/SLSA verification check blocking merge on violation.",
        estimated_refactor_days=4.5,
    ),
)

SEV_RISK_MASS: Dict[str, float] = {"critical": 10.0, "high": 6.0, "medium": 2.5, "low": 0.8, "info": 0.2}


class CognitiveRootCauseSynthesizer:
    """Clusters raw findings into systemic architectural root causes & secure-by-construction blueprints."""

    def synthesize_root_causes(self, vulns: Sequence[Any]) -> Dict[str, Any]:
        total_risk_mass = 0.0
        clusters: Dict[str, List[Dict[str, Any]]] = {a.archetype_id: [] for a in ROOT_CAUSE_ARCHETYPES}
        unclustered: List[Dict[str, Any]] = []

        for v in vulns:
            if isinstance(v, dict):
                cwes = {str(c).upper() for c in v.get("cwe_ids", [])}
                sev = str(v.get("severity", "medium")).lower()
                rid = str(v.get("rule_id", "RULE"))
                title = str(v.get("title", rid))
            else:
                cwes = {str(c).upper() for c in getattr(v, "cwe_ids", [])}
                s_obj = getattr(v, "severity", "medium")
                sev = s_obj.value.lower() if hasattr(s_obj, "value") else str(s_obj).lower()
                rid = str(getattr(v, "rule_id", "RULE"))
                title = str(getattr(v, "title", rid))

            mass = SEV_RISK_MASS.get(sev, 1.0)
            total_risk_mass += mass
            item = {"rule_id": rid, "title": title, "severity": sev, "cwes": sorted(cwes), "risk_mass": mass}

            matched_arch = None
            for arch in ROOT_CAUSE_ARCHETYPES:
                if cwes & set(arch.cwe_cluster):
                    matched_arch = arch.archetype_id
                    break
            if matched_arch:
                clusters[matched_arch].append(item)
            else:
                unclustered.append(item)

        blueprints: List[Dict[str, Any]] = []
        for arch in ROOT_CAUSE_ARCHETYPES:
            members = clusters[arch.archetype_id]
            if not members:
                continue
            cluster_mass = sum(m["risk_mass"] for m in members)
            risk_share_pct = round((cluster_mass / max(1e-9, total_risk_mass)) * 100.0, 2)
            crit_cnt = sum(1 for m in members if m["severity"] == "critical")
            high_cnt = sum(1 for m in members if m["severity"] == "high")
            leverage_per_day = round(cluster_mass / max(0.5, arch.estimated_refactor_days), 2)
            blueprints.append({
                "archetype_id": arch.archetype_id,
                "title": arch.title,
                "findings_eliminated": len(members),
                "critical_eliminated": crit_cnt,
                "high_eliminated": high_cnt,
                "risk_mass_eliminated_pct": risk_share_pct,
                "estimated_refactor_days": arch.estimated_refactor_days,
                "risk_leverage_per_eng_day": leverage_per_day,
                "anti_pattern_diagnosis": arch.anti_pattern_diagnosis,
                "secure_by_construction_blueprint": arch.secure_by_construction_blueprint,
                "preventive_ci_guardrail": arch.preventive_ci_guardrail,
                "sample_rule_ids": sorted({m["rule_id"] for m in members})[:8],
            })

        blueprints.sort(key=lambda b: (-b["risk_leverage_per_eng_day"], -b["findings_eliminated"]))
        clustered_count = sum(b["findings_eliminated"] for b in blueprints)
        compression_ratio = round(clustered_count / max(1, len(blueprints)), 2) if blueprints else 0.0

        return {
            "synthesized_at": utc_now_iso(),
            "total_findings_analyzed": len(vulns),
            "clustered_findings_count": clustered_count,
            "unclustered_findings_count": len(unclustered),
            "systemic_root_causes_identified": len(blueprints),
            "whack_a_mole_compression_ratio": compression_ratio,
            "total_estimated_refactor_days": round(sum(b["estimated_refactor_days"] for b in blueprints), 1),
            "architectural_blueprints": blueprints,
        }
