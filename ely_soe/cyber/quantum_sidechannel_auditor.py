"""
Post-Quantum Cryptography (NIST FIPS 203/204/205 & CNSA 2.0) Migration Planner
& Cryptographic Side-Channel / Timing-Oracle / Constant-Time Code Auditor.

Addresses both present-day cryptographic implementation attacks and future Harvest-Now-Decrypt-Later
(HNDL) quantum threats:
  1. **Side-Channel & Timing-Attack Static Code Auditor**:
       - Detects non-constant-time secret/HMAC/token equality comparisons (`token == expected`,
         `sig == expected_sig`, `digest == mac` instead of `hmac.compare_digest` / `secrets.compare_digest`
         / `crypto.timingSafeEqual` / `subtle.ConstantTimeCompare`).
       - Detects unauthenticated AES-CBC decryption without Encrypt-then-MAC (Padding Oracle CWE-209/CWE-327).
       - Detects RSA `PKCS1v15` encryption/decryption (Bleichenbacher / ROBOT / Marvin timing oracle!).
       - Detects non-CSPRNG `random.choice`/`Math.random()` used for tokens, nonces, or keys.
  2. **Mosca's Theorem (`X + Y > Z`) HNDL Quantum Risk Calculator**:
       Given `X` (data shelf-life years), `Y` (cryptographic migration duration years), and
       `Z` (estimated cryptographically relevant quantum computer arrival horizon, e.g. 10 yrs),
       flags immediate Harvest-Now-Decrypt-Later exposure whenever `X + Y > Z`!
  3. **NIST FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA) & CNSA 2.0 Roadmap Generator**:
       Maps every classical algorithm in an enterprise cryptographic inventory (CBOM) to its
       standardized PQC or Hybrid-PQC replacement (`X25519MLKEM768`, `ML-DSA-65`, `SLH-DSA-SHA2-128s`,
       `AES-256-GCM`, `SHA-384/SHA-512`) with priority tiers and target compliance deadlines.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import Severity, utc_now_iso
from ely_soe.cyber.models import (
    CVSSv4Metrics,
    CyberDomain,
    CyberVulnerability,
    VerificationMethod,
    make_cyber_vuln,
)


@dataclass(frozen=True)
class CryptoAssetInventoryItem:
    asset_name: str
    algorithm: str
    usage: str  # key_exchange | tls_cert | code_signing | data_at_rest | password_hash
    data_shelf_life_years: float = 10.0
    migration_effort_years: float = 2.0


PQC_MIGRATION_TABLE: Dict[str, Tuple[str, str, str, Severity]] = {
    "RSA-1024": ("BROKEN_CLASSICALLY", "ML-KEM-768 / ML-DSA-65 (Immediate Retire)", "P0_IMMEDIATE", Severity.CRITICAL),
    "RSA-2048": ("QUANTUM_VULNERABLE_SHOR", "Hybrid X25519+ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)", "P1_HIGH", Severity.HIGH),
    "RSA-3072": ("QUANTUM_VULNERABLE_SHOR", "Hybrid X25519+ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)", "P1_HIGH", Severity.MEDIUM),
    "RSA-4096": ("QUANTUM_VULNERABLE_SHOR", "Hybrid X25519+ML-KEM-1024 / ML-DSA-87 (CNSA 2.0)", "P2_PLANNED", Severity.MEDIUM),
    "ECDSA-P256": ("QUANTUM_VULNERABLE_SHOR", "ML-DSA-65 (FIPS 204) or Hybrid ECDSA+ML-DSA", "P1_HIGH", Severity.HIGH),
    "ECDH-P256": ("QUANTUM_VULNERABLE_SHOR", "X25519MLKEM768 (FIPS 203 Hybrid Key Exchange)", "P1_HIGH", Severity.HIGH),
    "X25519": ("QUANTUM_VULNERABLE_SHOR", "X25519MLKEM768 (FIPS 203 Hybrid Key Exchange)", "P1_HIGH", Severity.MEDIUM),
    "ED25519": ("QUANTUM_VULNERABLE_SHOR", "ML-DSA-65 (FIPS 204) / SLH-DSA-SHA2-128f (FIPS 205)", "P2_PLANNED", Severity.MEDIUM),
    "DH-2048": ("QUANTUM_VULNERABLE_SHOR", "ML-KEM-768 (FIPS 203)", "P1_HIGH", Severity.HIGH),
    "AES-128-GCM": ("GROVER_MARGIN_REDUCED", "Upgrade to AES-256-GCM (CNSA 2.0 128-bit quantum security)", "P2_PLANNED", Severity.LOW),
    "AES-256-GCM": ("QUANTUM_RESISTANT", "Retain AES-256-GCM (NIST/CNSA 2.0 Compliant)", "COMPLIANT", Severity.INFO),
    "CHACHA20-POLY1305": ("QUANTUM_RESISTANT", "Retain ChaCha20-Poly1305 (256-bit symmetric key)", "COMPLIANT", Severity.INFO),
    "SHA-256": ("GROVER_ACCEPTABLE", "Prefer SHA-384 / SHA-512 / SHA3-384 for CNSA 2.0", "P3_MONITOR", Severity.INFO),
    "SHA-384": ("QUANTUM_RESISTANT", "Retain SHA-384 (CNSA 2.0 Compliant)", "COMPLIANT", Severity.INFO),
    "ML-KEM-768": ("PQC_STANDARDIZED_FIPS203", "NIST FIPS 203 Compliant", "COMPLIANT", Severity.INFO),
    "ML-KEM-1024": ("PQC_STANDARDIZED_FIPS203", "NIST FIPS 203 & CNSA 2.0 Compliant", "COMPLIANT", Severity.INFO),
    "ML-DSA-65": ("PQC_STANDARDIZED_FIPS204", "NIST FIPS 204 Compliant", "COMPLIANT", Severity.INFO),
    "ML-DSA-87": ("PQC_STANDARDIZED_FIPS204", "NIST FIPS 204 & CNSA 2.0 Compliant", "COMPLIANT", Severity.INFO),
    "SLH-DSA": ("PQC_STANDARDIZED_FIPS205", "NIST FIPS 205 Stateless Hash-Based Signature Compliant", "COMPLIANT", Severity.INFO),
}


@dataclass(frozen=True)
class SideChannelRule:
    rule_id: str
    title: str
    severity: Severity
    cwe_id: str
    pattern: str
    description: str
    remediation: str


SIDECHANNEL_RULES: Tuple[SideChannelRule, ...] = (
    SideChannelRule(
        "CYB-SC-TIMING-EQ-001",
        "Non-Constant-Time Secret / HMAC / Signature Equality Check (`==` / `!=` Timing Side-Channel)",
        Severity.HIGH, "CWE-208",
        r"(?i)\b(?:hmac|signature|sig|digest|api_key|apikey|secret_token|auth_token|csrf_token|mac|expected_sig)\w*\s*(?:===?|!==?)\s*[a-zA-Z_]\w*",
        "Standard string/byte equality short-circuits on the first mismatching byte, enabling remote statistical timing recovery of MACs and API secrets.",
        "Use `hmac.compare_digest(a, b)` (Python), `crypto.timingSafeEqual(a, b)` (Node.js), or `subtle.ConstantTimeCompare(a, b)` (Go).",
    ),
    SideChannelRule(
        "CYB-SC-RSA-PKCS1V15-ORACLE",
        "RSA `PKCS1v15` Padding Used (Bleichenbacher / ROBOT / Marvin Timing Oracle)",
        Severity.HIGH, "CWE-203",
        r"(?:padding\.PKCS1v15\s*\(|RSA_PKCS1_PADDING|PKCS1_v1_5|Cipher\.getInstance\s*\(\s*['\"]RSA/ECB/PKCS1Padding['\"])",
        "RSA PKCS#1 v1.5 decryption leaks padding validity via microsecond timing/error side channels (CVE-2023-46126 Marvin attack class).",
        "Use `OAEP` with SHA-256 (`padding.OAEP`) for encryption and `RSA-PSS` or `ML-DSA` for signatures.",
    ),
    SideChannelRule(
        "CYB-SC-AES-CBC-NO-MAC",
        "Unauthenticated `AES-CBC` Mode Detected (Padding Oracle Attack Exposure)",
        Severity.HIGH, "CWE-327",
        r"(?:modes\.CBC\s*\(|AES\.MODE_CBC|aes-(?:128|192|256)-cbc|AES/CBC/PKCS5Padding)",
        "AES-CBC without Encrypt-then-MAC authentication enables adaptive chosen-ciphertext padding oracle decryption.",
        "Replace AES-CBC with Authenticated Encryption (`AES-256-GCM` or `ChaCha20-Poly1305`).",
    ),
    SideChannelRule(
        "CYB-SC-WEAK-PRNG-SECRET",
        "Non-Cryptographic PRNG (`random.*` / `Math.random()`) Used to Generate Security Secret/Token/Nonce",
        Severity.HIGH, "CWE-338",
        r"(?i)(?:token|secret|nonce|salt|key|otp|session_id|csrf)\w*\s*=\s*[^\n]{0,60}(?:random\.(?:choice|randint|random|randrange|getrandbits)|Math\.random\s*\()",
        "Mersenne Twister (`random`) and V8 XorShift (`Math.random`) internal states are predictable from observed outputs.",
        "Generate all cryptographic material exclusively with OS CSPRNGs (`secrets.token_urlsafe`, `os.urandom`, `crypto.randomBytes`).",
    ),
)


class QuantumAndSideChannelAuditor:
    """Audits side-channel timing/padding oracles and plans NIST PQC / CNSA 2.0 migrations."""

    def __init__(self) -> None:
        self._compiled = [(r, re.compile(r.pattern)) for r in SIDECHANNEL_RULES]

    def evaluate_cbom_pqc_migration(
        self,
        inventory: Sequence[CryptoAssetInventoryItem],
        crqc_horizon_years: float = 10.0,
    ) -> Dict[str, Any]:
        """Evaluate a Cryptographic Bill of Materials (CBOM) under Mosca's Theorem & NIST PQC."""
        vulns: List[CyberVulnerability] = []
        plan: List[Dict[str, Any]] = []
        compliant_cnt = 0
        hndl_urgent_cnt = 0

        for item in inventory:
            key = item.algorithm.upper().strip()
            status, replacement, priority, base_sev = PQC_MIGRATION_TABLE.get(
                key, ("UNKNOWN_ALGORITHM", "Audit algorithm against NIST FIPS 203/204/205", "P2_PLANNED", Severity.MEDIUM)
            )
            mosca_sum = item.data_shelf_life_years + item.migration_effort_years
            hndl_at_risk = (status == "QUANTUM_VULNERABLE_SHOR") and (mosca_sum > crqc_horizon_years)

            if status in ("QUANTUM_RESISTANT", "PQC_STANDARDIZED_FIPS203", "PQC_STANDARDIZED_FIPS204", "PQC_STANDARDIZED_FIPS205"):
                compliant_cnt += 1
            elif hndl_at_risk or status == "BROKEN_CLASSICALLY":
                if hndl_at_risk:
                    hndl_urgent_cnt += 1
                sev = Severity.CRITICAL if status == "BROKEN_CLASSICALLY" else (Severity.HIGH if item.usage in ("key_exchange", "tls_cert") else base_sev)
                vulns.append(
                    make_cyber_vuln(
                        rule_id=f"CYB-PQC-HNDL-{key.replace('-', '_')}",
                        title=f"[Mosca X+Y={mosca_sum:.1f}y > Z={crqc_horizon_years:.0f}y] `{item.asset_name}` ({key}) Vulnerable to HNDL Quantum Decryption",
                        description=(
                            f"Asset `{item.asset_name}` uses `{key}` for `{item.usage}` with {item.data_shelf_life_years:.1f}y confidentiality shelf-life "
                            f"and {item.migration_effort_years:.1f}y migration effort (`X+Y={mosca_sum:.1f} > Z={crqc_horizon_years:.1f}`). "
                            "Adversaries harvesting encrypted traffic today can decrypt it before confidentiality expires."
                        ),
                        cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                        severity=sev,
                        cwe_ids=["CWE-327"],
                        confidence=0.97,
                        verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                        endpoint_or_asset=item.asset_name,
                        remediation_guidance=f"Migrate `{item.asset_name}` to `{replacement}`.",
                        discovered_by="ely_cyber_quantum_sidechannel_auditor",
                    )
                )

            plan.append({
                "asset_name": item.asset_name,
                "current_algorithm": key,
                "usage": item.usage,
                "quantum_status": status,
                "mosca_x_plus_y_years": round(mosca_sum, 1),
                "hndl_urgent": hndl_at_risk,
                "recommended_target": replacement,
                "migration_priority": "P0_HNDL_URGENT" if hndl_at_risk else priority,
            })

        readiness_pct = round((compliant_cnt / max(1, len(inventory))) * 100.0, 2)
        return {
            "assessed_at": utc_now_iso(),
            "crqc_horizon_years": crqc_horizon_years,
            "cbom_assets_evaluated": len(inventory),
            "pqc_compliant_count": compliant_cnt,
            "hndl_urgent_count": hndl_urgent_cnt,
            "pqc_readiness_pct": readiness_pct,
            "migration_roadmap": plan,
            "vulnerabilities": vulns,
        }

    def scan_directory(self, root_path: Path) -> List[CyberVulnerability]:
        vulns: List[CyberVulnerability] = []
        exts = {".py", ".js", ".ts", ".go", ".java", ".rs", ".c", ".cpp"}
        for fp in sorted(root_path.rglob("*")):
            if not fp.is_file() or fp.suffix.lower() not in exts:
                continue
            if any(p in {".git", "node_modules", "__pycache__", ".venv"} for p in fp.parts):
                continue
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(fp.relative_to(root_path))
            for rule, rx in self._compiled:
                for m in rx.finditer(content):
                    ln = content[: m.start()].count("\n") + 1
                    vulns.append(
                        make_cyber_vuln(
                            rule_id=rule.rule_id,
                            title=rule.title,
                            description=rule.description,
                            cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                            severity=rule.severity,
                            cwe_ids=[rule.cwe_id],
                            confidence=0.91,
                            verification_method=VerificationMethod.STATIC_PATTERN,
                            file_path=rel,
                            line_start=ln,
                            line_end=ln,
                            code_snippet=m.group(0)[:160],
                            remediation_guidance=rule.remediation,
                            discovered_by="ely_cyber_quantum_sidechannel_auditor",
                        )
                    )
        return vulns
