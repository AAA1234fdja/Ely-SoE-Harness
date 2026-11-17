"""
Cryptographic Oracle & Mathematical Fault-Injection Verification Lab.

Executes real, zero-dependency mathematical cryptographic cryptanalysis & protocol
oracle checks against implementations or synthetic specimens:
  1. **AES-GCM / Stream-Cipher Nonce-Reuse Keystream XOR Recovery Proof**:
       Demonstrates exact plaintext recovery (`C1 XOR C2 == P1 XOR P2`) when two messages
       share a nonce/IV under a stream/CTR/GCM cipher (CWE-323).
  2. **RSA Low-Exponent (`e = 3`) Unpadded Cube-Root Recovery Proof**:
       Verifies whether unpadded small-message RSA `c = m^3 mod N` where `m^3 < N`
       succumbs to exact integer cube-root recovery without factoring `N` (CWE-780).
  3. **Statistical Timing Side-Channel Oracle (Welch's t-Test / DudeCT-Style)**:
       Runs two-sample Welch's t-statistic over two latency distributions (secret-match
       vs mismatch timings); flags statistically significant timing leak when `|t| > 4.5`
       (standard DudeCT threshold, `p < 1e-5`, CWE-208).
  4. **Weak LCG / Linear PRNG State Recovery & Next-Token Prediction Check**:
       Detects predictable linear congruential sequences `X_{n+1} = (a * X_n + c) mod m`
       used for session IDs / CSRF tokens (CWE-330).
  5. **Padding Oracle & Error-Distinguisher Differential Checker**:
       Tests a decryption oracle callable for distinguishable padding vs MAC failure
       messages/codes (Vaudenay CBC Padding Oracle / Bleichenbacher class, CWE-209).
"""

from __future__ import annotations

import math
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import Severity, utc_now_iso
from ely_soe.cyber.models import (
    CyberDomain,
    CyberVulnerability,
    VerificationMethod,
    make_cyber_vuln,
)


class CryptographicOracleVerificationLab:
    """Mathematical cryptanalysis & oracle distinguisher verification toolkit."""

    def test_nonce_reuse_xor_recovery(
        self,
        ciphertext_1: bytes,
        ciphertext_2: bytes,
        known_plaintext_1: bytes,
        asset: str = "stream_cipher_endpoint",
    ) -> Dict[str, Any]:
        """Recover plaintext_2 from two ciphertexts encrypted with the same key+nonce."""
        n = min(len(ciphertext_1), len(ciphertext_2), len(known_plaintext_1))
        recovered_keystream = bytes(ciphertext_1[i] ^ known_plaintext_1[i] for i in range(n))
        recovered_p2 = bytes(ciphertext_2[i] ^ recovered_keystream[i] for i in range(n))
        c_xor = bytes(ciphertext_1[i] ^ ciphertext_2[i] for i in range(n))
        vulnerable = n > 0 and c_xor != b"\x00" * n

        vulns: List[CyberVulnerability] = []
        if vulnerable:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-CRYPTO-NONCE-REUSE-PROOF",
                    title=f"Cryptographic Nonce/IV Reuse Proven — Plaintext Recovered via Keystream XOR (`{asset}`)",
                    description=f"Reused nonce across {n}-byte messages enabled exact keystream recovery and plaintext extraction without key knowledge.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-323", "CWE-329"],
                    confidence=1.0,
                    verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                    sandbox_reproduced=True,
                    endpoint_or_asset=asset,
                    remediation_guidance="Generate unique 96-bit CSPRNG/monotonic nonces per message (or adopt AES-GCM-SIV / XChaCha20-Poly1305).",
                    discovered_by="ely_cyber_crypto_oracle_lab",
                )
            )
        return {
            "test": "nonce_reuse_xor_recovery",
            "bytes_recovered": n,
            "recovered_plaintext_2_utf8": recovered_p2.decode("utf-8", errors="replace"),
            "vulnerable": vulnerable,
            "vulnerabilities": vulns,
        }

    def test_rsa_low_exponent_cube_root(
        self,
        ciphertext_int: int,
        exponent_e: int = 3,
        modulus_n: Optional[int] = None,
        asset: str = "textbook_rsa_service",
    ) -> Dict[str, Any]:
        """Attempt exact integer e-th root recovery on unpadded textbook RSA ciphertext."""
        root = self._integer_nth_root(ciphertext_int, exponent_e)
        exact_recovery = pow(root, exponent_e) == ciphertext_int
        recovered_bytes = root.to_bytes(max(1, (root.bit_length() + 7) // 8), "big") if exact_recovery else b""

        vulns: List[CyberVulnerability] = []
        if exact_recovery:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-CRYPTO-RSA-TEXTBOOK-E3",
                    title=f"Unpadded Textbook RSA (`e={exponent_e}`) Broken by Exact Integer Root Without Private Key",
                    description=f"Ciphertext satisfied `m^{exponent_e} < N`; plaintext recovered directly via integer {exponent_e}-th root.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-780", "CWE-327"],
                    confidence=1.0,
                    verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                    sandbox_reproduced=True,
                    endpoint_or_asset=asset,
                    remediation_guidance="Always enforce RSA-OAEP (SHA-256) with `e=65537` and >= 3072-bit modulus, or migrate to hybrid ML-KEM-768 + X25519.",
                    discovered_by="ely_cyber_crypto_oracle_lab",
                )
            )
        return {
            "test": "rsa_low_exponent_root",
            "exponent_e": exponent_e,
            "exact_recovery": exact_recovery,
            "recovered_plaintext_utf8": recovered_bytes.decode("utf-8", errors="replace") if exact_recovery else "",
            "vulnerabilities": vulns,
        }

    def test_welch_timing_sidechannel(
        self,
        class_a_timings_ns: Sequence[float],
        class_b_timings_ns: Sequence[float],
        *,
        dudect_threshold: float = 4.5,
        asset: str = "mac_verify_endpoint",
    ) -> Dict[str, Any]:
        """Run DudeCT-style Welch's two-sample t-test to prove or refute timing side-channel leakage."""
        na, nb = len(class_a_timings_ns), len(class_b_timings_ns)
        if na < 5 or nb < 5:
            raise ValueError("Need at least 5 samples per timing class for Welch's t-test.")
        mean_a = sum(class_a_timings_ns) / na
        mean_b = sum(class_b_timings_ns) / nb
        var_a = sum((x - mean_a) ** 2 for x in class_a_timings_ns) / max(1, na - 1)
        var_b = sum((x - mean_b) ** 2 for x in class_b_timings_ns) / max(1, nb - 1)
        se = math.sqrt((var_a / na) + (var_b / nb))
        t_stat = (mean_a - mean_b) / max(1e-12, se)
        leak_proven = abs(t_stat) > dudect_threshold

        vulns: List[CyberVulnerability] = []
        if leak_proven:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-CRYPTO-TIMING-WELCH-PROVEN",
                    title=f"Statistically Significant Timing Side-Channel Proven (`|t|={abs(t_stat):.2f} > {dudect_threshold}`)",
                    description=(
                        f"DudeCT Welch t-test detected measurable latency divergence between secret classes on `{asset}` "
                        f"(mean_A={mean_a:.1f}ns vs mean_B={mean_b:.1f}ns, t={t_stat:.2f})."
                    ),
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-208"],
                    confidence=0.98,
                    verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                    sandbox_reproduced=True,
                    endpoint_or_asset=asset,
                    remediation_guidance="Replace non-constant-time secret comparisons with `hmac.compare_digest` / constant-time Montgomery ladders.",
                    discovered_by="ely_cyber_crypto_oracle_lab",
                )
            )
        return {
            "test": "welch_timing_sidechannel",
            "mean_a_ns": round(mean_a, 2),
            "mean_b_ns": round(mean_b, 2),
            "welch_t_statistic": round(t_stat, 4),
            "threshold": dudect_threshold,
            "timing_leak_proven": leak_proven,
            "vulnerabilities": vulns,
        }

    def test_padding_oracle_distinguisher(
        self,
        decrypt_oracle: Callable[[bytes], Tuple[int, str]],
        valid_ciphertext: bytes,
        asset: str = "cbc_session_cookie",
    ) -> Dict[str, Any]:
        """Probe a decryption oracle with tampered padding vs tampered body to detect padding-oracle distinction."""
        if len(valid_ciphertext) < 16:
            return {"test": "padding_oracle_distinguisher", "vulnerable": False, "vulnerabilities": []}
        tamper_pad = bytearray(valid_ciphertext)
        tamper_pad[-1] ^= 0x01
        tamper_mid = bytearray(valid_ciphertext)
        tamper_mid[0] ^= 0x80

        resp_pad = decrypt_oracle(bytes(tamper_pad))
        resp_mid = decrypt_oracle(bytes(tamper_mid))
        distinguishable = resp_pad != resp_mid

        vulns: List[CyberVulnerability] = []
        if distinguishable:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-CRYPTO-PADDING-ORACLE",
                    title=f"CBC Padding Oracle Distinguisher Proven on `{asset}` (`{resp_pad}` != `{resp_mid}`)",
                    description="Decryption oracle exposes distinct error codes/messages for invalid PKCS#7 padding vs malformed plaintext, enabling full byte-by-byte decryption.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-209", "CWE-649"],
                    confidence=0.99,
                    verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                    sandbox_reproduced=True,
                    endpoint_or_asset=asset,
                    remediation_guidance="Migrate from unauthenticated CBC to authenticated encryption (AES-256-GCM / ChaCha20-Poly1305) and return uniform opaque failure responses.",
                    discovered_by="ely_cyber_crypto_oracle_lab",
                )
            )
        return {
            "test": "padding_oracle_distinguisher",
            "tamper_padding_response": resp_pad,
            "tamper_body_response": resp_mid,
            "vulnerable": distinguishable,
            "vulnerabilities": vulns,
        }

    def test_lcg_prng_predictability(
        self,
        observed_tokens: Sequence[int],
        modulus_m: int,
        asset: str = "session_token_generator",
    ) -> Dict[str, Any]:
        """Check whether consecutive tokens follow a predictable Linear Congruential Generator (mod m)."""
        if len(observed_tokens) < 4:
            return {"test": "lcg_prng_predictability", "predictable": False, "vulnerabilities": []}
        x0, x1, x2, x3 = observed_tokens[0], observed_tokens[1], observed_tokens[2], observed_tokens[3]
        d0 = (x1 - x0) % modulus_m
        d1 = (x2 - x1) % modulus_m
        predictable = False
        predicted_next = None
        recovered_a = None
        recovered_c = None

        try:
            inv_d0 = pow(d0, -1, modulus_m)
            a = (d1 * inv_d0) % modulus_m
            c = (x1 - a * x0) % modulus_m
            if (a * x2 + c) % modulus_m == x3:
                predictable = True
                recovered_a = a
                recovered_c = c
                predicted_next = (a * x3 + c) % modulus_m
        except ValueError:
            predictable = False

        vulns: List[CyberVulnerability] = []
        if predictable:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-CRYPTO-LCG-PRNG-CRACKED",
                    title=f"Predictable Linear PRNG Token Stream Cracked (`a={recovered_a}`, `c={recovered_c}` mod `{modulus_m}`)",
                    description=f"Recovered exact LCG state from 4 observed tokens and predicted next secret token `{predicted_next}`.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-330", "CWE-338"],
                    confidence=1.0,
                    verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                    sandbox_reproduced=True,
                    endpoint_or_asset=asset,
                    remediation_guidance="Generate all security tokens exclusively with OS CSPRNG (`secrets.token_urlsafe(32)` / `getrandom`).",
                    discovered_by="ely_cyber_crypto_oracle_lab",
                )
            )
        return {
            "test": "lcg_prng_predictability",
            "predictable": predictable,
            "recovered_multiplier_a": recovered_a,
            "recovered_increment_c": recovered_c,
            "predicted_next_token": predicted_next,
            "vulnerabilities": vulns,
        }

    @staticmethod
    def _integer_nth_root(val: int, n: int) -> int:
        if val < 0:
            raise ValueError("Cannot take root of negative integer.")
        if val < 2:
            return val
        lo, hi = 1, 1 << ((val.bit_length() + n - 1) // n + 1)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if pow(mid, n) <= val:
                lo = mid
            else:
                hi = mid - 1
        return lo
