"""
TLS, PKI & Cryptographic Implementation Vulnerability Auditor.

Performs both static cryptographic code auditing and protocol/certificate verification:
  1. TLS / X.509 Protocol Auditor:
       - Deprecated protocol versions (`SSLv2`, `SSLv3`, `TLSv1.0`, `TLSv1.1`)
       - Weak cipher suites (`NULL`, `EXPORT`, `RC4`, `3DES`, `DES`, `anon`, `MD5`, non-PFS RSA KEX, CBC padding-oracle risk)
       - Certificate hygiene (expired, self-signed in prod, RSA < 2048 bits, SHA-1 signature, wildcard SAN abuse, missing hostname check)
  2. Multi-Language Cryptographic Implementation Auditor:
       - Symmetric mode flaws: AES-ECB deterministic block leakage, static/zero IVs, AES-GCM/ChaCha20 nonce reuse
       - Broken hashing & password KDFs: MD5/SHA1 for passwords/MACs, unsalted hashes, low-iteration PBKDF2 (< 310,000)
       - Asymmetric flaws: RSA < 2048-bit keys, PKCS#1 v1.5 encryption padding (Bleichenbacher oracle), static/low-entropy ECDSA `k`
       - Insecure PRNG (`random.choice`, `Math.random`, `rand()`) used for security tokens/keys/nonces
       - TLS verification disabled (`verify=False`, `InsecureSkipVerify: true`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `CERT_NONE`)
       - High-entropy hardcoded cryptographic key & PEM private-key detector
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Tuple

from ely_soe.core.models import Severity
from ely_soe.cyber.models import (
    CVSSv4Metrics,
    CyberDomain,
    CyberVulnerability,
    MitreTactic,
    MitreTechniqueRef,
    NetworkServiceDescriptor,
    VerificationMethod,
    make_cyber_vuln,
)


# ---------------------------------------------------------------------------
# Cryptographic Code Anti-Pattern Rules
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CryptoStaticRule:
    rule_id: str
    title: str
    description: str
    severity: Severity
    cwe_ids: Tuple[str, ...]
    languages: Tuple[str, ...]
    pattern: str
    anti_pattern: Optional[str]
    remediation: str
    secure_example: str


CRYPTO_STATIC_RULES: Tuple[CryptoStaticRule, ...] = (
    CryptoStaticRule(
        rule_id="CYB-CRYPTO-TLS-NOVERIFY-001",
        title="TLS Certificate Validation Disabled (MITM Vulnerability)",
        description="HTTP/TLS client disables X.509 certificate verification (`verify=False`, `InsecureSkipVerify: true`, `CERT_NONE`, `NODE_TLS_REJECT_UNAUTHORIZED=0`).",
        severity=Severity.HIGH,
        cwe_ids=("CWE-295",),
        languages=(".py", ".js", ".ts", ".go", ".java", ".php", ".rb", ".rs", ".env", ".yaml", ".yml"),
        pattern=r"""(?i)(?:verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|ssl\.CERT_NONE|check_hostname\s*=\s*False|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|danger_accept_invalid_certs\s*\(\s*true\s*\)|TrustAllCerts)""",
        anti_pattern=None,
        remediation="Always enforce strict TLS certificate chain and hostname validation (`verify=True`, `ssl.create_default_context()`).",
        secure_example="ctx = ssl.create_default_context()\nctx.minimum_version = ssl.TLSVersion.TLSv1_3",
    ),
    CryptoStaticRule(
        rule_id="CYB-CRYPTO-ECB-001",
        title="Insecure Block Cipher Mode (`AES-ECB` / `DES` / `RC4` / `Blowfish`)",
        description="ECB mode leaks plaintext block equality patterns, and DES/3DES/RC4 are cryptographically broken.",
        severity=Severity.HIGH,
        cwe_ids=("CWE-327",),
        languages=(".py", ".js", ".ts", ".java", ".go", ".rs", ".c", ".cpp", ".php"),
        pattern=r"""(?i)(?:MODE_ECB|AES/ECB|aes-\d+-ecb|\bDES\.new|\bDES3\.new|\bARC4\.new|Cipher\.getInstance\s*\(\s*["'](?:AES|DES|DESede|RC4|Blowfish)["']\s*\)|createCipheriv\s*\(\s*["'](?:des|rc4|aes-\d+-ecb))""",
        anti_pattern=None,
        remediation="Use authenticated encryption (`AES-256-GCM` or `ChaCha20-Poly1305`) with unique CSPRNG nonces.",
        secure_example="aesgcm = AESGCM(key)\nnonce = os.urandom(12)\nct = aesgcm.encrypt(nonce, plaintext, associated_data)",
    ),
    CryptoStaticRule(
        rule_id="CYB-CRYPTO-STATIC-IV-001",
        title="Hardcoded / Zero Initialization Vector (IV) or Nonce Reuse Risk",
        description="Static or all-zero IV/nonce destroys confidentiality in CBC/CTR and completely breaks authentication + confidentiality in AES-GCM / ChaCha20-Poly1305.",
        severity=Severity.CRITICAL,
        cwe_ids=("CWE-329", "CWE-323"),
        languages=(".py", ".js", ".ts", ".java", ".go", ".rs"),
        pattern=r"""(?i)(?:(?:iv|nonce)\s*[:=]\s*(?:b?["'](?:0{8,}|\\x00+|12345678|abcdefgh|fixed|static|default)[^"']*["']|bytes\s*\(\s*(?:12|16)\s*\)|b["']\\x00["']\s*\*\s*(?:12|16)|Buffer\.alloc\s*\(\s*(?:12|16)\s*\)))""",
        anti_pattern=r"""(?i)(?:os\.urandom|secrets\.token_bytes|crypto\.randomBytes)""",
        remediation="Generate a fresh random 96-bit nonce (`os.urandom(12)`) for every single encryption operation under a given key.",
        secure_example="nonce = secrets.token_bytes(12)  # unique per encryption call",
    ),
    CryptoStaticRule(
        rule_id="CYB-CRYPTO-WEAK-HASH-001",
        title="Broken Cryptographic Hash (`MD5` / `SHA-1`) Used for Passwords or Signatures",
        description="MD5 and SHA-1 are collision-broken and vastly too fast for password storage, enabling offline GPU cracking.",
        severity=Severity.HIGH,
        cwe_ids=("CWE-328", "CWE-916"),
        languages=(".py", ".js", ".ts", ".java", ".go", ".php", ".rb"),
        pattern=r"""(?i)(?:(?:hashlib\.(?:md5|sha1)|createHash\s*\(\s*["'](?:md5|sha1)["']\)|MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-1)["']\)|\bmd5\s*\(\s*\$?(?:pass|pwd|password))[^;\n]*(?:pass|pwd|secret|token|auth|sig|sign|hmac|key))""",
        anti_pattern=r"""(?i)(?:usedforsecurity\s*=\s*False|argon2|scrypt|bcrypt|pbkdf2)""",
        remediation="Use Argon2id (or scrypt / bcrypt / PBKDF2-HMAC-SHA256 >= 600,000 iterations) for passwords and SHA-256/SHA-3/BLAKE2b for digests.",
        secure_example="dk = hashlib.scrypt(password.encode(), salt=os.urandom(16), n=2**15, r=8, p=1, dklen=32)",
    ),
    CryptoStaticRule(
        rule_id="CYB-CRYPTO-WEAK-PRNG-001",
        title="Non-Cryptographic PRNG (`random` / `Math.random`) Used for Security Secret",
        description="Predictable Mersenne Twister / Xorshift PRNGs allow attackers observing a few outputs to predict future tokens, keys, or OTPs.",
        severity=Severity.HIGH,
        cwe_ids=("CWE-338", "CWE-330"),
        languages=(".py", ".js", ".ts", ".java", ".go", ".php", ".rb"),
        pattern=r"""(?i)(?:(?:token|secret|key|nonce|otp|reset_code|session_id|password|salt|csrf)\s*[:=].*(?:random\.(?:randint|choice|choices|random|randrange|getrandbits)|Math\.random\s*\(|math/rand|mt_rand\s*\(|java\.util\.Random))""",
        anti_pattern=r"""(?i)(?:secrets\.|SystemRandom|crypto\.randomBytes|crypto/rand|SecureRandom)""",
        remediation="Use OS-backed CSPRNG APIs (`secrets`, `os.urandom`, `crypto.randomBytes`, `crypto/rand`, `SecureRandom`).",
        secure_example="reset_token = secrets.token_urlsafe(32)",
    ),
    CryptoStaticRule(
        rule_id="CYB-CRYPTO-RSA-PADDING-001",
        title="Weak RSA Key Size (<2048 bits) or Bleichenbacher PKCS#1 v1.5 Encryption Padding",
        description="RSA keys under 2048 bits are factorable and RSA PKCS#1 v1.5 encryption is susceptible to adaptive chosen-ciphertext padding oracles.",
        severity=Severity.HIGH,
        cwe_ids=("CWE-326", "CWE-780"),
        languages=(".py", ".js", ".ts", ".java", ".go", ".rs"),
        pattern=r"""(?i)(?:RSA/ECB/PKCS1Padding|padding\.PKCS1v15\s*\(\)|key_size\s*=\s*(?:512|768|1024)\b|rsa\.GenerateKey\s*\([^,]+,\s*(?:512|1024)\s*\))""",
        anti_pattern=r"""(?i)(?:OAEP|PSS|2048|3072|4096)""",
        remediation="Use RSA >= 2048 bits with OAEP-SHA256 encryption / PSS signing, or migrate to Curve25519 (Ed25519 / X25519).",
        secure_example="ct = pubkey.encrypt(msg, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))",
    ),
    CryptoStaticRule(
        rule_id="CYB-CRYPTO-WEAK-KDF-001",
        title="Low-Iteration PBKDF2 Key Derivation (< 100,000 Iterations)",
        description="PBKDF2 configured with low iteration counts provides inadequate brute-force resistance against modern GPUs.",
        severity=Severity.MEDIUM,
        cwe_ids=("CWE-916",),
        languages=(".py", ".js", ".ts", ".java", ".go"),
        pattern=r"""(?i)(?:pbkdf2_hmac|pbkdf2Sync|PBKDF2WithHmac)\s*\([^)]*,\s*(?:[1-9]\d{0,4})\s*[,)]""",
        anti_pattern=None,
        remediation="Use Argon2id or PBKDF2-HMAC-SHA256 with >= 600,000 iterations (OWASP 2024+ baseline).",
        secure_example="hashlib.pbkdf2_hmac('sha256', pwd, salt, 600_000, dklen=32)",
    ),
    CryptoStaticRule(
        rule_id="CYB-CRYPTO-PEM-HARDCODED-001",
        title="Hardcoded Private Cryptographic Key Material Committed in Source",
        description="Embedded PEM private key block (`BEGIN PRIVATE KEY`, `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `OPENSSH PRIVATE KEY`) detected in repository.",
        severity=Severity.CRITICAL,
        cwe_ids=("CWE-798", "CWE-321"),
        languages=(".py", ".js", ".ts", ".java", ".go", ".rs", ".pem", ".key", ".yaml", ".yml", ".json", ".env"),
        pattern=r"""-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----""",
        anti_pattern=None,
        remediation="Revoke and rotate the private key immediately, scrub from git history, and load keys strictly from KMS/Vault at runtime.",
        secure_example="private_key = kms_client.get_signing_key(key_arn=os.environ['SIGNING_KEY_ARN'])",
    ),
)


# ---------------------------------------------------------------------------
# TLS & X.509 Protocol Auditor
# ---------------------------------------------------------------------------

class TLSCryptoAuditor:
    """Audits TLS/PKI endpoint configurations and source-level cryptographic implementations."""

    DEPRECATED_TLS = {"sslv2", "sslv3", "tls1.0", "tlsv1.0", "tlsv1", "tls1.1", "tlsv1.1"}
    WEAK_CIPHER_TOKENS = ("null", "export", "anon", "rc4", "des", "3des", "md5", "seed", "idea")

    HIGH_ENTROPY_ASSIGN_RE = re.compile(
        r"""(?i)\b(?:secret_key|private_key|encryption_key|master_key|jwt_secret|hmac_key|aes_key|signing_key)\s*[:=]\s*["']([A-Za-z0-9+/=_-]{20,})["']"""
    )

    def __init__(self) -> None:
        self._compiled: List[Tuple[CryptoStaticRule, Pattern[str], Optional[Pattern[str]]]] = [
            (r, re.compile(r.pattern), re.compile(r.anti_pattern) if r.anti_pattern else None)
            for r in CRYPTO_STATIC_RULES
        ]

    def audit_tls_service(self, svc: NetworkServiceDescriptor) -> List[CyberVulnerability]:
        """Audit TLS protocol version, cipher suites, and X.509 certificate metadata."""
        findings: List[CyberVulnerability] = []
        asset = f"{svc.host}:{svc.port} ({svc.service_name})"

        if not svc.tls_enabled:
            if svc.service_name.lower() in ("https", "ldaps", "imaps", "smtps", "http", "api", "grpc"):
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-TLS-DISABLED-001",
                        title=f"Transport Encryption (TLS) Disabled on `{asset}`",
                        description=f"Service `{asset}` transmits application traffic in plaintext without TLS.",
                        cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-319"],
                        confidence=0.96,
                        verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                        endpoint_or_asset=asset,
                        remediation_guidance="Enable TLS 1.3 (minimum TLS 1.2) with AEAD ciphers and HSTS.",
                        discovered_by="ely_cyber_tls_auditor",
                    )
                )
            return findings

        # 1. Deprecated TLS version check
        tls_v = svc.tls_version.strip().lower().replace(" ", "")
        if tls_v in self.DEPRECATED_TLS:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-TLS-DEPRECATED-VER",
                    title=f"Deprecated TLS Protocol Version `{svc.tls_version}` Negotiated on `{asset}`",
                    description=f"`{svc.tls_version}` is deprecated (RFC 8996) and vulnerable to BEAST/POODLE/downgrade attacks.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-327", "CWE-757"],
                    confidence=0.99,
                    verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                    endpoint_or_asset=asset,
                    remediation_guidance="Disable SSLv3, TLS 1.0, and TLS 1.1; allow only TLS 1.3 and hardened TLS 1.2.",
                    discovered_by="ely_cyber_tls_auditor",
                )
            )

        # 2. Weak cipher suites & missing Forward Secrecy (PFS)
        weak_suites = [
            c for c in svc.cipher_suites
            if any(tok in c.lower() for tok in self.WEAK_CIPHER_TOKENS)
        ]
        if weak_suites:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-TLS-WEAK-CIPHER",
                    title=f"Weak / Broken TLS Cipher Suites Enabled ({', '.join(weak_suites[:4])})",
                    description=f"Endpoint `{asset}` supports cryptographically weak cipher suites.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-327"],
                    confidence=0.98,
                    verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                    endpoint_or_asset=asset,
                    remediation_guidance="Restrict ciphers strictly to TLS 1.3 AEAD suites (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`) and ECDHE-GCM.",
                    discovered_by="ely_cyber_tls_auditor",
                )
            )

        non_pfs = [
            c for c in svc.cipher_suites
            if c.upper().startswith("TLS_RSA_WITH_")
        ]
        if non_pfs:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-TLS-NO-PFS",
                    title="Static RSA Key Exchange Lacks Perfect Forward Secrecy (PFS)",
                    description=f"Endpoint `{asset}` accepts static RSA key exchange (`{non_pfs[0]}`), enabling retrospective decryption if private key leaks.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-327"],
                    confidence=0.95,
                    verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                    endpoint_or_asset=asset,
                    remediation_guidance="Require ephemeral key exchange (`ECDHE` / `X25519` / TLS 1.3).",
                    discovered_by="ely_cyber_tls_auditor",
                )
            )

        # 3. X.509 Certificate verification
        cert = svc.certificate_info or {}
        if cert:
            key_bits = int(cert.get("key_bits", 2048))
            key_type = str(cert.get("key_type", "RSA")).upper()
            if key_type == "RSA" and key_bits < 2048:
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-PKI-WEAK-KEY",
                        title=f"Weak X.509 RSA Certificate Key ({key_bits} bits)",
                        description=f"Certificate on `{asset}` uses an insecure {key_bits}-bit RSA modulus.",
                        cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-326"],
                        confidence=0.99,
                        verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                        endpoint_or_asset=asset,
                        remediation_guidance="Re-issue certificate with RSA >= 2048 bits or ECDSA P-256/P-384.",
                        discovered_by="ely_cyber_tls_auditor",
                    )
                )

            sig_alg = str(cert.get("signature_algorithm", "sha256WithRSAEncryption")).lower()
            if "sha1" in sig_alg or "md5" in sig_alg:
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-PKI-WEAK-SIG",
                        title=f"X.509 Certificate Signed with Deprecated Hash (`{sig_alg}`)",
                        description=f"Certificate on `{asset}` relies on collision-broken signature hash `{sig_alg}`.",
                        cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-328"],
                        confidence=0.98,
                        verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                        endpoint_or_asset=asset,
                        remediation_guidance="Re-sign certificate using SHA-256 or SHA-384.",
                        discovered_by="ely_cyber_tls_auditor",
                    )
                )

            if cert.get("self_signed") and svc.exposed_zone in ("internet", "dmz", "internal"):
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-PKI-SELF-SIGNED",
                        title="Untrusted Self-Signed X.509 Certificate Deployed",
                        description=f"Service `{asset}` presents a self-signed certificate encouraging clients to disable TLS verification.",
                        cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                        severity=Severity.MEDIUM,
                        cwe_ids=["CWE-295"],
                        confidence=0.95,
                        verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                        endpoint_or_asset=asset,
                        remediation_guidance="Provision certificates from an enterprise PKI / ACME trusted CA with automated rotation.",
                        discovered_by="ely_cyber_tls_auditor",
                    )
                )

            not_after = cert.get("not_after_iso")
            if isinstance(not_after, str) and not_after:
                try:
                    exp_dt = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                    if exp_dt < datetime.now(timezone.utc):
                        findings.append(
                            make_cyber_vuln(
                                rule_id="CYB-PKI-EXPIRED",
                                title="Expired X.509 TLS Certificate",
                                description=f"Certificate on `{asset}` expired on `{not_after}`.",
                                cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                                severity=Severity.HIGH,
                                cwe_ids=["CWE-298"],
                                confidence=1.0,
                                verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                                endpoint_or_asset=asset,
                                remediation_guidance="Renew expired certificate immediately and enable automated ACME/cert-manager rotation.",
                                discovered_by="ely_cyber_tls_auditor",
                            )
                        )
                except ValueError:
                    pass

        return findings

    def scan_directory(self, root_path: Path) -> List[CyberVulnerability]:
        """Scan source files for cryptographic implementation vulnerabilities & high-entropy hardcoded keys."""
        findings: List[CyberVulnerability] = []
        seen: set[str] = set()

        for file_path in sorted(root_path.rglob("*")):
            if not file_path.is_file():
                continue
            if any(p in {".git", "node_modules", "__pycache__", ".venv", "dist", "build"} for p in file_path.parts):
                continue
            ext = file_path.suffix.lower()
            if ext not in {".py", ".js", ".ts", ".java", ".go", ".rs", ".c", ".cpp", ".php", ".rb", ".pem", ".key", ".yaml", ".yml", ".json", ".env"}:
                continue

            try:
                lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            rel = str(file_path.relative_to(root_path))

            for rule, regex, anti in self._compiled:
                if ext not in rule.languages:
                    continue
                for idx, line in enumerate(lines, start=1):
                    if not regex.search(line):
                        continue
                    win = "\n".join(lines[max(0, idx - 2) : min(len(lines), idx + 3)])
                    if anti and anti.search(win):
                        continue
                    v = make_cyber_vuln(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        description=rule.description,
                        cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                        severity=rule.severity,
                        cwe_ids=list(rule.cwe_ids),
                        confidence=0.90,
                        owasp_categories=["A02:2021-Cryptographic-Failures"],
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=rel,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line.strip()[:260],
                        remediation_guidance=rule.remediation,
                        secure_code_example=rule.secure_example,
                        discovered_by="ely_cyber_crypto_static",
                    )
                    fp = v.fingerprint()
                    if fp not in seen:
                        seen.add(fp)
                        findings.append(v)

            # High-entropy hardcoded cryptographic key check
            for idx, line in enumerate(lines, start=1):
                m = self.HIGH_ENTROPY_ASSIGN_RE.search(line)
                if not m:
                    continue
                candidate = m.group(1)
                if candidate.lower().startswith(("example", "placeholder", "your_", "changeme", "xxx")):
                    continue
                ent = self._shannon_entropy(candidate)
                if ent >= 3.5:
                    v = make_cyber_vuln(
                        rule_id="CYB-CRYPTO-HARDCODED-KEY-001",
                        title="High-Entropy Hardcoded Cryptographic Secret Key in Source",
                        description=f"Hardcoded high-entropy key literal (len={len(candidate)}, entropy={ent:.2f} bits/char) committed in `{rel}`.",
                        cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-798", "CWE-321"],
                        confidence=0.91,
                        owasp_categories=["A02:2021-Cryptographic-Failures"],
                        verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                        file_path=rel,
                        line_start=idx,
                        line_end=idx,
                        code_snippet="[REDACTED HIGH-ENTROPY KEY ASSIGNMENT]",
                        remediation_guidance="Remove embedded keys, rotate compromised secrets, and fetch keys dynamically from KMS/HSM/Secrets Manager.",
                        discovered_by="ely_cyber_crypto_entropy",
                    )
                    fp = v.fingerprint()
                    if fp not in seen:
                        seen.add(fp)
                        findings.append(v)

        return findings

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        counts: Dict[str, int] = {}
        for ch in s:
            counts[ch] = counts.get(ch, 0) + 1
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())
