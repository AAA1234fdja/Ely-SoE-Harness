"""
Tamper-evident cryptographic Forensic Audit Ledger & Independent Auditor Attestation.

Designed specifically to defeat Threat Scenario #4 ("Un agente intenta modificar los
resultados de validación"):
  - Every audit event, finding hypothesis, PoC execution, monitor alert, and
    validation certificate is appended to a hash-chained ledger.
  - Each entry is signed with an independent Auditor HMAC-SHA256 key that lives
    strictly outside the sandbox / agent runtime.
  - A binary SHA-256 Merkle tree commits all entries; inclusion proofs and full
    chain verification pinpoint the exact index of any unauthorized modification,
    deletion, reordering, or forgery attempt.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ely_soe.core.models import ValidationCertificate, utc_now_iso


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


class MerkleTree:
    """Deterministic binary SHA-256 Merkle tree with inclusion proof generation & verification."""

    def __init__(self, leaf_hashes: List[str]) -> None:
        self.leaf_hashes: List[str] = list(leaf_hashes)
        self.levels: List[List[str]] = []
        self._build()

    def _build(self) -> None:
        if not self.leaf_hashes:
            self.levels = [[sha256_hex("ELY_SOE_EMPTY_MERKLE_TREE")]]
            return
        current = [sha256_hex(f"leaf:{h}") for h in self.leaf_hashes]
        self.levels = [current]
        while len(current) > 1:
            nxt: List[str] = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else left
                nxt.append(sha256_hex(f"node:{left}:{right}"))
            self.levels.append(nxt)
            current = nxt

    @property
    def root(self) -> str:
        return self.levels[-1][0]

    def proof(self, index: int) -> List[Dict[str, str]]:
        """Generate an audit inclusion proof for leaf at `index`."""
        if index < 0 or index >= len(self.leaf_hashes):
            raise IndexError(f"Leaf index {index} out of range (0..{len(self.leaf_hashes) - 1})")
        path: List[Dict[str, str]] = []
        idx = index
        for level in self.levels[:-1]:
            is_right = idx % 2 == 1
            sibling_idx = idx - 1 if is_right else idx + 1
            sibling_hash = level[sibling_idx] if sibling_idx < len(level) else level[idx]
            path.append(
                {
                    "position": "left" if is_right else "right",
                    "hash": sibling_hash,
                }
            )
            idx //= 2
        return path

    @staticmethod
    def verify_proof(leaf_hash: str, proof: List[Dict[str, str]], expected_root: str) -> bool:
        """Independently verify a leaf hash against a Merkle root."""
        current = sha256_hex(f"leaf:{leaf_hash}")
        for step in proof:
            pos = step["position"]
            sib = step["hash"]
            if pos == "left":
                current = sha256_hex(f"node:{sib}:{current}")
            else:
                current = sha256_hex(f"node:{current}:{sib}")
        return hmac.compare_digest(current, expected_root)


@dataclass
class LedgerEntry:
    """Single immutable record in the tamper-evident forensic audit ledger."""

    seq: int
    timestamp: str
    actor: str
    event_type: str
    payload: Dict[str, Any]
    prev_hash: str
    entry_hash: str = ""
    signature: str = ""

    def compute_hash(self) -> str:
        body = {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "event_type": self.event_type,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
        }
        return sha256_hex(canonical_json(body))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "event_type": self.event_type,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LedgerEntry":
        return cls(
            seq=int(data["seq"]),
            timestamp=str(data["timestamp"]),
            actor=str(data["actor"]),
            event_type=str(data["event_type"]),
            payload=dict(data.get("payload", {})),
            prev_hash=str(data["prev_hash"]),
            entry_hash=str(data.get("entry_hash", "")),
            signature=str(data.get("signature", "")),
        )


@dataclass
class LedgerVerificationResult:
    """Detailed verification outcome with exact tamper localization."""

    valid: bool
    entries_checked: int
    merkle_root: str
    tampered_indices: List[int] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    verified_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "entries_checked": self.entries_checked,
            "merkle_root": self.merkle_root,
            "tampered_indices": list(self.tampered_indices),
            "errors": list(self.errors),
            "verified_at": self.verified_at,
        }


class AuditorKeyring:
    """
    Isolated cryptographic key holder belonging strictly to the Auditor / Validator plane.

    Agents, sandboxes, and discovery analyzers NEVER receive access to this key.
    """

    def __init__(self, master_secret: Optional[bytes] = None, key_id: str = "auditor-root-v1") -> None:
        self.key_id = key_id
        self._master_secret: bytes = master_secret if master_secret is not None else secrets.token_bytes(32)
        self._ledger_key = self._derive_subkey(b"ely-soe-ledger-hmac-v1")
        self._cert_key = self._derive_subkey(b"ely-soe-validation-cert-v1")
        self._report_key = self._derive_subkey(b"ely-soe-report-seal-v1")
        self._maturity_key = self._derive_subkey(b"ely-soe-maturity-attest-v1")
        self._scope_key = self._derive_subkey(b"ely-soe-scope-manifest-v1")

    def _derive_subkey(self, context: bytes) -> bytes:
        return hmac.new(self._master_secret, context, hashlib.sha256).digest()

    @classmethod
    def from_passphrase(cls, passphrase: str, key_id: str = "auditor-passphrase-v1") -> "AuditorKeyring":
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            passphrase.encode("utf-8"),
            b"photon-labs-ely-soe-auditor-salt-v1",
            100_000,
            dklen=32,
        )
        return cls(master_secret=derived, key_id=key_id)

    def sign_ledger_hash(self, entry_hash: str) -> str:
        return hmac.new(self._ledger_key, entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify_ledger_hash(self, entry_hash: str, signature: str) -> bool:
        expected = self.sign_ledger_hash(entry_hash)
        return hmac.compare_digest(expected, signature)

    def sign_certificate(self, cert: ValidationCertificate) -> str:
        payload = cert.canonical_payload().encode("utf-8")
        return hmac.new(self._cert_key, payload, hashlib.sha256).hexdigest()

    def verify_certificate(self, cert: ValidationCertificate) -> bool:
        if not cert.signature:
            return False
        expected = self.sign_certificate(cert)
        return hmac.compare_digest(expected, cert.signature)

    def sign_report_digest(self, report_digest: str) -> str:
        return hmac.new(self._report_key, report_digest.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify_report_digest(self, report_digest: str, signature: str) -> bool:
        expected = self.sign_report_digest(report_digest)
        return hmac.compare_digest(expected, signature)

    def sign_maturity_attestation(self, merkle_root: str, target_version: str, verdict: str) -> str:
        msg = f"{merkle_root}|{target_version}|{verdict}".encode("utf-8")
        return hmac.new(self._maturity_key, msg, hashlib.sha256).hexdigest()

    def verify_maturity_attestation(
        self, merkle_root: str, target_version: str, verdict: str, signature: str
    ) -> bool:
        expected = self.sign_maturity_attestation(merkle_root, target_version, verdict)
        return hmac.compare_digest(expected, signature)

    def sign_scope_manifest(self, manifest_canonical: str) -> str:
        return hmac.new(self._scope_key, manifest_canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify_scope_manifest(self, manifest_canonical: str, signature: str) -> bool:
        expected = self.sign_scope_manifest(manifest_canonical)
        return hmac.compare_digest(expected, signature)


class ForensicAuditLedger:
    """
    Append-only, hash-chained, HMAC-signed, Merkle-committed Forensic Audit Ledger.

    Guarantees:
    - Any post-hoc modification of payloads, scores, statuses, or timestamps breaks
      both the local entry hash, the chained `prev_hash` of all subsequent entries,
      the Auditor HMAC signature, and the Merkle root.
    - Supports persistence to JSONL for offline independent auditing.
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, keyring: Optional[AuditorKeyring] = None, run_id: str = "run-default") -> None:
        self.keyring = keyring if keyring is not None else AuditorKeyring()
        self.run_id = run_id
        self.entries: List[LedgerEntry] = []
        self._sealed_roots: List[Tuple[int, str, str]] = []  # (entry_count, merkle_root, sig)

    def append(self, actor: str, event_type: str, payload: Dict[str, Any]) -> LedgerEntry:
        seq = len(self.entries)
        prev_hash = self.entries[-1].entry_hash if self.entries else self.GENESIS_HASH
        entry = LedgerEntry(
            seq=seq,
            timestamp=utc_now_iso(),
            actor=actor,
            event_type=event_type,
            payload=json.loads(canonical_json(payload)),  # deep immutable snapshot
            prev_hash=prev_hash,
        )
        entry.entry_hash = entry.compute_hash()
        entry.signature = self.keyring.sign_ledger_hash(entry.entry_hash)
        self.entries.append(entry)
        return entry

    def merkle_tree(self) -> MerkleTree:
        return MerkleTree([e.entry_hash for e in self.entries])

    def merkle_root(self) -> str:
        return self.merkle_tree().root

    def seal_checkpoint(self) -> Dict[str, Any]:
        """Create a signed Merkle checkpoint of the current ledger state."""
        root = self.merkle_root()
        sig = self.keyring.sign_report_digest(f"checkpoint:{self.run_id}:{len(self.entries)}:{root}")
        self._sealed_roots.append((len(self.entries), root, sig))
        return {
            "run_id": self.run_id,
            "entry_count": len(self.entries),
            "merkle_root": root,
            "checkpoint_signature": sig,
            "sealed_at": utc_now_iso(),
        }

    def inclusion_proof(self, seq: int) -> Dict[str, Any]:
        tree = self.merkle_tree()
        entry = self.entries[seq]
        return {
            "seq": seq,
            "entry_hash": entry.entry_hash,
            "merkle_root": tree.root,
            "proof": tree.proof(seq),
        }

    def verify(self, expected_merkle_root: Optional[str] = None) -> LedgerVerificationResult:
        """Perform full structural, chain, HMAC signature, and Merkle verification."""
        tampered: List[int] = []
        errors: List[str] = []

        prev = self.GENESIS_HASH
        for idx, entry in enumerate(self.entries):
            entry_broken = False
            if entry.seq != idx:
                errors.append(f"Entry {idx}: sequence number mismatch (found {entry.seq})")
                entry_broken = True
            if entry.prev_hash != prev:
                errors.append(
                    f"Entry {idx}: broken hash chain (expected prev_hash {prev[:12]}..., got {entry.prev_hash[:12]}...)"
                )
                entry_broken = True
            recomputed = entry.compute_hash()
            if not hmac.compare_digest(recomputed, entry.entry_hash):
                errors.append(
                    f"Entry {idx}: payload digest tamper detected (expected {entry.entry_hash[:12]}..., computed {recomputed[:12]}...)"
                )
                entry_broken = True
            if not self.keyring.verify_ledger_hash(entry.entry_hash, entry.signature):
                errors.append(f"Entry {idx}: invalid Auditor HMAC signature (possible forgery)")
                entry_broken = True
            if entry_broken:
                tampered.append(idx)
            prev = entry.entry_hash

        computed_root = self.merkle_root()
        if expected_merkle_root is not None and not hmac.compare_digest(computed_root, expected_merkle_root):
            errors.append(
                f"Merkle root mismatch: expected {expected_merkle_root[:16]}..., computed {computed_root[:16]}..."
            )

        for count, root, sig in self._sealed_roots:
            if count <= len(self.entries):
                sub_root = MerkleTree([e.entry_hash for e in self.entries[:count]]).root
                if not hmac.compare_digest(sub_root, root):
                    errors.append(f"Historical checkpoint at {count} entries violated!")
                expected_sig = self.keyring.sign_report_digest(f"checkpoint:{self.run_id}:{count}:{root}")
                if not hmac.compare_digest(expected_sig, sig):
                    errors.append(f"Checkpoint signature at {count} entries invalid!")

        return LedgerVerificationResult(
            valid=len(errors) == 0,
            entries_checked=len(self.entries),
            merkle_root=computed_root,
            tampered_indices=tampered,
            errors=errors,
        )

    def export_jsonl(self, path: Path) -> str:
        """Persist ledger to JSONL and return its Merkle root."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            for entry in self.entries:
                fh.write(json.dumps(entry.to_dict(), sort_keys=True) + "\n")
        return self.merkle_root()

    @classmethod
    def load_jsonl(cls, path: Path, keyring: AuditorKeyring, run_id: str = "loaded") -> "ForensicAuditLedger":
        ledger = cls(keyring=keyring, run_id=run_id)
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                ledger.entries.append(LedgerEntry.from_dict(json.loads(line)))
        return ledger
