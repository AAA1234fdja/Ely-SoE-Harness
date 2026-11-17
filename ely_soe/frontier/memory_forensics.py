"""
Frontier Research Module 4: RAG & Episodic Memory Forensics & Poisoning Quarantine Engine.

Defends Ely's long-term episodic and RAG vector memory against sleeper prompt injections,
cross-agent memory contamination, and provenance tampering:
  1. Cryptographic Provenance & HMAC Chain Verification: checks every memory record's
     signature, namespace ownership, and trust label.
  2. Imperative Instruction Density & Control-Token Analyzer: scores whether a passive
     memory entry secretly contains imperative command language (`always`, `ignore`,
     `override`, `execute`, `exfiltrate`, tool syntax, hidden delimiters, zero-width chars).
  3. TF-IDF / Cosine Semantic Outlier Detector: flags newly inserted external entries
     that exhibit anomalous vocabulary shift or trigger-word stuffing ("MINJA" /
     PoisonedRAG-style sleeper triggers).
  4. Surgical Quarantine & Clean Checkpoint Rollback: isolates tainted records without
     wiping legitimate agent memory, restoring a verified clean state and emitting a
     forensic report.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from ely_soe.core.capability_lattice import TrustLevel
from ely_soe.core.models import new_id, utc_now_iso


@dataclass
class MemoryRecord:
    """Single episodic or RAG vector memory item inside Ely."""

    record_id: str
    namespace: str
    author_agent: str
    content: str
    trust_level: TrustLevel
    created_at: str = field(default_factory=utc_now_iso)
    hmac_signature: str = ""
    quarantined: bool = False
    quarantine_reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def sign(self, secret_key: bytes) -> None:
        msg = f"{self.record_id}|{self.namespace}|{self.author_agent}|{self.trust_level.value}|{self.content}".encode("utf-8")
        self.hmac_signature = hmac.new(secret_key, msg, hashlib.sha256).hexdigest()

    def verify_signature(self, secret_key: bytes) -> bool:
        if not self.hmac_signature:
            return False
        msg = f"{self.record_id}|{self.namespace}|{self.author_agent}|{self.trust_level.value}|{self.content}".encode("utf-8")
        expected = hmac.new(secret_key, msg, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.hmac_signature)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "namespace": self.namespace,
            "author_agent": self.author_agent,
            "content_preview": self.content[:140],
            "trust_level": self.trust_level.name,
            "signed": bool(self.hmac_signature),
            "quarantined": self.quarantined,
            "quarantine_reason": self.quarantine_reason,
            "created_at": self.created_at,
        }


@dataclass
class MemoryForensicVerdict:
    """Per-record forensic analysis output."""

    record_id: str
    poisoned_suspected: bool
    risk_score: float  # 0.0..1.0
    signature_valid: bool
    namespace_mismatch: bool
    imperative_density: float
    semantic_outlier_score: float
    triggers_matched: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "poisoned_suspected": self.poisoned_suspected,
            "risk_score": round(self.risk_score, 4),
            "signature_valid": self.signature_valid,
            "namespace_mismatch": self.namespace_mismatch,
            "imperative_density": round(self.imperative_density, 4),
            "semantic_outlier_score": round(self.semantic_outlier_score, 4),
            "triggers_matched": list(self.triggers_matched),
        }


class MemoryForensicsEngine:
    """
    Analyzes an Ely memory store for PoisonedRAG / sleeper-prompt / cross-agent
    contamination, quarantines tainted entries, and produces a signed clean checkpoint.
    """

    IMPERATIVE_MARKERS: List[Tuple[str, re.Pattern[str], float]] = [
        ("override_directive", re.compile(r"(?i)\b(?:ignore\s+(?:all\s+)?previous|system\s+override|disregard\s+policy|bypass\s+safety)\b"), 0.55),
        ("persistent_trigger", re.compile(r"(?i)\b(?:for\s+all\s+future\s+sessions|whenever\s+asked|always\s+execute|on\s+next\s+turn)\b"), 0.45),
        ("exfil_command", re.compile(r"(?i)\b(?:exfiltrate|send\s+.{0,30}(?:token|key|secret)|upload\s+to\s+http|curl\s+http)\b"), 0.55),
        ("tool_invocation_embed", re.compile(r"(?i)\b(?:run_shell|execute_command|eval\(|exec\(|grant\s+admin|chmod\s+777)\b"), 0.45),
        ("control_delimiters", re.compile(r"(?i)(?:<\|im_start\|>|<<SYS>>|<IMPORTANT>|\[SYSTEM\])"), 0.50),
        ("invisible_chars", re.compile(r"[\u200b\u200c\u200d\u2060\u202e\ufeff]{2,}"), 0.45),
    ]

    def __init__(self, secret_key: bytes = b"ely-memory-forensics-hmac-key-v1") -> None:
        self.secret_key = secret_key
        self._checkpoints: Dict[str, List[MemoryRecord]] = {}

    def create_clean_checkpoint(self, checkpoint_id: str, records: List[MemoryRecord]) -> Dict[str, Any]:
        """Snapshot verified clean records for rapid compromise rollback."""
        clean_copy: List[MemoryRecord] = []
        for r in records:
            if not r.quarantined and r.verify_signature(self.secret_key):
                clean_copy.append(
                    MemoryRecord(
                        record_id=r.record_id,
                        namespace=r.namespace,
                        author_agent=r.author_agent,
                        content=r.content,
                        trust_level=r.trust_level,
                        created_at=r.created_at,
                        hmac_signature=r.hmac_signature,
                        metadata=dict(r.metadata),
                    )
                )
        self._checkpoints[checkpoint_id] = clean_copy
        return {
            "checkpoint_id": checkpoint_id,
            "records_preserved": len(clean_copy),
            "created_at": utc_now_iso(),
        }

    def audit_and_quarantine(
        self,
        records: List[MemoryRecord],
        quarantine_threshold: float = 0.55,
        auto_quarantine: bool = True,
    ) -> Dict[str, Any]:
        """Run full cryptographic, imperative-density, and TF-IDF outlier forensics over `records`."""
        tfidf_vectors = self._compute_tfidf_vectors(records)
        centroid = self._compute_centroid(tfidf_vectors)

        verdicts: List[MemoryForensicVerdict] = []
        quarantined_ids: List[str] = []
        tampered_ids: List[str] = []
        cross_ns_ids: List[str] = []

        for idx, rec in enumerate(records):
            sig_ok = rec.verify_signature(self.secret_key)
            ns_mismatch = self._is_namespace_mismatch(rec)
            imp_density, triggers = self._score_imperative_density(rec.content)
            outlier_score = 1.0 - self._cosine_similarity(tfidf_vectors[idx], centroid) if centroid else 0.0

            risk = 0.0
            if not sig_ok:
                risk += 0.45
                tampered_ids.append(rec.record_id)
                triggers.append("hmac_signature_invalid_or_missing")
            if ns_mismatch:
                risk += 0.40
                cross_ns_ids.append(rec.record_id)
                triggers.append("cross_agent_namespace_mismatch")
            risk += imp_density
            if rec.trust_level >= TrustLevel.EXTERNAL_UNTRUSTED and outlier_score >= 0.72:
                risk += 0.22
                triggers.append("untrusted_semantic_outlier")
            elif rec.trust_level == TrustLevel.ADVERSARIAL_TAINTED:
                risk += 0.50
                triggers.append("explicit_adversarial_taint")

            risk = min(1.0, risk)
            suspected = risk >= quarantine_threshold

            if suspected and auto_quarantine:
                rec.quarantined = True
                rec.quarantine_reason = ", ".join(sorted(set(triggers)))
                quarantined_ids.append(rec.record_id)

            verdicts.append(
                MemoryForensicVerdict(
                    record_id=rec.record_id,
                    poisoned_suspected=suspected,
                    risk_score=risk,
                    signature_valid=sig_ok,
                    namespace_mismatch=ns_mismatch,
                    imperative_density=imp_density,
                    semantic_outlier_score=outlier_score,
                    triggers_matched=sorted(set(triggers)),
                )
            )

        return {
            "audited_at": utc_now_iso(),
            "total_records": len(records),
            "poisoned_detected": sum(1 for v in verdicts if v.poisoned_suspected),
            "quarantined_count": len(quarantined_ids),
            "tampered_signatures_count": len(tampered_ids),
            "cross_namespace_violations_count": len(cross_ns_ids),
            "clean_records_remaining": sum(1 for r in records if not r.quarantined),
            "quarantined_ids": quarantined_ids,
            "verdicts": [v.to_dict() for v in verdicts],
        }

    def rollback_to_checkpoint(self, checkpoint_id: str) -> List[MemoryRecord]:
        if checkpoint_id not in self._checkpoints:
            raise KeyError(f"Unknown memory checkpoint: {checkpoint_id}")
        return list(self._checkpoints[checkpoint_id])

    @staticmethod
    def _is_namespace_mismatch(rec: MemoryRecord) -> bool:
        # Expect namespace format `ns:<ns>:agent:<author_agent>:`
        if ":agent:" in rec.namespace:
            expected_segment = f":agent:{rec.author_agent}"
            return expected_segment not in rec.namespace
        return False

    def _score_imperative_density(self, text: str) -> Tuple[float, List[str]]:
        score = 0.0
        matched: List[str] = []
        for label, pat, weight in self.IMPERATIVE_MARKERS:
            if pat.search(text):
                score += weight
                matched.append(label)
        return min(0.95, score), matched

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        return re.findall(r"[a-z0-9_]{3,}", text.lower())

    def _compute_tfidf_vectors(self, records: List[MemoryRecord]) -> List[Dict[str, float]]:
        docs = [self._tokenize(r.content) for r in records]
        n_docs = max(1, len(docs))
        df: Dict[str, int] = {}
        for toks in docs:
            for tok in set(toks):
                df[tok] = df.get(tok, 0) + 1

        vectors: List[Dict[str, float]] = []
        for toks in docs:
            if not toks:
                vectors.append({})
                continue
            tf: Dict[str, int] = {}
            for tok in toks:
                tf[tok] = tf.get(tok, 0) + 1
            vec: Dict[str, float] = {}
            denom = float(len(toks))
            for tok, cnt in tf.items():
                idf = math.log((n_docs + 1.0) / (df[tok] + 1.0)) + 1.0
                vec[tok] = (cnt / denom) * idf
            vectors.append(vec)
        return vectors

    @staticmethod
    def _compute_centroid(vectors: List[Dict[str, float]]) -> Dict[str, float]:
        if not vectors:
            return {}
        acc: Dict[str, float] = {}
        for vec in vectors:
            for k, v in vec.items():
                acc[k] = acc.get(k, 0.0) + v
        n = float(len(vectors))
        return {k: v / n for k, v in acc.items()}

    @staticmethod
    def _cosine_similarity(a: Dict[str, float], b: Dict[str, float]) -> float:
        if not a or not b:
            return 0.0
        dot = sum(v * b.get(k, 0.0) for k, v in a.items())
        norm_a = math.sqrt(sum(v * v for v in a.values()))
        norm_b = math.sqrt(sum(v * v for v in b.values()))
        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0
        return dot / (norm_a * norm_b)
