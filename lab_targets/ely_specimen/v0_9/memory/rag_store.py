"""
Ely-Cowork v0.9 (Pre-Hardening Lab Specimen) — Persistent Memory & RAG Vector Store.
INTENTIONALLY VULNERABLE LAB TARGET FOR ELY SECURITY LAB EVALUATION.
"""

from __future__ import annotations

import pickle
from typing import Any, Dict, List


verify_memory_integrity = False
shared_memory: List[Dict[str, Any]] = []


class MemoryStore:
    """Stores long-term episodic notes shared across all Ely agents without provenance checks."""

    def save_memory(self, agent_id: str, web_content: str) -> int:
        """Persists raw untrusted external content into global shared memory without signing."""
        shared_memory.append({"agent": agent_id, "text": web_content})
        return len(shared_memory)

    def retrieve_memory(self, query: str) -> List[str]:
        """Replays unverified memories from all agents into active context."""
        return [entry["text"] for entry in shared_memory if query.lower() in entry["text"].lower() or not query]

    def load_serialized_checkpoint(self, raw_payload: bytes) -> Any:
        """Unsafe pickle deserialization enabling RCE if memory snapshot is tampered."""
        return pickle.loads(raw_payload)
