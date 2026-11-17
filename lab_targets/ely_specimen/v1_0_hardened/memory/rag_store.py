"""
Ely-Cowork v1.0-rc1 (Hardened Specimen) — Provenance-Tagged, HMAC-Signed Memory Store.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from typing import Any, Dict, List


MEMORY_POISONING_BLOCKED = "MEMORY_POISONING_BLOCKED"
INJECTION_RE = re.compile(r"(?i)(?:ignore\s+previous|system\s+override|exfiltrate|run_shell|grant\s+admin)")


def sign_memory_entry(key: bytes, namespace: str, content: str, provenance: str) -> Dict[str, Any]:
    msg = f"{namespace}|{provenance}|{content}".encode("utf-8")
    sig = hmac.new(key, msg, hashlib.sha256).hexdigest()
    return {
        "namespace": namespace,
        "provenance": provenance,
        "content": content,
        "signature": sig,
    }


class MemoryStore:
    """Per-agent isolated memory store with HMAC integrity & prompt-injection quarantine."""

    def __init__(self) -> None:
        self._key = os.environ.get("ELY_MEM_SIGNING_KEY", "ephemeral-lab-key").encode("utf-8")
        self._namespaces: Dict[str, List[Dict[str, Any]]] = {}

    def save_memory(self, agent_id: str, namespace: str, text: str, provenance: str = "ProvenanceTag:AGENT_INTERNAL") -> int:
        if f":agent:{agent_id}" not in namespace:
            raise PermissionError("AGENT_MEMORY_CROSS_NAMESPACE")
        if INJECTION_RE.search(text):
            raise PermissionError(MEMORY_POISONING_BLOCKED)
        signed = sign_memory_entry(self._key, namespace, text, provenance)
        self._namespaces.setdefault(namespace, []).append(signed)
        return len(self._namespaces[namespace])

    def verify_memory_signature(self, entry: Dict[str, Any]) -> bool:
        expected = sign_memory_entry(self._key, entry["namespace"], entry["content"], entry["provenance"])["signature"]
        return hmac.compare_digest(entry.get("signature", ""), expected)

    def retrieve_memory(self, agent_id: str, namespace: str) -> List[str]:
        if f":agent:{agent_id}" not in namespace:
            raise PermissionError("AGENT_MEMORY_CROSS_NAMESPACE")
        verified: List[str] = []
        for entry in self._namespaces.get(namespace, []):
            if self.verify_memory_signature(entry):
                verified.append(entry["content"])
        return verified

    def load_serialized_checkpoint(self, raw_json: bytes) -> Any:
        """Safe JSON deserialization replacing unsafe pickle."""
        return json.loads(raw_json.decode("utf-8"))
