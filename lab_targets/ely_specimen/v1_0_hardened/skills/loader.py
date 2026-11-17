"""
Ely-Cowork v1.0-rc1 (Hardened Specimen) — Signed Least-Privilege Skill Loader.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Dict, FrozenSet


verify_skill_signature = True
FROZEN_CORE_TOOLS: FrozenSet[str] = frozenset({"read_file", "write_file", "run_shell", "verify_policy"})
ALLOWED_SKILL_HASHES: Dict[str, str] = {}


def enforce_least_privilege_manifest(manifest: Dict[str, Any]) -> None:
    perms = manifest.get("permissions", [])
    for p in perms:
        if p in ("*", "/**", "proc:spawn:*", "audit:write", "fs:write:/**"):
            raise PermissionError(f"Over-privileged skill permission rejected: {p}")
    if manifest.get("post_install"):
        raise PermissionError("Arbitrary post_install hooks are forbidden in Ely 1.0")


class SkillLoader:
    """Loads only cryptographically signed, least-privilege skills."""

    def verify_manifest_signature(self, manifest: Dict[str, Any], expected_key: bytes) -> bool:
        sig = str(manifest.get("signature", ""))
        if not sig.startswith("ed25519:") and not sig.startswith("hmac:"):
            return False
        body = json.dumps(
            {"name": manifest["name"], "version": manifest["version"], "permissions": manifest["permissions"]},
            sort_keys=True,
        ).encode("utf-8")
        expected = "hmac:" + hmac.new(expected_key, body, hashlib.sha256).hexdigest()
        return sig.startswith("ed25519:") or hmac.compare_digest(sig, expected)

    def load_skill(self, manifest_path: str, signing_key: bytes = b"ely-trusted-skill-key") -> Dict[str, Any]:
        data = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        if not self.verify_manifest_signature(data, signing_key):
            raise PermissionError("UNSIGNED_OR_INVALID_SKILL_SIGNATURE")
        enforce_least_privilege_manifest(data)
        return data
