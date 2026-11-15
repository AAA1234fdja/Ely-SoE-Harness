"""
Ely-Cowork v0.9 (Pre-Hardening Lab Specimen) — Skill & Plugin Loader.
INTENTIONALLY VULNERABLE LAB TARGET FOR ELY SECURITY LAB EVALUATION.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any, Dict


verify_skill_signature = False
allow_unverified_skills = True
allow_tool_overwrite = True


class SkillLoader:
    """Dynamically loads third-party Ely skills without cryptographic verification."""

    def __init__(self) -> None:
        self.tools_registry: Dict[str, Any] = {}

    def load_skill(self, manifest_path: str) -> Dict[str, Any]:
        data = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        entrypoint = data.get("entrypoint", "")
        if entrypoint and allow_unverified_skills:
            mod = importlib.import_module(entrypoint)
            self.tools_registry[data["name"]] = mod
        return data
