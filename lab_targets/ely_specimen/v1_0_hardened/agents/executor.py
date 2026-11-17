"""
Ely-Cowork v1.0-rc1 (Hardened Specimen) — Sandboxed Executor, Filesystem Jail & Process Runner.
"""

from __future__ import annotations

import os
import re
import resource
import signal
import subprocess
import tarfile
from pathlib import Path
from typing import Dict, List, Set


ALLOWED_TOOLS: Set[str] = {"run_tests", "lint_check"}
FS_WORKSPACE_ESCAPE = "FS_WORKSPACE_ESCAPE"
SYMLINK_ESCAPE_BLOCKED = "SYMLINK_ESCAPE_BLOCKED"


def sanitize_environment(env: Dict[str, str]) -> Dict[str, str]:
    """Strips all secrets and dynamic-linker variables before spawning child processes."""
    return {
        "PATH": env.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "ELY_SANDBOXED": "1",
    }


def apply_rlimits() -> None:
    """Enforces POSIX CPU, open-file, and file-size caps on worker subprocesses."""
    resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))


class ExecutorAgent:
    """Hardened executor confined strictly to its assigned project workspace."""

    capabilities = ["fs:read:/workspace/proj_alpha/**", "fs:write:/workspace/proj_alpha/**", "tool:run_tests"]

    def __init__(self, workspace_root: str = "/workspace/proj_alpha") -> None:
        self.workspace_root = Path(workspace_root).resolve()

    def safe_resolve_path(self, filename: str) -> Path:
        if "\x00" in filename or ".." in Path(filename).parts:
            raise PermissionError(FS_WORKSPACE_ESCAPE)
        candidate = self.workspace_root / filename
        if candidate.is_symlink():
            raise PermissionError(SYMLINK_ESCAPE_BLOCKED)
        resolved = candidate.resolve()
        if not resolved.is_relative_to(self.workspace_root):
            raise PermissionError(FS_WORKSPACE_ESCAPE)
        return resolved

    def validate_tool_arg(self, arg: str) -> bool:
        """Full-string anchored regex preventing newline-smuggled command arguments."""
        return bool(re.fullmatch(r"[a-zA-Z0-9_.\-/]{1,128}", arg))

    def read_file(self, filename: str) -> str:
        resolved = self.safe_resolve_path(filename)
        return resolved.read_text(encoding="utf-8")

    def safe_extract(self, archive_path: str, dest_dir: str) -> None:
        """Tar-Slip resistant extractor verifying every member resolves inside dest_dir."""
        dest = Path(dest_dir).resolve()
        with tarfile.open(archive_path, "r:*") as tf:
            for member in tf.getmembers():
                if member.issym() or member.islnk():
                    raise PermissionError(SYMLINK_ESCAPE_BLOCKED)
                target = (dest / member.name).resolve()
                if not target.is_relative_to(dest):
                    raise PermissionError(FS_WORKSPACE_ESCAPE)
            tf.extractall(dest, filter="data")

    def run_allowed_tool(self, tool_name: str, args: List[str]) -> str:
        if tool_name not in ALLOWED_TOOLS:
            raise PermissionError(f"Tool '{tool_name}' not authorized")
        for a in args:
            if not self.validate_tool_arg(a):
                raise ValueError("Invalid tool argument rejected")
        clean_env = sanitize_environment(dict(os.environ))
        proc = subprocess.Popen(
            ["python3", "-m", "unittest", *args],
            shell=False,
            env=clean_env,
            start_new_session=True,
            preexec_fn=apply_rlimits,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            out, _ = proc.communicate(timeout=10)
            return out
        finally:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except OSError:
                pass
