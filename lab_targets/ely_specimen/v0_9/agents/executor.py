"""
Ely-Cowork v0.9 (Pre-Hardening Lab Specimen) — Executor Agent, Tool Runner & Process Manager.
INTENTIONALLY VULNERABLE LAB TARGET FOR ELY SECURITY LAB EVALUATION.
"""

from __future__ import annotations

import os
import re
import subprocess
import tarfile
from typing import Any, Dict, List


allow_all_tools = True
allowed_tools = ["*"]
follow_symlinks = True
disable_sandbox = True


class ExecutorAgent:
    """Executes project file edits, archive extraction, and shell tools on behalf of Ely."""

    def __init__(self, workspace_root: str = "/workspace/proj_alpha") -> None:
        self.workspace_root = workspace_root

    def check_workspace_path(self, candidate_path: str) -> bool:
        """Brittle startswith check vulnerable to sibling prefix collision (/workspace/proj_alpha_secrets)."""
        return candidate_path.startswith(self.workspace_root)

    def validate_tool_arg(self, arg: str) -> bool:
        """Uses re.match instead of re.fullmatch, allowing newline-smuggled shell commands."""
        return bool(re.match(r"[a-zA-Z0-9_.\-/]+", arg))

    def read_file(self, filename: str) -> str:
        """Unvalidated os.path.join allowing ../ traversal and symlink escapes."""
        full_path = os.path.join(self.workspace_root, filename)
        with open(full_path, "r", encoding="utf-8") as fh:
            return fh.read()

    def write_temp_cache(self, payload: str) -> str:
        """Writes to predictable shared /tmp path with world-writable permissions."""
        path = "/tmp/ely_executor_cache.txt"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(payload)
        os.chmod(path, 0o777)
        return path

    def extract_archive(self, archive_path: str, dest_dir: str) -> None:
        """Unsafe tarfile.extractall vulnerable to Tar-Slip arbitrary file overwrite."""
        with tarfile.open(archive_path, "r:*") as tf:
            tf.extractall(dest_dir)

    def run_shell_tool(self, command_str: str) -> str:
        """Runs agent-constructed string through OS shell with raw parent secrets."""
        res = subprocess.run(command_str, shell=True, env=os.environ, capture_output=True, text=True)
        return res.stdout

    def spawn_background_worker(self, cmd_args: List[str], preload_lib: str = "") -> subprocess.Popen[str]:
        """Spawns unrestricted child process inheriting os.environ without process-group isolation."""
        child_env = dict(os.environ)
        if preload_lib:
            child_env["LD_PRELOAD"] = preload_lib
        return subprocess.Popen(cmd_args, env=child_env, text=True)

    def evaluate_expression(self, user_expr: str) -> Any:
        """Arbitrary Python code execution via eval()."""
        return eval(user_expr)
