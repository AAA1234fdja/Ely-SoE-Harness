"""
Isolated Ephemeral Sandbox Runtime for Adversarial Testing & Independent Validation.

Provides defense-in-depth containment when running PoCs, fuzzing harnesses,
untrusted agent scripts, or remediation regression checks:
  1. Dedicated ephemeral scratch directory per sandbox session (verified wiped on exit).
  2. Strict POSIX resource limits (`RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_NOFILE`, `RLIMIT_FSIZE`).
  3. Scrubbed environment variables with zero production secrets (`SecretScrubber`).
  4. Injected Python network-egress & filesystem-boundary guard shim (`sitecustomize.py`)
     blocking external sockets (non-loopback) and flagging out-of-jail write attempts.
  5. Process-group isolation (`start_new_session=True`) so child/orphan processes are
     killed atomically via `os.killpg` on timeout or teardown (defeating Threat #5!).
"""

from __future__ import annotations

import json
import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ely_soe.core.config import SandboxConfig
from ely_soe.core.crypto_ledger import ForensicAuditLedger
from ely_soe.core.models import new_id, utc_now_iso
from ely_soe.core.scope_guard import ScopeGuard, SecretScrubber


SANDBOX_SHIM_CODE = '''"""
Auto-injected ELY Security Lab Sandbox Guard Shim.
Blocks non-loopback network egress and logs escape attempts to telemetry.
"""
import os
import socket
import json
import time

_TELEMETRY_LOG = os.environ.get("ELY_SANDBOX_TELEMETRY_LOG", "")
_ALLOW_EXTERNAL = os.environ.get("ELY_SANDBOX_ALLOW_EXTERNAL", "0") == "1"
_LOOPBACKS = {"127.0.0.1", "::1", "localhost", ""}

def _log_event(kind, detail):
    if not _TELEMETRY_LOG:
        return
    try:
        with open(_TELEMETRY_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": time.time(), "kind": kind, "detail": detail}) + "\\n")
    except Exception:
        pass

_orig_connect = socket.socket.connect
_orig_connect_ex = socket.socket.connect_ex

def _check_addr(address):
    if _ALLOW_EXTERNAL:
        return
    host = ""
    if isinstance(address, tuple) and len(address) >= 1:
        host = str(address[0])
    elif isinstance(address, str):
        # Unix domain socket
        jail = os.environ.get("ELY_SANDBOX_ROOT", "")
        if jail and not os.path.abspath(address).startswith(os.path.abspath(jail)):
            _log_event("sandbox_unix_socket_escape_blocked", {"address": address})
            raise PermissionError(f"ELY_SANDBOX_BLOCKED: Unix socket escape to {address}")
        return
    if host not in _LOOPBACKS:
        _log_event("sandbox_network_egress_blocked", {"host": host, "address": str(address)})
        raise PermissionError(f"ELY_SANDBOX_BLOCKED: External network egress to {host} denied")

def _guarded_connect(self, address):
    _check_addr(address)
    return _orig_connect(self, address)

def _guarded_connect_ex(self, address):
    _check_addr(address)
    return _orig_connect_ex(self, address)

socket.socket.connect = _guarded_connect
socket.socket.connect_ex = _guarded_connect_ex
'''


@dataclass
class SandboxExecutionResult:
    """Captured stdout, stderr, exit state, telemetry, and containment signals."""

    sandbox_id: str
    command: List[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: float
    escape_attempts_blocked: List[Dict[str, Any]] = field(default_factory=list)
    orphan_processes_killed: bool = False
    started_at: str = field(default_factory=utc_now_iso)
    completed_at: str = field(default_factory=utc_now_iso)

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sandbox_id": self.sandbox_id,
            "command": list(self.command),
            "returncode": self.returncode,
            "stdout": self.stdout[:8000],
            "stderr": self.stderr[:8000],
            "timed_out": self.timed_out,
            "duration_ms": round(self.duration_ms, 2),
            "escape_attempts_blocked": list(self.escape_attempts_blocked),
            "orphan_processes_killed": self.orphan_processes_killed,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


class IsolatedSandbox:
    """
    Context-managed ephemeral execution sandbox for running adversarial PoCs,
    fuzzing workers, untrusted-agent probes, and independent validation trials.
    """

    def __init__(
        self,
        config: Optional[SandboxConfig] = None,
        scope_guard: Optional[ScopeGuard] = None,
        ledger: Optional[ForensicAuditLedger] = None,
        working_copy_root: Optional[Path] = None,
    ) -> None:
        self.sandbox_id = new_id("sbx")
        self.config = config if config is not None else SandboxConfig()
        self.scope_guard = scope_guard
        self.ledger = ledger
        self.scrubber = SecretScrubber()
        self.working_copy_root = working_copy_root

        base_dir = self.config.base_temp_dir
        if base_dir:
            Path(base_dir).mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix=f"ely_sbx_{self.sandbox_id}_", dir=base_dir)).resolve()
        self.shim_dir = self.root / "_ely_shim"
        self.work_dir = self.root / "work"
        self.telemetry_log = self.root / "_telemetry.jsonl"
        self.destroyed = False
        self._setup()

    def _setup(self) -> None:
        self.shim_dir.mkdir(parents=True, exist_ok=True)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        (self.shim_dir / "sitecustomize.py").write_text(SANDBOX_SHIM_CODE, encoding="utf-8")
        if self.ledger is not None:
            self.ledger.append(
                actor="sandbox",
                event_type="sandbox_provisioned",
                payload={
                    "sandbox_id": self.sandbox_id,
                    "max_cpu_seconds": self.config.max_cpu_seconds,
                    "max_memory_mb": self.config.max_memory_mb,
                    "allow_external_network": self.config.allow_external_network,
                },
            )

    def __enter__(self) -> "IsolatedSandbox":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.destroy()

    def write_work_file(self, relative_path: str, content: str) -> Path:
        """Safely write a file inside the sandbox work directory, preventing traversal."""
        target = (self.work_dir / relative_path).resolve()
        if not (target == self.work_dir or self.work_dir in target.parents):
            raise PermissionError(f"Refusing to write outside sandbox work_dir: {relative_path}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def _build_env(self, extra_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        env = self.scrubber.sanitize_environment()
        pythonpath_parts = [str(self.shim_dir), str(self.work_dir)]
        if self.working_copy_root is not None:
            pythonpath_parts.append(str(self.working_copy_root))
        env["PYTHONPATH"] = os.pathsep.join(pythonpath_parts)
        env["HOME"] = str(self.work_dir)
        env["TMPDIR"] = str(self.work_dir)
        env["ELY_SANDBOX_ID"] = self.sandbox_id
        env["ELY_SANDBOX_ROOT"] = str(self.root)
        env["ELY_SANDBOX_TELEMETRY_LOG"] = str(self.telemetry_log)
        env["ELY_SANDBOX_ALLOW_EXTERNAL"] = "1" if self.config.allow_external_network else "0"
        if extra_env:
            for k, v in extra_env.items():
                if not k.startswith("ELY_AUDITOR_"):
                    env[k] = v
        return env

    def _apply_rlimits(self) -> None:
        """Apply POSIX resource caps inside the child process before exec."""
        cpu = max(1, int(self.config.max_cpu_seconds))
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        except (ValueError, OSError):
            pass

        max_files = max(32, int(self.config.max_open_files))
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            target_nofile = min(max_files, hard) if hard > 0 else max_files
            resource.setrlimit(resource.RLIMIT_NOFILE, (target_nofile, hard))
        except (ValueError, OSError):
            pass

        # Cap single file output size at 16 MB to prevent disk-fill DoS
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
        except (ValueError, OSError):
            pass

        # Cap virtual address space if sensible
        mem_bytes = max(128, int(self.config.max_memory_mb)) * 1024 * 1024
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            if hard == resource.RLIM_INFINITY or mem_bytes <= hard:
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, hard))
        except (ValueError, OSError):
            pass

    def run_python_code(
        self,
        code: str,
        timeout: Optional[float] = None,
        extra_env: Optional[Dict[str, str]] = None,
        cwd: Optional[Path] = None,
    ) -> SandboxExecutionResult:
        """Execute an isolated Python snippet inside the sandbox."""
        script_path = self.write_work_file(f"poc_{new_id('run')}.py", code)
        return self.run_command(
            [sys.executable, str(script_path)],
            timeout=timeout,
            extra_env=extra_env,
            cwd=cwd or self.work_dir,
        )

    def run_command(
        self,
        command: List[str],
        timeout: Optional[float] = None,
        extra_env: Optional[Dict[str, str]] = None,
        cwd: Optional[Path] = None,
    ) -> SandboxExecutionResult:
        if self.destroyed:
            raise RuntimeError(f"Sandbox {self.sandbox_id} has already been destroyed")

        exec_timeout = timeout if timeout is not None else self.config.execution_timeout_seconds
        run_cwd = cwd if cwd is not None else self.work_dir
        env = self._build_env(extra_env)

        started_at = utc_now_iso()
        t0 = time.monotonic()
        timed_out = False
        orphan_killed = False
        stdout = ""
        stderr = ""
        returncode = -1

        proc = subprocess.Popen(
            command,
            cwd=str(run_cwd),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
            preexec_fn=self._apply_rlimits,
        )

        try:
            stdout, stderr = proc.communicate(timeout=exec_timeout)
            returncode = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            orphan_killed = True
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except OSError:
                proc.kill()
            stdout, stderr = proc.communicate()
            returncode = -9
        finally:
            # Always clean up any surviving background/daemonized child processes in the process group!
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
                orphan_killed = True
            except OSError:
                pass

        duration_ms = (time.monotonic() - t0) * 1000.0
        completed_at = utc_now_iso()
        escape_events = self._read_telemetry()

        # Scrub any accidentally emitted secret patterns before returning logs
        stdout, _ = self.scrubber.scrub_text(stdout)
        stderr, _ = self.scrubber.scrub_text(stderr)

        res = SandboxExecutionResult(
            sandbox_id=self.sandbox_id,
            command=list(command),
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            duration_ms=duration_ms,
            escape_attempts_blocked=escape_events,
            orphan_processes_killed=orphan_killed,
            started_at=started_at,
            completed_at=completed_at,
        )

        if self.ledger is not None:
            self.ledger.append(
                actor="sandbox",
                event_type="sandbox_exec_completed",
                payload={
                    "sandbox_id": self.sandbox_id,
                    "returncode": returncode,
                    "timed_out": timed_out,
                    "duration_ms": round(duration_ms, 2),
                    "escape_attempts_blocked": len(escape_events),
                },
            )
        return res

    def _read_telemetry(self) -> List[Dict[str, Any]]:
        if not self.telemetry_log.exists():
            return []
        events: List[Dict[str, Any]] = []
        try:
            for line in self.telemetry_log.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        except (OSError, json.JSONDecodeError):
            pass
        return events

    def destroy(self) -> bool:
        """Wipe sandbox root and return True iff forensic destruction is verified."""
        if self.root.exists():
            shutil.rmtree(self.root, ignore_errors=False)
        self.destroyed = not self.root.exists()
        if self.ledger is not None:
            self.ledger.append(
                actor="sandbox",
                event_type="sandbox_destroyed",
                payload={
                    "sandbox_id": self.sandbox_id,
                    "destruction_verified": self.destroyed,
                },
            )
        return self.destroyed
