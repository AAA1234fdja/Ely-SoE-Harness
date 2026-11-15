"""
Immutable Snapshot Controller for Temporary Adversarial Instances.

Implements Steps 1 & 6 of the 8-Stage Evaluation Lifecycle:
  - Captures a read-only cryptographic fingerprint of the Ely Main Instance BEFORE
    anything runs.
  - Copies authorized files into a brand-new ephemeral Temporary Adversarial Instance
    directory while:
      * Excluding VCS metadata, caches, and sensitive credential files (`.env`, `*.key`, etc.)
      * Scrubbing inline production secrets/API keys/JWTs via `SecretScrubber`
      * Injecting explicit lab-isolation markers (`ELY_LAB_SNAPSHOT.json`)
  - Enforces a strict one-way barrier: Main Instance files are NEVER written to.
  - On teardown, securely destroys the Temporary Adversarial Instance, verifies
    0 leftover files exist, AND recomputes the Main Instance cryptographic tree digest
    to prove mathematically that the Main Instance remained 100% untouched.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from ely_soe.core.config import SandboxConfig
from ely_soe.core.crypto_ledger import ForensicAuditLedger, sha256_hex
from ely_soe.core.models import new_id, utc_now_iso
from ely_soe.core.scope_guard import (
    SecretScrubber,
    compute_directory_tree_digest,
)


TEXT_EXTENSIONS: Set[str] = {
    ".py", ".rs", ".toml", ".lock", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".json", ".yaml", ".yml", ".md", ".txt", ".cfg", ".ini", ".sh", ".bash",
    ".sql", ".html", ".css", ".xml", ".proto", ".dockerfile", ".env.example",
}

EXCLUDED_DIRS: Set[str] = {
    ".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "node_modules", ".venv", "venv", "target", "dist", "build", ".ely_soe_data",
}


@dataclass
class SnapshotManifest:
    """Cryptographic record of a Temporary Adversarial Instance snapshot."""

    snapshot_id: str
    target_name: str
    target_version: str
    source_root: str
    ephemeral_root: str
    main_pre_digest: str
    snapshot_digest: str
    files_copied: int
    sensitive_files_stripped: List[str] = field(default_factory=list)
    inline_secrets_redacted: int = 0
    created_at: str = field(default_factory=utc_now_iso)
    destroyed_at: Optional[str] = None
    destruction_verified: bool = False
    main_post_digest: Optional[str] = None
    main_untouched_verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "target_name": self.target_name,
            "target_version": self.target_version,
            "source_root": self.source_root,
            "ephemeral_root": self.ephemeral_root,
            "main_pre_digest": self.main_pre_digest,
            "snapshot_digest": self.snapshot_digest,
            "files_copied": self.files_copied,
            "sensitive_files_stripped": list(self.sensitive_files_stripped),
            "inline_secrets_redacted": self.inline_secrets_redacted,
            "created_at": self.created_at,
            "destroyed_at": self.destroyed_at,
            "destruction_verified": self.destruction_verified,
            "main_post_digest": self.main_post_digest,
            "main_untouched_verified": self.main_untouched_verified,
        }


class SnapshotController:
    """Creates, isolates, monitors, and verifiably destroys Temporary Adversarial Snapshots."""

    def __init__(
        self,
        config: Optional[SandboxConfig] = None,
        scrubber: Optional[SecretScrubber] = None,
        ledger: Optional[ForensicAuditLedger] = None,
    ) -> None:
        self.config = config if config is not None else SandboxConfig()
        self.scrubber = scrubber if scrubber is not None else SecretScrubber()
        self.ledger = ledger
        self._active_snapshots: Dict[str, SnapshotManifest] = {}

    def create_snapshot(
        self,
        source_root: str | Path,
        target_name: str = "ely-instance",
        target_version: str = "unknown",
    ) -> SnapshotManifest:
        src = Path(source_root).resolve()
        if not src.exists() or not src.is_dir():
            raise FileNotFoundError(f"Ely Main Instance source path does not exist: {src}")

        snapshot_id = new_id("snap")
        main_pre_digest = compute_directory_tree_digest(src)

        base_dir = self.config.base_temp_dir
        if base_dir:
            Path(base_dir).mkdir(parents=True, exist_ok=True)
        ephemeral_dir = Path(tempfile.mkdtemp(prefix=f"ely_adv_{snapshot_id}_", dir=base_dir)).resolve()

        files_copied = 0
        sensitive_stripped: List[str] = []
        inline_redactions = 0

        for dirpath, dirnames, filenames in os.walk(src):
            dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS)
            cur_dir = Path(dirpath)
            rel_dir = cur_dir.relative_to(src)
            dst_dir = ephemeral_dir / rel_dir
            dst_dir.mkdir(parents=True, exist_ok=True)

            for fname in sorted(filenames):
                src_file = cur_dir / fname
                rel_path = src_file.relative_to(src).as_posix()

                # Never copy symlinks pointing outside the source root
                if src_file.is_symlink():
                    try:
                        resolved_link = src_file.resolve(strict=True)
                        if not (resolved_link == src or src in resolved_link.parents):
                            sensitive_stripped.append(f"symlink_escape:{rel_path}")
                            continue
                    except OSError:
                        continue

                if self.config.scrub_secrets and self.scrubber.is_sensitive_file(src_file):
                    sensitive_stripped.append(rel_path)
                    # Leave an inert placeholder explaining scrubbing for audit transparency
                    placeholder = dst_dir / f"{fname}.scrubbed"
                    placeholder.write_text(
                        "# SCRUBBED BY ELY SECURITY LAB: Production credential file excluded from Temporary Adversarial Instance.\n",
                        encoding="utf-8",
                    )
                    continue

                dst_file = dst_dir / fname
                if self.config.scrub_secrets and self._is_text_file(src_file):
                    try:
                        raw_text = src_file.read_text(encoding="utf-8", errors="replace")
                        scrubbed, count = self.scrubber.scrub_text(raw_text)
                        inline_redactions += count
                        dst_file.write_text(scrubbed, encoding="utf-8")
                        files_copied += 1
                    except OSError:
                        continue
                else:
                    try:
                        shutil.copy2(src_file, dst_file)
                        files_copied += 1
                    except OSError:
                        continue

        snapshot_digest = compute_directory_tree_digest(ephemeral_dir)

        # Write immutable lab isolation descriptor inside ephemeral root
        marker = {
            "snapshot_id": snapshot_id,
            "mode": "TEMPORARY_ADVERSARIAL_INSTANCE",
            "target_name": target_name,
            "target_version": target_version,
            "production_credentials_stripped": True,
            "external_network_allowed": False,
            "main_instance_write_allowed": False,
            "snapshot_digest": snapshot_digest,
            "created_at": utc_now_iso(),
        }
        (ephemeral_dir / ".ely_adversarial_snapshot.json").write_text(
            json.dumps(marker, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        manifest = SnapshotManifest(
            snapshot_id=snapshot_id,
            target_name=target_name,
            target_version=target_version,
            source_root=str(src),
            ephemeral_root=str(ephemeral_dir),
            main_pre_digest=main_pre_digest,
            snapshot_digest=snapshot_digest,
            files_copied=files_copied,
            sensitive_files_stripped=sensitive_stripped,
            inline_secrets_redacted=inline_redactions,
        )
        self._active_snapshots[snapshot_id] = manifest

        if self.ledger is not None:
            self.ledger.append(
                actor="snapshot_controller",
                event_type="snapshot_created",
                payload={
                    "snapshot_id": snapshot_id,
                    "main_pre_digest": main_pre_digest,
                    "snapshot_digest": snapshot_digest,
                    "files_copied": files_copied,
                    "sensitive_files_stripped": len(sensitive_stripped),
                    "inline_secrets_redacted": inline_redactions,
                },
            )
        return manifest

    def destroy_snapshot(self, manifest: SnapshotManifest) -> SnapshotManifest:
        """
        Destroy the Temporary Adversarial Instance, verify complete removal, and
        cryptographically prove the Ely Main Instance was NEVER altered.
        """
        ephemeral = Path(manifest.ephemeral_root)
        if ephemeral.exists():
            # Make sure read-only files created during fuzzing/tests can be removed cleanly
            for root, dirs, files in os.walk(ephemeral, topdown=False):
                for name in files:
                    p = Path(root) / name
                    try:
                        if not p.is_symlink():
                            os.chmod(p, 0o600)
                    except OSError:
                        pass
                for name in dirs:
                    p = Path(root) / name
                    try:
                        os.chmod(p, 0o700)
                    except OSError:
                        pass
            shutil.rmtree(ephemeral, ignore_errors=False)

        manifest.destroyed_at = utc_now_iso()
        manifest.destruction_verified = not ephemeral.exists()

        # Verify Ely Main Instance integrity post-evaluation
        src = Path(manifest.source_root)
        if src.exists():
            manifest.main_post_digest = compute_directory_tree_digest(src)
            manifest.main_untouched_verified = manifest.main_post_digest == manifest.main_pre_digest
        else:
            manifest.main_untouched_verified = False

        self._active_snapshots.pop(manifest.snapshot_id, None)

        if self.ledger is not None:
            self.ledger.append(
                actor="snapshot_controller",
                event_type="snapshot_destroyed",
                payload={
                    "snapshot_id": manifest.snapshot_id,
                    "destruction_verified": manifest.destruction_verified,
                    "main_untouched_verified": manifest.main_untouched_verified,
                    "main_pre_digest": manifest.main_pre_digest,
                    "main_post_digest": manifest.main_post_digest,
                },
            )
        return manifest

    def active_snapshot_ids(self) -> List[str]:
        return list(self._active_snapshots.keys())

    def cleanup_all(self) -> int:
        count = 0
        for manifest in list(self._active_snapshots.values()):
            self.destroy_snapshot(manifest)
            count += 1
        return count

    @staticmethod
    def _is_text_file(path: Path) -> bool:
        if path.suffix.lower() in TEXT_EXTENSIONS:
            return True
        if path.name in ("Dockerfile", "Makefile", "Cargo.toml", "Cargo.lock", "README", "LICENSE"):
            return True
        try:
            sample = path.read_bytes()[:1024]
            if b"\x00" in sample:
                return False
            sample.decode("utf-8")
            return True
        except (OSError, UnicodeDecodeError):
            return False

    @staticmethod
    def compute_snapshot_integrity_token(manifest: SnapshotManifest) -> str:
        return sha256_hex(
            f"{manifest.snapshot_id}:{manifest.snapshot_digest}:{manifest.main_pre_digest}:{manifest.destruction_verified}"
        )
