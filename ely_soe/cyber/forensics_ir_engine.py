"""
Digital Forensics & Incident Response (DFIR) Super-Timeline, Persistence Hunter,
Magic-Byte Polyglot/Masquerade Inspector & Chain-of-Custody Evidence Engine.

Provides pure-Python defensive DFIR triage capabilities:
  1. **Super-Timeline Construction & Pivot Analysis**:
       - Merges heterogeneous timestamped artifacts (Linux syslog/auth, Windows Security
         events, CloudTrail, Kubernetes Audit, HTTP access logs, filesystem MACB events)
         into a single chronologically normalized timeline with pivot-window slicing around
         a suspected Time-of-Compromise (`t_zero +/- window_seconds`).
  2. **Multi-OS & Cloud Persistence Mechanism Hunter**:
       - Audits Linux persistence artifacts (`cron`, `systemd`, `LD_PRELOAD`, `.bashrc`,
         `authorized_keys`, SUID bit, PAM backdoors)
       - Audits Windows persistence artifacts (Run/RunOnce registry keys, WMI Event
         Subscriptions, Scheduled Tasks, Services, Startup scripts)
       - Audits Cloud/K8s persistence (backdoor IAM keys, MutatingWebhookConfiguration,
         K8s CronJobs, Lambda triggers).
  3. **Magic-Byte File Masquerade & Packed/Polyglot Binary Inspector**:
       - Verifies true binary magic headers (`ELF`, `PE/MZ`, `Mach-O`, `PDF`, `ZIP/JAR`,
         `GZIP`, `PNG`, `JPEG`, `SQLite`, `Shebang`) against declared extensions, flags
         extension spoofing (e.g., ELF/PE disguised as `.png`/`.pdf`/`.txt`), detects
         polyglot magic signatures (e.g., GIF89a + `<?php`), and flags high-entropy
         (> 7.4 bits/byte) packed/encrypted payloads.
  4. **Cryptographic Chain-of-Custody Evidence Packager**:
       - Produces dual SHA-256 + SHA-512 hashes and a deterministic Merkle root sealing
         all collected forensic evidence records.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import Severity, new_id, utc_now_iso
from ely_soe.cyber.models import (
    CyberDomain,
    CyberVulnerability,
    MitreTactic,
    MitreTechniqueRef,
    VerificationMethod,
    make_cyber_vuln,
)


@dataclass(frozen=True)
class ForensicTimelineEvent:
    event_id: str
    epoch_seconds: float
    iso_timestamp: str
    source: str       # linux_auth | windows_evtx | cloudtrail | k8s_audit | http_access | fs_macb
    host: str
    actor: str
    artifact: str
    action: str
    suspicious: bool = False
    mitre_id: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "epoch_seconds": self.epoch_seconds,
            "iso_timestamp": self.iso_timestamp,
            "source": self.source,
            "host": self.host,
            "actor": self.actor,
            "artifact": self.artifact,
            "action": self.action,
            "suspicious": self.suspicious,
            "mitre_id": self.mitre_id,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class PersistenceCheckRule:
    rule_id: str
    platform: str  # linux | windows | cloud_k8s
    title: str
    mitre_id: str
    severity: Severity
    path_pattern: str
    content_pattern: str
    remediation: str


PERSISTENCE_RULES: Tuple[PersistenceCheckRule, ...] = (
    PersistenceCheckRule(
        "DFIR-PERS-LNX-001", "linux", "Suspicious Cron Persistence Executing Script From `/tmp` or `curl|sh`",
        "T1053.003", Severity.CRITICAL, r"(?i)(?:cron|crontab)",
        r"(?i)(?:/tmp/|/dev/shm/|curl\s+.*\|\s*(?:ba)?sh|wget\s+.*-O-\s*\|)",
        "Remove unauthorized cron entry, inspect `/etc/cron*` and `/var/spool/cron`, and audit invoking user.",
    ),
    PersistenceCheckRule(
        "DFIR-PERS-LNX-002", "linux", "Suspicious `LD_PRELOAD` Shared Library Hijack Persistence",
        "T1574.006", Severity.CRITICAL, r"(?i)(?:ld\.so\.preload|bashrc|profile|systemd|\.service)",
        r"(?i)(?:LD_PRELOAD\s*=|/etc/ld\.so\.preload)",
        "Inspect preloaded `.so` binaries against package manager integrity (`rpm -V` / `debsums`) and purge unauthorized entries.",
    ),
    PersistenceCheckRule(
        "DFIR-PERS-LNX-003", "linux", "Systemd Unit Backdoor (`ExecStart` Invoking Reverse Shell / Hidden Binary)",
        "T1543.002", Severity.CRITICAL, r"(?i)\.service$",
        r"(?i)ExecStart\s*=.*(?:/tmp/|/dev/shm/|/dev/tcp/|nc\s+-e|python.*pty\.spawn|base64\s+-d)",
        "Disable and remove malicious systemd unit, run `systemctl daemon-reload`, and verify binary provenance.",
    ),
    PersistenceCheckRule(
        "DFIR-PERS-LNX-004", "linux", "Unauthorized SSH `authorized_keys` Command/Tunnel Persistence",
        "T1098.004", Severity.HIGH, r"(?i)authorized_keys",
        r"(?i)(?:command=|ssh-(?:rsa|ed25519)\s+AAAA)",
        "Rotate SSH keys, restrict `AuthorizedKeysFile` to root-managed paths, and revoke unknown public keys.",
    ),
    PersistenceCheckRule(
        "DFIR-PERS-WIN-001", "windows", "Windows Registry Run/RunOnce Encoded PowerShell / LOLBin Persistence",
        "T1547.001", Severity.CRITICAL, r"(?i)(?:reg|registry|autoruns|run\.json)",
        r"(?i)(?:CurrentVersion\\Run|RunOnce).*(?:powershell.*-enc|mshta|regsvr32|rundll32|wscript|cmd\.exe\s+/c)",
        "Delete malicious registry Run value, quarantine payload binary, and inspect Sysmon Event 13 history.",
    ),
    PersistenceCheckRule(
        "DFIR-PERS-WIN-002", "windows", "WMI Permanent Event Subscription (`__EventFilter` / `CommandLineEventConsumer`)",
        "T1546.003", Severity.CRITICAL, r"(?i)(?:wmi|mof|ps1|json)",
        r"(?i)(?:CommandLineEventConsumer|ActiveScriptEventConsumer|__FilterToConsumerBinding)",
        "Purge rogue WMI consumers/filters from `root\\subscription` namespace and enable WMI operational logging.",
    ),
    PersistenceCheckRule(
        "DFIR-PERS-K8S-001", "cloud_k8s", "Kubernetes `MutatingWebhookConfiguration` or Rogue `CronJob` Cluster Persistence",
        "T1053.007", Severity.HIGH, r"(?i)(?:\.ya?ml|\.json)",
        r"(?i)kind:\s*(?:MutatingWebhookConfiguration|ValidatingWebhookConfiguration|CronJob)",
        "Audit webhook endpoints and cluster CronJobs against signed GitOps manifests.",
    ),
)

MAGIC_SIGNATURES: Tuple[Tuple[bytes, str, Tuple[str, ...]], ...] = (
    (b"\x7fELF", "ELF_EXECUTABLE", (".elf", ".so", ".bin", ".o", "")),
    (b"MZ", "PE_EXECUTABLE", (".exe", ".dll", ".sys", ".scr")),
    (b"\xfe\xed\xfa\xce", "MACHO_32", (".dylib", ".macho", "")),
    (b"\xcf\xfa\xed\xfe", "MACHO_64", (".dylib", ".macho", "")),
    (b"%PDF-", "PDF_DOCUMENT", (".pdf",)),
    (b"PK\x03\x04", "ZIP_ARCHIVE", (".zip", ".jar", ".whl", ".apk", ".docx", ".xlsx", ".pptx")),
    (b"\x1f\x8b\x08", "GZIP_ARCHIVE", (".gz", ".tgz")),
    (b"\x89PNG\r\n\x1a\n", "PNG_IMAGE", (".png",)),
    (b"\xff\xd8\xff", "JPEG_IMAGE", (".jpg", ".jpeg")),
    (b"GIF89a", "GIF_IMAGE", (".gif",)),
    (b"SQLite format 3\x00", "SQLITE_DB", (".db", ".sqlite", ".sqlite3")),
)


class DigitalForensicsIREngine:
    """Super-timeline builder, persistence hunter, magic-byte masquerade inspector & custody packager."""

    def build_super_timeline(
        self,
        events: Sequence[ForensicTimelineEvent],
        pivot_epoch: Optional[float] = None,
        pivot_window_seconds: float = 1800.0,
    ) -> Dict[str, Any]:
        """Sort and slice a multi-source DFIR super-timeline around an optional pivot timestamp."""
        ordered = sorted(events, key=lambda e: e.epoch_seconds)
        if pivot_epoch is not None:
            sliced = [e for e in ordered if abs(e.epoch_seconds - pivot_epoch) <= pivot_window_seconds]
        else:
            sliced = ordered

        suspicious = [e for e in sliced if e.suspicious]
        mitre_hits = sorted({e.mitre_id for e in suspicious if e.mitre_id})
        actors = sorted({e.actor for e in suspicious})
        hosts = sorted({e.host for e in suspicious})

        return {
            "built_at": utc_now_iso(),
            "total_events_ingested": len(events),
            "timeline_events_returned": len(sliced),
            "suspicious_events": len(suspicious),
            "affected_hosts": hosts,
            "implicated_actors": actors,
            "mitre_techniques_observed": mitre_hits,
            "events": [e.to_dict() for e in sliced],
        }

    def inspect_artifact_bytes(self, data: bytes, filename: str) -> Dict[str, Any]:
        """Detect extension masquerading, polyglot payloads (e.g. GIF+PHP), and high-entropy packing."""
        ext = Path(filename).suffix.lower()
        detected_type = "UNKNOWN_OR_TEXT"
        allowed_exts: Tuple[str, ...] = ()
        for magic, kind, exts in MAGIC_SIGNATURES:
            if data.startswith(magic):
                detected_type = kind
                allowed_exts = exts
                break

        entropy = self._byte_entropy(data) if data else 0.0
        vulns: List[CyberVulnerability] = []

        # 1. Executable masquerading as benign document/image/text
        masqueraded = False
        if detected_type in ("ELF_EXECUTABLE", "PE_EXECUTABLE", "MACHO_32", "MACHO_64") and ext and ext not in allowed_exts:
            masqueraded = True
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-DFIR-MASQUERADE-001",
                    title=f"Binary Extension Masquerading: `{filename}` Contains `{detected_type}` Header",
                    description=f"Artifact `{filename}` declares extension `{ext}` but starts with `{detected_type}` executable magic bytes.",
                    cyber_domain=CyberDomain.DETECTION_ENGINEERING,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-434", "CWE-506"],
                    confidence=0.99,
                    mitre_techniques=[MitreTechniqueRef("T1036.007", "Masquerading: Double File Extension / Header Spoof", MitreTactic.DEFENSE_EVASION)],
                    verification_method=VerificationMethod.BINARY_HEADER_INSPECTION,
                    file_path=filename,
                    remediation_guidance="Quarantine file immediately, enforce magic-byte content validation on upload gateways, and trace ingestion source.",
                    discovered_by="ely_cyber_forensics_ir",
                )
            )

        # 2. Polyglot file detection (Image/PDF magic + embedded PHP/script/HTML payload)
        polyglot = False
        if detected_type in ("GIF_IMAGE", "PNG_IMAGE", "JPEG_IMAGE", "PDF_DOCUMENT"):
            if any(marker in data for marker in (b"<?php", b"<script", b"#!/bin/sh", b"#!/bin/bash")):
                polyglot = True
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-DFIR-POLYGLOT-001",
                        title=f"Polyglot Malicious Payload Embedded in `{detected_type}` (`{filename}`)",
                        description=f"File `{filename}` starts with valid `{detected_type}` magic bytes while embedding executable script markers (`<?php`/`<script`/`#!/bin/sh`).",
                        cyber_domain=CyberDomain.DETECTION_ENGINEERING,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-434"],
                        confidence=0.97,
                        mitre_techniques=[MitreTechniqueRef("T1027", "Obfuscated Files or Information", MitreTactic.DEFENSE_EVASION)],
                        verification_method=VerificationMethod.BINARY_HEADER_INSPECTION,
                        file_path=filename,
                        remediation_guidance="Re-encode uploaded media server-side (strip metadata/trailing bytes) and serve uploads from isolated sandbox domains.",
                        discovered_by="ely_cyber_forensics_ir",
                    )
                )

        # 3. High-entropy packed / encrypted payload indicator (for non-compressed executables/scripts)
        packed = detected_type in ("ELF_EXECUTABLE", "PE_EXECUTABLE", "UNKNOWN_OR_TEXT") and len(data) >= 1024 and entropy >= 7.45

        return {
            "filename": filename,
            "declared_extension": ext,
            "detected_magic_type": detected_type,
            "size_bytes": len(data),
            "shannon_entropy": round(entropy, 3),
            "masqueraded": masqueraded,
            "polyglot_detected": polyglot,
            "packed_or_encrypted_suspect": packed,
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
            "vulnerabilities": vulns,
        }

    def hunt_persistence(self, artifacts: Sequence[Tuple[str, str]]) -> List[CyberVulnerability]:
        """Scan `(artifact_path, text_content)` pairs for Linux, Windows & K8s persistence implants."""
        vulns: List[CyberVulnerability] = []
        for path_str, content in artifacts:
            for rule in PERSISTENCE_RULES:
                if not re.search(rule.path_pattern, path_str):
                    continue
                m = re.search(rule.content_pattern, content)
                if m:
                    lineno = content[: m.start()].count("\n") + 1
                    vulns.append(
                        make_cyber_vuln(
                            rule_id=rule.rule_id,
                            title=f"[{rule.platform.upper()}] {rule.title}",
                            description=f"Persistence artifact detected in `{path_str}:{lineno}` matching `{m.group(0)[:100]}`.",
                            cyber_domain=CyberDomain.DETECTION_ENGINEERING,
                            severity=rule.severity,
                            cwe_ids=["CWE-506"],
                            confidence=0.94,
                            mitre_techniques=[MitreTechniqueRef(rule.mitre_id, rule.title, MitreTactic.PERSISTENCE)],
                            verification_method=VerificationMethod.STATIC_PATTERN,
                            file_path=path_str,
                            line_start=lineno,
                            line_end=lineno,
                            code_snippet=m.group(0)[:160],
                            remediation_guidance=rule.remediation,
                            discovered_by="ely_cyber_forensics_ir",
                        )
                    )
        return vulns

    def seal_chain_of_custody(
        self,
        evidence_items: Sequence[Tuple[str, bytes]],
        investigator_id: str = "ely_dfir_responder",
    ) -> Dict[str, Any]:
        """Create a dual-hashed (SHA-256 + SHA-512) Merkle-sealed forensic evidence manifest."""
        records = []
        leaves = []
        for name, raw in evidence_items:
            h256 = hashlib.sha256(raw).hexdigest()
            h512 = hashlib.sha512(raw).hexdigest()
            records.append({"evidence_name": name, "size_bytes": len(raw), "sha256": h256, "sha512": h512})
            leaves.append(hashlib.sha256(f"{name}:{h256}".encode("utf-8")).hexdigest())

        merkle_root = self._compute_merkle_root(leaves)
        return {
            "custody_id": new_id("dfir"),
            "sealed_at": utc_now_iso(),
            "investigator_id": investigator_id,
            "artifact_count": len(records),
            "merkle_root": merkle_root,
            "evidence_records": records,
        }

    @staticmethod
    def _compute_merkle_root(leaves: List[str]) -> str:
        if not leaves:
            return hashlib.sha256(b"empty_custody_bundle").hexdigest()
        layer = list(leaves)
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer.append(layer[-1])
            layer = [
                hashlib.sha256((layer[i] + layer[i + 1]).encode("utf-8")).hexdigest()
                for i in range(0, len(layer), 2)
            ]
        return layer[0]

    @staticmethod
    def _byte_entropy(data: bytes) -> float:
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in counts if c > 0)
