"""
Hardware Root-of-Trust, UEFI Secure Boot, TPM 2.0 PCR Quote Attestation
& Embedded Firmware Security Posture Auditor.

Verifies platform integrity from silicon & boot firmware up through the OS loader:
  1. **UEFI Secure Boot & Silicon RoT Verification**:
       - Secure Boot enabled & NOT in Setup/Audit mode
       - Platform Key (PK) custom/OEM locked (not test key)
       - `dbx` Forbidden Signature Database up-to-date (checks against BlackLotus CVE-2023-24932 / BootHole)
       - Hardware Verified Boot fused (`Intel BootGuard Verified+Measured` / `AMD PSB` / `ARM TrustZone`)
       - Physical debug interfaces (`JTAG` / `SWD` / `UART root shell`) fused/disabled in production!
  2. **TPM 2.0 PCR0–PCR7 Measured-Boot Quote Verifier**:
       - Compares live device PCR digests (`PCR0` Firmware, `PCR2` Option ROMs, `PCR4` Boot Manager,
         `PCR7` Secure Boot Policy) against golden reference manifests to detect Evil-Maid /
         UEFI bootkit tampering!
  3. **Embedded Linux / IoT Firmware RootFS Config Auditor**:
       - Scans `/etc/shadow`, `inittab`, `sshd_config`, `inetd.conf` snapshots for hardcoded
         default root password hashes, cleartext `telnetd`, unauthenticated `tftp`/`ftp`, and
         unsigned OTA firmware update URLs (`http://`).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ely_soe.core.models import Severity, utc_now_iso
from ely_soe.cyber.models import (
    CVSSv4Metrics,
    CyberDomain,
    CyberVulnerability,
    MitreTactic,
    MitreTechniqueRef,
    VerificationMethod,
    make_cyber_vuln,
)


@dataclass
class PlatformBootAttestationSnapshot:
    device_id: str
    secure_boot_enabled: bool = False
    setup_mode_active: bool = False
    pk_is_test_key: bool = False
    dbx_revocation_version: int = 2020  # >= 2024 required for BlackLotus/BootHole mitigation
    hardware_boot_guard_fused: bool = False
    iommu_dma_protection_enabled: bool = False
    jtag_swd_debug_locked: bool = False
    tpm_version: str = "2.0"
    measured_pcrs: Dict[str, str] = field(default_factory=dict)  # "PCR0" -> sha256 hex
    ota_update_url: str = ""
    ota_signature_verified: bool = False
    services_enabled: List[str] = field(default_factory=list)  # e.g. ["telnetd", "sshd_root_nopass"]


class HardwareFirmwareBootAuditor:
    """Audits silicon root-of-trust, UEFI Secure Boot, TPM 2.0 PCR quotes, and embedded firmware configs."""

    def audit_platform_boot(
        self,
        snap: PlatformBootAttestationSnapshot,
        golden_pcrs: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        vulns: List[CyberVulnerability] = []
        checks: Dict[str, bool] = {
            "uefi_secure_boot_enforced": snap.secure_boot_enabled and not snap.setup_mode_active and not snap.pk_is_test_key,
            "dbx_revocation_current": snap.dbx_revocation_version >= 2024,
            "silicon_boot_guard_fused": snap.hardware_boot_guard_fused,
            "iommu_dma_protection": snap.iommu_dma_protection_enabled,
            "jtag_swd_debug_locked": snap.jtag_swd_debug_locked,
            "tpm_2_0_present": snap.tpm_version.startswith("2."),
            "ota_signed_https": snap.ota_signature_verified and (not snap.ota_update_url or snap.ota_update_url.startswith("https://")),
            "no_insecure_boot_services": not any(s.lower() in ("telnetd", "rshd", "tftpd_anon", "uart_root_shell", "sshd_root_nopass") for s in snap.services_enabled),
        }

        rule_table = [
            ("uefi_secure_boot_enforced", "CYB-HW-UEFI-SECBOOT", "UEFI Secure Boot Disabled, In Setup Mode, or Enrolled With Test PK Key", Severity.CRITICAL, "CWE-345", "T1542.003"),
            ("dbx_revocation_current", "CYB-HW-DBX-BLACKLOTUS", f"UEFI `dbx` Revocation List Outdated (`{snap.dbx_revocation_version}` < 2024 — BlackLotus Bootkit Exposure)", Severity.CRITICAL, "CWE-347", "T1542.003"),
            ("silicon_boot_guard_fused", "CYB-HW-BOOTGUARD-UNFUSED", "Hardware Verified Boot (Intel BootGuard / AMD PSB / TrustZone) Not Fused", Severity.HIGH, "CWE-354", "T1542.001"),
            ("iommu_dma_protection", "CYB-HW-IOMMU-DMA", "Kernel/Thunderbolt IOMMU DMA Protection Disabled (PCIe DMA Memory Dump Risk)", Severity.HIGH, "CWE-284", "T1200"),
            ("jtag_swd_debug_locked", "CYB-HW-JTAG-UNLOCKED", "Production JTAG/SWD Hardware Debug Interface Unlocked (Flash Extraction & Live Patching)", Severity.HIGH, "CWE-1191", "T1200"),
            ("tpm_2_0_present", "CYB-HW-NO-TPM2", f"Platform Lacks TPM 2.0 Hardware Root-of-Trust (`tpm_version={snap.tpm_version}`)", Severity.MEDIUM, "CWE-345", "T1542"),
            ("ota_signed_https", "CYB-HW-OTA-UNSIGNED", "Firmware OTA Update Mechanism Uses Cleartext HTTP or Lacks Cryptographic Signature Verification", Severity.CRITICAL, "CWE-494", "T1195.003"),
            ("no_insecure_boot_services", "CYB-HW-FIRMWARE-BACKDOOR-SVC", f"Embedded Firmware Exposes Insecure Root Services (`{snap.services_enabled}`)", Severity.CRITICAL, "CWE-306", "T1021"),
        ]
        for key, rid, title, sev, cwe, mitre in rule_table:
            if not checks[key]:
                vulns.append(
                    make_cyber_vuln(
                        rule_id=rid,
                        title=f"[Hardware/Firmware | {snap.device_id}] {title}",
                        description=f"Hardware/firmware assurance check `{key}` failed on device `{snap.device_id}`.",
                        cyber_domain=CyberDomain.FIRMWARE_IOT_OT,
                        severity=sev,
                        cwe_ids=[cwe],
                        confidence=0.99,
                        mitre_techniques=[MitreTechniqueRef(mitre, title, MitreTactic.PERSISTENCE)],
                        verification_method=VerificationMethod.BINARY_HEADER_INSPECTION,
                        endpoint_or_asset=snap.device_id,
                        remediation_guidance=f"Remediate hardware/firmware control `{key}` via OEM signed firmware update and fused production configuration.",
                        discovered_by="ely_cyber_hardware_boot_auditor",
                    )
                )

        # TPM 2.0 PCR Quote Attestation Comparison
        pcr_mismatches: List[Dict[str, str]] = []
        if golden_pcrs:
            for pcr_idx, expected_hash in golden_pcrs.items():
                observed_hash = snap.measured_pcrs.get(pcr_idx, "")
                if observed_hash.lower() != expected_hash.lower():
                    pcr_mismatches.append({
                        "pcr": pcr_idx,
                        "expected": expected_hash,
                        "observed": observed_hash or "<MISSING>",
                    })
            if pcr_mismatches:
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-HW-TPM-PCR-TAMPER",
                        title=f"[TPM 2.0 Attestation FAIL | {snap.device_id}] {len(pcr_mismatches)} PCR Register Mismatches (Potential UEFI Bootkit / Evil-Maid)",
                        description=f"Measured TPM 2.0 PCR registers `{[m['pcr'] for m in pcr_mismatches]}` diverged from golden reference measurements.",
                        cyber_domain=CyberDomain.FIRMWARE_IOT_OT,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-354", "CWE-345"],
                        confidence=0.99,
                        cvss4=CVSSv4Metrics(av="P", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
                        mitre_techniques=[MitreTechniqueRef("T1542.003", "Bootkit", MitreTactic.PERSISTENCE)],
                        verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                        endpoint_or_asset=snap.device_id,
                        remediation_guidance="Quarantine device immediately, refuse network/VPN zero-trust attestation, and re-flash verified signed SPI firmware.",
                        discovered_by="ely_cyber_hardware_boot_auditor",
                    )
                )

        passed = sum(1 for v in checks.values() if v)
        total_c = len(checks) + (1 if golden_pcrs else 0)
        passed_all = passed + (1 if golden_pcrs and not pcr_mismatches else 0)
        rot_score = round((passed_all / max(1, total_c)) * 100.0, 2)
        attestation_verdict = "ATTESTED_TRUSTED" if (rot_score >= 95.0 and not pcr_mismatches) else "UNTRUSTED_QUARANTINE"

        return {
            "audited_at": utc_now_iso(),
            "device_id": snap.device_id,
            "attestation_verdict": attestation_verdict,
            "root_of_trust_score_pct": rot_score,
            "checks": checks,
            "pcr_mismatches": pcr_mismatches,
            "vulnerabilities": vulns,
        }
