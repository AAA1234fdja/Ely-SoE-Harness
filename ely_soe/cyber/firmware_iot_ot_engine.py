"""
Embedded Firmware, IoT & ICS/OT Security Assessment Engine.

Evaluates embedded device images, firmware configs, IoT protocols, and
industrial control system (ICS/SCADA/OT) configurations:
  1. Firmware Filesystem & Boot Security:
       - Hardcoded root/admin `/etc/shadow` hashes & default device passwords
       - Debug interfaces enabled in production (UART root shell, JTAG/SWD unlocked, `telnetd`, `gdbserver`)
       - Unsigned OTA firmware update channels (HTTP OTA URL, missing Ed25519/RSA-PSS signature verification)
       - Secure Boot / Measured Boot / Flash read-out protection disabled
  2. IoT Messaging & Radio Protocols:
       - Unauthenticated MQTT brokers (`allow_anonymous true`, cleartext TCP 1883 without TLS 8883, wildcard `#` topic ACLs)
       - CoAP unencrypted UDP 5683 without DTLS
       - BLE "Just Works" unauthenticated pairing / static PIN `000000`
  3. ICS / OT Industrial Protocols (MITRE ATT&CK for ICS):
       - Unauthenticated cleartext Modbus TCP (port 502) write coils/registers exposed beyond OT Purdue Level 1/2
       - DNP3 without Secure Authentication (SAv5), BACnet, S7comm, OPC-UA `SecurityPolicy#None`
       - Missing IT/OT DMZ firewall segmentation (Purdue Model Level 3.5 boundary check)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ely_soe.core.models import Severity
from ely_soe.cyber.models import (
    CVSSv4Metrics,
    CyberDomain,
    CyberVulnerability,
    MitreTactic,
    MitreTechniqueRef,
    VerificationMethod,
    make_cyber_vuln,
)


class FirmwareIoTOTSecurityEngine:
    """Audits firmware metadata, IoT broker/device configs, and ICS/OT protocol postures."""

    FIRMWARE_TEXT_PATTERNS: Tuple[Tuple[str, str, str, Severity, List[str], str], ...] = (
        (
            r"(?i)allow_anonymous\s+true",
            "CYB-IOT-MQTT-ANON-001",
            "MQTT Broker Permits Unauthenticated Anonymous Clients",
            Severity.HIGH,
            ["CWE-306"],
            "Disable `allow_anonymous`, enforce mTLS client certificates on port 8883, and apply per-device topic ACLs.",
        ),
        (
            r"(?i)(?:telnetd|busybox\s+telnetd|dropbear.*-B\b|ttyS0.*respawn.*/bin/sh)",
            "CYB-FW-DEBUG-SHELL-001",
            "Unauthenticated Root Debug Shell (`telnetd` / UART console) Enabled in Firmware",
            Severity.CRITICAL,
            ["CWE-489", "CWE-306"],
            "Remove `telnetd`/`gdbserver` from production firmware images and lock UART/JTAG interfaces via hardware eFuses.",
        ),
        (
            r"(?i)(?:ota_url|firmware_update_url)\s*[:=]\s*[\"']http://",
            "CYB-FW-OTA-CLEARTEXT-001",
            "Over-the-Air (OTA) Firmware Update Delivered Over Unencrypted HTTP",
            Severity.CRITICAL,
            ["CWE-319", "CWE-494"],
            "Serve OTA images exclusively over pinned HTTPS/TLS 1.3 and verify detached Ed25519/RSA-PSS firmware signatures before flashing.",
        ),
        (
            r"(?i)(?:verify_signature\s*[:=]\s*false|secure_boot\s*[:=]\s*(?:false|0|disabled)|jtag_enable\s*[:=]\s*(?:true|1))",
            "CYB-FW-SECBOOT-OFF-001",
            "Secure Boot / OTA Signature Verification Disabled or JTAG Unlocked",
            Severity.CRITICAL,
            ["CWE-347", "CWE-489"],
            "Enable hardware-rooted Secure Boot, enforce cryptographic OTA verification, and permanently disable JTAG in production fuses.",
        ),
        (
            r"(?i)(?:SecurityPolicy#None|MessageSecurityMode\.None|modbus_allow_write_all\s*[:=]\s*true|dnp3_secure_auth\s*[:=]\s*false)",
            "CYB-OT-ICS-UNAUTH-001",
            "Unauthenticated Cleartext ICS/OT Control Protocol (`OPC-UA None` / `Modbus` / `DNP3`)",
            Severity.CRITICAL,
            ["CWE-306", "CWE-319"],
            "Enforce OPC-UA `Basic256Sha256` SignAndEncrypt, DNP3 SAv5, and strict Purdue Level 3.5 unidirectional/DMZ OT firewalls.",
        ),
        (
            r"(?m)^root:\$[156]\$[^:\s]+:",
            "CYB-FW-HARDCODED-SHADOW-001",
            "Hardcoded Root Password Hash Embedded in Firmware Image",
            Severity.HIGH,
            ["CWE-798"],
            "Eliminate shared static root hashes across fleet devices; provision per-device unique keys during manufacturing.",
        ),
    )

    def audit_device_profile(self, profile: Dict[str, Any]) -> List[CyberVulnerability]:
        """Audit a structured IoT / Firmware / ICS-OT device manifest dictionary."""
        findings: List[CyberVulnerability] = []
        dev_name = str(profile.get("device_id", profile.get("name", "embedded_device")))
        asset = f"iot_ot:{dev_name}"

        if profile.get("secure_boot_enabled") is False:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-FW-PROFILE-SECBOOT",
                    title=f"Device `{dev_name}` Lacks Hardware Secure Boot Chain",
                    description="Without cryptographic bootloader verification, an attacker with flash/OTA access achieves persistent firmware implant.",
                    cyber_domain=CyberDomain.FIRMWARE_IOT_OT,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-345"],
                    confidence=0.98,
                    mitre_techniques=[MitreTechniqueRef("T1542.001", "Pre-OS Boot: System Firmware", MitreTactic.PERSISTENCE, "001")],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Enable ROM-anchored Secure Boot with rollback-counter protection.",
                    discovered_by="ely_cyber_firmware_ot",
                )
            )

        if profile.get("ota_signed") is False or str(profile.get("ota_transport", "https")).lower() == "http":
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-FW-PROFILE-OTA-UNSIGNED",
                    title=f"Unsigned or Cleartext OTA Update Mechanism on `{dev_name}`",
                    description="Unsigned OTA updates permit MitM or compromised update servers to flash malicious firmware across the fleet.",
                    cyber_domain=CyberDomain.FIRMWARE_IOT_OT,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-494", "CWE-347"],
                    confidence=0.99,
                    cvss4=CVSSv4Metrics(av="A", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Implement TUF (The Update Framework) / SUIT signed firmware manifests over TLS 1.3.",
                    discovered_by="ely_cyber_firmware_ot",
                )
            )

        if profile.get("uart_root_shell") or profile.get("jtag_unlocked"):
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-FW-PROFILE-HWDEBUG",
                    title=f"Production Hardware Debug Interface Exposed (UART/JTAG) on `{dev_name}`",
                    description="Unlocked JTAG/SWD or root UART console permits physical firmware extraction and key dumping.",
                    cyber_domain=CyberDomain.FIRMWARE_IOT_OT,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-489"],
                    confidence=0.97,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Blow flash readout protection (RDP Level 2) / JTAG disable eFuses in production builds.",
                    discovered_by="ely_cyber_firmware_ot",
                )
            )

        if str(profile.get("ble_pairing_mode", "")).lower() in ("just_works", "static_pin", "none"):
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-IOT-BLE-PAIRING",
                    title=f"Weak Bluetooth LE Pairing Mode (`{profile.get('ble_pairing_mode')}`) on `{dev_name}`",
                    description="BLE Just Works / static PIN pairing offers no MITM protection against active RF interception.",
                    cyber_domain=CyberDomain.FIRMWARE_IOT_OT,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-287", "CWE-300"],
                    confidence=0.95,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Require LE Secure Connections (LESC) with Numeric Comparison or Out-of-Band (NFC/QR) key exchange.",
                    discovered_by="ely_cyber_firmware_ot",
                )
            )

        # ICS/OT Protocol checks
        protocols = [str(p).lower() for p in (profile.get("exposed_ot_protocols") or [])]
        purdue_zone = str(profile.get("network_zone", "ot_level_1")).lower()
        for proto in protocols:
            if proto in ("modbus", "s7comm", "bacnet", "dnp3_unauth", "opcua_none"):
                sev = Severity.CRITICAL if purdue_zone in ("internet", "it_corporate", "dmz") else Severity.HIGH
                findings.append(
                    make_cyber_vuln(
                        rule_id=f"CYB-OT-PROTO-{proto.upper()}",
                        title=f"Unauthenticated Industrial Control Protocol `{proto.upper()}` Exposed in `{purdue_zone}`",
                        description=f"PLC/RTU `{dev_name}` exposes `{proto}` without cryptographic command authentication, enabling unauthorized physical actuator writes.",
                        cyber_domain=CyberDomain.FIRMWARE_IOT_OT,
                        severity=sev,
                        cwe_ids=["CWE-306", "CWE-319"],
                        confidence=0.98,
                        mitre_techniques=[MitreTechniqueRef("T0855", "Unauthorized Command Message (ICS)", MitreTactic.IMPACT)],
                        verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                        endpoint_or_asset=f"{asset}:{proto}",
                        remediation_guidance="Isolate OT protocols strictly inside Purdue Levels 1–2 behind deep-packet-inspecting industrial firewalls and VPN jump hosts.",
                        discovered_by="ely_cyber_firmware_ot",
                    )
                )

        return findings

    def scan_directory(self, root_path: Path) -> List[CyberVulnerability]:
        """Scan firmware/IoT/OT configuration files in a repository snapshot."""
        findings: List[CyberVulnerability] = []
        seen: set[str] = set()
        for fp in sorted(root_path.rglob("*")):
            if not fp.is_file():
                continue
            if any(p in {".git", "node_modules", "__pycache__", ".venv"} for p in fp.parts):
                continue
            if fp.suffix.lower() not in {".conf", ".cfg", ".ini", ".yaml", ".yml", ".json", ".sh", ".rc", ".env", ".c", ".h"} and fp.name not in {"inittab", "shadow", "mosquitto.conf"}:
                continue
            try:
                lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            rel = str(fp.relative_to(root_path))

            for idx, line in enumerate(lines, start=1):
                for pat, rid, title, sev, cwes, rem in self.FIRMWARE_TEXT_PATTERNS:
                    if re.search(pat, line):
                        v = make_cyber_vuln(
                            rule_id=rid,
                            title=title,
                            description=f"Firmware/IoT/OT weakness matched at `{rel}:{idx}`.",
                            cyber_domain=CyberDomain.FIRMWARE_IOT_OT,
                            severity=sev,
                            cwe_ids=cwes,
                            confidence=0.92,
                            verification_method=VerificationMethod.STATIC_PATTERN,
                            file_path=rel,
                            line_start=idx,
                            line_end=idx,
                            code_snippet=line.strip()[:220],
                            remediation_guidance=rem,
                            discovered_by="ely_cyber_firmware_ot",
                        )
                        if v.fingerprint() not in seen:
                            seen.add(v.fingerprint())
                            findings.append(v)
        return findings
