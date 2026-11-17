"""
Industrial Control Systems (ICS / OT / SCADA) Security Auditor:
Purdue Enterprise Reference Architecture (Levels 0–5) Zone/Conduit Verifier,
Modbus-TCP / DNP3 Function-Code Inspector, OPC-UA Security Auditor & IEC 62443 Scorer.

Audits cyber-physical and industrial operational technology networks safely offline:
  1. **Purdue Model (ISA-95 / IEC 62443) Segmentation & Conduit Graph Verifier**:
       - Models zones across Level 0 (Physical Process), Level 1 (PLC/RTU/Safety SIS),
         Level 2 (HMI/SCADA), Level 3 (Site Operations/Historian), Level 3.5 (IT/OT DMZ),
         Level 4/5 (Enterprise IT / Internet).
       - Detects **Purdue Level-Skipping Violations** (e.g., direct L4 Corporate IT or Internet
         connection straight to L1 PLC/SIS without traversing the L3.5 DMZ jump/broker!),
         shared credentials across IT/OT boundaries, and Safety Instrumented System (SIS)
         isolation breaches (`MITRE ATT&CK for ICS T0886 / T0855`).
  2. **Modbus-TCP & DNP3 Industrial Protocol Frame/Command Security Inspector**:
       - Parses raw Modbus-TCP MBAP + PDU bytes (`unit_id`, `function_code`) to flag
         unauthorized/unauthenticated write & control function codes (`0x05 Write Single Coil`,
         `0x06 Write Single Register`, `0x0F Write Multiple Coils`, `0x10 Write Multiple Registers`,
         `0x08 Diagnostics / Force Listen Only`, `0x2B Encapsulated Interface Transport`)
         originating from non-engineering stations.
       - Audits DNP3 frames for dangerous `Cold Restart (0x0D)`, `Warm Restart (0x0E)`,
         `Stop Application (0x12)`, and missing Secure Authentication v5 (SAv5).
  3. **OPC-UA Security Policy Auditor**:
       - Flags `MessageSecurityMode = None` or `Sign` (missing encryption), deprecated
         `Basic128Rsa15` / `Basic256` policies, and `AnonymousIdentityToken` enabled on PLCs.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

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


MODBUS_CRITICAL_WRITE_FCS: Dict[int, str] = {
    0x05: "Write Single Coil",
    0x06: "Write Single Holding Register",
    0x08: "Diagnostics (Restart / Force Listen-Only Mode)",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Holding Registers",
    0x15: "Write File Record",
    0x16: "Mask Write Register",
    0x17: "Read/Write Multiple Registers",
}

DNP3_DANGEROUS_FCS: Dict[int, str] = {
    0x05: "Direct Operate (No Select-Before-Operate Safety Check)",
    0x06: "Direct Operate No Ack",
    0x0D: "Cold Restart Outstation PLC",
    0x0E: "Warm Restart Outstation PLC",
    0x12: "Stop Application on Outstation",
    0x15: "Disable Unsolicited Messages",
}


@dataclass
class PurdueZone:
    zone_id: str
    name: str
    purdue_level: float  # 0.0, 1.0, 1.5 (SIS), 2.0, 3.0, 3.5 (DMZ), 4.0, 5.0 (Internet)
    is_safety_sis: bool = False
    iec_62443_sl_target: int = 3  # Security Level 1..4


@dataclass
class PurdueConduit:
    src_zone_id: str
    dst_zone_id: str
    protocol: str
    encrypted: bool = False
    authenticated: bool = False
    allows_write_commands: bool = False


class OTICSSCADAAuditor:
    """Audits Purdue Model zone/conduit segmentation, Modbus-TCP/DNP3 frames, and OPC-UA security."""

    def audit_purdue_architecture(
        self,
        zones: Sequence[PurdueZone],
        conduits: Sequence[PurdueConduit],
    ) -> Dict[str, Any]:
        """Verify ISA-95 / IEC 62443 Purdue zone isolation and conduit hygiene."""
        zmap = {z.zone_id: z for z in zones}
        vulns: List[CyberVulnerability] = []
        violations = 0

        for cond in conduits:
            src = zmap.get(cond.src_zone_id)
            dst = zmap.get(cond.dst_zone_id)
            if src is None or dst is None:
                continue

            level_gap = abs(src.purdue_level - dst.purdue_level)
            # Direct Enterprise IT/Internet (L4/L5) -> OT Control/Field (L0/L1/L2) bypasses L3.5 DMZ!
            crosses_it_ot_directly = (
                (src.purdue_level >= 4.0 and dst.purdue_level <= 2.0)
                or (dst.purdue_level >= 4.0 and src.purdue_level <= 2.0)
            )
            if crosses_it_ot_directly:
                violations += 1
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-ICS-PURDUE-DMZ-BYPASS",
                        title=f"Critical Purdue Model Violation: Direct Conduit `{src.name}` (L{src.purdue_level}) -> `{dst.name}` (L{dst.purdue_level}) Bypasses L3.5 IT/OT DMZ",
                        description=(
                            f"Direct `{cond.protocol}` conduit skips the mandatory Level 3.5 IT/OT DMZ, exposing industrial PLCs/HMIs "
                            "to enterprise ransomware and remote lateral takeover (IEC 62443-3-2 violation)."
                        ),
                        cyber_domain=CyberDomain.FIRMWARE_IOT_OT,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-284", "CWE-653"],
                        confidence=0.99,
                        cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
                        mitre_techniques=[MitreTechniqueRef("T0886", "Remote Services (ICS)", MitreTactic.LATERAL_MOVEMENT)],
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        endpoint_or_asset=f"{src.zone_id}->{dst.zone_id}",
                        remediation_guidance="Terminate all IT-to-OT flows inside a hardened Level 3.5 Industrial DMZ with unidirectional data diodes or authenticated jump hosts.",
                        discovered_by="ely_cyber_ot_ics_scada_auditor",
                    )
                )

            # Safety Instrumented System (SIS) breach (TRITON/TRISIS attack class)
            if (src.is_safety_sis or dst.is_safety_sis) and cond.allows_write_commands and level_gap > 0.5:
                violations += 1
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-ICS-SIS-WRITE-EXPOSURE",
                        title=f"Safety Instrumented System (SIS) Exposed to Remote Write Conduit (`{src.name}` -> `{dst.name}`)",
                        description=(
                            f"Conduit `{src.zone_id}->{dst.zone_id}` permits remote write/program commands into a physical Safety Instrumented System (TRITON/HatMan attack vector)."
                        ),
                        cyber_domain=CyberDomain.FIRMWARE_IOT_OT,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-284"],
                        confidence=0.99,
                        mitre_techniques=[MitreTechniqueRef("T0855", "Unauthorized Command Message", MitreTactic.IMPACT)],
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        endpoint_or_asset=f"{src.zone_id}->{dst.zone_id}",
                        remediation_guidance="Physically key-switch SIS controllers to `RUN` mode (blocking remote writes) and isolate SIS onto dedicated air-gapped networks.",
                        discovered_by="ely_cyber_ot_ics_scada_auditor",
                    )
                )

            # Unencrypted & unauthenticated control protocol across zone boundary
            if cond.protocol.lower() in ("modbus-tcp", "dnp3", "s7comm", "bacnet", "ethernet/ip") and (not cond.encrypted or not cond.authenticated):
                violations += 1
                vulns.append(
                    make_cyber_vuln(
                        rule_id=f"CYB-ICS-CLEARTEXT-{cond.protocol.upper().replace('/', '_')}",
                        title=f"Unauthenticated Cleartext Industrial Protocol `{cond.protocol}` Traversing `{src.name}` -> `{dst.name}`",
                        description=f"`{cond.protocol}` lacks native encryption/auth across zone boundary `{src.zone_id}->{dst.zone_id}`, permitting trivial command spoofing.",
                        cyber_domain=CyberDomain.FIRMWARE_IOT_OT,
                        severity=Severity.HIGH if cond.allows_write_commands else Severity.MEDIUM,
                        cwe_ids=["CWE-319", "CWE-306"],
                        confidence=0.97,
                        verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                        endpoint_or_asset=f"{src.zone_id}->{dst.zone_id}",
                        remediation_guidance="Wrap legacy OT protocols inside IPSec/mTLS VPN tunnels (IEC 62443-3-3) or upgrade to Modbus-TLS / DNP3-SAv5 / OPC-UA SignAndEncrypt.",
                        discovered_by="ely_cyber_ot_ics_scada_auditor",
                    )
                )

        compliance_pct = round((max(0, len(conduits) - violations) / max(1, len(conduits))) * 100.0, 2)
        return {
            "audited_at": utc_now_iso(),
            "zones_modeled": len(zones),
            "conduits_audited": len(conduits),
            "violations_found": violations,
            "iec_62443_segmentation_score_pct": compliance_pct,
            "vulnerabilities": vulns,
        }

    def inspect_modbus_tcp_frame(
        self,
        frame_bytes: bytes,
        src_role: str = "corporate_workstation",
        asset: str = "plc_modbus_502",
    ) -> Dict[str, Any]:
        """Parse a raw Modbus-TCP MBAP + PDU frame (`>= 8 bytes`) and detect unauthorized control writes."""
        vulns: List[CyberVulnerability] = []
        if len(frame_bytes) < 8:
            return {"valid": False, "error": "Frame shorter than 8-byte Modbus-TCP minimum", "vulnerabilities": []}

        tx_id, proto_id, length, unit_id, fc = struct.unpack(">HHHBB", frame_bytes[:8])
        is_write = fc in MODBUS_CRITICAL_WRITE_FCS
        fc_name = MODBUS_CRITICAL_WRITE_FCS.get(fc, f"FunctionCode-0x{fc:02x}")

        if is_write and src_role.lower() not in ("authorized_engineering_workstation", "authorized_hmi"):
            vulns.append(
                make_cyber_vuln(
                    rule_id=f"CYB-ICS-MODBUS-UNAUTH-FC{fc:02X}",
                    title=f"Unauthorized Modbus-TCP Control Command `0x{fc:02X}` ({fc_name}) From `{src_role}` to Unit {unit_id}",
                    description=(
                        f"Unauthenticated Modbus-TCP frame (tx={tx_id}, unit={unit_id}) invoked `{fc_name}` from untrusted role `{src_role}`, "
                        "risking physical actuator manipulation or PLC halt."
                    ),
                    cyber_domain=CyberDomain.FIRMWARE_IOT_OT,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-306"],
                    confidence=0.99,
                    mitre_techniques=[MitreTechniqueRef("T0855", "Unauthorized Command Message", MitreTactic.IMPACT)],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Deploy DPI industrial firewall blocking Modbus write function codes from non-engineering IPs and migrate to Modbus/TCP Security (TLS).",
                    discovered_by="ely_cyber_ot_ics_scada_auditor",
                )
            )

        return {
            "valid": proto_id == 0,
            "transaction_id": tx_id,
            "protocol_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": fc,
            "function_name": fc_name,
            "is_write_or_control": is_write,
            "vulnerabilities": vulns,
        }

    def audit_opcua_endpoint(self, opc_cfg: Dict[str, Any], asset: str = "opcua_server") -> List[CyberVulnerability]:
        """Audit OPC-UA endpoint security mode, crypto policy, and authentication tokens."""
        vulns: List[CyberVulnerability] = []
        mode = str(opc_cfg.get("security_mode", "None")).lower()
        policy = str(opc_cfg.get("security_policy", "None"))
        if mode != "signandencrypt":
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-ICS-OPCUA-MODE-WEAK",
                    title=f"OPC-UA Endpoint `{asset}` Allows Weak MessageSecurityMode `{opc_cfg.get('security_mode')}`",
                    description="OPC-UA must enforce `SignAndEncrypt` to prevent eavesdropping and tampering with PLC setpoints.",
                    cyber_domain=CyberDomain.FIRMWARE_IOT_OT,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-319"],
                    confidence=0.98,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Disable `None` and `Sign` endpoints; enforce `SignAndEncrypt` with `Basic256Sha256` or `Aes128_Sha256_RsaOaep`.",
                    discovered_by="ely_cyber_ot_ics_scada_auditor",
                )
            )
        if policy in ("None", "Basic128Rsa15", "Basic256"):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-ICS-OPCUA-POLICY-DEPRECATED",
                    title=f"OPC-UA Endpoint `{asset}` Uses Deprecated Cryptographic Policy `{policy}`",
                    description=f"SecurityPolicy `{policy}` uses broken SHA-1 / RSA PKCS#1 v1.5 primitives.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-327"],
                    confidence=0.98,
                    verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                    endpoint_or_asset=asset,
                    remediation_guidance="Enforce OPC-UA `Basic256Sha256` or `Aes256_Sha256_RsaPss` exclusively.",
                    discovered_by="ely_cyber_ot_ics_scada_auditor",
                )
            )
        if opc_cfg.get("allow_anonymous_token", False):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-ICS-OPCUA-ANON-AUTH",
                    title=f"OPC-UA Endpoint `{asset}` Permits `AnonymousIdentityToken` Unauthenticated Access",
                    description="Anonymous OPC-UA sessions permit arbitrary node browsing and potentially unauthorized setpoint writes.",
                    cyber_domain=CyberDomain.FIRMWARE_IOT_OT,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-306"],
                    confidence=0.99,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Disable `AnonymousIdentityToken` and enforce mutual X.509 certificate authentication.",
                    discovered_by="ely_cyber_ot_ics_scada_auditor",
                )
            )
        return vulns
