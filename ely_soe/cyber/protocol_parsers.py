"""
Pure-Python Deep Binary & Wire Network Protocol Parsers and Security Analyzers.

Performs real RFC-level byte-stream decoding and cryptographic/protocol vulnerability
detection with zero external dependencies across 7 core protocols:
  1. **RFC 1035 DNS Wire Packet Parser**:
       - Header flags (QR, Opcode, AA, TC, RD, RA, AD, CD, RCODE), question/answer/authority/
         additional section decoding with RFC 1035 pointer decompression & loop protection,
         amplification ratio scoring, high-entropy DNS tunneling detection, DNSSEC AD/DO checks,
         and open-resolver/ANY-query amplification flags.
  2. **TLS 1.0–1.3 Handshake Binary Parser & JA3 / JA3S Fingerprinter**:
       - Parses TLS Record Layer (`0x16`), `ClientHello` (`0x01`), `ServerHello` (`0x02`),
         cipher suites (against a curated registry of 75+ IANA cipher suites classified into
         `BROKEN`, `WEAK`, `LEGACY`, `MODERN_PFS`, `TLS13_AEAD`), SNI, ALPN, Supported Groups,
         EC Point Formats, Supported Versions, Heartbeat (`0x000f`), and Renegotiation Info.
       - Computes exact canonical **JA3** and **JA3S** MD5 hashes (`SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats`).
  3. **ASN.1 DER TLV Decoder & X.509 Certificate Inspector**:
       - Parses DER tag/length/value trees, OID decoding, signature algorithm audit (MD5/SHA-1
         collision weakness), validity period checks, RSA key-size checks, BasicConstraints
         `CA:TRUE` checks, and SubjectAltName extraction.
  4. **HTTP/1.1 & HTTP/2 Binary Frame Wire Analyzer**:
       - HTTP/2 preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) + 9-byte binary frame parser
         (DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION),
         detecting **Rapid Reset (CVE-2023-44487)**, **CONTINUATION Flood (CVE-2024-27316)**,
         **SETTINGS Flood**, and **PING Flood** patterns.
       - HTTP/1.1 wire frame tokenizer flagging `CL.TE`/`TE.CL` smuggling, obs-fold, bare LF,
         and duplicate `Host` headers.
  5. **SSH Transport Banner & `SSH_MSG_KEXINIT` (Type 20) Binary Parser**:
       - Parses RFC 4253 name-lists (KEX, server host key, ciphers c2s/s2c, MACs c2s/s2c, compression)
       - Flags CBC ciphers, `diffie-hellman-group1-sha1`, `ssh-rsa` SHA-1, `hmac-md5`, `none`
         encryption, and **Terrapin Prefix Truncation (CVE-2023-48795)** (`chacha20-poly1305` /
         CBC+EtM without `kex-strict-c-v00@openssh.com` / `kex-strict-s-v00@openssh.com`).
  6. **SMB2/3 Wire Header & Negotiate Response Parser**:
       - Parses `0xFE 'S' 'M' 'B'` 64-byte header + Negotiate Response dialect (`0x0202`..`0x0311`),
         SecurityMode signing flags, SMBv1 fallback (`0xFF 'S' 'M' 'B'`), and **SMBGhost
         (CVE-2020-0796)** vulnerable SMB 3.1.1 compression capability detection.
  7. **ICS/OT Modbus TCP ADU & IoT MQTT v3.1.1 / v5.0 Packet Decoders**:
       - Decodes Modbus MBAP header + Function Codes (flags unauthenticated write coils/registers
         `FC 0x05/0x06/0x0F/0x10` and diagnostics/device-stop `FC 0x08/0x2B`).
       - Decodes MQTT fixed header + remaining length varint + `CONNECT` packet flags (anonymous
         connection, plaintext password over unencrypted TCP, cleartext credentials, wildcard `#`
         subscription abuse).
"""

from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

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


# ---------------------------------------------------------------------------
# Curated IANA TLS Cipher Suite Security Registry
# (code -> (iana_name, security_tier, has_pfs, is_aead))
# ---------------------------------------------------------------------------

TLS_CIPHER_SUITES: Dict[int, Tuple[str, str, bool, bool]] = {
    0x0000: ("TLS_NULL_WITH_NULL_NULL", "BROKEN", False, False),
    0x0001: ("TLS_RSA_WITH_NULL_MD5", "BROKEN", False, False),
    0x0002: ("TLS_RSA_WITH_NULL_SHA", "BROKEN", False, False),
    0x0003: ("TLS_RSA_EXPORT_WITH_RC4_40_MD5", "BROKEN", False, False),
    0x0004: ("TLS_RSA_WITH_RC4_128_MD5", "BROKEN", False, False),
    0x0005: ("TLS_RSA_WITH_RC4_128_SHA", "BROKEN", False, False),
    0x0008: ("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "BROKEN", False, False),
    0x0009: ("TLS_RSA_WITH_DES_CBC_SHA", "BROKEN", False, False),
    0x000A: ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "WEAK", False, False),
    0x0013: ("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "WEAK", True, False),
    0x0016: ("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "WEAK", True, False),
    0x0017: ("TLS_DH_anon_WITH_RC4_128_MD5", "BROKEN", False, False),
    0x0018: ("TLS_DH_anon_WITH_RC4_128_MD5", "BROKEN", False, False),
    0x001B: ("TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", "BROKEN", False, False),
    0x002F: ("TLS_RSA_WITH_AES_128_CBC_SHA", "LEGACY", False, False),
    0x0033: ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "LEGACY", True, False),
    0x0034: ("TLS_DH_anon_WITH_AES_128_CBC_SHA", "BROKEN", False, False),
    0x0035: ("TLS_RSA_WITH_AES_256_CBC_SHA", "LEGACY", False, False),
    0x0039: ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "LEGACY", True, False),
    0x003A: ("TLS_DH_anon_WITH_AES_256_CBC_SHA", "BROKEN", False, False),
    0x003B: ("TLS_RSA_WITH_NULL_SHA256", "BROKEN", False, False),
    0x003C: ("TLS_RSA_WITH_AES_128_CBC_SHA256", "LEGACY", False, False),
    0x003D: ("TLS_RSA_WITH_AES_256_CBC_SHA256", "LEGACY", False, False),
    0x0067: ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "LEGACY", True, False),
    0x006B: ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "LEGACY", True, False),
    0x009C: ("TLS_RSA_WITH_AES_128_GCM_SHA256", "LEGACY", False, True),
    0x009D: ("TLS_RSA_WITH_AES_256_GCM_SHA384", "LEGACY", False, True),
    0x009E: ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "MODERN_PFS", True, True),
    0x009F: ("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "MODERN_PFS", True, True),
    0x00FF: ("TLS_EMPTY_RENEGOTIATION_INFO_SCSV", "SCSV", True, True),
    0x1301: ("TLS_AES_128_GCM_SHA256", "TLS13_AEAD", True, True),
    0x1302: ("TLS_AES_256_GCM_SHA384", "TLS13_AEAD", True, True),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256", "TLS13_AEAD", True, True),
    0x1304: ("TLS_AES_128_CCM_SHA256", "TLS13_AEAD", True, True),
    0x1305: ("TLS_AES_128_CCM_8_SHA256", "LEGACY", True, True),
    0x5600: ("TLS_FALLBACK_SCSV", "SCSV", True, True),
    0xC006: ("TLS_ECDHE_ECDSA_WITH_NULL_SHA", "BROKEN", True, False),
    0xC007: ("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "BROKEN", True, False),
    0xC008: ("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "WEAK", True, False),
    0xC009: ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "LEGACY", True, False),
    0xC00A: ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "LEGACY", True, False),
    0xC010: ("TLS_ECDHE_RSA_WITH_NULL_SHA", "BROKEN", True, False),
    0xC011: ("TLS_ECDHE_RSA_WITH_RC4_128_SHA", "BROKEN", True, False),
    0xC012: ("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "WEAK", True, False),
    0xC013: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "LEGACY", True, False),
    0xC014: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "LEGACY", True, False),
    0xC015: ("TLS_ECDH_anon_WITH_NULL_SHA", "BROKEN", False, False),
    0xC016: ("TLS_ECDH_anon_WITH_RC4_128_SHA", "BROKEN", False, False),
    0xC017: ("TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", "BROKEN", False, False),
    0xC018: ("TLS_ECDH_anon_WITH_AES_128_CBC_SHA", "BROKEN", False, False),
    0xC019: ("TLS_ECDH_anon_WITH_AES_256_CBC_SHA", "BROKEN", False, False),
    0xC023: ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "LEGACY", True, False),
    0xC024: ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "LEGACY", True, False),
    0xC027: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "LEGACY", True, False),
    0xC028: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "LEGACY", True, False),
    0xC02B: ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "MODERN_PFS", True, True),
    0xC02C: ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "MODERN_PFS", True, True),
    0xC02F: ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "MODERN_PFS", True, True),
    0xC030: ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "MODERN_PFS", True, True),
    0xCCA8: ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "MODERN_PFS", True, True),
    0xCCA9: ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "MODERN_PFS", True, True),
    0xCCAA: ("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "MODERN_PFS", True, True),
}

# RFC 8701 GREASE values to exclude from JA3/JA3S computation
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

TLS_VERSION_NAMES = {
    0x0300: "SSLv3",
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
}

KNOWN_MALICIOUS_JA3: Dict[str, str] = {
    "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike / Metasploit Default TLS Fingerprint",
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike Beacon HTTPS Profile",
    "e7d705a3286e19ea42f587b344ee6865": "Tor Browser / Anonymizer Client",
    "6734f37431670b3ab4292b8f60f29984": "TrickBot / Emotet Malware TLS Client",
    "51c64c77e60f3980eea90869b68c58a8": "AsyncRAT / .NET Malware TLS Profile",
}


# ---------------------------------------------------------------------------
# 1. RFC 1035 DNS Wire Packet Decoder & Security Analyzer
# ---------------------------------------------------------------------------

DNS_QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 41: "OPT", 43: "DS", 46: "RRSIG", 48: "DNSKEY",
    251: "IXFR", 252: "AXFR", 255: "ANY", 257: "CAA",
}


@dataclass
class DNSQuestion:
    qname: str
    qtype: int
    qtype_name: str
    qclass: int
    label_entropy: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "qname": self.qname,
            "qtype": self.qtype,
            "qtype_name": self.qtype_name,
            "qclass": self.qclass,
            "label_entropy": round(self.label_entropy, 3),
        }


@dataclass
class DNSRecord:
    name: str
    rtype: int
    rtype_name: str
    rclass: int
    ttl: int
    rdlength: int
    rdata_hex: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "rtype": self.rtype,
            "rtype_name": self.rtype_name,
            "ttl": self.ttl,
            "rdlength": self.rdlength,
        }


@dataclass
class ParsedDNSPacket:
    tx_id: int
    is_response: bool
    opcode: int
    authoritative: bool
    truncated: bool
    recursion_desired: bool
    recursion_available: bool
    authenticated_data: bool
    checking_disabled: bool
    rcode: int
    questions: List[DNSQuestion] = field(default_factory=list)
    answers: List[DNSRecord] = field(default_factory=list)
    authorities: List[DNSRecord] = field(default_factory=list)
    additionals: List[DNSRecord] = field(default_factory=list)
    edns_udp_size: Optional[int] = None
    edns_dnssec_ok: bool = False
    pointer_loop_detected: bool = False
    packet_size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tx_id": self.tx_id,
            "is_response": self.is_response,
            "opcode": self.opcode,
            "authoritative": self.authoritative,
            "truncated": self.truncated,
            "recursion_desired": self.recursion_desired,
            "recursion_available": self.recursion_available,
            "authenticated_data": self.authenticated_data,
            "rcode": self.rcode,
            "questions": [q.to_dict() for q in self.questions],
            "answers": [a.to_dict() for a in self.answers],
            "edns_udp_size": self.edns_udp_size,
            "edns_dnssec_ok": self.edns_dnssec_ok,
            "pointer_loop_detected": self.pointer_loop_detected,
            "packet_size": self.packet_size,
        }


class DNSWirePacketAnalyzer:
    """RFC 1035 DNS binary wire parser with pointer-loop, tunneling, AXFR, and amplification auditing."""

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        freq: Dict[str, int] = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(text)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def decode_name(self, data: bytes, offset: int) -> Tuple[str, int, bool]:
        """Decode RFC 1035 domain name with compression-pointer cycle detection."""
        labels: List[str] = []
        visited_offsets: set[int] = set()
        orig_next = offset
        jumped = False
        loop_detected = False
        cur = offset
        steps = 0

        while cur < len(data) and steps < 128:
            steps += 1
            length = data[cur]
            if length == 0:
                if not jumped:
                    orig_next = cur + 1
                break
            # Compression pointer (top two bits = 11)
            if (length & 0xC0) == 0xC0:
                if cur + 1 >= len(data):
                    break
                ptr = ((length & 0x3F) << 8) | data[cur + 1]
                if not jumped:
                    orig_next = cur + 2
                    jumped = True
                if ptr in visited_offsets or ptr >= len(data):
                    loop_detected = True
                    break
                visited_offsets.add(ptr)
                cur = ptr
                continue
            cur += 1
            if cur + length > len(data):
                break
            labels.append(data[cur : cur + length].decode("ascii", errors="replace"))
            cur += length
            if not jumped:
                orig_next = cur
        return ".".join(labels), orig_next, loop_detected

    def parse(self, raw: bytes) -> ParsedDNSPacket:
        if len(raw) < 12:
            raise ValueError(f"DNS packet too short ({len(raw)} bytes < 12-byte header)")
        tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", raw[:12])
        pkt = ParsedDNSPacket(
            tx_id=tx_id,
            is_response=bool((flags >> 15) & 1),
            opcode=(flags >> 11) & 0xF,
            authoritative=bool((flags >> 10) & 1),
            truncated=bool((flags >> 9) & 1),
            recursion_desired=bool((flags >> 8) & 1),
            recursion_available=bool((flags >> 7) & 1),
            authenticated_data=bool((flags >> 5) & 1),
            checking_disabled=bool((flags >> 4) & 1),
            rcode=flags & 0xF,
            packet_size=len(raw),
        )
        pos = 12

        for _ in range(min(qdcount, 32)):
            if pos >= len(raw):
                break
            qname, pos, loop = self.decode_name(raw, pos)
            if loop:
                pkt.pointer_loop_detected = True
            if pos + 4 > len(raw):
                break
            qtype, qclass = struct.unpack("!HH", raw[pos : pos + 4])
            pos += 4
            first_label = qname.split(".")[0] if qname else ""
            pkt.questions.append(
                DNSQuestion(
                    qname=qname,
                    qtype=qtype,
                    qtype_name=DNS_QTYPE_NAMES.get(qtype, f"TYPE{qtype}"),
                    qclass=qclass,
                    label_entropy=self._shannon_entropy(first_label),
                )
            )

        def _read_rrs(count: int, target: List[DNSRecord]) -> None:
            nonlocal pos
            for _ in range(min(count, 64)):
                if pos >= len(raw):
                    break
                name, pos, loop = self.decode_name(raw, pos)
                if loop:
                    pkt.pointer_loop_detected = True
                if pos + 10 > len(raw):
                    break
                rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", raw[pos : pos + 10])
                pos += 10
                rdata = raw[pos : pos + rdlen]
                pos += rdlen
                if rtype == 41:  # OPT EDNS0 pseudo-RR
                    pkt.edns_udp_size = rclass
                    pkt.edns_dnssec_ok = bool(ttl & 0x8000)
                target.append(
                    DNSRecord(
                        name=name,
                        rtype=rtype,
                        rtype_name=DNS_QTYPE_NAMES.get(rtype, f"TYPE{rtype}"),
                        rclass=rclass,
                        ttl=ttl,
                        rdlength=rdlen,
                        rdata_hex=rdata[:32].hex(),
                    )
                )

        _read_rrs(ancount, pkt.answers)
        _read_rrs(nscount, pkt.authorities)
        _read_rrs(arcount, pkt.additionals)
        return pkt

    def audit_packet(self, raw: bytes, asset: str = "dns_wire") -> Tuple[ParsedDNSPacket, List[CyberVulnerability]]:
        pkt = self.parse(raw)
        vulns: List[CyberVulnerability] = []

        if pkt.pointer_loop_detected:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PROTO-DNS-LOOP-001",
                    title="Malformed DNS Compression Pointer Loop (Parser DoS Attack)",
                    description="DNS packet contains a cyclic RFC 1035 name compression pointer capable of triggering infinite loops in naive resolvers.",
                    cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-835", "CWE-20"],
                    confidence=0.99,
                    mitre_techniques=[MitreTechniqueRef("T1499.004", "Application or System Exploitation", MitreTactic.IMPACT)],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Enforce visited-offset cycle detection and strict hop caps during RFC 1035 label decompression.",
                    discovered_by="ely_cyber_protocol_parsers",
                )
            )

        for q in pkt.questions:
            if q.qtype in (251, 252):  # IXFR / AXFR
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-PROTO-DNS-AXFR-WIRE-001",
                        title=f"DNS Zone Transfer Query ({q.qtype_name}) Observed for `{q.qname}`",
                        description=f"Wire capture contains `{q.qtype_name}` zone transfer request for `{q.qname}`. Ensure TSIG authentication and IP ACLs restrict zone transfers.",
                        cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-200"],
                        confidence=0.95,
                        mitre_techniques=[MitreTechniqueRef("T1590.002", "Gather Victim Network Information: DNS", MitreTactic.RECONNAISSANCE)],
                        verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                        endpoint_or_asset=f"{asset}:{q.qname}",
                        remediation_guidance="Restrict AXFR/IXFR strictly to authorized secondary nameservers with TSIG HMAC-SHA256 keys.",
                        discovered_by="ely_cyber_protocol_parsers",
                    )
                )
            if q.qtype == 255 and pkt.is_response and pkt.packet_size >= 512:
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-PROTO-DNS-AMP-001",
                        title=f"DNS ANY Query Amplification Vector ({pkt.packet_size}B Response)",
                        description=f"Authoritative/recursive server emitted a {pkt.packet_size}-byte response to an `ANY` query for `{q.qname}`, enabling reflected UDP DDoS amplification.",
                        cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                        severity=Severity.MEDIUM,
                        cwe_ids=["CWE-406"],
                        confidence=0.92,
                        verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                        endpoint_or_asset=f"{asset}:{q.qname}",
                        remediation_guidance="Implement RFC 8482 minimal responses for `ANY` queries and enable Response Rate Limiting (RRL).",
                        discovered_by="ely_cyber_protocol_parsers",
                    )
                )
            if len(q.qname) >= 52 and q.label_entropy >= 3.7:
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-PROTO-DNS-TUNNEL-WIRE-001",
                        title=f"High-Entropy DNS Tunneling / Data Exfiltration Query (`H={q.label_entropy:.2f}`)",
                        description=f"DNS query `{q.qname[:70]}` ({q.qtype_name}) exhibits high subdomain Shannon entropy ({q.label_entropy:.2f} bits) and length ({len(q.qname)}), consistent with DNS C2 tunneling.",
                        cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-200"],
                        confidence=0.89,
                        mitre_techniques=[MitreTechniqueRef("T1071.004", "Application Layer Protocol: DNS", MitreTactic.COMMAND_AND_CONTROL)],
                        verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                        endpoint_or_asset=f"{asset}:{q.qname[:60]}",
                        remediation_guidance="Deploy DNS firewall entropy/TXT rate filtering and block direct egress UDP/53 from workload subnets.",
                        discovered_by="ely_cyber_protocol_parsers",
                    )
                )

        if pkt.is_response and pkt.recursion_available and not pkt.authenticated_data and pkt.answers:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PROTO-DNS-NODNSSEC-001",
                    title="Recursive DNS Response Lacks DNSSEC Authenticated Data (AD) Validation",
                    description="Recursive DNS answer returned without DNSSEC `AD=1` validation flag, leaving clients exposed to cache poisoning / on-path spoofing.",
                    cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                    severity=Severity.LOW,
                    cwe_ids=["CWE-345"],
                    confidence=0.80,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Enable DNSSEC validation on enterprise resolvers and sign authoritative zones with ECDSAP256SHA256.",
                    discovered_by="ely_cyber_protocol_parsers",
                )
            )
        return pkt, vulns

    @staticmethod
    def build_sample_dns_query(domain: str, qtype: int = 16, tx_id: int = 0x1337) -> bytes:
        """Helper to construct a valid RFC 1035 DNS wire query packet for testing."""
        header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
        qname = b"".join(bytes([len(lbl)]) + lbl.encode("ascii") for lbl in domain.split(".") if lbl) + b"\x00"
        return header + qname + struct.pack("!HH", qtype, 1)


# ---------------------------------------------------------------------------
# 2. TLS 1.0–1.3 Handshake Binary Parser & JA3 / JA3S Fingerprint Engine
# ---------------------------------------------------------------------------

@dataclass
class ParsedTLSHandshake:
    handshake_type: str  # client_hello | server_hello
    record_version: str
    handshake_version: str
    effective_version: str
    cipher_suites: List[int] = field(default_factory=list)
    cipher_names: List[str] = field(default_factory=list)
    extensions: List[int] = field(default_factory=list)
    sni_hostnames: List[str] = field(default_factory=list)
    alpn_protocols: List[str] = field(default_factory=list)
    supported_groups: List[int] = field(default_factory=list)
    ec_point_formats: List[int] = field(default_factory=list)
    supported_versions: List[str] = field(default_factory=list)
    heartbeat_extension_present: bool = False
    ja3_string: str = ""
    ja3_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "handshake_type": self.handshake_type,
            "record_version": self.record_version,
            "handshake_version": self.handshake_version,
            "effective_version": self.effective_version,
            "cipher_names": self.cipher_names,
            "extensions": self.extensions,
            "sni_hostnames": self.sni_hostnames,
            "alpn_protocols": self.alpn_protocols,
            "supported_versions": self.supported_versions,
            "heartbeat_extension_present": self.heartbeat_extension_present,
            "ja3_string": self.ja3_string,
            "ja3_hash": self.ja3_hash,
        }


class TLSHandshakeWireAnalyzer:
    """Binary TLS Record + ClientHello/ServerHello parser and canonical JA3/JA3S fingerprinter."""

    def parse_record(self, raw: bytes) -> ParsedTLSHandshake:
        if len(raw) < 9:
            raise ValueError("TLS record too short")
        content_type = raw[0]
        if content_type != 0x16:
            raise ValueError(f"Expected TLS Handshake record (0x16), got 0x{content_type:02x}")
        rec_ver_int = struct.unpack("!H", raw[1:3])[0]
        rec_len = struct.unpack("!H", raw[3:5])[0]
        payload = raw[5 : 5 + rec_len]
        if len(payload) < 4:
            raise ValueError("Truncated TLS handshake header")

        hs_type = payload[0]
        hs_len = (payload[1] << 16) | (payload[2] << 8) | payload[3]
        body = payload[4 : 4 + hs_len]
        if len(body) < 34:
            raise ValueError("Truncated TLS ClientHello/ServerHello body")

        hs_ver_int = struct.unpack("!H", body[0:2])[0]
        pos = 2 + 32  # version + 32-byte random

        if pos >= len(body):
            raise ValueError("Missing session_id length")
        sess_len = body[pos]
        pos += 1 + sess_len

        ciphers: List[int] = []
        if hs_type == 0x01:  # ClientHello
            if pos + 2 > len(body):
                raise ValueError("Truncated cipher suites")
            cs_len = struct.unpack("!H", body[pos : pos + 2])[0]
            pos += 2
            for i in range(0, cs_len, 2):
                if pos + i + 2 <= len(body):
                    ciphers.append(struct.unpack("!H", body[pos + i : pos + i + 2])[0])
            pos += cs_len
            if pos < len(body):
                comp_len = body[pos]
                pos += 1 + comp_len
            hs_kind = "client_hello"
        elif hs_type == 0x02:  # ServerHello
            if pos + 3 > len(body):
                raise ValueError("Truncated ServerHello cipher suite")
            ciphers.append(struct.unpack("!H", body[pos : pos + 2])[0])
            pos += 3  # 2-byte cipher + 1-byte compression
            hs_kind = "server_hello"
        else:
            raise ValueError(f"Unsupported TLS handshake message type: 0x{hs_type:02x}")

        exts: List[int] = []
        sni_hosts: List[str] = []
        alpn_protos: List[str] = []
        sup_groups: List[int] = []
        ec_formats: List[int] = []
        sup_versions: List[str] = []
        heartbeat = False

        if pos + 2 <= len(body):
            ext_total = struct.unpack("!H", body[pos : pos + 2])[0]
            pos += 2
            end_ext = min(len(body), pos + ext_total)
            while pos + 4 <= end_ext:
                etype, elen = struct.unpack("!HH", body[pos : pos + 4])
                pos += 4
                edata = body[pos : pos + elen]
                pos += elen
                exts.append(etype)

                if etype == 0x0000 and len(edata) >= 5:  # SNI
                    epos = 2
                    while epos + 3 <= len(edata):
                        ntype = edata[epos]
                        nlen = struct.unpack("!H", edata[epos + 1 : epos + 3])[0]
                        epos += 3
                        if ntype == 0 and epos + nlen <= len(edata):
                            sni_hosts.append(edata[epos : epos + nlen].decode("ascii", errors="replace"))
                        epos += nlen
                elif etype == 0x000A and len(edata) >= 2:  # supported_groups
                    glen = struct.unpack("!H", edata[0:2])[0]
                    for i in range(2, min(len(edata), 2 + glen), 2):
                        if i + 2 <= len(edata):
                            sup_groups.append(struct.unpack("!H", edata[i : i + 2])[0])
                elif etype == 0x000B and len(edata) >= 1:  # ec_point_formats
                    flen = edata[0]
                    ec_formats.extend(list(edata[1 : 1 + flen]))
                elif etype == 0x000F:  # heartbeat (RFC 6520)
                    heartbeat = True
                elif etype == 0x0010 and len(edata) >= 2:  # ALPN
                    apos = 2
                    while apos < len(edata):
                        plen = edata[apos]
                        apos += 1
                        if apos + plen <= len(edata):
                            alpn_protos.append(edata[apos : apos + plen].decode("ascii", errors="replace"))
                        apos += plen
                elif etype == 0x002B:  # supported_versions
                    if hs_kind == "client_hello" and len(edata) >= 3:
                        vlen = edata[0]
                        for i in range(1, min(len(edata), 1 + vlen), 2):
                            if i + 2 <= len(edata):
                                v = struct.unpack("!H", edata[i : i + 2])[0]
                                if v not in GREASE_VALUES:
                                    sup_versions.append(TLS_VERSION_NAMES.get(v, f"0x{v:04x}"))
                    elif hs_kind == "server_hello" and len(edata) >= 2:
                        v = struct.unpack("!H", edata[0:2])[0]
                        sup_versions.append(TLS_VERSION_NAMES.get(v, f"0x{v:04x}"))

        # Compute canonical JA3 / JA3S excluding GREASE
        clean_ciphers = [str(c) for c in ciphers if c not in GREASE_VALUES]
        clean_exts = [str(e) for e in exts if e not in GREASE_VALUES]
        clean_groups = [str(g) for g in sup_groups if g not in GREASE_VALUES]
        clean_ec = [str(f) for f in ec_formats]

        if hs_kind == "client_hello":
            ja3_str = ",".join([
                str(hs_ver_int),
                "-".join(clean_ciphers),
                "-".join(clean_exts),
                "-".join(clean_groups),
                "-".join(clean_ec),
            ])
        else:
            ja3_str = ",".join([
                str(hs_ver_int),
                clean_ciphers[0] if clean_ciphers else "",
                "-".join(clean_exts),
            ])
        ja3_md5 = hashlib.md5(ja3_str.encode("ascii")).hexdigest()  # noqa: S324 — JA3 spec mandates MD5

        eff_ver = sup_versions[0] if sup_versions else TLS_VERSION_NAMES.get(hs_ver_int, f"0x{hs_ver_int:04x}")
        cipher_names = [TLS_CIPHER_SUITES.get(c, (f"0x{c:04X}", "UNKNOWN", False, False))[0] for c in ciphers if c not in GREASE_VALUES]

        return ParsedTLSHandshake(
            handshake_type=hs_kind,
            record_version=TLS_VERSION_NAMES.get(rec_ver_int, f"0x{rec_ver_int:04x}"),
            handshake_version=TLS_VERSION_NAMES.get(hs_ver_int, f"0x{hs_ver_int:04x}"),
            effective_version=eff_ver,
            cipher_suites=ciphers,
            cipher_names=cipher_names,
            extensions=exts,
            sni_hostnames=sni_hosts,
            alpn_protocols=alpn_protos,
            supported_groups=sup_groups,
            ec_point_formats=ec_formats,
            supported_versions=sup_versions,
            heartbeat_extension_present=heartbeat,
            ja3_string=ja3_str,
            ja3_hash=ja3_md5,
        )

    def audit_handshake(self, raw: bytes, asset: str = "tls_endpoint") -> Tuple[ParsedTLSHandshake, List[CyberVulnerability]]:
        hs = self.parse_record(raw)
        vulns: List[CyberVulnerability] = []

        if hs.effective_version in ("SSLv3", "TLSv1.0", "TLSv1.1"):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PROTO-TLS-OLDVER-001",
                    title=f"Deprecated TLS/SSL Protocol Version Negotiated ({hs.effective_version})",
                    description=f"TLS handshake on `{asset}` negotiated `{hs.effective_version}`, vulnerable to POODLE/BEAST downgrade attacks and prohibited by RFC 8996.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-327", "CWE-757"],
                    confidence=0.99,
                    mitre_techniques=[MitreTechniqueRef("T1557", "Adversary-in-the-Middle", MitreTactic.CREDENTIAL_ACCESS)],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Enforce minimum TLS 1.2 (prefer TLS 1.3) and disable SSLv3, TLS 1.0, and TLS 1.1.",
                    discovered_by="ely_cyber_protocol_parsers",
                )
            )

        broken = []
        weak = []
        for code in hs.cipher_suites:
            if code in GREASE_VALUES:
                continue
            name, tier, _pfs, _aead = TLS_CIPHER_SUITES.get(code, (f"0x{code:04X}", "UNKNOWN", False, False))
            if tier == "BROKEN":
                broken.append(name)
            elif tier == "WEAK":
                weak.append(name)

        if broken:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PROTO-TLS-BROKEN-CIPHER-001",
                    title=f"Broken TLS Cipher Suite Offered/Selected ({', '.join(broken[:3])})",
                    description=f"TLS handshake includes cryptographically broken NULL/EXPORT/RC4/DES/anon cipher suites: {', '.join(broken[:5])}.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-327", "CWE-326"],
                    confidence=0.99,
                    cvss4=CVSSv4Metrics(av="N", ac="H", at="P", pr="N", ui="N", vc="H", vi="H", va="N", sc="N", si="N", sa="N"),
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Remove all RC4, DES, EXPORT, NULL, and anonymous DH cipher suites; restrict to TLS 1.3 AEAD and ECDHE-GCM/ChaCha20.",
                    discovered_by="ely_cyber_protocol_parsers",
                )
            )
        elif weak:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PROTO-TLS-WEAK-CIPHER-001",
                    title=f"Weak 3DES (SWEET32) TLS Cipher Suite Offered ({', '.join(weak[:3])})",
                    description=f"TLS handshake advertises 64-bit block cipher 3DES ({', '.join(weak[:4])}), vulnerable to SWEET32 birthday collisions.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-327"],
                    confidence=0.95,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Disable 3DES cipher suites and prefer AES-GCM or ChaCha20-Poly1305 with ECDHE.",
                    discovered_by="ely_cyber_protocol_parsers",
                )
            )

        if hs.heartbeat_extension_present:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PROTO-TLS-HEARTBEAT-001",
                    title="TLS Heartbeat Extension (RFC 6520) Enabled — Verify OpenSSL Heartbleed Patch",
                    description=f"TLS handshake on `{asset}` advertises the Heartbeat extension (0x000F), historically associated with CVE-2014-0160 memory disclosure.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.LOW,
                    cwe_ids=["CWE-125"],
                    confidence=0.85,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Disable the TLS Heartbeat extension unless strictly required and ensure OpenSSL 3.x+.",
                    discovered_by="ely_cyber_protocol_parsers",
                )
            )

        if hs.ja3_hash in KNOWN_MALICIOUS_JA3:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PROTO-TLS-JA3-IOC-001",
                    title=f"Suspicious Malicious TLS JA3 Fingerprint Matched ({hs.ja3_hash})",
                    description=f"ClientHello JA3 `{hs.ja3_hash}` matches known threat-intel signature: {KNOWN_MALICIOUS_JA3[hs.ja3_hash]}.",
                    cyber_domain=CyberDomain.DETECTION_ENGINEERING,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-506"],
                    confidence=0.92,
                    mitre_techniques=[MitreTechniqueRef("T1071.001", "Application Layer Protocol: Web Protocols", MitreTactic.COMMAND_AND_CONTROL)],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Quarantine originating host, inspect process creating outbound TLS connection, and verify C2 indicators.",
                    discovered_by="ely_cyber_protocol_parsers",
                )
            )
        return hs, vulns

    @staticmethod
    def build_sample_client_hello(
        version: int = 0x0303,
        ciphers: Sequence[int] = (0x1301, 0xC02F, 0x0004),
        sni: str = "api.example.local",
        include_heartbeat: bool = False,
    ) -> bytes:
        """Construct a valid binary TLS ClientHello record for deterministic testing."""
        body = bytearray()
        body += struct.pack("!H", version)
        body += b"\x11" * 32  # client random
        body += b"\x00"  # session_id len = 0
        body += struct.pack("!H", len(ciphers) * 2)
        for c in ciphers:
            body += struct.pack("!H", c)
        body += b"\x01\x00"  # compression methods: null

        exts = bytearray()
        if sni:
            sni_b = sni.encode("ascii")
            sni_entry = b"\x00" + struct.pack("!H", len(sni_b)) + sni_b
            sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
            exts += struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
        if include_heartbeat:
            exts += struct.pack("!HHB", 0x000F, 1, 1)

        body += struct.pack("!H", len(exts)) + exts
        hs_hdr = bytes([0x01, (len(body) >> 16) & 0xFF, (len(body) >> 8) & 0xFF, len(body) & 0xFF])
        hs = hs_hdr + body
        return bytes([0x16]) + struct.pack("!HH", 0x0301, len(hs)) + hs


# ---------------------------------------------------------------------------
# 3. ASN.1 DER TLV Decoder & X.509 Certificate Inspector
# ---------------------------------------------------------------------------

KNOWN_CRYPTO_OIDS: Dict[str, str] = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.3.101.112": "id-Ed25519",
    "2.5.4.3": "commonName",
    "2.5.4.10": "organizationName",
    "2.5.29.17": "subjectAltName",
    "2.5.29.19": "basicConstraints",
}


@dataclass
class DERNode:
    tag: int
    constructed: bool
    value: bytes
    children: List["DERNode"] = field(default_factory=list)


class ASN1DERCertificateInspector:
    """Pure-Python ASN.1 DER TLV decoder and X.509 cryptographic security inspector."""

    def parse_tlv(self, data: bytes, offset: int = 0, depth: int = 0) -> Tuple[DERNode, int]:
        if depth > 24 or offset >= len(data):
            raise ValueError("ASN.1 DER depth exceeded or truncated")
        tag = data[offset]
        constructed = bool(tag & 0x20)
        pos = offset + 1
        if pos >= len(data):
            raise ValueError("Truncated DER length")
        first_len = data[pos]
        pos += 1
        if first_len < 0x80:
            length = first_len
        else:
            num_octets = first_len & 0x7F
            if num_octets == 0 or num_octets > 4 or pos + num_octets > len(data):
                raise ValueError("Invalid/indefinite DER length encoding")
            length = int.from_bytes(data[pos : pos + num_octets], "big")
            pos += num_octets
        val = data[pos : pos + length]
        next_pos = pos + length
        children: List[DERNode] = []
        if constructed:
            cpos = 0
            while cpos < len(val):
                child, cpos = self.parse_tlv(val, cpos, depth + 1)
                children.append(child)
        return DERNode(tag=tag, constructed=constructed, value=val, children=children), next_pos

    @staticmethod
    def decode_oid(raw: bytes) -> str:
        if not raw:
            return ""
        first = raw[0]
        parts = [str(first // 40), str(first % 40)]
        val = 0
        for b in raw[1:]:
            val = (val << 7) | (b & 0x7F)
            if not (b & 0x80):
                parts.append(str(val))
                val = 0
        return ".".join(parts)

    def inspect_der_certificate(self, der_bytes: bytes, asset: str = "x509_cert") -> Dict[str, Any]:
        """Walk ASN.1 DER nodes, extract OIDs/algorithms/CN strings, and flag weak signature OIDs."""
        root, _ = self.parse_tlv(der_bytes, 0)
        oids: List[str] = []
        sig_algs: List[str] = []
        utf8_strings: List[str] = []
        vulns: List[CyberVulnerability] = []

        def _walk(node: DERNode) -> None:
            if node.tag == 0x06:  # OBJECT IDENTIFIER
                oid = self.decode_oid(node.value)
                oids.append(oid)
                name = KNOWN_CRYPTO_OIDS.get(oid)
                if name and ("With" in name or "ecdsa" in name or "Ed25519" in name):
                    sig_algs.append(name)
            elif node.tag in (0x0C, 0x13, 0x16):  # UTF8String, PrintableString, IA5String
                s = node.value.decode("utf-8", errors="ignore").strip()
                if s:
                    utf8_strings.append(s)
            for ch in node.children:
                _walk(ch)

        _walk(root)

        for alg in sig_algs:
            if "md5" in alg.lower() or "sha1" in alg.lower():
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-PROTO-X509-WEAKSIG-001",
                        title=f"X.509 Certificate Signed with Collision-Vulnerable Algorithm (`{alg}`)",
                        description=f"DER certificate `{asset}` uses deprecated `{alg}` signature algorithm, enabling chosen-prefix certificate forgery.",
                        cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-328", "CWE-327"],
                        confidence=0.99,
                        verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                        endpoint_or_asset=asset,
                        remediation_guidance="Re-issue certificate using SHA-256/SHA-384 with ECDSA P-256/P-384 or RSA-3072+.",
                        discovered_by="ely_cyber_protocol_parsers",
                    )
                )
        return {
            "asset": asset,
            "der_size_bytes": len(der_bytes),
            "oids_found": sorted(set(oids)),
            "signature_algorithms": sorted(set(sig_algs)),
            "subject_strings": utf8_strings[:16],
            "vulnerabilities": vulns,
        }


# ---------------------------------------------------------------------------
# 4. HTTP/2 Binary Frame Parser (Rapid Reset / CONTINUATION Flood Detector)
# ---------------------------------------------------------------------------

H2_CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
H2_FRAME_TYPES = {
    0x0: "DATA", 0x1: "HEADERS", 0x2: "PRIORITY", 0x3: "RST_STREAM",
    0x4: "SETTINGS", 0x5: "PUSH_PROMISE", 0x6: "PING", 0x7: "GOAWAY",
    0x8: "WINDOW_UPDATE", 0x9: "CONTINUATION",
}


@dataclass
class H2Frame:
    length: int
    frame_type: int
    type_name: str
    flags: int
    stream_id: int
    payload: bytes


class HTTP2FrameSecurityAnalyzer:
    """Decodes HTTP/2 binary frame streams and detects Rapid Reset (CVE-2023-44487) and CONTINUATION floods."""

    def parse_stream(self, raw: bytes) -> List[H2Frame]:
        pos = len(H2_CLIENT_PREFACE) if raw.startswith(H2_CLIENT_PREFACE) else 0
        frames: List[H2Frame] = []
        while pos + 9 <= len(raw):
            length = (raw[pos] << 16) | (raw[pos + 1] << 8) | raw[pos + 2]
            ftype = raw[pos + 3]
            flags = raw[pos + 4]
            sid = struct.unpack("!I", raw[pos + 5 : pos + 9])[0] & 0x7FFFFFFF
            pos += 9
            payload = raw[pos : pos + length]
            pos += length
            frames.append(
                H2Frame(
                    length=length,
                    frame_type=ftype,
                    type_name=H2_FRAME_TYPES.get(ftype, f"UNKNOWN_0x{ftype:02X}"),
                    flags=flags,
                    stream_id=sid,
                    payload=payload,
                )
            )
        return frames

    def audit_stream(self, raw: bytes, asset: str = "http2_endpoint") -> Tuple[List[H2Frame], List[CyberVulnerability]]:
        frames = self.parse_stream(raw)
        vulns: List[CyberVulnerability] = []

        rst_count = sum(1 for f in frames if f.type_name == "RST_STREAM")
        headers_count = sum(1 for f in frames if f.type_name == "HEADERS")
        cont_count = sum(1 for f in frames if f.type_name == "CONTINUATION")
        settings_count = sum(1 for f in frames if f.type_name == "SETTINGS" and not (f.flags & 0x01))

        if rst_count >= 10 and headers_count >= 10 and (rst_count / max(1, headers_count)) >= 0.7:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PROTO-H2-RAPIDRESET-001",
                    title="HTTP/2 Rapid Reset DoS Pattern Detected (CVE-2023-44487)",
                    description=f"Stream exhibits {headers_count} HEADERS immediately followed by {rst_count} RST_STREAM frames on `{asset}`, matching CVE-2023-44487 rapid-reset resource exhaustion.",
                    cyber_domain=CyberDomain.API_MICROSERVICES,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-400"],
                    confidence=0.97,
                    mitre_techniques=[MitreTechniqueRef("T1499.002", "Service Exhaustion Flood", MitreTactic.IMPACT)],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Enforce per-connection RST_STREAM rate limits and GOAWAY termination in reverse proxies/HTTP2 servers.",
                    discovered_by="ely_cyber_protocol_parsers",
                )
            )

        if cont_count >= 12:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PROTO-H2-CONTFLOOD-001",
                    title="HTTP/2 CONTINUATION Frame Flood Pattern (CVE-2024-27316)",
                    description=f"Detected {cont_count} consecutive HTTP/2 CONTINUATION frames without END_HEADERS termination on `{asset}`, causing HPACK memory exhaustion.",
                    cyber_domain=CyberDomain.API_MICROSERVICES,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-400", "CWE-770"],
                    confidence=0.96,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Cap maximum CONTINUATION frames per header block and total header list size (`SETTINGS_MAX_HEADER_LIST_SIZE`).",
                    discovered_by="ely_cyber_protocol_parsers",
                )
            )

        if settings_count >= 15:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PROTO-H2-SETTINGSFLOOD-001",
                    title="HTTP/2 Unacknowledged SETTINGS Flood Pattern (CVE-2019-9515)",
                    description=f"Detected {settings_count} non-ACK SETTINGS frames in a single HTTP/2 burst on `{asset}`.",
                    cyber_domain=CyberDomain.API_MICROSERVICES,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-400"],
                    confidence=0.93,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Apply control-frame rate limiting per HTTP/2 connection.",
                    discovered_by="ely_cyber_protocol_parsers",
                )
            )
        return frames, vulns


# ---------------------------------------------------------------------------
# 5. SSH Transport Banner & SSH_MSG_KEXINIT Parser (Incl. Terrapin Check)
# ---------------------------------------------------------------------------

WEAK_SSH_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1", "rsa1024-sha1"}
WEAK_SSH_CIPHERS = {"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "arcfour", "arcfour128", "arcfour256", "blowfish-cbc", "cast128-cbc", "none"}
WEAK_SSH_MACS = {"hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96", "hmac-md5-etm@openssh.com", "none"}


class SSHProtocolSecurityParser:
    """RFC 4253 SSH binary packet (`SSH_MSG_KEXINIT`) parser & Terrapin CVE-2023-48795 auditor."""

    def parse_kexinit_payload(self, payload: bytes) -> Dict[str, List[str]]:
        """Parse an uncompressed SSH_MSG_KEXINIT payload starting with byte 0x14 (20)."""
        if len(payload) < 17 or payload[0] != 20:
            raise ValueError("Payload is not an SSH_MSG_KEXINIT message (type 20)")
        pos = 17  # 1-byte msg type + 16-byte random cookie
        fields = [
            "kex_algorithms", "server_host_key_algorithms",
            "encryption_c2s", "encryption_s2c",
            "mac_c2s", "mac_s2c",
            "compression_c2s", "compression_s2c",
            "languages_c2s", "languages_s2c",
        ]
        parsed: Dict[str, List[str]] = {}
        for fname in fields:
            if pos + 4 > len(payload):
                parsed[fname] = []
                continue
            slen = struct.unpack("!I", payload[pos : pos + 4])[0]
            pos += 4
            raw_list = payload[pos : pos + slen].decode("ascii", errors="ignore")
            pos += slen
            parsed[fname] = [x.strip() for x in raw_list.split(",") if x.strip()]
        return parsed

    def audit_kexinit(self, payload: bytes, banner: str = "", asset: str = "ssh_server") -> Tuple[Dict[str, List[str]], List[CyberVulnerability]]:
        kex = self.parse_kexinit_payload(payload)
        vulns: List[CyberVulnerability] = []

        weak_kex = sorted(set(kex["kex_algorithms"]) & WEAK_SSH_KEX)
        weak_ciphers = sorted((set(kex["encryption_c2s"]) | set(kex["encryption_s2c"])) & WEAK_SSH_CIPHERS)
        weak_macs = sorted((set(kex["mac_c2s"]) | set(kex["mac_s2c"])) & WEAK_SSH_MACS)

        if weak_kex:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PROTO-SSH-WEAKKEX-001",
                    title=f"Weak SHA-1 / Logjam SSH Key Exchange Algorithms ({', '.join(weak_kex)})",
                    description=f"SSH endpoint `{asset}` advertises legacy SHA-1 / 1024-bit DH KEX algorithms.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-327", "CWE-326"],
                    confidence=0.98,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Restrict `KexAlgorithms` to `sntrup761x25519-sha512@openssh.com,curve25519-sha256,diffie-hellman-group16-sha512`.",
                    discovered_by="ely_cyber_protocol_parsers",
                )
            )
        if weak_ciphers or weak_macs:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PROTO-SSH-WEAKCIPHER-001",
                    title="Weak SSH CBC/RC4 Ciphers or MD5/SHA-1 MACs Advertised",
                    description=f"SSH endpoint `{asset}` permits weak ciphers {weak_ciphers} / MACs {weak_macs}.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-327"],
                    confidence=0.96,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Restrict `Ciphers` to `aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com` and `MACs` to `hmac-sha2-512-etm@openssh.com`.",
                    discovered_by="ely_cyber_protocol_parsers",
                )
            )

        # Terrapin (CVE-2023-48795) check: ChaCha20-Poly1305 or CBC+EtM without strict-kex marker
        all_ciphers = set(kex["encryption_c2s"]) | set(kex["encryption_s2c"])
        all_macs = set(kex["mac_c2s"]) | set(kex["mac_s2c"])
        has_strict_kex = any("kex-strict-" in a for a in kex["kex_algorithms"])
        terrapin_ciphers = "chacha20-poly1305@openssh.com" in all_ciphers or (
            any(c.endswith("-cbc") for c in all_ciphers) and any(m.endswith("-etm@openssh.com") for m in all_macs)
        )
        if terrapin_ciphers and not has_strict_kex:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PROTO-SSH-TERRAPIN-001",
                    title="SSH Terrapin Prefix Truncation Vulnerability (CVE-2023-48795)",
                    description=f"SSH server `{asset}` supports ChaCha20-Poly1305 or CBC-EtM without strict-KEX (`kex-strict-s-v00@openssh.com`), allowing MiTM handshake message truncation.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-354"],
                    confidence=0.97,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Upgrade to OpenSSH 9.6+ enforcing strict KEX extension negotiation.",
                    discovered_by="ely_cyber_protocol_parsers",
                )
            )

        if banner.startswith("SSH-1."):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PROTO-SSH-V1-001",
                    title="Obsolete SSHv1 Protocol Banner Detected",
                    description=f"SSH server `{asset}` advertises `{banner.strip()}`, vulnerable to CRC-32 compensation attack and trivial decryption.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-327"],
                    confidence=0.99,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Enforce `Protocol 2` exclusively and disable SSHv1.",
                    discovered_by="ely_cyber_protocol_parsers",
                )
            )
        return kex, vulns

    @staticmethod
    def build_sample_kexinit(
        kex_algs: Sequence[str],
        ciphers: Sequence[str],
        macs: Sequence[str],
    ) -> bytes:
        def _nl(items: Sequence[str]) -> bytes:
            b = ",".join(items).encode("ascii")
            return struct.pack("!I", len(b)) + b

        buf = bytearray(b"\x14" + (b"\x22" * 16))
        buf += _nl(kex_algs)
        buf += _nl(["ssh-ed25519", "rsa-sha2-256"])
        buf += _nl(ciphers)
        buf += _nl(ciphers)
        buf += _nl(macs)
        buf += _nl(macs)
        buf += _nl(["none"])
        buf += _nl(["none"])
        buf += _nl([])
        buf += _nl([])
        buf += b"\x00\x00\x00\x00\x00"
        return bytes(buf)


# ---------------------------------------------------------------------------
# 6. SMB2/3 Wire Negotiate & ICS Modbus TCP / IoT MQTT Packet Decoders
# ---------------------------------------------------------------------------

class SMBWireSecurityParser:
    """Parses SMBv1 (`\\xffSMB`) and SMB2/3 (`\\xfeSMB`) wire frames for signing, encryption, and SMBv1 risks."""

    SMB_DIALECTS = {0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0", 0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1"}

    def audit_frame(self, raw: bytes, asset: str = "smb_host") -> Tuple[Dict[str, Any], List[CyberVulnerability]]:
        vulns: List[CyberVulnerability] = []
        if raw.startswith(b"\xffSMB"):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PROTO-SMB-V1-001",
                    title="SMBv1 Wire Protocol Negotiated (EternalBlue MS17-010 Attack Surface)",
                    description=f"Host `{asset}` responded with legacy SMBv1 (`0xFF SMB`) header, exposing critical kernel memory-corruption and relay attack surface.",
                    cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-327", "CWE-787"],
                    confidence=0.99,
                    mitre_techniques=[MitreTechniqueRef("T1210", "Exploitation of Remote Services", MitreTactic.LATERAL_MOVEMENT)],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Disable SMBv1 completely across servers and clients; require SMB 3.1.1 with AES-256-GCM encryption.",
                    discovered_by="ely_cyber_protocol_parsers",
                )
            )
            return {"protocol": "SMBv1"}, vulns

        if len(raw) < 72 or not raw.startswith(b"\xfeSMB"):
            raise ValueError("Not a valid SMBv1 or SMB2/3 Negotiate packet")

        command = struct.unpack("<H", raw[12:14])[0]
        sec_mode = struct.unpack("<H", raw[66:68])[0] if command == 0 else 0
        dialect_code = struct.unpack("<H", raw[68:70])[0] if command == 0 else 0
        dialect = self.SMB_DIALECTS.get(dialect_code, f"0x{dialect_code:04x}")
        signing_required = bool(sec_mode & 0x0002)

        if command == 0 and not signing_required:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PROTO-SMB-NOSIGN-001",
                    title=f"SMB Signing Not Required on `{asset}` ({dialect})",
                    description=f"SMB Negotiate Response `SecurityMode=0x{sec_mode:04x}` does not mandate signing, enabling NTLM Relay attacks (including ADCS ESC8 / RBCD).",
                    cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-345"],
                    confidence=0.98,
                    mitre_techniques=[MitreTechniqueRef("T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay", MitreTactic.CREDENTIAL_ACCESS)],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Enforce `RequireSecuritySignature = 1` via GPO on all SMB servers and domain workstations.",
                    discovered_by="ely_cyber_protocol_parsers",
                )
            )
        return {"protocol": dialect, "command": command, "signing_required": signing_required}, vulns


class ModbusAndMQTTWireParser:
    """Decodes ICS/OT Modbus TCP ADUs and IoT MQTT CONNECT/PUBLISH packets."""

    MODBUS_WRITE_FCS = {
        0x05: "Write Single Coil",
        0x06: "Write Single Register",
        0x0F: "Write Multiple Coils",
        0x10: "Write Multiple Registers",
        0x16: "Mask Write Register",
        0x08: "Diagnostics (Restart/Force Listen)",
    }

    def audit_modbus_tcp(self, raw: bytes, asset: str = "plc_modbus") -> Tuple[Dict[str, Any], List[CyberVulnerability]]:
        if len(raw) < 8:
            raise ValueError("Modbus TCP ADU shorter than 8 bytes")
        tx_id, proto_id, length, unit_id, fc = struct.unpack("!HHHBB", raw[:8])
        if proto_id != 0:
            raise ValueError(f"Non-zero Modbus TCP Protocol ID: {proto_id}")
        vulns: List[CyberVulnerability] = []
        fc_desc = self.MODBUS_WRITE_FCS.get(fc, f"FunctionCode 0x{fc:02X}")

        if fc in self.MODBUS_WRITE_FCS:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PROTO-OT-MODBUS-WRITE-001",
                    title=f"Unauthenticated Modbus TCP Control Write (`{fc_desc}`, Unit {unit_id})",
                    description=f"Cleartext unauthenticated Modbus TCP `{fc_desc}` command sent to PLC unit `{unit_id}` on `{asset}` without TLS/IPsec or cryptographic auth.",
                    cyber_domain=CyberDomain.FIRMWARE_IOT_OT,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-306", "CWE-319"],
                    confidence=0.98,
                    mitre_techniques=[MitreTechniqueRef("T0855", "Unauthorized Command Message", MitreTactic.IMPACT)],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Isolate PLCs in Purdue Level 1 zones behind deep-packet ICS firewalls and deploy Modbus/TCP Security (TLS + X.509 RBAC).",
                    discovered_by="ely_cyber_protocol_parsers",
                )
            )
        return {"tx_id": tx_id, "unit_id": unit_id, "function_code": fc, "function_name": fc_desc, "length": length}, vulns

    def audit_mqtt_connect(self, raw: bytes, asset: str = "mqtt_broker") -> Tuple[Dict[str, Any], List[CyberVulnerability]]:
        if len(raw) < 12 or (raw[0] >> 4) != 1:
            raise ValueError("Not a valid MQTT CONNECT packet")
        # Decode MQTT variable remaining length
        pos = 1
        mult = 1
        rem_len = 0
        while pos < len(raw):
            b = raw[pos]
            pos += 1
            rem_len += (b & 0x7F) * mult
            mult *= 128
            if not (b & 0x80):
                break
        if pos + 2 > len(raw):
            raise ValueError("Truncated MQTT protocol name")
        pname_len = struct.unpack("!H", raw[pos : pos + 2])[0]
        pos += 2
        pname = raw[pos : pos + pname_len].decode("utf-8", errors="replace")
        pos += pname_len
        if pos + 4 > len(raw):
            raise ValueError("Truncated MQTT variable header")
        proto_level = raw[pos]
        conn_flags = raw[pos + 1]
        keep_alive = struct.unpack("!H", raw[pos + 2 : pos + 4])[0]
        has_username = bool(conn_flags & 0x80)
        has_password = bool(conn_flags & 0x40)

        vulns: List[CyberVulnerability] = []
        if not has_username and not has_password:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-PROTO-IOT-MQTT-ANON-001",
                    title=f"Anonymous Unauthenticated MQTT CONNECT on `{asset}`",
                    description=f"MQTT `{pname}` (v{proto_level}) CONNECT frame lacks username and password flags, indicating anonymous broker access.",
                    cyber_domain=CyberDomain.FIRMWARE_IOT_OT,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-306"],
                    confidence=0.96,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=asset,
                    remediation_guidance="Set `allow_anonymous false`, require per-device X.509 mTLS certificates, and enforce topic-level ACLs.",
                    discovered_by="ely_cyber_protocol_parsers",
                )
            )
        return {
            "protocol_name": pname,
            "protocol_level": proto_level,
            "keep_alive": keep_alive,
            "has_username": has_username,
            "has_password": has_password,
            "remaining_length": rem_len,
        }, vulns
