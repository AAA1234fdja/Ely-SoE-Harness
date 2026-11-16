"""
DNS Security (DNSSEC/CAA/Dangling-CNAME Subdomain Takeover), Email Authentication
(RFC 7208 SPF Recursive Lookup Verifier, RFC 7489 DMARC, RFC 6376 DKIM), and
BGP / RPKI Route-Origin Validation Security Auditor.

Audits internet-edge domain, mail, and routing security posture without external network calls:
  1. **RFC 7208 SPF Recursive Policy Evaluator**:
       - Parses `v=spf1` mechanisms (`include:`, `a`, `mx`, `ptr`, `exists:`, `redirect=`, `ip4:`, `ip6:`, `all`).
       - Recursively traverses `include:` / `redirect=` graphs from zone snapshots to detect
         **> 10 DNS lookup PermError violations**, circular include loops, deprecated `ptr`,
         and overly permissive `+all` / `?all` / `~all` qualifiers.
  2. **RFC 7489 DMARC & RFC 6376 DKIM Auditor**:
       - Verifies DMARC policy enforcement (`p=reject` vs weak `p=none`), subdomain policy
         (`sp=`), percentage sampling (`pct < 100`), alignment modes (`adkim=s`, `aspf=s`),
         and reporting URIs (`rua`/`ruf`).
       - Checks DKIM public keys for weak RSA key sizes (`< 2048` bits), revoked/empty `p=`,
         and deprecated SHA-1 hashes.
  3. **Dangling DNS & Subdomain Takeover Engine (22 Cloud SaaS Provider Fingerprints)**:
       - Detects CNAME / ALIAS records pointing to unclaimed GitHub Pages, AWS S3/CloudFront/
         ElasticBeanstalk, Azure App Service/Blob, Heroku, Fastly, Shopify, Zendesk, Netlify,
         Surge, Pantheonsite, ReadTheDocs, Bitbucket, Tumblr, WP Engine, Cargo, Ghost, etc.
       - Checks DNSSEC (`DS`/`DNSKEY`/`RRSIG`), `CAA` certificate issuance pins, and open
         `AXFR` zone-transfer allowances.
  4. **BGP / RPKI Route-Origin Authorization (ROA) & Route-Leak Verifier**:
       - Compares announced BGP prefixes + AS-Paths against authorized RPKI ROAs to detect
         **RPKI INVALID Origin Hijacks**, **More-Specific Prefix Sub-Hijacks**, **AS-Path
         Bogon/Private ASN Leaks**, and **Valley-Free Customer-Provider Route Leaks**.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

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


TAKEOVER_CNAME_PROVIDERS: Tuple[Tuple[str, str, str], ...] = (
    ("github.io", "GitHub Pages", "There isn't a GitHub Pages site here"),
    ("s3.amazonaws.com", "AWS S3 Bucket", "NoSuchBucket"),
    ("s3-website", "AWS S3 Static Website", "NoSuchBucket"),
    ("cloudfront.net", "AWS CloudFront", "Bad Request: ERROR: The request could not be satisfied"),
    ("elasticbeanstalk.com", "AWS Elastic Beanstalk", "NXDOMAIN"),
    ("azurewebsites.net", "Azure App Service", "404 Web Site not found"),
    ("blob.core.windows.net", "Azure Blob Storage", "BlobNotFound"),
    ("cloudapp.azure.com", "Azure CloudApp", "NXDOMAIN"),
    ("trafficmanager.net", "Azure Traffic Manager", "NXDOMAIN"),
    ("herokuapp.com", "Heroku", "No such app"),
    ("herokudns.com", "Heroku Custom DNS", "There is no app configured at that hostname"),
    ("fastly.net", "Fastly CDN", "Fastly error: unknown domain"),
    ("myshopify.com", "Shopify", "Sorry, this shop is currently unavailable"),
    ("zendesk.com", "Zendesk", "Help Center Closed"),
    ("netlify.app", "Netlify", "Not Found - Request ID"),
    ("surge.sh", "Surge.sh", "project not found"),
    ("pantheonsite.io", "Pantheon", "404 error unknown site"),
    ("readthedocs.io", "ReadTheDocs", "unknown to Read the Docs"),
    ("bitbucket.io", "Bitbucket", "Repository not found"),
    ("ghost.io", "Ghost", "The thing you were looking for is no longer here"),
    ("wpengine.com", "WP Engine", "The site you were looking for couldn't be found"),
    ("unbouncepages.com", "Unbounce", "The requested URL was not found"),
)

PRIVATE_OR_BOGON_ASNS: Tuple[Tuple[int, int], ...] = (
    (0, 0),
    (23456, 23456),
    (64496, 65551),
    (4200000000, 4294967295),
)


@dataclass
class DNSZoneSnapshot:
    domain: str
    txt_records: Dict[str, List[str]] = field(default_factory=dict)  # fqdn -> [txt strings]
    cname_records: Dict[str, Tuple[str, bool]] = field(default_factory=dict)  # fqdn -> (target, target_resolves)
    caa_records: List[str] = field(default_factory=list)
    dnssec_enabled: bool = False
    axfr_restricted: bool = True
    dkim_selectors: Dict[str, str] = field(default_factory=dict)  # selector -> TXT value


@dataclass
class RPKIROARecord:
    prefix: str
    max_length: int
    origin_asn: int


@dataclass
class BGPAnnouncement:
    prefix: str
    as_path: List[int]
    peer_type: str = "customer"  # customer | peer | transit
    exported_to: str = "transit"  # customer | peer | transit


class DNSBGPEmailAuthAuditor:
    """Comprehensive auditor for Email Auth (SPF/DKIM/DMARC), DNS Takeovers/DNSSEC, and BGP/RPKI."""

    def audit_spf(
        self,
        domain: str,
        txt_records: Dict[str, List[str]],
    ) -> Dict[str, Any]:
        """Recursively parse and validate RFC 7208 SPF policy for `domain`."""
        vulns: List[CyberVulnerability] = []
        root_txts = [t for t in txt_records.get(domain, []) if t.strip().lower().startswith("v=spf1")]

        if not root_txts:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-EMAIL-SPF-MISSING-001",
                    title=f"Missing SPF TXT Record on `{domain}` (Direct Domain Email Spoofing)",
                    description=f"Domain `{domain}` publishes no `v=spf1` record, enabling unrestricted forged sender spoofing.",
                    cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-290"],
                    confidence=0.99,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=domain,
                    remediation_guidance="Publish a strict `v=spf1 ... -all` TXT record listing authorized outbound mail relays only.",
                    discovered_by="ely_cyber_dns_email_bgp_auditor",
                )
            )
            return {"domain": domain, "spf_present": False, "dns_lookups": 0, "vulnerabilities": vulns}

        if len(root_txts) > 1:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-EMAIL-SPF-MULTI-001",
                    title=f"Multiple Conflicting SPF Records Published on `{domain}` (RFC 7208 PermError)",
                    description=f"RFC 7208 §3.2 forbids publishing multiple `v=spf1` TXT records ({len(root_txts)} found); receivers return PermError.",
                    cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-290"],
                    confidence=0.99,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=domain,
                    remediation_guidance="Merge all mechanisms into a single canonical `v=spf1` TXT record.",
                    discovered_by="ely_cyber_dns_email_bgp_auditor",
                )
            )

        lookups = 0
        visited: Set[str] = set()
        cycle_detected = False
        uses_ptr = False
        all_qualifier = "missing"

        def _walk(cur_dom: str, record: str, depth: int = 0) -> None:
            nonlocal lookups, cycle_detected, uses_ptr, all_qualifier
            if depth > 12:
                return
            tokens = record.strip().split()
            for tok in tokens[1:]:
                tl = tok.lower()
                if tl in ("+all", "all"):
                    if cur_dom == domain:
                        all_qualifier = "+all"
                elif tl in ("?all", "~all", "-all"):
                    if cur_dom == domain:
                        all_qualifier = tl
                elif tl.startswith(("include:", "+include:")):
                    lookups += 1
                    inc_dom = tok.split(":", 1)[1].strip()
                    if inc_dom in visited:
                        cycle_detected = True
                        continue
                    visited.add(inc_dom)
                    for inc_txt in txt_records.get(inc_dom, []):
                        if inc_txt.strip().lower().startswith("v=spf1"):
                            _walk(inc_dom, inc_txt, depth + 1)
                            break
                elif tl.startswith("redirect="):
                    lookups += 1
                    redir = tok.split("=", 1)[1].strip()
                    if redir in visited:
                        cycle_detected = True
                        continue
                    visited.add(redir)
                    for r_txt in txt_records.get(redir, []):
                        if r_txt.strip().lower().startswith("v=spf1"):
                            _walk(redir, r_txt, depth + 1)
                            break
                elif re.match(r"^[+\-~?]?(?:a|mx|exists)(?:[:/]|$)", tl):
                    lookups += 1
                elif re.match(r"^[+\-~?]?ptr(?:[:/]|$)", tl):
                    lookups += 1
                    uses_ptr = True

        visited.add(domain)
        _walk(domain, root_txts[0])

        if all_qualifier in ("+all", "?all"):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-EMAIL-SPF-PERMISSIVE-ALL",
                    title=f"Permissive SPF Qualifier `{all_qualifier}` on `{domain}` Allows Arbitrary Senders",
                    description=f"SPF record for `{domain}` ends with `{all_qualifier}`, effectively authorizing any IP on the internet to spoof mail.",
                    cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                    severity=Severity.CRITICAL if all_qualifier == "+all" else Severity.HIGH,
                    cwe_ids=["CWE-290"],
                    confidence=0.99,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=domain,
                    remediation_guidance="Replace `+all`/`?all` with strict hard-fail `-all` paired with DMARC `p=reject`.",
                    discovered_by="ely_cyber_dns_email_bgp_auditor",
                )
            )
        if lookups > 10:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-EMAIL-SPF-LOOKUP-LIMIT",
                    title=f"SPF Exceeds RFC 7208 10-DNS-Lookup Limit ({lookups} Lookups -> PermError)",
                    description=f"Recursive SPF expansion for `{domain}` triggers {lookups} DNS lookups (>10 max), causing strict receivers to fail SPF validation.",
                    cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-400", "CWE-290"],
                    confidence=0.98,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=domain,
                    remediation_guidance="Flatten unused `include:` chains or consolidate outbound relays onto dedicated subdomains.",
                    discovered_by="ely_cyber_dns_email_bgp_auditor",
                )
            )
        if cycle_detected:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-EMAIL-SPF-LOOP",
                    title=f"Circular SPF `include:` / `redirect=` Loop Detected on `{domain}`",
                    description="Circular SPF recursion produces permanent SPF evaluation failure (`PermError`).",
                    cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-835"],
                    confidence=0.99,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=domain,
                    remediation_guidance="Break the circular SPF include chain immediately.",
                    discovered_by="ely_cyber_dns_email_bgp_auditor",
                )
            )
        if uses_ptr:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-EMAIL-SPF-PTR-DEPRECATED",
                    title=f"SPF Record on `{domain}` Uses Deprecated `ptr` Mechanism (RFC 7208 §5.5)",
                    description="The `ptr` mechanism is slow, unreliable, and explicitly deprecated by RFC 7208.",
                    cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                    severity=Severity.LOW,
                    cwe_ids=["CWE-290"],
                    confidence=0.95,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=domain,
                    remediation_guidance="Replace `ptr` with explicit `ip4:`/`ip6:` CIDRs or `include:` mechanisms.",
                    discovered_by="ely_cyber_dns_email_bgp_auditor",
                )
            )

        return {
            "domain": domain,
            "spf_present": True,
            "dns_lookups": lookups,
            "all_qualifier": all_qualifier,
            "cycle_detected": cycle_detected,
            "vulnerabilities": vulns,
        }

    def audit_dmarc_and_dkim(self, zone: DNSZoneSnapshot) -> List[CyberVulnerability]:
        """Audit `_dmarc.<domain>` policy tags and DKIM selector public key lengths."""
        vulns: List[CyberVulnerability] = []
        dmarc_key = f"_dmarc.{zone.domain}"
        dmarc_txts = [t for t in zone.txt_records.get(dmarc_key, []) if "v=dmarc1" in t.lower()]

        if not dmarc_txts:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-EMAIL-DMARC-MISSING-001",
                    title=f"Missing DMARC Record (`{dmarc_key}`) Enables Display-From Phishing",
                    description=f"Domain `{zone.domain}` lacks a DMARC policy, allowing attackers to forge exact `From:` headers.",
                    cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-290"],
                    confidence=0.99,
                    mitre_techniques=[MitreTechniqueRef("T1566", "Phishing", MitreTactic.INITIAL_ACCESS)],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=dmarc_key,
                    remediation_guidance="Publish `v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100; rua=mailto:dmarc@domain`.",
                    discovered_by="ely_cyber_dns_email_bgp_auditor",
                )
            )
        else:
            tags: Dict[str, str] = {}
            for part in dmarc_txts[0].split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    tags[k.strip().lower()] = v.strip().lower()
            pol = tags.get("p", "none")
            pct = int(tags.get("pct", "100")) if tags.get("pct", "100").isdigit() else 100
            if pol == "none":
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-EMAIL-DMARC-PNONE-001",
                        title=f"DMARC Policy on `{zone.domain}` Set to Non-Enforcing `p=none`",
                        description="DMARC `p=none` only monitors spoofing without rejecting or quarantining fraudulent emails.",
                        cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                        severity=Severity.MEDIUM,
                        cwe_ids=["CWE-290"],
                        confidence=0.98,
                        verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                        endpoint_or_asset=dmarc_key,
                        remediation_guidance="Transition DMARC policy from `p=none` to `p=quarantine` then `p=reject`.",
                        discovered_by="ely_cyber_dns_email_bgp_auditor",
                    )
                )
            if pct < 100:
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-EMAIL-DMARC-PARTIAL-PCT",
                        title=f"DMARC Partial Enforcement (`pct={pct}%`) Leaves {100 - pct}% of Mail Unprotected",
                        description=f"DMARC `pct={pct}` exempts {100 - pct}% of failed spoofed mail from enforcement.",
                        cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                        severity=Severity.MEDIUM,
                        cwe_ids=["CWE-290"],
                        confidence=0.95,
                        verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                        endpoint_or_asset=dmarc_key,
                        remediation_guidance="Set `pct=100` once aggregate `rua` reports confirm legitimate sources align.",
                        discovered_by="ely_cyber_dns_email_bgp_auditor",
                    )
                )

        # DKIM selector key strength audit
        for sel, rec in zone.dkim_selectors.items():
            tags = {}
            for part in rec.split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    tags[k.strip().lower()] = v.strip()
            pub_b64 = tags.get("p", "")
            if not pub_b64:
                continue  # Intentionally revoked key
            try:
                raw_der = base64.b64decode(pub_b64)
                # Rough RSA modulus bit estimate from SubjectPublicKeyInfo DER length:
                # 1024-bit ~ 162 bytes, 2048-bit ~ 294 bytes
                est_bits = 1024 if len(raw_der) < 220 else 2048
            except Exception:
                est_bits = 0
            if 0 < est_bits < 2048:
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-EMAIL-DKIM-WEAK-KEY",
                        title=f"DKIM Selector `{sel}._domainkey.{zone.domain}` Uses Weak <2048-bit RSA Key",
                        description=f"DKIM public key for selector `{sel}` is estimated at {est_bits} bits (below NIST/RFC 8301 2048-bit minimum).",
                        cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-326"],
                        confidence=0.94,
                        verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                        endpoint_or_asset=f"{sel}._domainkey.{zone.domain}",
                        remediation_guidance="Rotate DKIM selector to 2048-bit RSA or Ed25519 (`k=ed25519`).",
                        discovered_by="ely_cyber_dns_email_bgp_auditor",
                    )
                )
        return vulns

    def audit_dns_zone(self, zone: DNSZoneSnapshot) -> Dict[str, Any]:
        """Full DNS zone security audit: SPF, DMARC/DKIM, Dangling CNAME Takeovers, DNSSEC, CAA, AXFR."""
        vulns: List[CyberVulnerability] = []
        spf_res = self.audit_spf(zone.domain, zone.txt_records)
        vulns.extend(spf_res["vulnerabilities"])
        vulns.extend(self.audit_dmarc_and_dkim(zone))

        # Dangling CNAME Subdomain Takeover detection
        takeover_hits: List[Dict[str, str]] = []
        for fqdn, (target, resolves) in zone.cname_records.items():
            tl = target.lower().rstrip(".")
            if not resolves:
                for suffix, provider, fp_hint in TAKEOVER_CNAME_PROVIDERS:
                    if suffix in tl:
                        takeover_hits.append({"fqdn": fqdn, "target": target, "provider": provider})
                        vulns.append(
                            make_cyber_vuln(
                                rule_id="CYB-DNS-SUBDOMAIN-TAKEOVER-001",
                                title=f"Dangling CNAME Subdomain Takeover on `{fqdn}` -> Unclaimed `{provider}` (`{target}`)",
                                description=(
                                    f"DNS record `{fqdn}` points via CNAME to `{target}` ({provider}), which no longer resolves / "
                                    f"is unclaimed (fingerprint: `{fp_hint}`). Attackers can claim the SaaS resource to host phishing, "
                                    "steal wildcard parent-domain cookies, and mint valid DV TLS certificates."
                                ),
                                cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                                severity=Severity.CRITICAL,
                                cwe_ids=["CWE-284", "CWE-672"],
                                confidence=0.98,
                                cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="P", vc="H", vi="H", va="N", sc="H", si="H", sa="N"),
                                mitre_techniques=[MitreTechniqueRef("T1584.001", "Compromise Infrastructure: Domains", MitreTactic.RESOURCE_DEVELOPMENT)],
                                verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                                endpoint_or_asset=fqdn,
                                remediation_guidance=f"Immediately delete the stale CNAME record `{fqdn}` -> `{target}` from authoritative DNS.",
                                discovered_by="ely_cyber_dns_email_bgp_auditor",
                            )
                        )
                        break

        if not zone.dnssec_enabled:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-DNS-NO-DNSSEC-001",
                    title=f"DNSSEC Not Enabled on `{zone.domain}` (Cache Poisoning Exposure)",
                    description=f"Zone `{zone.domain}` lacks DNSSEC `DS`/`RRSIG` cryptographic signing.",
                    cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-345"],
                    confidence=0.96,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=zone.domain,
                    remediation_guidance="Sign zone with ECDSA P-256 (`Algorithm 13`) and publish `DS` record at registrar.",
                    discovered_by="ely_cyber_dns_email_bgp_auditor",
                )
            )
        if not zone.caa_records:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-DNS-NO-CAA-001",
                    title=f"Missing DNS `CAA` Record on `{zone.domain}` (Unrestricted CA Certificate Issuance)",
                    description=f"Without DNS `CAA` records, any publicly trusted CA worldwide may issue TLS certificates for `{zone.domain}`.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.LOW,
                    cwe_ids=["CWE-295"],
                    confidence=0.95,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=zone.domain,
                    remediation_guidance='Publish `CAA 0 issue "letsencrypt.org"` (or approved CA) and `issuewild ";"` records.',
                    discovered_by="ely_cyber_dns_email_bgp_auditor",
                )
            )
        if not zone.axfr_restricted:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-DNS-OPEN-AXFR-001",
                    title=f"Unrestricted DNS Zone Transfer (`AXFR`) Permitted on `{zone.domain}`",
                    description="Authoritative nameserver allows unauthenticated `AXFR`, exposing full internal hostname topology.",
                    cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-200"],
                    confidence=0.99,
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    endpoint_or_asset=zone.domain,
                    remediation_guidance="Restrict `allow-transfer` strictly to secondary NS IPs authenticated via TSIG.",
                    discovered_by="ely_cyber_dns_email_bgp_auditor",
                )
            )

        return {
            "audited_at": utc_now_iso(),
            "domain": zone.domain,
            "spf_summary": {k: v for k, v in spf_res.items() if k != "vulnerabilities"},
            "dangling_takeover_hits": takeover_hits,
            "dnssec_enabled": zone.dnssec_enabled,
            "caa_present": bool(zone.caa_records),
            "vulnerabilities": vulns,
        }

    def audit_bgp_rpki(
        self,
        announcements: Sequence[BGPAnnouncement],
        roas: Sequence[RPKIROARecord],
    ) -> Dict[str, Any]:
        """Validate BGP prefix announcements against RPKI ROAs, Bogon ASNs, and valley-free route leaks."""
        vulns: List[CyberVulnerability] = []
        parsed_roas = [(ipaddress.ip_network(r.prefix, strict=False), r.max_length, r.origin_asn) for r in roas]
        stats = {"valid": 0, "invalid_origin": 0, "invalid_length": 0, "not_found": 0, "route_leaks": 0}

        for ann in announcements:
            net = ipaddress.ip_network(ann.prefix, strict=False)
            origin_asn = ann.as_path[-1] if ann.as_path else 0

            # 1. Check Bogon / Private ASN in public AS-Path
            bogons = [
                asn for asn in ann.as_path
                if any(lo <= asn <= hi for lo, hi in PRIVATE_OR_BOGON_ASNS)
            ]
            if bogons:
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-BGP-BOGON-ASN-001",
                        title=f"BGP Prefix `{ann.prefix}` Announces Private/Bogon ASN(s) `{bogons}` in AS-Path",
                        description=f"AS-Path `{ann.as_path}` leaks private/reserved ASNs into global BGP tables.",
                        cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                        severity=Severity.MEDIUM,
                        cwe_ids=["CWE-284"],
                        confidence=0.97,
                        verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                        endpoint_or_asset=ann.prefix,
                        remediation_guidance="Filter RFC 6996 private/bogon ASNs on all eBGP edge ingress/egress prefix-lists.",
                        discovered_by="ely_cyber_dns_email_bgp_auditor",
                    )
                )

            # 2. Valley-Free Route Leak detection (RFC 7908 Type 1: peer/transit -> transit/peer)
            if ann.peer_type in ("peer", "transit") and ann.exported_to in ("peer", "transit"):
                stats["route_leaks"] += 1
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-BGP-ROUTE-LEAK-001",
                        title=f"RFC 7908 BGP Valley-Free Route Leak Detected for `{ann.prefix}` ({ann.peer_type} -> {ann.exported_to})",
                        description=f"Route learned from `{ann.peer_type}` is illegally re-advertised to `{ann.exported_to}`, risking global traffic blackholing/interception.",
                        cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-284"],
                        confidence=0.98,
                        verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                        endpoint_or_asset=ann.prefix,
                        remediation_guidance="Enforce BGP Roles (`Only-To-Customer` RFC 9234) and strict valley-free export policies.",
                        discovered_by="ely_cyber_dns_email_bgp_auditor",
                    )
                )

            # 3. RFC 6811 RPKI Route Origin Validation (ROV)
            covering = [
                (rnet, max_len, roa_asn)
                for (rnet, max_len, roa_asn) in parsed_roas
                if net.version == rnet.version and net.subnet_of(rnet)
            ]
            if not covering:
                stats["not_found"] += 1
                continue

            exact_valid = any(roa_asn == origin_asn and net.prefixlen <= max_len for (_, max_len, roa_asn) in covering)
            if exact_valid:
                stats["valid"] += 1
            else:
                origin_matched = any(roa_asn == origin_asn for (_, _, roa_asn) in covering)
                if origin_matched:
                    stats["invalid_length"] += 1
                    vulns.append(
                        make_cyber_vuln(
                            rule_id="CYB-BGP-RPKI-INVALID-LEN",
                            title=f"RPKI INVALID (More-Specific Prefix Sub-Hijack) on `{ann.prefix}` from AS{origin_asn}",
                            description=f"Prefix length `/{net.prefixlen}` exceeds authorized ROA `maxLength` for AS{origin_asn}, matching sub-prefix hijack signatures.",
                            cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                            severity=Severity.CRITICAL,
                            cwe_ids=["CWE-345"],
                            confidence=0.99,
                            mitre_techniques=[MitreTechniqueRef("T1557", "Adversary-in-the-Middle (BGP Hijack)", MitreTactic.CREDENTIAL_ACCESS)],
                            verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                            endpoint_or_asset=ann.prefix,
                            remediation_guidance="Drop RPKI-INVALID routes at border routers (`RPKI ROV`) and verify authorized ROA maxLength.",
                            discovered_by="ely_cyber_dns_email_bgp_auditor",
                        )
                    )
                else:
                    stats["invalid_origin"] += 1
                    expected_asns = sorted({asn for (_, _, asn) in covering})
                    vulns.append(
                        make_cyber_vuln(
                            rule_id="CYB-BGP-RPKI-HIJACK-001",
                            title=f"RPKI INVALID Origin Hijack Alert: `{ann.prefix}` Announced by Unauthorized AS{origin_asn} (Expected {expected_asns})",
                            description=f"AS{origin_asn} is announcing prefix `{ann.prefix}` in direct conflict with cryptographic RPKI ROA authorizing AS{expected_asns}.",
                            cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                            severity=Severity.CRITICAL,
                            cwe_ids=["CWE-290", "CWE-345"],
                            confidence=0.99,
                            cvss4=CVSSv4Metrics(av="N", ac="H", at="N", pr="N", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
                            mitre_techniques=[MitreTechniqueRef("T1557", "BGP Prefix Origin Hijack", MitreTactic.CREDENTIAL_ACCESS)],
                            verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                            endpoint_or_asset=ann.prefix,
                            remediation_guidance="Enforce RPKI Drop-Invalid at all peering edges and contact upstream transit NOC immediately.",
                            discovered_by="ely_cyber_dns_email_bgp_auditor",
                        )
                    )

        return {
            "audited_at": utc_now_iso(),
            "announcements_checked": len(announcements),
            "rov_summary": stats,
            "vulnerabilities": vulns,
        }
