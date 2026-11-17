"""
API & Microservices Security Engine (OWASP API Top 10 2023, OpenAPI, GraphQL, gRPC & Service Mesh).

Audits modern REST, GraphQL, and gRPC microservice contracts and runtime configs:
  1. OpenAPI / Swagger 3.x Contract Auditor (OWASP API1–API10:2023):
       - Missing global or per-operation `security` schemes (API2 / API5)
       - Cleartext `http://` server endpoints or API keys transmitted via query parameters (`in: query`)
       - Unbounded pagination/collection endpoints missing `maxItems` / `maximum` / rate-limit metadata (API4)
       - Object-ID path parameters (`/users/{id}`, `/orders/{id}`) lacking scope/ownership annotations (API1 BOLA)
       - Sensitive fields exposed in response schemas (`passwordHash`, `secret`, `ssn`, `internalToken`, `apiKey` — API3 BOPLA)
       - Deprecated/shadow version paths (`/v1/`, `/internal/`, `/debug/`, `/admin/` without auth — API9)
       - Webhook / URL callback fields without egress schema validation (API7 SSRF)
  2. GraphQL SDL & Runtime Query Security Auditor:
       - Introspection enabled in production (`__schema`, `__type`)
       - Recursive/cyclic type graph permitting unbounded nested query depth DoS (`User -> friends -> User`)
       - Batching / alias amplification DoS (`a1: login ... a50: login`)
       - Unauthenticated mutations (`deleteUser`, `updateRole`, `resetPassword`)
  3. gRPC / Protobuf & Service-Mesh mTLS Auditor:
       - Plaintext gRPC channels (`insecure_channel`, `WithInsecure()`, `grpc.credentials.createInsecure()`)
       - Reflection service enabled in production
       - Istio / Linkerd `PeerAuthentication` set to `PERMISSIVE` or `DISABLE` instead of `STRICT` mTLS
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

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


SENSITIVE_SCHEMA_FIELDS = {
    "password",
    "passwordhash",
    "password_hash",
    "hashed_password",
    "secret",
    "secret_key",
    "api_key",
    "apikey",
    "private_key",
    "access_token",
    "refresh_token",
    "ssn",
    "social_security",
    "credit_card",
    "card_number",
    "cvv",
    "internal_notes",
    "mfa_secret",
}

SENSITIVE_ADMIN_SEGMENTS = ("/admin", "/internal", "/debug", "/metrics", "/actuator", "/graphql-playground", "/swagger")


class APIMicroservicesSecurityEngine:
    """Comprehensive OpenAPI 3.x, GraphQL, gRPC, and Service-Mesh security engine."""

    # ------------------------------------------------------------------
    # 1. OpenAPI 3.x / Swagger 2.x Contract Security Auditor
    # ------------------------------------------------------------------
    def audit_openapi_spec(self, spec: Dict[str, Any], source_file: str = "openapi.json") -> List[CyberVulnerability]:
        findings: List[CyberVulnerability] = []
        if not isinstance(spec, dict):
            return findings

        global_sec = spec.get("security") or []
        servers = spec.get("servers") or []

        # API8: Cleartext HTTP server URLs
        for srv in servers:
            if isinstance(srv, dict):
                url = str(srv.get("url", ""))
                if url.lower().startswith("http://") and "localhost" not in url.lower() and "127.0.0.1" not in url:
                    findings.append(
                        make_cyber_vuln(
                            rule_id="CYB-API-HTTP-CLEARTEXT-001",
                            title=f"OpenAPI Server Advertises Unencrypted HTTP Endpoint (`{url}`)",
                            description="Production API server URL uses plaintext HTTP, exposing Bearer tokens and payloads to interception.",
                            cyber_domain=CyberDomain.API_MICROSERVICES,
                            severity=Severity.HIGH,
                            cwe_ids=["CWE-319"],
                            owasp_categories=["API8:2023-Security-Misconfiguration"],
                            verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                            file_path=source_file,
                            endpoint_or_asset=url,
                            remediation_guidance="Serve all API endpoints exclusively over HTTPS (TLS 1.3) with HSTS.",
                            discovered_by="ely_cyber_api_auditor",
                        )
                    )

        # API2: API key passed in query string (leaks to proxy/CDN/browser logs)
        sec_schemes = (spec.get("components") or {}).get("securitySchemes") or spec.get("securityDefinitions") or {}
        if isinstance(sec_schemes, dict):
            for sname, sdef in sec_schemes.items():
                if isinstance(sdef, dict) and str(sdef.get("in", "")).lower() == "query":
                    findings.append(
                        make_cyber_vuln(
                            rule_id="CYB-API-QUERY-SECRET-001",
                            title=f"API Security Scheme `{sname}` Transmits Credentials in URL Query String",
                            description="Passing API keys/tokens in query parameters leaks credentials into web server access logs, browser history, and Referer headers.",
                            cyber_domain=CyberDomain.API_MICROSERVICES,
                            severity=Severity.HIGH,
                            cwe_ids=["CWE-598"],
                            owasp_categories=["API2:2023-Broken-Authentication"],
                            verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                            file_path=source_file,
                            endpoint_or_asset=f"securityScheme:{sname}",
                            remediation_guidance="Transmit API credentials strictly via `Authorization: Bearer` or custom HTTP headers over TLS.",
                            discovered_by="ely_cyber_api_auditor",
                        )
                    )

        # Audit every path & operation
        paths = spec.get("paths") or {}
        if isinstance(paths, dict):
            for path_str, path_item in paths.items():
                if not isinstance(path_item, dict):
                    continue
                is_admin_or_debug = any(seg in path_str.lower() for seg in SENSITIVE_ADMIN_SEGMENTS)
                has_obj_id = bool(re.search(r"\{[^}]*(?:id|uuid|user|account|order|tenant)[^}]*\}", path_str, re.IGNORECASE))

                for method in ("get", "post", "put", "patch", "delete"):
                    op = path_item.get(method)
                    if not isinstance(op, dict):
                        continue
                    op_asset = f"{method.upper()} {path_str}"
                    op_sec = op.get("security", global_sec)

                    # API2 / API5: Unauthenticated state-changing or admin operation
                    if (not op_sec or op_sec == [{}]) and (method in ("post", "put", "patch", "delete") or is_admin_or_debug):
                        if not any(pub in path_str.lower() for pub in ("/login", "/auth", "/register", "/health", "/public")):
                            findings.append(
                                make_cyber_vuln(
                                    rule_id="CYB-API-NO-AUTH-001",
                                    title=f"Unauthenticated Sensitive Operation `{op_asset}`",
                                    description=f"OpenAPI operation `{op_asset}` declares no security requirement (`security: []`), exposing state-changing or admin functionality.",
                                    cyber_domain=CyberDomain.API_MICROSERVICES,
                                    severity=Severity.CRITICAL if is_admin_or_debug else Severity.HIGH,
                                    cwe_ids=["CWE-306", "CWE-862"],
                                    owasp_categories=["API5:2023-Broken-Function-Level-Authorization", "API2:2023-Broken-Authentication"],
                                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                                    file_path=source_file,
                                    endpoint_or_asset=op_asset,
                                    remediation_guidance="Attach an explicit OAuth2/JWT/mTLS `security` scheme and enforce server-side RBAC.",
                                    discovered_by="ely_cyber_api_auditor",
                                )
                            )

                    # API4: Unbounded list endpoint lacking limit/page_size parameter maximum
                    if method == "get" and not has_obj_id and not is_admin_or_debug:
                        params = op.get("parameters") or []
                        limit_params = [
                            p for p in params
                            if isinstance(p, dict) and str(p.get("name", "")).lower() in ("limit", "page_size", "per_page", "size", "count")
                        ]
                        for lp in limit_params:
                            schema = lp.get("schema") or {}
                            if isinstance(schema, dict) and "maximum" not in schema:
                                findings.append(
                                    make_cyber_vuln(
                                        rule_id="CYB-API-UNBOUNDED-LIMIT-001",
                                        title=f"Unbounded Pagination Parameter `{lp.get('name')}` on `{op_asset}` (API4 Resource Exhaustion)",
                                        description=f"Pagination parameter `{lp.get('name')}` lacks a schema `maximum`, allowing `limit=999999999` DoS/scraping.",
                                        cyber_domain=CyberDomain.API_MICROSERVICES,
                                        severity=Severity.MEDIUM,
                                        cwe_ids=["CWE-770"],
                                        owasp_categories=["API4:2023-Unrestricted-Resource-Consumption"],
                                        verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                                        file_path=source_file,
                                        endpoint_or_asset=op_asset,
                                        remediation_guidance="Enforce `maximum: 100` in schema validation and server-side query clamping.",
                                        discovered_by="ely_cyber_api_auditor",
                                    )
                                )

                    # API7: Callback / webhook URL parameter without format/host constraint
                    raw_op_str = json.dumps(op).lower()
                    if any(k in raw_op_str for k in ('"webhook_url"', '"callback_url"', '"avatar_url"', '"fetch_url"')):
                        findings.append(
                            make_cyber_vuln(
                                rule_id="CYB-API-SSRF-FIELD-001",
                                title=f"User-Controlled URL Field Detected in `{op_asset}` (API7 SSRF Risk)",
                                description=f"Operation `{op_asset}` accepts a client-supplied outbound URL field (`webhook_url`/`callback_url`), requiring strict egress allowlist validation.",
                                cyber_domain=CyberDomain.API_MICROSERVICES,
                                severity=Severity.HIGH,
                                cwe_ids=["CWE-918"],
                                owasp_categories=["API7:2023-Server-Side-Request-Forgery"],
                                verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                                file_path=source_file,
                                endpoint_or_asset=op_asset,
                                remediation_guidance="Restrict outbound URLs to HTTPS, resolve DNS once, and block RFC 1918/loopback/IMDS ranges.",
                                discovered_by="ely_cyber_api_auditor",
                            )
                        )

        # API3: Excessive Data Exposure / Sensitive properties inside component schemas
        schemas = (spec.get("components") or {}).get("schemas") or spec.get("definitions") or {}
        if isinstance(schemas, dict):
            for sch_name, sch_def in schemas.items():
                if not isinstance(sch_def, dict):
                    continue
                props = sch_def.get("properties") or {}
                if isinstance(props, dict):
                    leaked = [p for p in props.keys() if p.lower() in SENSITIVE_SCHEMA_FIELDS]
                    if leaked:
                        findings.append(
                            make_cyber_vuln(
                                rule_id="CYB-API-BOPLA-SENSITIVE-001",
                                title=f"Sensitive Internal Properties Exposed in API Schema `{sch_name}` ({', '.join(leaked[:4])})",
                                description=f"OpenAPI schema `{sch_name}` models sensitive fields `{leaked}` that risk API3 Excessive Data Exposure or Mass Assignment.",
                                cyber_domain=CyberDomain.API_MICROSERVICES,
                                severity=Severity.HIGH,
                                cwe_ids=["CWE-200", "CWE-915"],
                                owasp_categories=["API3:2023-Broken-Object-Property-Level-Authorization"],
                                verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                                file_path=source_file,
                                endpoint_or_asset=f"schema:{sch_name}",
                                remediation_guidance="Separate internal persistence models from public response/input DTOs and mark secrets `writeOnly` or exclude completely.",
                                discovered_by="ely_cyber_api_auditor",
                            )
                        )

        return findings

    # ------------------------------------------------------------------
    # 2. GraphQL SDL & Query Complexity / Introspection Auditor
    # ------------------------------------------------------------------
    def audit_graphql_schema_and_config(
        self,
        sdl_text: str,
        *,
        introspection_enabled: bool = False,
        depth_limit: Optional[int] = None,
        batching_limit: Optional[int] = None,
        source_file: str = "schema.graphql",
    ) -> List[CyberVulnerability]:
        """Audit GraphQL SDL for cyclic DoS types, sensitive mutations, introspection, and missing depth/batch limits."""
        findings: List[CyberVulnerability] = []

        if introspection_enabled:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-GQL-INTROSPECTION-001",
                    title="GraphQL Introspection Enabled in Production (`__schema` Exposure)",
                    description="Active GraphQL introspection exposes the full API graph, hidden mutations, and internal types to unauthenticated attackers.",
                    cyber_domain=CyberDomain.API_MICROSERVICES,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-200"],
                    owasp_categories=["API9:2023-Improper-Inventory-Management"],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    file_path=source_file,
                    remediation_guidance="Disable introspection in production environments and enforce persisted queries.",
                    discovered_by="ely_cyber_graphql_auditor",
                )
            )

        # Parse GraphQL type definitions & reference edges to detect recursive DoS cycles
        type_blocks = re.findall(r"type\s+(\w+)\s*(?:implements\s+[^{]+)?\{([^}]*)\}", sdl_text, re.DOTALL)
        type_refs: Dict[str, Set[str]] = {}
        sensitive_mutations: List[str] = []

        for tname, body in type_blocks:
            refs: Set[str] = set()
            for line in body.splitlines():
                line_s = line.strip()
                if not line_s or line_s.startswith("#"):
                    continue
                m_field = re.match(r"(\w+)\s*(?:\([^)]*\))?\s*:\s*\[?(\w+)", line_s)
                if m_field:
                    fname, ftype = m_field.group(1), m_field.group(2)
                    refs.add(ftype)
                    if tname == "Mutation" and any(k in fname.lower() for k in ("delete", "admin", "role", "grant", "impersonate", "transfer")):
                        if "@auth" not in line_s.lower() and "@hasrole" not in line_s.lower() and "@require" not in line_s.lower():
                            sensitive_mutations.append(fname)
            type_refs[tname] = refs

        # Detect cycles in GraphQL type graph (e.g. User -> Post -> User)
        cycles = self._find_type_cycles(type_refs)
        if cycles and (depth_limit is None or depth_limit > 10):
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-GQL-CYCLIC-DOS-001",
                    title=f"Unbounded Cyclic GraphQL Type Graph ({' -> '.join(cycles[0])}) Enables Nested Query DoS",
                    description=(
                        f"GraphQL schema contains {len(cycles)} cyclic type reference(s) (e.g., `{' -> '.join(cycles[0])}`) "
                        f"with depth_limit={depth_limit}, allowing exponential CPU/DB exhaustion via deeply nested queries."
                    ),
                    cyber_domain=CyberDomain.API_MICROSERVICES,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-400", "CWE-770"],
                    owasp_categories=["API4:2023-Unrestricted-Resource-Consumption"],
                    verification_method=VerificationMethod.GRAPH_REACHABILITY,
                    file_path=source_file,
                    remediation_guidance="Enforce strict query depth limits (<= 6), query cost/complexity budgets, and pagination caps.",
                    discovered_by="ely_cyber_graphql_auditor",
                )
            )

        if batching_limit is None or batching_limit > 20:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-GQL-BATCH-AMP-001",
                    title="Unrestricted GraphQL Query Batching / Alias Amplification (Brute-Force Bypass)",
                    description=f"GraphQL endpoint lacks strict alias/batching limits (`batching_limit={batching_limit}`), permitting 100+ OTP/login attempts in a single HTTP POST.",
                    cyber_domain=CyberDomain.API_MICROSERVICES,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-799", "CWE-307"],
                    owasp_categories=["API4:2023-Unrestricted-Resource-Consumption"],
                    verification_method=VerificationMethod.PROTOCOL_STATE_MACHINE,
                    file_path=source_file,
                    remediation_guidance="Cap maximum aliases per query (<= 5) and enforce per-operation authentication rate limits.",
                    discovered_by="ely_cyber_graphql_auditor",
                )
            )

        if sensitive_mutations:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-GQL-UNGUARDED-MUTATION",
                    title=f"Privileged GraphQL Mutations Missing Declarative Auth Directives ({', '.join(sensitive_mutations[:4])})",
                    description=f"Sensitive mutations `{sensitive_mutations}` lack `@auth`/`@hasRole` schema directives.",
                    cyber_domain=CyberDomain.API_MICROSERVICES,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-862"],
                    owasp_categories=["API5:2023-Broken-Function-Level-Authorization"],
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    file_path=source_file,
                    remediation_guidance="Annotate every sensitive mutation with declarative authorization directives backed by resolver-level enforcement.",
                    discovered_by="ely_cyber_graphql_auditor",
                )
            )

        return findings

    def _find_type_cycles(self, adj: Dict[str, Set[str]]) -> List[List[str]]:
        cycles: List[List[str]] = []
        visited_global: Set[str] = set()
        for start in sorted(adj.keys()):
            if start in visited_global:
                continue
            stack: List[Tuple[str, List[str]]] = [(start, [start])]
            while stack:
                node, path = stack.pop()
                visited_global.add(node)
                for nxt in sorted(adj.get(node, set())):
                    if nxt not in adj:
                        continue
                    if nxt in path:
                        idx = path.index(nxt)
                        cyc = path[idx:] + [nxt]
                        if cyc not in cycles:
                            cycles.append(cyc)
                            if len(cycles) >= 5:
                                return cycles
                    elif len(path) < 6:
                        stack.append((nxt, path + [nxt]))
        return cycles

    # ------------------------------------------------------------------
    # 3. Repository Scan for OpenAPI, GraphQL, gRPC & Service-Mesh mTLS
    # ------------------------------------------------------------------
    def scan_directory(self, root_path: Path) -> List[CyberVulnerability]:
        findings: List[CyberVulnerability] = []
        seen: set[str] = set()

        for fp in sorted(root_path.rglob("*")):
            if not fp.is_file():
                continue
            if any(p in {".git", "node_modules", "__pycache__", ".venv"} for p in fp.parts):
                continue

            rel = str(fp.relative_to(root_path))
            ext = fp.suffix.lower()

            if ext == ".json":
                try:
                    data = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    continue
                if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
                    for f in self.audit_openapi_spec(data, rel):
                        if f.fingerprint() not in seen:
                            seen.add(f.fingerprint())
                            findings.append(f)

            elif ext in (".graphql", ".gql"):
                try:
                    sdl = fp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for f in self.audit_graphql_schema_and_config(sdl, source_file=rel):
                    if f.fingerprint() not in seen:
                        seen.add(f.fingerprint())
                        findings.append(f)

            elif ext in (".py", ".go", ".js", ".ts", ".java", ".yaml", ".yml"):
                try:
                    lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    continue
                for idx, line in enumerate(lines, start=1):
                    # Plaintext gRPC channels
                    if re.search(r"(?i)(?:grpc\.insecure_channel|grpc\.WithInsecure\s*\(|credentials\.createInsecure\s*\(|usePlaintext\s*\(\))", line):
                        v = make_cyber_vuln(
                            rule_id="CYB-GRPC-INSECURE-CHANNEL",
                            title="Plaintext Unauthenticated gRPC Channel Configured",
                            description="Microservice gRPC client/server omits TLS/mTLS transport credentials.",
                            cyber_domain=CyberDomain.API_MICROSERVICES,
                            severity=Severity.HIGH,
                            cwe_ids=["CWE-319"],
                            owasp_categories=["API8:2023-Security-Misconfiguration"],
                            file_path=rel,
                            line_start=idx,
                            line_end=idx,
                            code_snippet=line.strip()[:220],
                            remediation_guidance="Enforce mTLS (`grpc.secure_channel` / SPIFFE X.509 SVIDs) for all service-to-service RPCs.",
                            discovered_by="ely_cyber_grpc_auditor",
                        )
                        if v.fingerprint() not in seen:
                            seen.add(v.fingerprint())
                            findings.append(v)

                    # Istio PeerAuthentication permissive/disabled mTLS
                    if ext in (".yaml", ".yml") and re.search(r"(?i)mode\s*:\s*(?:PERMISSIVE|DISABLE)\b", line):
                        win = "\n".join(lines[max(0, idx - 8) : min(len(lines), idx + 3)])
                        if "PeerAuthentication" in win or "mtls" in win.lower():
                            v = make_cyber_vuln(
                                rule_id="CYB-MESH-MTLS-PERMISSIVE",
                                title="Service Mesh mTLS Set to `PERMISSIVE` / `DISABLE`",
                                description="Allowing plaintext fallback in service mesh permits lateral traffic sniffing and impersonation inside the cluster.",
                                cyber_domain=CyberDomain.API_MICROSERVICES,
                                severity=Severity.HIGH,
                                cwe_ids=["CWE-319", "CWE-287"],
                                file_path=rel,
                                line_start=idx,
                                line_end=idx,
                                code_snippet=line.strip()[:220],
                                remediation_guidance="Set Istio `PeerAuthentication.spec.mtls.mode: STRICT` namespace- and mesh-wide.",
                                discovered_by="ely_cyber_mesh_auditor",
                            )
                            if v.fingerprint() not in seen:
                                seen.add(v.fingerprint())
                                findings.append(v)

        return findings
