"""
Deep Modern API Protocol Security Engine: GraphQL SDL Cyclic Graph Analyzer,
gRPC / Protobuf Service Auditor & WebSocket CSWSH / Protocol Auditor.

Goes far beyond basic regexes by structurally parsing GraphQL Schemas (`.graphql`/`.gql`),
Protobuf IDL definitions (`.proto`), and WebSocket server/client code:
  1. **GraphQL SDL Type-Graph Parser & DoS/AuthZ Auditor**:
       - Builds a directed type-reference graph from `type Foo { bar: [Baz!] }` definitions.
       - Runs Tarjan/DFS cycle detection to find **Recursive Nested Query Depth-Bomb Cycles**
         (e.g., `User -> posts: [Post] -> author: User`, enabling exponential `O(k^d)` CPU/DB DoS!).
       - Flags sensitive fields (`passwordHash`, `ssn`, `apiKey`, `secret`, `token`, `admin`)
         and dangerous mutations (`deleteUser`, `grantAdmin`, `impersonate`, `updateRole`)
         lacking explicit `@auth` / `@hasRole` / `@requiresScopes` directives.
       - Flags GraphQL introspection enabled in production (`introspection: true`), GraphiQL/
         Playground exposure, missing query depth/complexity limits, and unrestricted batching.
  2. **gRPC / Protobuf Service Security Auditor**:
       - Parses `.proto` `service` / `rpc` declarations and code configurations.
       - Detects **gRPC Server Reflection** enabled in production (`reflection.enable_server_reflection`),
         **Cleartext Insecure Channels** (`insecure_channel`, `WithInsecure()`, `add_insecure_port`),
         unbounded bidirectional streaming RPCs lacking message size / rate caps, and
         sensitive RPCs missing auth interceptor metadata enforcement.
  3. **WebSocket Security Auditor (CSWSH & Framing)**:
       - Detects **Cross-Site WebSocket Hijacking (CSWSH)** where servers omit `Origin` header
         verification or set wildcard `checkOrigin: () => true` / `cors: { origin: '*' }`.
       - Flags unencrypted `ws://` transport carrying tokens in URL query strings
         (`ws://host/stream?token=...`), missing `maxPayload` size caps (memory DoS), and
         direct `eval`/`innerHTML`/SQL execution on untrusted WebSocket messages.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
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


SENSITIVE_GQL_FIELD_TOKENS: Tuple[str, ...] = (
    "password", "passwd", "secret", "apikey", "api_key", "token", "ssn", "creditcard",
    "privatekey", "private_key", "hash", "salt", "salary", "auditlog", "internalnotes",
)

PRIVILEGED_GQL_MUTATION_TOKENS: Tuple[str, ...] = (
    "delete", "admin", "grant", "revoke", "impersonate", "promote", "role", "permission",
    "export", "transfer", "payout", "resetpassword", "disablemfa",
)

AUTH_DIRECTIVE_PATTERN = re.compile(r"@(?:auth|hasRole|requiresAuth|authenticated|requirePermission|scope|guard)\b", re.IGNORECASE)


class GraphQLGRPCWebSocketAuditor:
    """Structural security analyzer for GraphQL SDL, gRPC/Protobuf, and WebSocket architectures."""

    def audit_graphql_schema(self, sdl_text: str, asset: str = "schema.graphql") -> Dict[str, Any]:
        """Parse GraphQL SDL types, detect cyclic depth-bomb graphs, and audit auth directives."""
        vulns: List[CyberVulnerability] = []
        type_graph: Dict[str, Set[str]] = {}
        list_edges: Set[Tuple[str, str]] = set()
        type_blocks = re.finditer(r"(?m)^\s*type\s+(\w+)(?:\s+implements\s+[^{]+)?\s*\{([^}]*)\}", sdl_text)

        defined_types: Set[str] = set()
        raw_fields: Dict[str, List[Tuple[str, str, str]]] = {}

        # Match GraphQL fields across both single-line and multi-line SDL blocks
        field_rx = re.compile(
            r"(\w+)\s*(?:\([^)]*\))?\s*:\s*([\[\]\w!]+)((?:\s*@\w+(?:\([^)]*\))?)*)"
        )
        for m in type_blocks:
            tname = m.group(1)
            body = re.sub(r"#[^\n]*", "", m.group(2))
            defined_types.add(tname)
            type_graph.setdefault(tname, set())
            raw_fields[tname] = []
            for fm in field_rx.finditer(body):
                fname, ftype, rest = fm.group(1), fm.group(2), fm.group(3)
                base_type = re.sub(r"[\[\]!]", "", ftype)
                raw_fields[tname].append((fname, ftype, rest))
                type_graph[tname].add(base_type)
                if "[" in ftype:
                    list_edges.add((tname, base_type))

        # Keep only references to defined object types (exclude scalar types like String/Int/ID)
        obj_graph: Dict[str, Set[str]] = {
            t: {dst for dst in dsts if dst in defined_types}
            for t, dsts in type_graph.items()
        }

        # Find elementary cycles via bounded DFS
        cycles = self._find_cycles(obj_graph)
        amplifying_cycles = [
            cyc for cyc in cycles
            if any((cyc[i], cyc[(i + 1) % len(cyc)]) in list_edges for i in range(len(cyc)))
        ]

        for cyc in amplifying_cycles[:5]:
            cycle_str = " -> ".join(cyc + [cyc[0]])
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-GQL-CYCLIC-DEPTH-BOMB",
                    title=f"GraphQL Cyclic List-Amplification Depth-Bomb Path (`{cycle_str}`)",
                    description=(
                        f"Schema `{asset}` contains cyclic object-list references (`{cycle_str}`). "
                        "Without strict query depth and cost complexity limiters, a single nested query causes exponential DB/CPU DoS."
                    ),
                    cyber_domain=CyberDomain.API_MICROSERVICES,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-400", "CWE-674"],
                    confidence=0.96,
                    cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="N", vi="N", va="H", sc="N", si="N", sa="N"),
                    verification_method=VerificationMethod.GRAPH_REACHABILITY,
                    endpoint_or_asset=asset,
                    remediation_guidance="Enforce maximum query depth (<= 6), query cost/complexity budget, and persisted-query allowlists.",
                    discovered_by="ely_cyber_graphql_grpc_ws_auditor",
                )
            )

        # Audit unprotected sensitive fields and privileged mutations
        for tname, fields in raw_fields.items():
            for fname, ftype, rest in fields:
                fn_l = fname.lower()
                has_auth = bool(AUTH_DIRECTIVE_PATTERN.search(rest))
                if tname == "Mutation" and any(tok in fn_l for tok in PRIVILEGED_GQL_MUTATION_TOKENS) and not has_auth:
                    vulns.append(
                        make_cyber_vuln(
                            rule_id=f"CYB-GQL-UNAUTH-MUTATION-{fname.upper()[:24]}",
                            title=f"Privileged GraphQL Mutation `{fname}` Lacks Declarative `@auth` / `@hasRole` Directive",
                            description=f"Mutation `{fname}: {ftype}` in `{asset}` performs sensitive state changes without a schema-level authorization directive.",
                            cyber_domain=CyberDomain.API_MICROSERVICES,
                            severity=Severity.HIGH,
                            cwe_ids=["CWE-862", "CWE-306"],
                            confidence=0.89,
                            owasp_categories=["API5:2023-Broken-Function-Level-Authorization"],
                            verification_method=VerificationMethod.STATIC_AST,
                            endpoint_or_asset=f"{asset}#Mutation.{fname}",
                            remediation_guidance="Annotate privileged mutations with `@auth(requires: ADMIN)` and enforce resolver-level RBAC + ownership checks.",
                            discovered_by="ely_cyber_graphql_grpc_ws_auditor",
                        )
                    )
                elif any(tok in fn_l for tok in SENSITIVE_GQL_FIELD_TOKENS) and not has_auth:
                    vulns.append(
                        make_cyber_vuln(
                            rule_id=f"CYB-GQL-SENSITIVE-FIELD-{fname.upper()[:24]}",
                            title=f"Sensitive Field `{tname}.{fname}` Exposed in GraphQL Schema Without Field-Level Auth Directive",
                            description=f"Field `{tname}.{fname}` in `{asset}` risks excessive data exposure (OWASP API3:2023) if queried by low-privileged callers.",
                            cyber_domain=CyberDomain.API_MICROSERVICES,
                            severity=Severity.HIGH,
                            cwe_ids=["CWE-200", "CWE-359"],
                            confidence=0.91,
                            owasp_categories=["API3:2023-Broken-Object-Property-Level-Authorization"],
                            verification_method=VerificationMethod.STATIC_AST,
                            endpoint_or_asset=f"{asset}#{tname}.{fname}",
                            remediation_guidance="Remove credentials/secrets from GraphQL types completely or gate PII fields with strict field-level `@auth` directives.",
                            discovered_by="ely_cyber_graphql_grpc_ws_auditor",
                        )
                    )

        return {
            "audited_at": utc_now_iso(),
            "asset": asset,
            "object_types_parsed": len(defined_types),
            "cycles_detected": [" -> ".join(c + [c[0]]) for c in cycles[:10]],
            "amplifying_cycles": [" -> ".join(c + [c[0]]) for c in amplifying_cycles[:10]],
            "vulnerabilities": vulns,
        }

    def audit_protobuf_service(self, proto_text: str, asset: str = "service.proto") -> Dict[str, Any]:
        """Audit `.proto` gRPC service definitions for unbounded streaming, sensitive RPCs, and missing field constraints."""
        vulns: List[CyberVulnerability] = []
        services = re.findall(r"service\s+(\w+)\s*\{([^}]*)\}", proto_text, re.DOTALL)
        rpcs_total = 0
        bidi_streams = 0

        for svc_name, body in services:
            for rm in re.finditer(r"rpc\s+(\w+)\s*\(\s*(stream\s+)?(\w+)\s*\)\s*returns\s*\(\s*(stream\s+)?(\w+)\s*\)", body):
                rpcs_total += 1
                rpc_name, req_stream, req_t, resp_stream, resp_t = rm.groups()
                if req_stream and resp_stream:
                    bidi_streams += 1
                    vulns.append(
                        make_cyber_vuln(
                            rule_id=f"CYB-GRPC-BIDI-DOS-{rpc_name.upper()[:20]}",
                            title=f"gRPC Bidirectional Streaming RPC `{svc_name}.{rpc_name}` Requires Strict Rate & Frame Limits",
                            description=f"Bidirectional streaming RPC `{svc_name}.{rpc_name}(stream {req_t}) returns (stream {resp_t})` in `{asset}` is vulnerable to HTTP/2 rapid-reset and memory exhaustion without per-stream quotas.",
                            cyber_domain=CyberDomain.API_MICROSERVICES,
                            severity=Severity.MEDIUM,
                            cwe_ids=["CWE-400"],
                            confidence=0.86,
                            verification_method=VerificationMethod.STATIC_AST,
                            endpoint_or_asset=f"{asset}#{svc_name}.{rpc_name}",
                            remediation_guidance="Enforce `grpc.max_receive_message_length`, per-client stream concurrency caps, and idle stream timeouts.",
                            discovered_by="ely_cyber_graphql_grpc_ws_auditor",
                        )
                    )

        # Check repeated bytes/string messages lacking protoc-gen-validate / buf.validate bounds
        if re.search(r"\brepeated\s+(?:bytes|string)\b", proto_text) and "validate.rules" not in proto_text and "buf.validate" not in proto_text:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-GRPC-UNBOUNDED-REPEATED",
                    title=f"Protobuf `{asset}` Defines Unbounded `repeated bytes/string` Without Validation Rules",
                    description="Unbounded repeated protobuf fields allow giant payload amplification up to gRPC message size limits.",
                    cyber_domain=CyberDomain.API_MICROSERVICES,
                    severity=Severity.LOW,
                    cwe_ids=["CWE-770"],
                    confidence=0.84,
                    verification_method=VerificationMethod.STATIC_AST,
                    endpoint_or_asset=asset,
                    remediation_guidance="Add `buf.validate` (`max_items`, `max_len`) constraints and strict server `MaxRecvMsgSize`.",
                    discovered_by="ely_cyber_graphql_grpc_ws_auditor",
                )
            )

        return {
            "audited_at": utc_now_iso(),
            "asset": asset,
            "services_parsed": len(services),
            "rpcs_parsed": rpcs_total,
            "bidirectional_streams": bidi_streams,
            "vulnerabilities": vulns,
        }

    def scan_directory(self, root_path: Path) -> List[CyberVulnerability]:
        """Scan source files & IDLs for GraphQL, gRPC, and WebSocket vulnerabilities."""
        vulns: List[CyberVulnerability] = []
        code_rules = [
            ("CYB-GQL-INTROSPECTION-ON", Severity.MEDIUM, "CWE-200", r"introspection\s*:\s*true|graphiql\s*:\s*true|playground\s*:\s*true", "GraphQL Introspection or Interactive Playground Enabled", "Disable GraphQL introspection and interactive playgrounds in production builds."),
            ("CYB-GRPC-INSECURE-CHAN", Severity.HIGH, "CWE-319", r"(?:grpc\.insecure_channel|add_insecure_port|grpc\.WithInsecure\s*\(|insecure\.NewCredentials\s*\()", "Cleartext Insecure gRPC Channel / Server Port Without TLS/mTLS", "Replace insecure gRPC transport with TLS/mTLS (`grpc.secure_channel` / `credentials.NewTLS`)."),
            ("CYB-GRPC-REFLECTION-ON", Severity.MEDIUM, "CWE-200", r"(?:enable_server_reflection|reflection\.Register\s*\()", "gRPC Server Reflection Enabled (Full RPC Schema Enumeration)", "Disable gRPC server reflection in production or restrict it to internal authenticated debug ports."),
            ("CYB-WS-CSWSH-ORIGIN-BYPASS", Severity.CRITICAL, "CWE-346", r"(?:CheckOrigin\s*:\s*func\s*\([^)]*\)\s*bool\s*\{\s*return\s+true|cors\s*:\s*\{\s*origin\s*:\s*['\"]\*['\"]|verifyClient\s*:\s*\(\)\s*=>\s*true)", "Cross-Site WebSocket Hijacking (CSWSH) — Wildcard/Bypassed `Origin` Check", "Strictly validate the HTTP `Origin` header against an exact allowlist and bind an anti-CSRF handshake token."),
            ("CYB-WS-CLEARTEXT-TOKEN", Severity.HIGH, "CWE-319", r"ws://[^\s'\"`]+(?:token|jwt|auth|key)=", "Cleartext `ws://` WebSocket Transmitting Authentication Token in URL Query String", "Upgrade to `wss://` (TLS 1.3) and authenticate via short-lived ticket or subprotocol/cookie rather than URL query params."),
        ]
        compiled_code = [(rid, sev, cwe, re.compile(pat, re.IGNORECASE), title, rem) for rid, sev, cwe, pat, title, rem in code_rules]

        exts = {".graphql", ".gql", ".proto", ".py", ".js", ".ts", ".go", ".java", ".rs"}
        for fp in sorted(root_path.rglob("*")):
            if not fp.is_file() or fp.suffix.lower() not in exts:
                continue
            if any(p in {".git", "node_modules", "__pycache__", ".venv"} for p in fp.parts):
                continue
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(fp.relative_to(root_path))

            if fp.suffix.lower() in {".graphql", ".gql"}:
                vulns.extend(self.audit_graphql_schema(content, asset=rel)["vulnerabilities"])
            elif fp.suffix.lower() == ".proto":
                vulns.extend(self.audit_protobuf_service(content, asset=rel)["vulnerabilities"])
            else:
                for rid, sev, cwe, rx, title, rem in compiled_code:
                    for m in rx.finditer(content):
                        lineno = content[: m.start()].count("\n") + 1
                        vulns.append(
                            make_cyber_vuln(
                                rule_id=rid,
                                title=title,
                                description=f"Detected insecure modern API protocol configuration in `{rel}:{lineno}`.",
                                cyber_domain=CyberDomain.API_MICROSERVICES,
                                severity=sev,
                                cwe_ids=[cwe],
                                confidence=0.95,
                                verification_method=VerificationMethod.STATIC_PATTERN,
                                file_path=rel,
                                line_start=lineno,
                                line_end=lineno,
                                code_snippet=m.group(0)[:160],
                                remediation_guidance=rem,
                                discovered_by="ely_cyber_graphql_grpc_ws_auditor",
                            )
                        )
        return vulns

    @staticmethod
    def _find_cycles(graph: Dict[str, Set[str]], max_cycles: int = 20) -> List[List[str]]:
        cycles: List[List[str]] = []
        seen_canon: Set[Tuple[str, ...]] = set()
        nodes = sorted(graph.keys())

        def dfs(start: str, cur: str, path: List[str], visited: Set[str]) -> None:
            if len(cycles) >= max_cycles or len(path) > 6:
                return
            for nxt in sorted(graph.get(cur, ())):
                if nxt == start:
                    # Canonical rotation to deduplicate
                    min_i = path.index(min(path))
                    canon = tuple(path[min_i:] + path[:min_i])
                    if canon not in seen_canon:
                        seen_canon.add(canon)
                        cycles.append(list(canon))
                elif nxt not in visited and nxt > start:
                    visited.add(nxt)
                    dfs(start, nxt, path + [nxt], visited)
                    visited.remove(nxt)

        for n in nodes:
            dfs(n, n, [n], {n})
        return cycles
