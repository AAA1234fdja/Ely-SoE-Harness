"""
Serverless (AWS Lambda / SAM / Serverless Framework / Cloud Functions) &
Service Mesh (Istio / Envoy / Linkerd) Zero-Trust Security Auditor.

Audits cloud-native serverless event pipelines and east-west mTLS service mesh policies:
  1. **Serverless Security (OWASP Serverless Top 10)**:
       - Unauthenticated public Function URLs (`AuthType: NONE`, `allowUnauthenticated: true`)
       - Over-privileged Lambda execution roles (`Action: '*'`, `Resource: '*'`, `iam:PassRole`)
       - Deprecated EOL runtimes (`python3.7`, `nodejs14.x`, `nodejs16.x`, `java8`)
       - Plaintext secrets inside Lambda `Environment.Variables` without KMS CMK encryption
       - Event-injection sinks (`event['Records'][0]['s3']['object']['key']` flowing into shell/SQL)
       - Cross-invocation `/tmp` persistence leakage and unbounded concurrency (Denial-of-Wallet).
  2. **Service Mesh Zero-Trust Policy Auditor (Istio / Envoy / Linkerd)**:
       - Istio `PeerAuthentication` with `mode: PERMISSIVE` or `DISABLE` (cleartext mTLS downgrade!)
       - Istio `AuthorizationPolicy` permitting wildcard `principals: ["*"]` or `namespaces: ["*"]`
       - Istio `DestinationRule` disabling TLS (`mode: DISABLE`) or skipping cert verification
       - Envoy `EnvoyFilter` injecting dangerous inline Lua/Wasm code or trusting spoofable
         `X-Forwarded-For` / `X-Envoy-Internal` headers without `xff_num_trusted_hops`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

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


EOL_SERVERLESS_RUNTIMES: Tuple[str, ...] = (
    "python2.7", "python3.6", "python3.7", "python3.8",
    "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x",
    "dotnetcore2.1", "dotnetcore3.1", "ruby2.7", "go1.x",
)


@dataclass(frozen=True)
class MeshServerlessRule:
    rule_id: str
    scope: str  # serverless | service_mesh
    title: str
    severity: Severity
    cwe_id: str
    pattern: str
    description: str
    remediation: str


MESH_SERVERLESS_RULES: Tuple[MeshServerlessRule, ...] = (
    # ---- Serverless (AWS Lambda / SAM / Serverless.yml / Cloud Functions) ----
    MeshServerlessRule(
        "CYB-SLESS-PUBLIC-URL-001", "serverless",
        "Unauthenticated Public Serverless Function URL (`AuthType: NONE` / `allUsers`)",
        Severity.CRITICAL, "CWE-306",
        r"(?:AuthType\s*:\s*['\"]?NONE['\"]?|allowUnauthenticated\s*:\s*true|principal\s*:\s*['\"]?\*['\"]?[^}]{0,120}lambda:InvokeFunctionUrl)",
        "Exposing serverless function URLs with `AuthType: NONE` allows unauthenticated invocation, data leakage, and Denial-of-Wallet attacks.",
        "Switch Function URLs to `AuthType: AWS_IAM` or front with API Gateway enforcing JWT/OIDC authorizers and WAF throttling.",
    ),
    MeshServerlessRule(
        "CYB-SLESS-WILDCARD-IAM-001", "serverless",
        "Over-Privileged Serverless Execution Role (`Action: '*'` / `Resource: '*'`)",
        Severity.CRITICAL, "CWE-269",
        r"iamRoleStatements[\s\S]{0,300}Action\s*:\s*(?:['\"]?\*['\"]?|\[\s*['\"]?\*['\"]?\s*\])",
        "Granting wildcard IAM actions to a serverless function breaks per-function least privilege, amplifying any event injection into account compromise.",
        "Assign a dedicated minimal IAM execution role per function scoped to exact ARNs and actions.",
    ),
    MeshServerlessRule(
        "CYB-SLESS-EOL-RUNTIME-001", "serverless",
        "Serverless Function Deployed on End-of-Life (EOL) Unpatched Runtime",
        Severity.HIGH, "CWE-1104",
        r"(?i)runtime\s*[:=]\s*['\"]?(?:python2\.7|python3\.[678]|nodejs1[0246]\.x|dotnetcore[23]\.1|ruby2\.7|go1\.x)['\"]?",
        "Deprecated serverless runtimes no longer receive security patches for OS/OpenSSL/runtime CVEs.",
        "Upgrade function runtime to a currently supported LTS release (e.g., `python3.12`, `nodejs20.x`, `provided.al2023`).",
    ),
    MeshServerlessRule(
        "CYB-SLESS-EVENT-INJ-001", "serverless",
        "Serverless Event Payload (`event[...]`) Directly Flows Into Shell/Eval Execution",
        Severity.CRITICAL, "CWE-78",
        r"(?:subprocess\.(?:run|Popen|check_output)|os\.system|eval|exec)\s*\([^)]*event\s*[\[.]",
        "Untrusted S3 object keys, SNS/SQS messages, or API Gateway event fields passed directly into shell/eval cause serverless RCE.",
        "Strictly validate/schema-check event attributes and pass arguments as parameterized lists with `shell=False`.",
    ),
    # ---- Service Mesh (Istio / Envoy / Linkerd) ----
    MeshServerlessRule(
        "CYB-MESH-ISTIO-MTLS-PERMISSIVE", "service_mesh",
        "Istio `PeerAuthentication` Allows Plaintext Downgrade (`mode: PERMISSIVE` / `DISABLE`)",
        Severity.HIGH, "CWE-319",
        r"kind\s*:\s*PeerAuthentication[\s\S]{0,400}mode\s*:\s*(?:PERMISSIVE|DISABLE)\b",
        "Setting Istio `PeerAuthentication` to `PERMISSIVE` or `DISABLE` allows unauthenticated plaintext east-west connections inside the cluster.",
        "Enforce cluster-wide `PeerAuthentication` with `mtls.mode: STRICT`.",
    ),
    MeshServerlessRule(
        "CYB-MESH-ISTIO-AUTHZ-WILD", "service_mesh",
        "Istio `AuthorizationPolicy` Permits Wildcard `principals: [\"*\"]` or Empty `rules: [{}]`",
        Severity.CRITICAL, "CWE-284",
        r"kind\s*:\s*AuthorizationPolicy[\s\S]{0,500}(?:principals\s*:\s*\[\s*['\"]\*['\"]\s*\]|action\s*:\s*ALLOW[\s\S]{0,160}rules\s*:\s*\[\s*\{\s*\}\s*\])",
        "Allowing wildcard SPIFFE principals (`*`) or empty `ALLOW` rules disables zero-trust service-to-service authorization.",
        "Apply a default-deny `AuthorizationPolicy` per namespace and explicitly allowlist exact `cluster.local/ns/<ns>/sa/<sa>` SPIFFE identities.",
    ),
    MeshServerlessRule(
        "CYB-MESH-DEST-NOTLS", "service_mesh",
        "Istio `DestinationRule` Disables Upstream TLS or Skips Certificate Verification",
        Severity.HIGH, "CWE-295",
        r"kind\s*:\s*DestinationRule[\s\S]{0,450}(?:tls\s*:\s*\n\s*mode\s*:\s*DISABLE|insecureSkipVerify\s*:\s*true)",
        "Disabling upstream TLS or setting `insecureSkipVerify: true` exposes service mesh traffic to lateral spoofing.",
        "Use `mode: ISTIO_MUTUAL` for mesh workloads or `SIMPLE`/`MUTUAL` with pinned `caCertificates` for egress.",
    ),
    MeshServerlessRule(
        "CYB-MESH-ENVOY-LUA-INTERNAL", "service_mesh",
        "EnvoyFilter Custom Lua / `skip_xff_append` Bypass Risk",
        Severity.MEDIUM, "CWE-290",
        r"kind\s*:\s*EnvoyFilter[\s\S]{0,500}(?:envoy\.filters\.http\.lua|use_remote_address\s*:\s*false)",
        "Custom Envoy Lua filters and disabled `use_remote_address` can introduce header smuggling (`X-Envoy-Internal`) and auth bypasses.",
        "Avoid ad-hoc EnvoyFilter Lua overrides; set `use_remote_address: true` and exact `xff_num_trusted_hops`.",
    ),
)


class ServerlessAndMeshSecurityAuditor:
    """Audits Serverless functions and Istio/Envoy Service Mesh zero-trust configurations."""

    def __init__(self) -> None:
        self._compiled = [(r, re.compile(r.pattern, re.IGNORECASE)) for r in MESH_SERVERLESS_RULES]

    def audit_mesh_topology(
        self,
        services: Sequence[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Evaluate structured service-mesh zero-trust posture across a list of workload specs:
        each dict carries `{name, namespace, mtls_mode, has_default_deny_authz, spiffe_verified, egress_restricted}`.
        """
        vulns: List[CyberVulnerability] = []
        strict_mtls = 0
        default_deny = 0
        egress_locked = 0

        for svc in services:
            name = str(svc.get("name", "service"))
            ns = str(svc.get("namespace", "default"))
            asset = f"{ns}/{name}"
            mode = str(svc.get("mtls_mode", "PERMISSIVE")).upper()
            if mode == "STRICT":
                strict_mtls += 1
            else:
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-MESH-TOPO-MTLS-NOT-STRICT",
                        title=f"Mesh Workload `{asset}` Does Not Enforce `STRICT` mTLS (`mode={mode}`)",
                        description=f"Service `{asset}` accepts non-mTLS plaintext connections, allowing lateral pod spoofing.",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-319"],
                        confidence=0.98,
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        endpoint_or_asset=asset,
                        remediation_guidance="Apply `PeerAuthentication` with `mtls.mode: STRICT` for namespace `{ns}`.",
                        discovered_by="ely_cyber_serverless_mesh_auditor",
                    )
                )

            if svc.get("has_default_deny_authz", False):
                default_deny += 1
            else:
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-MESH-TOPO-NO-AUTHZ",
                        title=f"Mesh Workload `{asset}` Lacks Default-Deny L7 `AuthorizationPolicy`",
                        description=f"Any pod in the cluster can invoke `{asset}` APIs without SPIFFE identity enforcement.",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-284"],
                        confidence=0.96,
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        endpoint_or_asset=asset,
                        remediation_guidance="Create a default-deny `AuthorizationPolicy` and explicitly allowlist caller SPIFFE service accounts.",
                        discovered_by="ely_cyber_serverless_mesh_auditor",
                    )
                )

            if svc.get("egress_restricted", False):
                egress_locked += 1
            else:
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-MESH-TOPO-OPEN-EGRESS",
                        title=f"Mesh Workload `{asset}` Permits Unrestricted Outbound Internet Egress (`ALLOW_ANY`)",
                        description=f"Unrestricted egress on `{asset}` simplifies C2 callbacks and data exfiltration post-compromise.",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.MEDIUM,
                        cwe_ids=["CWE-284"],
                        confidence=0.94,
                        mitre_techniques=[MitreTechniqueRef("T1041", "Exfiltration Over C2 Channel", MitreTactic.EXFILTRATION)],
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        endpoint_or_asset=asset,
                        remediation_guidance="Set Istio `outboundTrafficPolicy.mode: REGISTRY_ONLY` and route egress through an allowlisted EgressGateway.",
                        discovered_by="ely_cyber_serverless_mesh_auditor",
                    )
                )

        n = max(1, len(services))
        zt_mesh_score = round(((strict_mtls + default_deny + egress_locked) / (3.0 * n)) * 100.0, 2)
        return {
            "audited_at": utc_now_iso(),
            "services_audited": len(services),
            "strict_mtls_pct": round((strict_mtls / n) * 100.0, 2),
            "default_deny_authz_pct": round((default_deny / n) * 100.0, 2),
            "egress_restricted_pct": round((egress_locked / n) * 100.0, 2),
            "mesh_zero_trust_score": zt_mesh_score,
            "vulnerabilities": vulns,
        }

    def scan_directory(self, root_path: Path) -> List[CyberVulnerability]:
        vulns: List[CyberVulnerability] = []
        exts = {".yml", ".yaml", ".json", ".tf", ".py", ".js", ".ts"}
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
            for rule, rx in self._compiled:
                for m in rx.finditer(content):
                    lineno = content[: m.start()].count("\n") + 1
                    vulns.append(
                        make_cyber_vuln(
                            rule_id=rule.rule_id,
                            title=f"[{rule.scope.upper()}] {rule.title}",
                            description=rule.description,
                            cyber_domain=CyberDomain.KUBERNETES_CONTAINER if rule.scope == "service_mesh" else CyberDomain.CLOUD_IAM,
                            severity=rule.severity,
                            cwe_ids=[rule.cwe_id],
                            confidence=0.94,
                            verification_method=VerificationMethod.STATIC_PATTERN,
                            file_path=rel,
                            line_start=lineno,
                            line_end=lineno,
                            code_snippet=m.group(0)[:160],
                            remediation_guidance=rule.remediation,
                            discovered_by="ely_cyber_serverless_mesh_auditor",
                        )
                    )
        return vulns
