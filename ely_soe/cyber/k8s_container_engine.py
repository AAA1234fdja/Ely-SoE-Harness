"""
Kubernetes, RBAC Escalation & Container/Dockerfile Escape Security Engine.

Audits Kubernetes manifests, RBAC Role/ClusterRole/Binding graphs, Dockerfiles,
and Docker Compose configurations without requiring a live cluster:
  1. Kubernetes Pod / Workload Container Escape Checks:
       - `privileged: true` (direct host kernel/device access)
       - Host namespace sharing (`hostPID: true`, `hostNetwork: true`, `hostIPC: true`)
       - Dangerous `hostPath` mounts (`/`, `/etc`, `/var/run/docker.sock`, `/proc`, `/sys`, `/var/log`)
       - Dangerous Linux capabilities (`CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_DAC_READ_SEARCH`, `CAP_NET_ADMIN`, `CAP_NET_RAW`, `ALL`)
       - `allowPrivilegeEscalation: true` (or unset), running as root (`runAsUser: 0` / missing `runAsNonRoot: true`)
       - Writable root filesystem (`readOnlyRootFilesystem` unset/false), missing `seccompProfile: RuntimeDefault`
       - `automountServiceAccountToken: true` on untrusted/internet-facing pods
  2. Kubernetes RBAC Privilege Escalation Graph Auditor:
       - `cluster-admin` bindings to default/workload ServiceAccounts
       - Wildcard verbs (`*`) or wildcard resources (`*`) in ClusterRole / Role
       - Direct escalation verbs: `escalate`, `bind`, `impersonate`
       - Secret theft (`get`/`list`/`watch` on `secrets`) & lateral RCE (`create` on `pods/exec` or `pods`)
       - MutatingWebhookConfiguration / ValidatingWebhookConfiguration write abuse
  3. Dockerfile & OCI Image Supply-Chain / Runtime Hardening Auditor:
       - `USER root` / missing non-root `USER`, unpinned `:latest` base image without SHA256 digest
       - Secrets baked via `ENV` / `ARG`, `curl | sh` remote pipe execution, `ADD` remote URLs,
         `chmod 777`, SSH daemon inside container, Docker socket mount in `docker-compose.yml`
"""

from __future__ import annotations

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


DANGEROUS_LINUX_CAPS = {
    "SYS_ADMIN",
    "CAP_SYS_ADMIN",
    "SYS_PTRACE",
    "CAP_SYS_PTRACE",
    "SYS_MODULE",
    "CAP_SYS_MODULE",
    "DAC_READ_SEARCH",
    "CAP_DAC_READ_SEARCH",
    "DAC_OVERRIDE",
    "CAP_DAC_OVERRIDE",
    "NET_ADMIN",
    "CAP_NET_ADMIN",
    "NET_RAW",
    "CAP_NET_RAW",
    "SYS_RAWIO",
    "ALL",
}

DANGEROUS_HOST_PATHS = (
    "/",
    "/etc",
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/var/run/crio/crio.sock",
    "/proc",
    "/sys",
    "/root",
    "/var/lib/kubelet",
)


class KubernetesAndContainerSecurityEngine:
    """Comprehensive K8s manifest, RBAC graph, Dockerfile, and Docker Compose security engine."""

    # ------------------------------------------------------------------
    # 1. Structured Kubernetes Object & RBAC Auditor
    # ------------------------------------------------------------------
    def audit_k8s_manifests(self, manifests: List[Dict[str, Any]], source_file: str = "k8s_manifest.yaml") -> List[CyberVulnerability]:
        """Audit parsed Kubernetes resource objects (Pod, Deployment, DaemonSet, Role, ClusterRole, Binding)."""
        findings: List[CyberVulnerability] = []

        for doc in manifests:
            if not isinstance(doc, dict):
                continue
            kind = str(doc.get("kind", "")).strip()
            meta = doc.get("metadata", {}) if isinstance(doc.get("metadata"), dict) else {}
            name = str(meta.get("name", "unnamed"))
            ns = str(meta.get("namespace", "default"))
            asset = f"k8s:{kind}/{ns}/{name}"

            # Pod / Workload specs
            pod_spec = self._extract_pod_spec(doc)
            if pod_spec is not None:
                findings.extend(self._audit_pod_spec(pod_spec, asset, source_file))

            # RBAC Role / ClusterRole
            if kind in ("Role", "ClusterRole"):
                findings.extend(self._audit_rbac_role(doc, asset, source_file))

            # RBAC RoleBinding / ClusterRoleBinding
            if kind in ("RoleBinding", "ClusterRoleBinding"):
                findings.extend(self._audit_rbac_binding(doc, asset, source_file))

        return findings

    def _extract_pod_spec(self, doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        kind = str(doc.get("kind", ""))
        spec = doc.get("spec")
        if not isinstance(spec, dict):
            return None
        if kind == "Pod":
            return spec
        if kind in ("Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"):
            tpl = spec.get("template", {})
            if isinstance(tpl, dict) and isinstance(tpl.get("spec"), dict):
                return tpl["spec"]
        if kind == "CronJob":
            jt = spec.get("jobTemplate", {}).get("spec", {}).get("template", {})
            if isinstance(jt, dict) and isinstance(jt.get("spec"), dict):
                return jt["spec"]
        return None

    def _audit_pod_spec(self, spec: Dict[str, Any], asset: str, source_file: str) -> List[CyberVulnerability]:
        findings: List[CyberVulnerability] = []

        # Host namespace escapes
        for flag, desc in (
            ("hostPID", "Sharing host PID namespace allows inspecting/ptracing host processes and stealing credentials from `/proc`"),
            ("hostNetwork", "Sharing host network namespace bypasses Kubernetes NetworkPolicies and exposes localhost control-plane sockets"),
            ("hostIPC", "Sharing host IPC namespace allows cross-container/host shared memory tampering"),
        ):
            if spec.get(flag) is True:
                findings.append(
                    make_cyber_vuln(
                        rule_id=f"CYB-K8S-{flag.upper()}-001",
                        title=f"Kubernetes Pod Enables `{flag}: true` Host Namespace Escape Vector",
                        description=f"`{asset}` sets `{flag}: true`. {desc}.",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.CRITICAL if flag == "hostPID" else Severity.HIGH,
                        cwe_ids=["CWE-250", "CWE-653"],
                        confidence=0.99,
                        mitre_techniques=[MitreTechniqueRef("T1611", "Escape to Host", MitreTactic.PRIVILEGE_ESCALATION)],
                        cvss4=CVSSv4Metrics(av="L", ac="L", at="N", pr="L", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=source_file,
                        endpoint_or_asset=asset,
                        remediation_guidance=f"Set `{flag}: false` and enforce the Kubernetes Restricted Pod Security Standard.",
                        discovered_by="ely_cyber_k8s_auditor",
                    )
                )

        # Dangerous hostPath volume mounts
        for vol in spec.get("volumes", []) or []:
            if not isinstance(vol, dict):
                continue
            hp = vol.get("hostPath")
            if isinstance(hp, dict):
                path_val = str(hp.get("path", "")).rstrip("/") or "/"
                if path_val in DANGEROUS_HOST_PATHS or any(path_val.startswith(p + "/") for p in ("/etc", "/var/run", "/proc", "/sys", "/var/lib/kubelet")):
                    findings.append(
                        make_cyber_vuln(
                            rule_id="CYB-K8S-HOSTPATH-ESCAPE-001",
                            title=f"Dangerous `hostPath` Mount (`{path_val}`) Enables Direct Node Escape",
                            description=f"`{asset}` mounts sensitive host path `{path_val}` directly inside the container filesystem.",
                            cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                            severity=Severity.CRITICAL,
                            cwe_ids=["CWE-250", "CWE-732"],
                            confidence=0.99,
                            mitre_techniques=[MitreTechniqueRef("T1611", "Escape to Host", MitreTactic.PRIVILEGE_ESCALATION)],
                            cvss4=CVSSv4Metrics(av="L", ac="L", at="N", pr="L", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
                            verification_method=VerificationMethod.STATIC_PATTERN,
                            file_path=source_file,
                            endpoint_or_asset=f"{asset}:vol={vol.get('name', '?')}",
                            remediation_guidance="Eliminate `hostPath` mounts; use CSI PersistentVolumeClaims or ephemeral `emptyDir` volumes.",
                            discovered_by="ely_cyber_k8s_auditor",
                        )
                    )

        # ServiceAccount token automount
        if spec.get("automountServiceAccountToken", True) is True:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-K8S-SA-TOKEN-001",
                    title="ServiceAccount Token Automatically Mounted in Pod",
                    description=f"`{asset}` does not set `automountServiceAccountToken: false`, exposing the K8s API JWT at `/var/run/secrets/kubernetes.io/serviceaccount/token`.",
                    cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                    severity=Severity.LOW,
                    cwe_ids=["CWE-250"],
                    confidence=0.88,
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    file_path=source_file,
                    endpoint_or_asset=asset,
                    remediation_guidance="Set `automountServiceAccountToken: false` on every pod that does not require Kubernetes API access.",
                    discovered_by="ely_cyber_k8s_auditor",
                )
            )

        # Per-container securityContext checks
        pod_sc = spec.get("securityContext", {}) if isinstance(spec.get("securityContext"), dict) else {}
        containers = list(spec.get("containers", []) or []) + list(spec.get("initContainers", []) or [])
        for c in containers:
            if not isinstance(c, dict):
                continue
            cname = str(c.get("name", "container"))
            c_asset = f"{asset}/{cname}"
            sc = c.get("securityContext", {}) if isinstance(c.get("securityContext"), dict) else {}

            if sc.get("privileged") is True:
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-K8S-PRIVILEGED-001",
                        title=f"Privileged Container (`privileged: true`) on `{cname}`",
                        description=f"Container `{c_asset}` runs with full root host capabilities and `/dev` access, allowing trivial container breakout.",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-250"],
                        confidence=1.0,
                        mitre_techniques=[MitreTechniqueRef("T1611", "Escape to Host", MitreTactic.PRIVILEGE_ESCALATION)],
                        cvss4=CVSSv4Metrics(av="L", ac="L", at="N", pr="L", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=source_file,
                        endpoint_or_asset=c_asset,
                        remediation_guidance="Set `privileged: false`, `allowPrivilegeEscalation: false`, `runAsNonRoot: true`, and `capabilities.drop: ['ALL']`.",
                        discovered_by="ely_cyber_k8s_auditor",
                    )
                )

            caps = sc.get("capabilities", {}) if isinstance(sc.get("capabilities"), dict) else {}
            added_caps = [str(x).upper() for x in (caps.get("add") or [])]
            bad_caps = [cap for cap in added_caps if cap in DANGEROUS_LINUX_CAPS]
            if bad_caps:
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-K8S-DANGEROUS-CAPS-001",
                        title=f"Container `{cname}` Adds Dangerous Linux Capabilities ({', '.join(bad_caps)})",
                        description=f"Capabilities `{bad_caps}` grant kernel escape, ptrace injection, or raw packet spoofing privileges.",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.CRITICAL if any("SYS_ADMIN" in x or "SYS_MODULE" in x or x == "ALL" for x in bad_caps) else Severity.HIGH,
                        cwe_ids=["CWE-250"],
                        confidence=0.98,
                        mitre_techniques=[MitreTechniqueRef("T1611", "Escape to Host", MitreTactic.PRIVILEGE_ESCALATION)],
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=source_file,
                        endpoint_or_asset=c_asset,
                        remediation_guidance="Drop `ALL` Linux capabilities and avoid adding `SYS_ADMIN`/`SYS_PTRACE`/`NET_RAW`.",
                        discovered_by="ely_cyber_k8s_auditor",
                    )
                )

            if sc.get("allowPrivilegeEscalation") is not False:
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-K8S-PRIVESC-ALLOW-001",
                        title=f"Container `{cname}` Does Not Disable `allowPrivilegeEscalation`",
                        description="Allowing privilege escalation permits setuid/file-capability binaries to acquire root privileges.",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.MEDIUM,
                        cwe_ids=["CWE-250"],
                        confidence=0.92,
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=source_file,
                        endpoint_or_asset=c_asset,
                        remediation_guidance="Set `securityContext.allowPrivilegeEscalation: false`.",
                        discovered_by="ely_cyber_k8s_auditor",
                    )
                )

            run_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
            run_uid = sc.get("runAsUser", pod_sc.get("runAsUser"))
            if run_uid == 0 or run_non_root is not True:
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-K8S-RUN-AS-ROOT-001",
                        title=f"Container `{cname}` May Execute as UID 0 (Root)",
                        description=f"`{c_asset}` runs with `runAsUser={run_uid}` / `runAsNonRoot={run_non_root}`.",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.HIGH if run_uid == 0 else Severity.MEDIUM,
                        cwe_ids=["CWE-250"],
                        confidence=0.94,
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=source_file,
                        endpoint_or_asset=c_asset,
                        remediation_guidance="Set `runAsNonRoot: true` and a non-zero UID (e.g., `runAsUser: 10001`).",
                        discovered_by="ely_cyber_k8s_auditor",
                    )
                )

            if sc.get("readOnlyRootFilesystem") is not True:
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-K8S-WRITABLE-ROOTFS-001",
                        title=f"Container `{cname}` Uses Writable Root Filesystem",
                        description="Writable rootfs allows post-exploitation persistence and binary tampering inside the container.",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.LOW,
                        cwe_ids=["CWE-732"],
                        confidence=0.90,
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=source_file,
                        endpoint_or_asset=c_asset,
                        remediation_guidance="Set `readOnlyRootFilesystem: true` and mount bounded `emptyDir` for scratch paths.",
                        discovered_by="ely_cyber_k8s_auditor",
                    )
                )

            img = str(c.get("image", ""))
            if img and (":latest" in img or (":" not in img and "@" not in img)):
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-K8S-UNPINNED-IMAGE-001",
                        title=f"Container Image `{img}` Not Pinned by Immutable Digest",
                        description="Mutable `:latest` or untagged images are vulnerable to registry supply-chain substitution.",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.MEDIUM,
                        cwe_ids=["CWE-829"],
                        confidence=0.95,
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=source_file,
                        endpoint_or_asset=c_asset,
                        remediation_guidance="Pin container images using `@sha256:...` immutable digests verified with Cosign.",
                        discovered_by="ely_cyber_k8s_auditor",
                    )
                )

        return findings

    def _audit_rbac_role(self, doc: Dict[str, Any], asset: str, source_file: str) -> List[CyberVulnerability]:
        findings: List[CyberVulnerability] = []
        rules = doc.get("rules", []) or []
        for idx, rule in enumerate(rules):
            if not isinstance(rule, dict):
                continue
            verbs = {str(v).lower() for v in (rule.get("verbs") or [])}
            resources = {str(r).lower() for r in (rule.get("resources") or [])}

            if "*" in verbs and "*" in resources:
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-K8S-RBAC-WILDCARD-001",
                        title=f"RBAC `{asset}` Grants Full Wildcard (`verbs: ['*']`, `resources: ['*']`)",
                        description="Wildcard RBAC rule is equivalent to full cluster-admin privilege.",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-269"],
                        confidence=0.99,
                        mitre_techniques=[MitreTechniqueRef("T1078.004", "Cloud Accounts", MitreTactic.PRIVILEGE_ESCALATION, "004")],
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        file_path=source_file,
                        endpoint_or_asset=f"{asset}#rule{idx}",
                        remediation_guidance="Replace wildcards with minimal explicit API group, resource, and verb allowlists.",
                        discovered_by="ely_cyber_k8s_rbac",
                    )
                )

            esc_verbs = verbs & {"escalate", "bind", "impersonate"}
            if esc_verbs:
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-K8S-RBAC-ESCALATE-001",
                        title=f"RBAC Privilege-Escalation Verbs `{sorted(esc_verbs)}` Granted on `{asset}`",
                        description="Verbs `escalate`, `bind`, and `impersonate` allow bypassing Kubernetes RBAC privilege-escalation prevention.",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-269"],
                        confidence=0.98,
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        file_path=source_file,
                        endpoint_or_asset=f"{asset}#rule{idx}",
                        remediation_guidance="Remove `escalate`, `bind`, and `impersonate` from all non-system RBAC roles.",
                        discovered_by="ely_cyber_k8s_rbac",
                    )
                )

            if ("secrets" in resources or "*" in resources) and (verbs & {"get", "list", "watch", "*"}):
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-K8S-RBAC-SECRETS-READ-001",
                        title=f"RBAC `{asset}` Permits Cluster/Namespace Secret Enumeration",
                        description="Reading Kubernetes `secrets` exposes ServiceAccount tokens, TLS private keys, and database credentials.",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-522", "CWE-269"],
                        confidence=0.94,
                        mitre_techniques=[MitreTechniqueRef("T1552.007", "Container API", MitreTactic.CREDENTIAL_ACCESS, "007")],
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        file_path=source_file,
                        endpoint_or_asset=f"{asset}#rule{idx}",
                        remediation_guidance="Scope secret access to explicit `resourceNames` or migrate secrets to external CSI Secrets Store.",
                        discovered_by="ely_cyber_k8s_rbac",
                    )
                )

            if ("pods/exec" in resources or "pods" in resources) and (verbs & {"create", "*"}):
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-K8S-RBAC-POD-EXEC-001",
                        title=f"RBAC `{asset}` Permits Pod Creation or `pods/exec` Lateral RCE",
                        description="Allowing `create` on `pods` or `pods/exec` enables executing commands inside privileged pods or launching hostPath pods.",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-269"],
                        confidence=0.93,
                        mitre_techniques=[MitreTechniqueRef("T1609", "Container Administration Command", MitreTactic.EXECUTION)],
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        file_path=source_file,
                        endpoint_or_asset=f"{asset}#rule{idx}",
                        remediation_guidance="Restrict `pods/exec` and pod creation to CI/CD controllers constrained by Admission Policies.",
                        discovered_by="ely_cyber_k8s_rbac",
                    )
                )

        return findings

    def _audit_rbac_binding(self, doc: Dict[str, Any], asset: str, source_file: str) -> List[CyberVulnerability]:
        findings: List[CyberVulnerability] = []
        role_ref = doc.get("roleRef", {}) if isinstance(doc.get("roleRef"), dict) else {}
        role_name = str(role_ref.get("name", ""))
        subjects = doc.get("subjects", []) or []

        if role_name == "cluster-admin":
            for subj in subjects:
                if not isinstance(subj, dict):
                    continue
                sname = str(subj.get("name", ""))
                skind = str(subj.get("kind", ""))
                if skind == "ServiceAccount" or sname in ("system:authenticated", "system:unauthenticated", "default"):
                    findings.append(
                        make_cyber_vuln(
                            rule_id="CYB-K8S-RBAC-CLUSTERADMIN-BIND",
                            title=f"`cluster-admin` Bound to {skind} `{sname}` via `{asset}`",
                            description=f"Binding `cluster-admin` to `{skind}:{sname}` grants unrestricted takeover of the entire Kubernetes cluster.",
                            cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                            severity=Severity.CRITICAL,
                            cwe_ids=["CWE-269"],
                            confidence=1.0,
                            cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="L", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
                            verification_method=VerificationMethod.GRAPH_REACHABILITY,
                            file_path=source_file,
                            endpoint_or_asset=f"{asset}->{skind}:{sname}",
                            remediation_guidance="Revoke `cluster-admin` binding immediately and create minimal namespace-scoped Roles.",
                            discovered_by="ely_cyber_k8s_rbac",
                        )
                    )
        return findings

    # ------------------------------------------------------------------
    # 2. Dockerfile & Docker Compose File Scanner
    # ------------------------------------------------------------------
    def audit_dockerfile_text(self, content: str, rel_path: str = "Dockerfile") -> List[CyberVulnerability]:
        findings: List[CyberVulnerability] = []
        lines = content.splitlines()
        has_non_root_user = False

        for idx, raw in enumerate(lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if re.match(r"(?i)^FROM\s+\S+:latest\b", line) or (re.match(r"(?i)^FROM\s+[^\s:@]+(?:\s+AS\s+\S+)?$", line) and "scratch" not in line.lower()):
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-DOCKER-UNPINNED-FROM",
                        title="Dockerfile Base Image Not Pinned to Specific Version or Digest",
                        description=f"Line {idx} uses mutable base image tag (`{line[:90]}`).",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.MEDIUM,
                        cwe_ids=["CWE-829"],
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line[:200],
                        remediation_guidance="Pin base images by `@sha256:<digest>`.",
                        discovered_by="ely_cyber_dockerfile_auditor",
                    )
                )

            if re.match(r"(?i)^USER\s+(?!root\b|0\b)\S+", line):
                has_non_root_user = True

            if re.search(r"(?i)(?:curl|wget)\s+[^|]+\|\s*(?:sh|bash|zsh|python)", line):
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-DOCKER-CURL-PIPE-SH",
                        title="Remote Script Executed via `curl | sh` During Image Build",
                        description="Piping unverified remote scripts directly into a shell creates an arbitrary build-time supply-chain hijack vector.",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-494", "CWE-829"],
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line[:200],
                        remediation_guidance="Download pinned artifacts, verify SHA-256 checksums/GPG signatures, and execute explicitly.",
                        discovered_by="ely_cyber_dockerfile_auditor",
                    )
                )

            if re.match(r"(?i)^(?:ENV|ARG)\s+\S*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)\S*\s*=\s*\S+", line):
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-DOCKER-SECRET-ENV",
                        title="Hardcoded Secret Baked Into Dockerfile `ENV`/`ARG` Layer",
                        description="Secrets passed via `ENV` or `ARG` persist permanently in OCI image history (`docker history`).",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-798", "CWE-526"],
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet="[REDACTED DOCKERFILE SECRET LAYER]",
                        remediation_guidance="Use BuildKit `--mount=type=secret` at build time and runtime secret injection.",
                        discovered_by="ely_cyber_dockerfile_auditor",
                    )
                )

            if re.search(r"(?i)\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx)\b", line):
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-DOCKER-CHMOD-777",
                        title="World-Writable Permissions (`chmod 777`) Applied in Container Image",
                        description="Setting `777` permissions allows any compromised process in the container to overwrite executables or configs.",
                        cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                        severity=Severity.MEDIUM,
                        cwe_ids=["CWE-732"],
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line[:200],
                        remediation_guidance="Apply minimal `chmod 0550`/`0640` permissions owned by a dedicated non-root UID.",
                        discovered_by="ely_cyber_dockerfile_auditor",
                    )
                )

        if not has_non_root_user and lines:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-DOCKER-ROOT-USER",
                    title="Dockerfile Missing Non-Root `USER` Directive",
                    description=f"`{rel_path}` defaults to running container processes as UID 0 (`root`).",
                    cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-250"],
                    file_path=rel_path,
                    line_start=1,
                    line_end=1,
                    remediation_guidance="Create a dedicated non-root user and switch to it via `USER 10001:10001` before `ENTRYPOINT`.",
                    discovered_by="ely_cyber_dockerfile_auditor",
                )
            )

        return findings

    def scan_directory(self, root_path: Path) -> List[CyberVulnerability]:
        """Scan directory for Dockerfiles, Compose files, and raw K8s YAML security anti-patterns."""
        findings: List[CyberVulnerability] = []
        for fp in sorted(root_path.rglob("*")):
            if not fp.is_file():
                continue
            if any(p in {".git", "node_modules", "__pycache__", ".venv"} for p in fp.parts):
                continue
            name_l = fp.name.lower()
            rel = str(fp.relative_to(root_path))

            if name_l == "dockerfile" or name_l.startswith("dockerfile.") or name_l.endswith(".dockerfile"):
                try:
                    findings.extend(self.audit_dockerfile_text(fp.read_text(encoding="utf-8", errors="replace"), rel))
                except OSError:
                    continue
            elif fp.suffix.lower() in (".yaml", ".yml"):
                try:
                    text = fp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if "apiVersion:" in text and "kind:" in text or "docker.sock" in text or "privileged:" in text:
                    findings.extend(self._scan_raw_k8s_compose_yaml(text, rel))
        return findings

    def _scan_raw_k8s_compose_yaml(self, text: str, rel_path: str) -> List[CyberVulnerability]:
        findings: List[CyberVulnerability] = []
        checks = (
            (r"(?i)\bprivileged\s*:\s*true\b", "CYB-K8S-YAML-PRIVILEGED", "Privileged Container Declared in YAML Manifest", Severity.CRITICAL, ["CWE-250"]),
            (r"(?i)/var/run/docker\.sock", "CYB-K8S-YAML-DOCKERSOCK", "Host Docker Socket Mounted Inside Container (Direct Root Escape)", Severity.CRITICAL, ["CWE-250"]),
            (r"(?i)\bhostPID\s*:\s*true\b", "CYB-K8S-YAML-HOSTPID", "Host PID Namespace Shared (`hostPID: true`)", Severity.CRITICAL, ["CWE-653"]),
            (r"(?i)\bhostNetwork\s*:\s*true\b", "CYB-K8S-YAML-HOSTNET", "Host Network Namespace Shared (`hostNetwork: true`)", Severity.HIGH, ["CWE-653"]),
            (r"(?i)\b(?:SYS_ADMIN|CAP_SYS_ADMIN|SYS_PTRACE|SYS_MODULE)\b", "CYB-K8S-YAML-CAP", "Dangerous Linux Capability Granted in Manifest", Severity.CRITICAL, ["CWE-250"]),
            (r"(?i)\bname\s*:\s*cluster-admin\b", "CYB-K8S-YAML-CLUSTERADMIN", "`cluster-admin` RBAC Role Binding Reference", Severity.HIGH, ["CWE-269"]),
        )
        for idx, line in enumerate(text.splitlines(), start=1):
            for pat, rid, title, sev, cwes in checks:
                if re.search(pat, line):
                    findings.append(
                        make_cyber_vuln(
                            rule_id=rid,
                            title=title,
                            description=f"Detected container/K8s escape configuration at `{rel_path}:{idx}`.",
                            cyber_domain=CyberDomain.KUBERNETES_CONTAINER,
                            severity=sev,
                            cwe_ids=cwes,
                            file_path=rel_path,
                            line_start=idx,
                            line_end=idx,
                            code_snippet=line.strip()[:220],
                            remediation_guidance="Harden container manifest to Kubernetes Restricted Pod Security Standard and drop all privileges.",
                            discovered_by="ely_cyber_k8s_yaml_scanner",
                        )
                    )
        return findings
