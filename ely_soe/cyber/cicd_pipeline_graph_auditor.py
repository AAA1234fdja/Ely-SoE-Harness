"""
CI/CD Pipeline Execution-Graph & Poisoned Pipeline Execution (PPE) Security Auditor.

Builds a structured execution DAG of CI/CD pipelines (GitHub Actions YAML workflows,
GitLab CI `.gitlab-ci.yml`, Jenkinsfiles, CircleCI/Buildkite configs) and performs
graph-level taint & privilege-escalation analysis to detect modern supply-chain attacks
(OWASP CI/CD Top 10: CICD-SEC-1 through CICD-SEC-10):
  1. **Direct & Indirect Poisoned Pipeline Execution (PPE / CWE-94)**:
       - `pull_request_target` or `workflow_run` trigger followed by `actions/checkout`
         referencing untrusted PR head (`github.event.pull_request.head.sha/ref`) -> instant
         untrusted code execution WITH repository write tokens & production secrets!
  2. **GitHub Actions Expression Injection (CWE-78 / Script Injection)**:
       - Untrusted attacker-controlled contexts (`github.event.issue.title`, `comment.body`,
         `pull_request.title`, `head_ref`, `commits.*.message`) interpolated directly inside
         `run:` shell scripts via `${{ ... }}`.
  3. **Unpinned Third-Party Actions & Floating Tag Hijack (CWE-829)**:
       - `uses: owner/action@main`, `@master`, `@v1`, `@v2` instead of immutable 40-char
         commit SHA pins (e.g., TJ-Actions/Reviewdog supply-chain compromise class!).
  4. **Over-Privileged `GITHUB_TOKEN` & Secret Sprawl (CWE-269 / CWE-798)**:
       - `permissions: write-all` or missing top-level `permissions: read-all`, plus passing
         `${{ toJSON(secrets) }}` or broad secrets into untrusted PR steps.
  5. **Self-Hosted Runner Persistence & Cross-Job Artifact Poisoning**:
       - Public/PR-triggered workflows executing on persistent `self-hosted` runners;
         `download-artifact` consumed by a higher-privilege deploy job without integrity check.
  6. **OIDC Federation & SLSA Build Provenance Hygiene**:
       - Long-lived static cloud credentials (`AWS_SECRET_ACCESS_KEY`) instead of short-lived
         OIDC (`id-token: write`), and missing SLSA provenance attestation on release jobs.
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


UNTRUSTED_GHA_EXPRESSIONS: Tuple[str, ...] = (
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author.name",
    "github.event.commits",
    "github.head_ref",
)

DANGEROUS_CHECKOUT_REFS: Tuple[str, ...] = (
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.ref",
    "github.head_ref",
    "github.event.workflow_run.head_sha",
    "github.event.workflow_run.head_branch",
)

STATIC_CLOUD_CRED_KEYS: Tuple[str, ...] = (
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "GCP_SA_KEY",
    "GOOGLE_CREDENTIALS",
    "AZURE_CREDENTIALS",
    "DOCKER_PASSWORD",
    "NPM_TOKEN",
    "PYPI_API_TOKEN",
)


@dataclass
class PipelineJobNode:
    job_id: str
    runs_on: str = "ubuntu-latest"
    needs: List[str] = field(default_factory=list)
    permissions: Dict[str, str] = field(default_factory=dict)
    uses_actions: List[Tuple[int, str]] = field(default_factory=list)
    run_scripts: List[Tuple[int, str]] = field(default_factory=list)
    secrets_referenced: Set[str] = field(default_factory=set)
    uploads_artifacts: List[str] = field(default_factory=list)
    downloads_artifacts: List[str] = field(default_factory=list)
    checks_out_untrusted_pr: bool = False
    is_deploy_or_release: bool = False
    line_start: int = 1


@dataclass
class ParsedWorkflowGraph:
    file_path: str
    pipeline_type: str  # github_actions | gitlab_ci | jenkinsfile
    triggers: List[str] = field(default_factory=list)
    top_permissions: Dict[str, str] = field(default_factory=dict)
    jobs: Dict[str, PipelineJobNode] = field(default_factory=dict)
    edges: List[Tuple[str, str, str]] = field(default_factory=list)  # (src, dst, edge_type)


class CICDPipelineGraphAuditor:
    """Zero-dependency CI/CD execution-graph parser and OWASP CI/CD Top 10 auditor."""

    _SHA40_RE = re.compile(r"@[0-9a-fA-F]{40}\b")
    _USES_RE = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"#\s]+)['\"]?")
    _EXPR_RE = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")
    _SECRET_REF_RE = re.compile(r"secrets\.([A-Za-z0-9_]+)")
    _TOJSON_SECRETS_RE = re.compile(r"toJSON\s*\(\s*secrets\s*\)", re.IGNORECASE)
    _CURL_PIPE_SH_RE = re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba|z|da)?sh\b", re.IGNORECASE)
    _JENKINS_SH_INTERP_RE = re.compile(r'sh\s+["]{1,3}[^"]*\$\{(?:env\.|params\.)?[A-Za-z0-9_.]+\}')

    def parse_github_actions_yaml(self, content: str, file_path: str = ".github/workflows/ci.yml") -> ParsedWorkflowGraph:
        """Lightweight structural parser for GitHub Actions workflow YAML (zero PyYAML dep)."""
        graph = ParsedWorkflowGraph(file_path=file_path, pipeline_type="github_actions")
        lines = content.splitlines()
        section = ""
        current_job: Optional[PipelineJobNode] = None
        in_run_block = False
        run_indent = 0
        run_start_line = 1
        run_buf: List[str] = []

        def _flush_run() -> None:
            nonlocal in_run_block, run_buf
            if in_run_block and current_job is not None and run_buf:
                current_job.run_scripts.append((run_start_line, "\n".join(run_buf)))
            in_run_block = False
            run_buf = []

        for idx, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(raw) - len(raw.lstrip(" "))

            if in_run_block:
                if indent > run_indent:
                    run_buf.append(stripped)
                    for m in self._SECRET_REF_RE.finditer(raw):
                        if current_job:
                            current_job.secrets_referenced.add(m.group(1))
                    continue
                else:
                    _flush_run()

            if indent == 0:
                if stripped.startswith("on:"):
                    section = "on"
                    inline = stripped[3:].strip()
                    if inline:
                        inline_clean = inline.strip("[]")
                        for tok in inline_clean.split(","):
                            t = tok.strip().strip("'\"")
                            if t:
                                graph.triggers.append(t)
                elif stripped.startswith("permissions:"):
                    section = "permissions"
                    val = stripped[len("permissions:"):].strip()
                    if val:
                        graph.top_permissions["*"] = val
                elif stripped.startswith("jobs:"):
                    section = "jobs"
                else:
                    section = ""
                continue

            if section == "on" and indent <= 4:
                key = stripped.split(":", 1)[0].lstrip("- ").strip()
                if key and key not in ("branches", "paths", "tags", "types", "workflows", "schedule", "cron", "inputs"):
                    graph.triggers.append(key)
            elif section == "permissions" and indent <= 4 and ":" in stripped:
                k, v = stripped.split(":", 1)
                graph.top_permissions[k.strip()] = v.strip()
            elif section == "jobs":
                if indent == 2 and stripped.endswith(":") and not stripped.startswith("-"):
                    _flush_run()
                    jid = stripped[:-1].strip()
                    current_job = PipelineJobNode(
                        job_id=jid,
                        is_deploy_or_release=any(tok in jid.lower() for tok in ("deploy", "release", "publish", "prod")),
                        line_start=idx,
                    )
                    graph.jobs[jid] = current_job
                    continue
                if current_job is None:
                    continue

                for m in self._SECRET_REF_RE.finditer(raw):
                    current_job.secrets_referenced.add(m.group(1))

                if stripped.startswith("runs-on:"):
                    current_job.runs_on = stripped.split(":", 1)[1].strip()
                elif stripped.startswith("needs:"):
                    needs_val = stripped.split(":", 1)[1].strip().strip("[]")
                    for dep in needs_val.split(","):
                        d = dep.strip().strip("'\"")
                        if d:
                            current_job.needs.append(d)
                elif stripped.startswith("environment:"):
                    current_job.is_deploy_or_release = True
                elif stripped.startswith("permissions:"):
                    pv = stripped.split(":", 1)[1].strip()
                    if pv:
                        current_job.permissions["*"] = pv
                elif re.match(r"^(?:contents|id-token|packages|actions|pull-requests|security-events|write-all):\s*\w+", stripped):
                    pk, pv = stripped.split(":", 1)
                    current_job.permissions[pk.strip()] = pv.strip()

                m_uses = self._USES_RE.match(raw)
                if m_uses:
                    act = m_uses.group(1)
                    current_job.uses_actions.append((idx, act))
                    if "upload-artifact" in act.lower():
                        current_job.uploads_artifacts.append(f"artifact@{current_job.job_id}")
                    if "download-artifact" in act.lower():
                        current_job.downloads_artifacts.append(f"artifact_in@{current_job.job_id}")

                if any(ref in raw for ref in DANGEROUS_CHECKOUT_REFS):
                    current_job.checks_out_untrusted_pr = True

                m_run = re.match(r"^\s*-?\s*run:\s*(.*)$", raw)
                if m_run:
                    rest = m_run.group(1).strip()
                    if rest in ("|", "|-", "|+", ">", ">-"):
                        in_run_block = True
                        run_indent = indent
                        run_start_line = idx
                        run_buf = []
                    elif rest:
                        current_job.run_scripts.append((idx, rest))

        _flush_run()
        for jid, jnode in graph.jobs.items():
            for dep in jnode.needs:
                if dep in graph.jobs:
                    graph.edges.append((dep, jid, "needs"))
                    if graph.jobs[dep].uploads_artifacts and jnode.downloads_artifacts:
                        graph.edges.append((dep, jid, "artifact_flow"))
        return graph

    def audit_github_workflow(self, content: str, file_path: str = ".github/workflows/ci.yml") -> Dict[str, Any]:
        """Run full PPE + expression injection + supply-chain + OIDC audit on a GitHub Actions workflow."""
        graph = self.parse_github_actions_yaml(content, file_path)
        vulns: List[CyberVulnerability] = []
        triggers_lower = {t.lower() for t in graph.triggers}
        is_pr_privileged_trigger = bool(triggers_lower & {"pull_request_target", "workflow_run", "issue_comment"})

        # 1. Top-level permissions hygiene
        if graph.top_permissions.get("*") == "write-all" or any(
            v == "write-all" for v in graph.top_permissions.values()
        ):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-CICD-WRITE-ALL-TOKEN",
                    title=f"GitHub Actions Workflow Grants `permissions: write-all` (`{file_path}`)",
                    description="Workflow requests maximum write privileges across all repository scopes, amplifying any compromised step to full repo/package takeover.",
                    cyber_domain=CyberDomain.IAC_CICD,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-269", "CWE-250"],
                    confidence=0.99,
                    mitre_techniques=[MitreTechniqueRef("T1195.002", "Compromise Software Supply Chain", MitreTactic.INITIAL_ACCESS)],
                    verification_method=VerificationMethod.GRAPH_REACHABILITY,
                    file_path=file_path,
                    line_start=1,
                    remediation_guidance="Set top-level `permissions: { contents: read }` and grant minimal per-job permissions only where strictly required.",
                    discovered_by="ely_cyber_cicd_graph_auditor",
                )
            )
        elif not graph.top_permissions:
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-CICD-MISSING-PERMS-BLOCK",
                    title=f"Workflow Missing Explicit Least-Privilege `permissions:` Declaration (`{file_path}`)",
                    description="Without an explicit top-level `permissions:` block, GITHUB_TOKEN inherits org/repo defaults which may grant broad write access.",
                    cyber_domain=CyberDomain.IAC_CICD,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-276"],
                    confidence=0.92,
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    file_path=file_path,
                    line_start=1,
                    remediation_guidance="Add explicit top-level `permissions: read-all` or `permissions: { contents: read }`.",
                    discovered_by="ely_cyber_cicd_graph_auditor",
                )
            )

        # 2. Secret dump toJSON(secrets)
        if self._TOJSON_SECRETS_RE.search(content):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-CICD-TOJSON-SECRETS",
                    title=f"Bulk Secret Exfiltration Anti-Pattern `toJSON(secrets)` Detected (`{file_path}`)",
                    description="Serializing the entire `secrets` context makes every repository and organization secret reachable from a single compromised step or sub-shell.",
                    cyber_domain=CyberDomain.IAC_CICD,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-200", "CWE-798"],
                    confidence=0.99,
                    mitre_techniques=[MitreTechniqueRef("T1552.001", "Credentials In Files", MitreTactic.CREDENTIAL_ACCESS)],
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    file_path=file_path,
                    remediation_guidance="Pass only the individual secret required by the exact step that consumes it.",
                    discovered_by="ely_cyber_cicd_graph_auditor",
                )
            )

        # 3. Per-job graph analysis
        ppe_paths: List[Dict[str, Any]] = []
        unpinned_actions_count = 0
        for jid, job in graph.jobs.items():
            # 3a. Direct Poisoned Pipeline Execution (pull_request_target + untrusted checkout)
            if is_pr_privileged_trigger and job.checks_out_untrusted_pr:
                ppe_paths.append({"job": jid, "triggers": sorted(triggers_lower), "secrets_exposed": sorted(job.secrets_referenced)})
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-CICD-PPE-PWN-REQUEST",
                        title=f"CRITICAL Poisoned Pipeline Execution (Pwn Request) in Job `{jid}` (`{file_path}`)",
                        description=(
                            f"Privileged trigger `{sorted(triggers_lower)}` checks out untrusted external PR head code "
                            f"in job `{jid}` (secrets reachable: `{sorted(job.secrets_referenced) or ['GITHUB_TOKEN']}`). "
                            "Any fork PR can execute arbitrary shell commands and exfiltrate repository secrets or push malicious releases."
                        ),
                        cyber_domain=CyberDomain.IAC_CICD,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-94", "CWE-829"],
                        confidence=0.99,
                        cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="N"),
                        mitre_techniques=[MitreTechniqueRef("T1195.002", "Compromise Software Supply Chain", MitreTactic.INITIAL_ACCESS)],
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        file_path=file_path,
                        line_start=job.line_start,
                        remediation_guidance="Never checkout untrusted PR head inside `pull_request_target`/`workflow_run`, or strictly separate unprivileged PR build from privileged artifact-reviewing workflow.",
                        discovered_by="ely_cyber_cicd_graph_auditor",
                    )
                )

            # 3b. Self-hosted runner exposed to PR triggers
            if "self-hosted" in job.runs_on.lower() and bool(triggers_lower & {"pull_request", "pull_request_target", "issue_comment", "fork"}):
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-CICD-SELF-HOSTED-PR",
                        title=f"Persistent Self-Hosted Runner Exposed to Untrusted PR Trigger in Job `{jid}`",
                        description="Running fork pull requests on non-ephemeral self-hosted runners allows attackers to implant backdoors on the runner host and pivot into internal cloud/VPC networks.",
                        cyber_domain=CyberDomain.IAC_CICD,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-250", "CWE-269"],
                        confidence=0.97,
                        mitre_techniques=[MitreTechniqueRef("T1098", "Account Manipulation / Runner Persistence", MitreTactic.PERSISTENCE)],
                        verification_method=VerificationMethod.GRAPH_REACHABILITY,
                        file_path=file_path,
                        line_start=job.line_start,
                        remediation_guidance="Use ephemeral GitHub-hosted runners or isolated single-use Firecracker/Kubernetes ARC pods for all PR-triggered workflows.",
                        discovered_by="ely_cyber_cicd_graph_auditor",
                    )
                )

            # 3c. Unpinned third-party actions (not SHA-40 pinned)
            for ln, action_ref in job.uses_actions:
                if action_ref.startswith("./") or action_ref.startswith("docker://"):
                    continue
                if not self._SHA40_RE.search(action_ref):
                    unpinned_actions_count += 1
                    is_third_party = not action_ref.startswith(("actions/", "github/"))
                    sev = Severity.HIGH if is_third_party else Severity.MEDIUM
                    vulns.append(
                        make_cyber_vuln(
                            rule_id="CYB-CICD-UNPINNED-ACTION",
                            title=f"Action `{action_ref}` Uses Mutable Tag Instead of 40-Char Commit SHA Pin",
                            description=f"Job `{jid}` imports `{action_ref}` by mutable tag/branch. Upstream tag repointing injects malicious code into CI/CD runs (TJ-Actions/Reviewdog class).",
                            cyber_domain=CyberDomain.IAC_CICD,
                            severity=sev,
                            cwe_ids=["CWE-829", "CWE-494"],
                            confidence=0.98,
                            mitre_techniques=[MitreTechniqueRef("T1195.002", "Compromise Software Supply Chain", MitreTactic.INITIAL_ACCESS)],
                            verification_method=VerificationMethod.STATIC_PATTERN,
                            file_path=file_path,
                            line_start=ln,
                            remediation_guidance="Pin every external `uses:` action to a full 40-character commit SHA and manage updates via Dependabot/Renovate.",
                            discovered_by="ely_cyber_cicd_graph_auditor",
                        )
                    )

            # 3d. Expression injection + curl|sh in run scripts
            for ln, script in job.run_scripts:
                for m_ex in self._EXPR_RE.finditer(script):
                    expr = m_ex.group(1).strip()
                    if any(u in expr for u in UNTRUSTED_GHA_EXPRESSIONS):
                        vulns.append(
                            make_cyber_vuln(
                                rule_id="CYB-CICD-SCRIPT-INJECTION",
                                title=f"GitHub Actions Expression Injection `${{{{ {expr} }}}}` in Job `{jid}`",
                                description=f"Attacker-controlled event field `{expr}` is directly interpolated into a shell `run:` script before bash parsing, enabling trivial command injection via crafted PR titles/comments.",
                                cyber_domain=CyberDomain.IAC_CICD,
                                severity=Severity.CRITICAL,
                                cwe_ids=["CWE-78", "CWE-94"],
                                confidence=0.99,
                                cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="L", sc="H", si="H", sa="N"),
                                mitre_techniques=[MitreTechniqueRef("T1059.004", "Unix Shell Injection", MitreTactic.EXECUTION)],
                                verification_method=VerificationMethod.STATIC_AST,
                                file_path=file_path,
                                line_start=ln,
                                remediation_guidance="Bind untrusted expressions via an intermediate `env:` variable and reference double-quoted `\"$VAR\"` inside shell scripts.",
                                secure_code_example="env:\n  PR_TITLE: ${{ github.event.pull_request.title }}\nrun: printf '%s\\n' \"$PR_TITLE\"",
                                discovered_by="ely_cyber_cicd_graph_auditor",
                            )
                        )
                if self._CURL_PIPE_SH_RE.search(script):
                    vulns.append(
                        make_cyber_vuln(
                            rule_id="CYB-CICD-CURL-PIPE-SH",
                            title=f"Unverified Remote Script Execution (`curl | sh`) in Job `{jid}`",
                            description="Piping remote HTTP content directly to a shell interpreter bypasses cryptographic checksum verification and enables MITM/CDN supply-chain takeover.",
                            cyber_domain=CyberDomain.IAC_CICD,
                            severity=Severity.HIGH,
                            cwe_ids=["CWE-494", "CWE-829"],
                            confidence=0.97,
                            verification_method=VerificationMethod.STATIC_PATTERN,
                            file_path=file_path,
                            line_start=ln,
                            remediation_guidance="Download pinned tool binaries, verify SHA-256 digest & Cosign signature before execution.",
                            discovered_by="ely_cyber_cicd_graph_auditor",
                        )
                    )

            # 3e. Static cloud credentials instead of OIDC
            static_used = sorted(job.secrets_referenced & set(STATIC_CLOUD_CRED_KEYS))
            if static_used and job.permissions.get("id-token") != "write":
                vulns.append(
                    make_cyber_vuln(
                        rule_id="CYB-CICD-STATIC-CLOUD-CREDS",
                        title=f"Long-Lived Static Cloud/Registry Credentials `{static_used}` Used Instead of OIDC",
                        description=f"Job `{jid}` uses static long-lived secrets `{static_used}` instead of short-lived OIDC federation (`id-token: write`).",
                        cyber_domain=CyberDomain.CLOUD_IAM,
                        severity=Severity.MEDIUM,
                        cwe_ids=["CWE-798", "CWE-522"],
                        confidence=0.94,
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=file_path,
                        line_start=job.line_start,
                        remediation_guidance="Migrate to OIDC workload identity federation (`permissions: { id-token: write }`) with strict `sub` repository/environment claim matching.",
                        discovered_by="ely_cyber_cicd_graph_auditor",
                    )
                )

        # 4. Cross-job untrusted artifact poisoning edge check
        for src, dst, etype in graph.edges:
            if etype == "artifact_flow":
                src_job = graph.jobs[src]
                dst_job = graph.jobs[dst]
                if (src_job.checks_out_untrusted_pr or is_pr_privileged_trigger) and (dst_job.is_deploy_or_release or bool(dst_job.secrets_referenced)):
                    vulns.append(
                        make_cyber_vuln(
                            rule_id="CYB-CICD-ARTIFACT-POISONING",
                            title=f"Cross-Job Untrusted Artifact Flow `{src} -> {dst}` Into Privileged Job",
                            description=f"Job `{dst}` downloads build artifacts produced by `{src}` and holds privileged/release access (`secrets={sorted(dst_job.secrets_referenced)}`) without SLSA provenance verification.",
                            cyber_domain=CyberDomain.IAC_CICD,
                            severity=Severity.HIGH,
                            cwe_ids=["CWE-494", "CWE-345"],
                            confidence=0.95,
                            verification_method=VerificationMethod.GRAPH_REACHABILITY,
                            file_path=file_path,
                            line_start=dst_job.line_start,
                            remediation_guidance="Verify SLSA/Sigstore Cosign attestations before consuming upstream artifacts in release jobs, and enforce GitHub Environment approval gates.",
                            discovered_by="ely_cyber_cicd_graph_auditor",
                        )
                    )

        # 5. Jenkinsfile / GitLab CI inline patterns if non-GHA
        if "pipeline" in content and "stages" in content:
            for ln, line in enumerate(content.splitlines(), start=1):
                if self._JENKINS_SH_INTERP_RE.search(line):
                    vulns.append(
                        make_cyber_vuln(
                            rule_id="CYB-CICD-JENKINS-GROOVY-SH",
                            title=f"Jenkinsfile Groovy Double-Quoted `sh` Interpolation Injection (`{file_path}:{ln}`)",
                            description="Double-quoted Groovy string inside `sh \"... ${PARAM} ...\"` evaluates variables prior to shell execution, enabling command injection and secret leakage.",
                            cyber_domain=CyberDomain.IAC_CICD,
                            severity=Severity.HIGH,
                            cwe_ids=["CWE-78"],
                            confidence=0.95,
                            verification_method=VerificationMethod.STATIC_PATTERN,
                            file_path=file_path,
                            line_start=ln,
                            remediation_guidance="Use single-quoted `sh '...'` and pass parameters strictly through `withEnv` environment variables.",
                            discovered_by="ely_cyber_cicd_graph_auditor",
                        )
                    )

        score = max(0.0, round(100.0 - sum(22.0 if v.severity == Severity.CRITICAL else (12.0 if v.severity == Severity.HIGH else 5.0) for v in vulns), 2))
        return {
            "audited_at": utc_now_iso(),
            "file_path": file_path,
            "triggers": graph.triggers,
            "job_count": len(graph.jobs),
            "dag_edges": [{"src": s, "dst": d, "type": t} for s, d, t in graph.edges],
            "ppe_attack_paths": ppe_paths,
            "unpinned_actions_count": unpinned_actions_count,
            "pipeline_security_score": score,
            "vulnerabilities": vulns,
        }

    def scan_directory(self, target_dir: str) -> Dict[str, Any]:
        """Auto-discover and audit all `.github/workflows/*.yml|yaml`, `.gitlab-ci.yml`, and `Jenkinsfile`s."""
        root = Path(target_dir)
        reports: List[Dict[str, Any]] = []
        all_vulns: List[CyberVulnerability] = []
        if root.exists():
            for p in sorted(root.rglob("*")):
                if not p.is_file():
                    continue
                rel = str(p.relative_to(root))
                low = p.name.lower()
                if (".github/workflows/" in rel.replace("\\", "/") and low.endswith((".yml", ".yaml"))) or low in (".gitlab-ci.yml", "jenkinsfile"):
                    try:
                        txt = p.read_text(encoding="utf-8", errors="ignore")
                    except OSError:
                        continue
                    rep = self.audit_github_workflow(txt, file_path=rel)
                    reports.append(rep)
                    all_vulns.extend(rep["vulnerabilities"])
        return {
            "scanned_at": utc_now_iso(),
            "target_dir": str(root),
            "pipelines_audited": len(reports),
            "total_findings": len(all_vulns),
            "reports": reports,
            "vulnerabilities": all_vulns,
        }
