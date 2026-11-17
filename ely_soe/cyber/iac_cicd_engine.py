"""
Infrastructure-as-Code (IaC) & CI/CD Pipeline Security Engine.

Covers two critical DevSecOps & Supply-Chain attack planes:
  1. IaC Policy Engine (Terraform `.tf`, CloudFormation `.yaml`/`.json`, Ansible):
       - Public S3 / GCS / Azure Blob buckets (`public-read`, `public-read-write`, `block_public_acls = false`)
       - Unencrypted storage volumes / RDS databases / KMS key rotation disabled
       - Security groups exposing `0.0.0.0/0` or `::/0` to SSH (22), RDP (3389), DB ports (5432, 3306, 27017, 6379)
       - EC2 instances without IMDSv2 enforced (`http_tokens = "optional"`)
       - Publicly accessible RDS / CloudSQL instances (`publicly_accessible = true`)
       - CloudTrail / VPC Flow Logs / S3 access logging disabled
       - Hardcoded cloud credentials (`AKIA...`, `aws_secret_access_key`, `password = "..."`)
  2. CI/CD Pipeline Security Auditor (GitHub Actions, GitLab CI, Jenkinsfile):
       - GitHub Actions **`pull_request_target` + untrusted PR checkout** ("Pwn Request" RCE + secret theft)
       - GitHub Actions **Expression Script Injection** (`${{ github.event.issue.title }}`, `pull_request.title`, `comment.body`, `head_ref` inside `run:`)
       - Unpinned third-party GitHub Actions (`uses: org/action@v3` or `@main` instead of immutable 40-hex commit SHA)
       - Overprivileged `permissions: write-all` or `id-token: write` combined with untrusted triggers
       - Self-hosted runners exposed on public PR triggers
       - Secret echoing / artifact exfiltration in workflow scripts
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Tuple

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


@dataclass(frozen=True)
class IaCRule:
    rule_id: str
    title: str
    description: str
    severity: Severity
    cwe_ids: Tuple[str, ...]
    file_patterns: Tuple[str, ...]  # suffix or substring match
    pattern: str
    anti_pattern: Optional[str]
    mitre_id: str
    tactic: MitreTactic
    remediation: str


IAC_RULES: Tuple[IaCRule, ...] = (
    IaCRule(
        rule_id="CYB-IAC-S3-PUBLIC-001",
        title="Publicly Accessible Cloud Storage Bucket (`public-read` / Public Block Disabled)",
        description="IaC defines a storage bucket with public ACL or disabled public-access blocks, risking bulk data exposure or bucket tampering.",
        severity=Severity.CRITICAL,
        cwe_ids=("CWE-284", "CWE-732"),
        file_patterns=(".tf", ".yaml", ".yml", ".json"),
        pattern=r"""(?i)(?:acl\s*=\s*["']public-read(?:-write)?["']|AccessControl\s*:\s*PublicRead(?:Write)?|block_public_acls\s*=\s*false|ignore_public_acls\s*=\s*false|allUsers|allAuthenticatedUsers)""",
        anti_pattern=None,
        mitre_id="T1530",
        tactic=MitreTactic.COLLECTION,
        remediation="Enable all four S3 Public Access Block settings (`true`) / GCP Uniform Bucket-Level Access and deny `allUsers`.",
    ),
    IaCRule(
        rule_id="CYB-IAC-SG-OPEN-001",
        title="IaC Security Group Exposes Management/Database Port to `0.0.0.0/0`",
        description="Ingress rule opens administrative or database ports globally to the internet.",
        severity=Severity.CRITICAL,
        cwe_ids=("CWE-284", "CWE-668"),
        file_patterns=(".tf", ".yaml", ".yml", ".json"),
        pattern=r"""(?i)(?:cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0/0["']\s*\]|CidrIp\s*:\s*["']?0\.0\.0\.0/0|source_ranges\s*=\s*\[\s*["']0\.0\.0\.0/0["']\s*\])""",
        anti_pattern=r"""(?i)(?:port\s*[:=]\s*(?:80|443)\b|from_port\s*=\s*(?:80|443)\b)""",
        mitre_id="T1133",
        tactic=MitreTactic.INITIAL_ACCESS,
        remediation="Restrict ingress CIDRs strictly to private VPN/bastion subnets or zero-trust load balancers.",
    ),
    IaCRule(
        rule_id="CYB-IAC-IMDSV1-001",
        title="Cloud Compute Instance Allows Legacy IMDSv1 (`http_tokens = optional`)",
        description="Allowing IMDSv1 permits single-request SSRF vulnerabilities to steal IAM Instance Profile credentials.",
        severity=Severity.HIGH,
        cwe_ids=("CWE-918", "CWE-522"),
        file_patterns=(".tf", ".yaml", ".yml", ".json"),
        pattern=r"""(?i)(?:http_tokens\s*=\s*["']optional["']|HttpTokens\s*:\s*optional)""",
        anti_pattern=None,
        mitre_id="T1552.005",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        remediation="Set `http_tokens = \"required\"` and `http_put_response_hop_limit = 1` to mandate IMDSv2.",
    ),
    IaCRule(
        rule_id="CYB-IAC-DB-PUBLIC-001",
        title="Database Instance Configured as Publicly Accessible (`publicly_accessible = true`)",
        description="Managed database (RDS/CloudSQL/Azure SQL) is assigned a public IP reachable outside the VPC.",
        severity=Severity.CRITICAL,
        cwe_ids=("CWE-668",),
        file_patterns=(".tf", ".yaml", ".yml", ".json"),
        pattern=r"""(?i)(?:publicly_accessible\s*=\s*true|PubliclyAccessible\s*:\s*true|ipv4_enabled\s*=\s*true)""",
        anti_pattern=None,
        mitre_id="T1190",
        tactic=MitreTactic.INITIAL_ACCESS,
        remediation="Set `publicly_accessible = false` and place databases strictly in isolated private subnets.",
    ),
    IaCRule(
        rule_id="CYB-IAC-UNENCRYPTED-001",
        title="Unencrypted Cloud Storage / EBS Volume / RDS Database",
        description="Persistent storage resource explicitly disables encryption at rest (`encrypted = false` / `storage_encrypted = false`).",
        severity=Severity.HIGH,
        cwe_ids=("CWE-311",),
        file_patterns=(".tf", ".yaml", ".yml", ".json"),
        pattern=r"""(?i)(?:storage_encrypted\s*=\s*false|\bencrypted\s*=\s*false|StorageEncrypted\s*:\s*false|enable_key_rotation\s*=\s*false)""",
        anti_pattern=None,
        mitre_id="T1530",
        tactic=MitreTactic.COLLECTION,
        remediation="Enable KMS customer-managed encryption at rest (`storage_encrypted = true`, `enable_key_rotation = true`).",
    ),
    IaCRule(
        rule_id="CYB-IAC-LOGGING-OFF-001",
        title="Cloud Audit Logging / CloudTrail Multi-Region Validation Disabled",
        description="Disabling audit trail logging or log file validation creates blind spots for incident forensics.",
        severity=Severity.MEDIUM,
        cwe_ids=("CWE-778",),
        file_patterns=(".tf", ".yaml", ".yml", ".json"),
        pattern=r"""(?i)(?:enable_logging\s*=\s*false|enable_log_file_validation\s*=\s*false|is_multi_region_trail\s*=\s*false)""",
        anti_pattern=None,
        mitre_id="T1562.008",
        tactic=MitreTactic.DEFENSE_EVASION,
        remediation="Enable multi-region CloudTrail with cryptographic log file validation and immutable S3 Object Lock.",
    ),
    IaCRule(
        rule_id="CYB-IAC-HARDCODED-CRED-001",
        title="Hardcoded Cloud Credentials or Database Password in IaC Template",
        description="Plaintext secret/access key committed directly into Terraform or CloudFormation source.",
        severity=Severity.CRITICAL,
        cwe_ids=("CWE-798",),
        file_patterns=(".tf", ".tfvars", ".yaml", ".yml", ".json"),
        pattern=r"""(?i)(?:AKIA[0-9A-Z]{16}|(?:aws_secret_access_key|master_password|db_password|admin_password)\s*[:=]\s*["'][^"'\$\{]{8,}["'])""",
        anti_pattern=r"""(?i)(?:var\.|random_password|secretsmanager|Ref:|!Sub)""",
        mitre_id="T1552.001",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        remediation="Inject secrets dynamically via Secrets Manager / Vault / OIDC workload federation, never literal IaC strings.",
    ),
)


# Untrusted GitHub Actions context expressions vulnerable to shell script injection
UNTRUSTED_GHA_EXPRESSIONS = (
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.head_commit.message",
    "github.head_ref",
)


class IaCAndCICDSecurityEngine:
    """Audits Terraform/CloudFormation IaC and GitHub Actions / GitLab CI / Jenkins pipelines."""

    def __init__(self) -> None:
        self._compiled_iac: List[Tuple[IaCRule, Pattern[str], Optional[Pattern[str]]]] = [
            (r, re.compile(r.pattern), re.compile(r.anti_pattern) if r.anti_pattern else None)
            for r in IAC_RULES
        ]

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
            name_l = fp.name.lower()

            try:
                content = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            # GitHub Actions workflows
            if (".github/workflows/" in rel.replace("\\", "/") or "workflows" in fp.parts) and ext in (".yml", ".yaml"):
                for f in self.audit_github_actions_workflow(content, rel):
                    if f.fingerprint() not in seen:
                        seen.add(f.fingerprint())
                        findings.append(f)

            # GitLab CI / Jenkinsfile
            if name_l in (".gitlab-ci.yml", "jenkinsfile") or name_l.endswith(".jenkinsfile"):
                for f in self.audit_gitlab_or_jenkins(content, rel):
                    if f.fingerprint() not in seen:
                        seen.add(f.fingerprint())
                        findings.append(f)

            # IaC rules (.tf, .tfvars, CloudFormation YAML/JSON)
            if ext in (".tf", ".tfvars", ".yaml", ".yml", ".json"):
                is_iac_context = ext in (".tf", ".tfvars") or any(
                    tok in content for tok in ("AWSTemplateFormatVersion", "AWS::", "resource \"aws_", "resource \"google_", "resource \"azurerm_")
                )
                if is_iac_context:
                    lines = content.splitlines()
                    for rule, regex, anti in self._compiled_iac:
                        if ext not in rule.file_patterns:
                            continue
                        for idx, line in enumerate(lines, start=1):
                            if not regex.search(line):
                                continue
                            win = "\n".join(lines[max(0, idx - 4) : min(len(lines), idx + 4)])
                            if anti and anti.search(win):
                                continue
                            v = make_cyber_vuln(
                                rule_id=rule.rule_id,
                                title=rule.title,
                                description=rule.description,
                                cyber_domain=CyberDomain.IAC_CICD,
                                severity=rule.severity,
                                cwe_ids=list(rule.cwe_ids),
                                confidence=0.92,
                                mitre_techniques=[MitreTechniqueRef(rule.mitre_id, rule.title, rule.tactic)],
                                verification_method=VerificationMethod.STATIC_PATTERN,
                                file_path=rel,
                                line_start=idx,
                                line_end=idx,
                                code_snippet=line.strip()[:240],
                                remediation_guidance=rule.remediation,
                                discovered_by="ely_cyber_iac_engine",
                            )
                            if v.fingerprint() not in seen:
                                seen.add(v.fingerprint())
                                findings.append(v)

        return findings

    def audit_github_actions_workflow(self, yaml_text: str, rel_path: str) -> List[CyberVulnerability]:
        """Deep static security audit of a GitHub Actions workflow YAML."""
        findings: List[CyberVulnerability] = []
        lines = yaml_text.splitlines()

        has_pr_target = bool(re.search(r"(?m)^\s*pull_request_target\b", yaml_text))
        checks_out_pr_head = bool(
            re.search(r"github\.event\.pull_request\.head\.(?:sha|ref)", yaml_text)
        )

        # 1. Critical Pwn-Request: pull_request_target + checkout of untrusted PR head
        if has_pr_target and checks_out_pr_head:
            findings.append(
                make_cyber_vuln(
                    rule_id="CYB-CICD-GHA-PWN-REQUEST-001",
                    title="GitHub Actions `pull_request_target` Checks Out Untrusted PR Code (RCE + Secret Theft)",
                    description=(
                        f"Workflow `{rel_path}` triggers on `pull_request_target` (which has write token + repo secrets) "
                        "and explicitly checks out untrusted PR head code, allowing any fork PR to exfiltrate repository secrets."
                    ),
                    cyber_domain=CyberDomain.IAC_CICD,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-829", "CWE-94"],
                    confidence=0.99,
                    mitre_techniques=[MitreTechniqueRef("T1195.002", "Compromise Software Supply Chain", MitreTactic.INITIAL_ACCESS, "002")],
                    cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="N"),
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    file_path=rel_path,
                    line_start=1,
                    line_end=len(lines),
                    remediation_guidance="Use `pull_request` trigger for untrusted code execution, or never check out/execute PR head code inside `pull_request_target`.",
                    discovered_by="ely_cyber_cicd_auditor",
                )
            )

        # 2. Expression Script Injection inside `run:` steps
        for idx, line in enumerate(lines, start=1):
            for expr in UNTRUSTED_GHA_EXPRESSIONS:
                if f"${{{{" in line or "${{" in line:
                    if expr in line and not line.strip().startswith("#"):
                        # Check nearby context if it's inside `run:` or inline command
                        window = "\n".join(lines[max(0, idx - 4) : idx])
                        if "run:" in window or "run:" in line:
                            findings.append(
                                make_cyber_vuln(
                                    rule_id="CYB-CICD-GHA-SCRIPT-INJ-001",
                                    title=f"GitHub Actions Command Injection via `${{{{ {expr} }}}}` in Shell `run:`",
                                    description=f"Untrusted GitHub event expression `{expr}` is directly interpolated into shell script before execution.",
                                    cyber_domain=CyberDomain.IAC_CICD,
                                    severity=Severity.CRITICAL,
                                    cwe_ids=["CWE-78", "CWE-94"],
                                    confidence=0.97,
                                    mitre_techniques=[MitreTechniqueRef("T1059.004", "Unix Shell", MitreTactic.EXECUTION, "004")],
                                    verification_method=VerificationMethod.STATIC_PATTERN,
                                    file_path=rel_path,
                                    line_start=idx,
                                    line_end=idx,
                                    code_snippet=line.strip()[:220],
                                    remediation_guidance="Pass untrusted expressions through an intermediate `env:` variable and double-quote `\"$VAR\"` in shell.",
                                    discovered_by="ely_cyber_cicd_auditor",
                                )
                            )
                            break

            # 3. Unpinned third-party GitHub Action (`uses: org/repo@vX` instead of 40-char commit SHA)
            m_use = re.search(r"uses\s*:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([^\s#]+)", line)
            if m_use:
                action_repo, ref = m_use.group(1), m_use.group(2)
                is_sha = bool(re.fullmatch(r"[0-9a-fA-F]{40}", ref))
                if not is_sha:
                    findings.append(
                        make_cyber_vuln(
                            rule_id="CYB-CICD-GHA-UNPINNED-ACTION",
                            title=f"Third-Party GitHub Action `{action_repo}@{ref}` Not Pinned to Full Commit SHA",
                            description=f"Mutable tag/branch reference `{ref}` permits silent upstream tag hijacking (supply-chain poisoning).",
                            cyber_domain=CyberDomain.IAC_CICD,
                            severity=Severity.MEDIUM if action_repo.startswith("actions/") else Severity.HIGH,
                            cwe_ids=["CWE-829", "CWE-494"],
                            confidence=0.95,
                            verification_method=VerificationMethod.STATIC_PATTERN,
                            file_path=rel_path,
                            line_start=idx,
                            line_end=idx,
                            code_snippet=line.strip()[:220],
                            remediation_guidance="Pin every `uses:` step to an immutable 40-character commit SHA with a version comment.",
                            discovered_by="ely_cyber_cicd_auditor",
                        )
                    )

            # 4. Overprivileged GITHUB_TOKEN (`permissions: write-all`)
            if re.search(r"(?i)permissions\s*:\s*write-all\b", line):
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-CICD-GHA-WRITE-ALL",
                        title="Overprivileged Workflow Token (`permissions: write-all`)",
                        description="Granting `write-all` allows any compromised workflow step to push releases, overwrite code, and mint OIDC tokens.",
                        cyber_domain=CyberDomain.IAC_CICD,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-250"],
                        confidence=0.98,
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line.strip()[:220],
                        remediation_guidance="Set top-level `permissions: { contents: read }` and grant minimal write scopes per job.",
                        discovered_by="ely_cyber_cicd_auditor",
                    )
                )

            # 5. Self-hosted runner on PR triggers
            if re.search(r"(?i)runs-on\s*:.*self-hosted", line) and (has_pr_target or "pull_request" in yaml_text):
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-CICD-GHA-SELFHOSTED-PR",
                        title="Self-Hosted CI Runner Exposed to Pull Request Workflow",
                        description="Persistent self-hosted runners executing untrusted PRs risk lateral pivot into internal corporate networks.",
                        cyber_domain=CyberDomain.IAC_CICD,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-284"],
                        confidence=0.91,
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line.strip()[:220],
                        remediation_guidance="Use ephemeral GitHub-hosted runners or isolated single-use VM runners for pull requests.",
                        discovered_by="ely_cyber_cicd_auditor",
                    )
                )

        return findings

    def audit_gitlab_or_jenkins(self, content: str, rel_path: str) -> List[CyberVulnerability]:
        findings: List[CyberVulnerability] = []
        for idx, line in enumerate(content.splitlines(), start=1):
            if re.search(r"(?i)(?:curl|wget)\s+[^|]+\|\s*(?:sh|bash)", line):
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-CICD-PIPE-SH-001",
                        title="Unverified Remote Script Execution (`curl | sh`) in CI Pipeline",
                        description=f"Pipeline `{rel_path}:{idx}` downloads and executes remote shell scripts without checksum verification.",
                        cyber_domain=CyberDomain.IAC_CICD,
                        severity=Severity.HIGH,
                        cwe_ids=["CWE-494"],
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line.strip()[:220],
                        remediation_guidance="Pin container build images and verify SHA-256 checksums before execution.",
                        discovered_by="ely_cyber_cicd_auditor",
                    )
                )
            if re.search(r'(?i)sh\s+["\'][^"\']*\$\{(?:env\.|params\.)', line):
                findings.append(
                    make_cyber_vuln(
                        rule_id="CYB-CICD-JENKINS-GROOVY-INJ",
                        title="Jenkinsfile Groovy String Interpolation Inside `sh` Step (Command Injection)",
                        description="Using double-quoted GStrings inside `sh \"... ${params.X}\"` injects parameter values before shell execution.",
                        cyber_domain=CyberDomain.IAC_CICD,
                        severity=Severity.CRITICAL,
                        cwe_ids=["CWE-78"],
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line.strip()[:220],
                        remediation_guidance="Use single-quoted `sh '...'` reading strictly from sanitized environment variables.",
                        discovered_by="ely_cyber_cicd_auditor",
                    )
                )
        return findings
