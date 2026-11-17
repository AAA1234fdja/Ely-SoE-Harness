"""
Harness² Deep Polyglot Target Surface Fingerprinter & Attack-Surface Prior Estimator.

Inspects any authorized repository or target snapshot in milliseconds to construct a
rich `TargetFingerprint` containing:
  - Language composition & total LOC metrics
  - Framework, Cloud Provider, K8s/Docker, IaC/CI-CD, OpenAPI/GraphQL, AI/LLM, Native
    Binary/C/C++, and IoT/OT surface detection
  - Dangerous sink density per kLOC (SQL, shell, eval, pickle, JWT, unsafe C, IAM wildcards)
  - 16-Domain `CyberDomain` Surface Affinity Vector (`[0.0, 1.0]`)
  - Canonical fixed 16-dimensional numeric `feature_vector` used directly by:
      * `LinUCBContextualBandit` for cold-start & warm-start genome selection
      * `MetaMemoryStore` for cosine-similarity transfer learning from prior targets!
"""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

from ely_soe.core.models import new_id
from ely_soe.cyber.models import CyberDomain
from ely_soe.harness_squared.models import TargetArchetype, TargetFingerprint


EXTENSION_TO_LANGUAGE: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".sql": "sql",
    ".sh": "shell",
    ".bash": "shell",
    ".ps1": "powershell",
    ".graphql": "graphql",
    ".gql": "graphql",
    ".proto": "protobuf",
    ".xml": "xml",
    ".html": "html",
    ".toml": "toml",
}

FRAMEWORK_SIGNATURES: Tuple[Tuple[str, str], ...] = (
    ("Flask", r"\bfrom\s+flask\b|\bFlask\s*\("),
    ("FastAPI", r"\bfrom\s+fastapi\b|\bFastAPI\s*\("),
    ("Django", r"\bfrom\s+django\b|\bdjango\.conf\b"),
    ("Express", r"require\(['\"]express['\"]\)|from\s+['\"]express['\"]"),
    ("Next.js", r"next/server|next/router|next\.config"),
    ("React", r"from\s+['\"]react['\"]|dangerouslySetInnerHTML"),
    ("SpringBoot", r"org\.springframework\.boot|@RestController"),
    ("GraphQL", r"type\s+Query\s*\{|graphql|ApolloServer|graphene"),
    ("gRPC", r"service\s+\w+\s*\{|grpc\.insecure_channel|protobuf"),
    ("OpenAI/Anthropic/LangChain", r"\b(?:openai|anthropic|langchain|llama_index|transformers|torch\.load)\b"),
    ("MCP-Agent", r"\bmcp\b|model_context_protocol|tool_registry|system_prompt"),
    ("PyJWT/OAuth", r"\bjwt\.decode\b|jsonwebtoken|oauth2|saml"),
    ("SQLAlchemy/SQLite/Psycopg", r"\bsqlite3\b|\bpsycopg2\b|\bsqlalchemy\b|SELECT\s+.+\s+FROM"),
    ("Modbus/MQTT/OT", r"\bpymodbus\b|\bpaho\.mqtt\b|modbus|s7comm|bacnet|opcua|dnp3"),
)

CLOUD_SIGNATURES: Tuple[Tuple[str, str], ...] = (
    ("aws", r"\b(?:boto3|aws_iam|aws_s3|arn:aws:|169\.254\.169\.254|AKIA[0-9A-Z]{16})\b"),
    ("gcp", r"\b(?:google_project_iam|googleapis\.com|service_account|AIza[0-9A-Za-z\-_]{35})\b"),
    ("azure", r"\b(?:azurerm_|DefaultEndpointsProtocol|SharedAccessSignature|azure\.identity)\b"),
)

SINK_PATTERNS: Tuple[Tuple[str, str], ...] = (
    ("sql", r"(?i)(?:execute|query)\s*\([^)]*(?:\+|%|f['\"]|\$\{)"),
    ("cmd", r"\b(?:os\.system|subprocess\.(?:run|Popen|call)|child_process\.exec|Runtime\.getRuntime\(\)\.exec)\b"),
    ("deser", r"\b(?:pickle\.loads?|yaml\.load|torch\.load|marshal\.loads|ObjectInputStream)\b"),
    ("crypto", r"\b(?:hashlib\.md5|hashlib\.sha1|MODE_ECB|verify\s*=\s*False|InsecureSkipVerify)\b"),
    ("auth", r"\b(?:jwt\.decode|verify_signature|alg.*none|SECRET_KEY|API_KEY|PRIVATE KEY)\b"),
    ("memory", r"\b(?:strcpy|strcat|sprintf|gets|memcpy|free\s*\(|unsafe\s*\{)\b"),
    ("k8s_iac", r"(?i)(?:privileged\s*:\s*true|hostPID\s*:\s*true|0\.0\.0\.0/0|pull_request_target|Action[\"']?\s*[:=]\s*[\"']?\*)"),
)


class TargetSurfaceFingerprinter:
    """Rapid polyglot static surface profiler producing 16-dim feature vectors for Harness²."""

    SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".mypy_cache"}

    def __init__(self) -> None:
        self._fw_rx = [(name, re.compile(pat)) for name, pat in FRAMEWORK_SIGNATURES]
        self._cloud_rx = [(name, re.compile(pat)) for name, pat in CLOUD_SIGNATURES]
        self._sink_rx = [(name, re.compile(pat)) for name, pat in SINK_PATTERNS]

    def fingerprint(self, target_path: Optional[Path] = None, target_name: Optional[str] = None) -> TargetFingerprint:
        if target_path is None or not Path(target_path).exists():
            return self._synthetic_enterprise_fingerprint(target_name or "synthetic_enterprise_range")

        root = Path(target_path).resolve()
        lang_counts: Dict[str, int] = {}
        frameworks: Set[str] = set()
        clouds: Set[str] = set()
        sink_hits: Dict[str, int] = {name: 0 for name, _ in SINK_PATTERNS}

        total_files = 0
        total_loc = 0
        has_k8s = False
        has_docker = False
        has_iac = False
        has_cicd = False
        has_api = False
        has_ai = False
        has_native = False
        has_iot_ot = False
        has_sbom = False
        has_env = False

        for fp in sorted(root.rglob("*")):
            if not fp.is_file():
                continue
            if any(p in self.SKIP_DIRS for p in fp.parts):
                continue
            total_files += 1
            rel_low = str(fp.relative_to(root)).lower()
            fname = fp.name.lower()
            ext = fp.suffix.lower()

            lang = EXTENSION_TO_LANGUAGE.get(ext)
            if lang:
                lang_counts[lang] = lang_counts.get(lang, 0) + 1

            if fname == "dockerfile" or fname.startswith("dockerfile.") or fname == "docker-compose.yml":
                has_docker = True
            if ext in (".tf", ".tfvars") or "cloudformation" in rel_low or "ansible" in rel_low:
                has_iac = True
            if ".github/workflows" in rel_low or fname in (".gitlab-ci.yml", "jenkinsfile"):
                has_cicd = True
            if ext in (".graphql", ".gql", ".proto") or "openapi" in fname or "swagger" in fname:
                has_api = True
            if ext in (".c", ".cpp", ".cc", ".h", ".hpp", ".so", ".elf", ".exe", ".dll"):
                has_native = True
            if fname in ("requirements.txt", "pyproject.toml", "package.json", "package-lock.json", "cargo.toml", "cargo.lock", "go.mod", "pom.xml"):
                has_sbom = True
            if fname == ".env" or fname.startswith(".env.") or "secret" in fname or "credential" in fname:
                has_env = True

            try:
                if fp.stat().st_size > 1_200_000:
                    continue
                raw = fp.read_bytes()
            except OSError:
                continue

            if raw.startswith(b"\x7fELF") or raw.startswith(b"MZ"):
                has_native = True
                continue

            text = raw.decode("utf-8", errors="ignore")
            total_loc += text.count("\n") + 1

            if re.search(r"apiVersion:\s*(?:v1|apps/v1|rbac\.authorization\.k8s\.io)", text):
                has_k8s = True
            if re.search(r'"openapi"\s*:|openapi:\s*["\']?3\.', text):
                has_api = True

            for fw_name, rx in self._fw_rx:
                if rx.search(text):
                    frameworks.add(fw_name)
                    if fw_name in ("OpenAI/Anthropic/LangChain", "MCP-Agent"):
                        has_ai = True
                    if fw_name == "Modbus/MQTT/OT":
                        has_iot_ot = True
                    if fw_name in ("GraphQL", "gRPC"):
                        has_api = True

            for cl_name, rx in self._cloud_rx:
                if rx.search(text):
                    clouds.add(cl_name)

            for sk_name, rx in self._sink_rx:
                cnt = len(rx.findall(text))
                if cnt:
                    sink_hits[sk_name] += cnt

        total_sinks = sum(sink_hits.values())
        kloc = max(0.1, total_loc / 1000.0)
        sink_density = total_sinks / kloc

        # Compute 16-Domain CyberDomain affinity scores in [0.15, 1.0]
        web_langs = sum(lang_counts.get(l, 0) for l in ("python", "javascript", "typescript", "php", "ruby", "java", "go"))
        has_web = web_langs > 0 or bool(frameworks & {"Flask", "FastAPI", "Django", "Express", "Next.js", "React", "SpringBoot"})

        affinities: Dict[str, float] = {
            CyberDomain.WEB_INJECTION.value: self._clamp(0.25 + (0.40 if has_web else 0.0) + min(0.35, (sink_hits["sql"] + sink_hits["cmd"]) * 0.08)),
            CyberDomain.WEB_CLIENT_PROTOCOL.value: self._clamp(0.20 + (0.45 if has_web else 0.0) + (0.25 if lang_counts.get("javascript", 0) + lang_counts.get("typescript", 0) + lang_counts.get("html", 0) > 0 else 0.0)),
            CyberDomain.WEB_SSRF_XXE_SSTI_DESER.value: self._clamp(0.25 + (0.35 if has_web else 0.0) + min(0.40, sink_hits["deser"] * 0.12)),
            CyberDomain.AUTH_ACCESS_CONTROL.value: self._clamp(0.30 + (0.35 if has_web or has_env else 0.0) + min(0.35, sink_hits["auth"] * 0.08)),
            CyberDomain.API_MICROSERVICES.value: self._clamp(0.20 + (0.65 if has_api else (0.30 if has_web else 0.0))),
            CyberDomain.NETWORK_PROTOCOL.value: self._clamp(0.25 + (0.35 if has_iac or has_k8s or has_iot_ot else 0.10)),
            CyberDomain.TLS_CRYPTOGRAPHY.value: self._clamp(0.25 + (0.35 if has_web or has_env else 0.0) + min(0.40, sink_hits["crypto"] * 0.10)),
            CyberDomain.CLOUD_IAM.value: self._clamp(0.20 + (0.60 if clouds or has_iac else 0.0) + min(0.20, sink_hits["k8s_iac"] * 0.06)),
            CyberDomain.KUBERNETES_CONTAINER.value: self._clamp(0.15 + (0.65 if has_k8s or has_docker else 0.0) + min(0.20, sink_hits["k8s_iac"] * 0.06)),
            CyberDomain.IAC_CICD.value: self._clamp(0.20 + (0.55 if has_iac or has_cicd or has_sbom else 0.0) + min(0.25, sink_hits["k8s_iac"] * 0.08)),
            CyberDomain.IDENTITY_ACTIVE_DIRECTORY.value: self._clamp(0.20 + (0.55 if lang_counts.get("powershell", 0) > 0 or "azure" in clouds else 0.10)),
            CyberDomain.BINARY_MEMORY_SAFETY.value: self._clamp(0.15 + (0.75 if has_native else 0.0) + min(0.10, sink_hits["memory"] * 0.05)),
            CyberDomain.FIRMWARE_IOT_OT.value: self._clamp(0.10 + (0.80 if has_iot_ot else 0.0)),
            CyberDomain.ADVERSARY_EMULATION.value: self._clamp(0.45 + (0.35 if has_ai or clouds or has_k8s else 0.15)),
            CyberDomain.DETECTION_ENGINEERING.value: self._clamp(0.40 + (0.30 if has_cicd or has_k8s or total_sinks > 3 else 0.10)),
            CyberDomain.THREAT_MODELING.value: self._clamp(0.50 + min(0.45, math.log1p(total_files) * 0.12)),
        }

        archetype = self._classify_archetype(
            has_k8s=has_k8s, has_docker=has_docker, has_iac=has_iac, has_cicd=has_cicd,
            has_ai=has_ai, has_native=has_native, has_iot_ot=has_iot_ot, has_web=has_web,
            clouds=clouds, lang_counts=lang_counts,
        )

        # Fixed 16-dimensional feature vector in [0.0, 1.0] for LinUCB & Cosine Meta-Memory
        feat_vec = [
            min(1.0, math.log1p(total_files) / 6.0),
            min(1.0, math.log1p(total_loc) / 11.0),
            min(1.0, sink_density / 25.0),
            1.0 if has_web else 0.0,
            1.0 if has_api else 0.0,
            1.0 if has_k8s else 0.0,
            1.0 if has_docker else 0.0,
            1.0 if has_iac else 0.0,
            1.0 if has_cicd else 0.0,
            1.0 if clouds else 0.0,
            1.0 if has_ai else 0.0,
            1.0 if has_native else 0.0,
            1.0 if has_iot_ot else 0.0,
            1.0 if has_sbom else 0.0,
            1.0 if has_env else 0.0,
            min(1.0, len(frameworks) / 6.0),
        ]

        risk_prior = self._clamp(0.25 + min(0.45, sink_density / 30.0) + (0.15 if has_env else 0.0) + (0.10 if has_ai else 0.0))

        return TargetFingerprint(
            fingerprint_id=new_id("fp"),
            target_name=target_name or root.name,
            target_root=str(root),
            archetype=archetype,
            total_files=total_files,
            total_loc=total_loc,
            language_distribution=lang_counts,
            detected_frameworks=sorted(frameworks),
            detected_cloud_providers=sorted(clouds),
            has_kubernetes=has_k8s,
            has_dockerfile=has_docker,
            has_terraform_or_iac=has_iac,
            has_cicd_workflows=has_cicd,
            has_openapi_or_graphql=has_api,
            has_ai_llm_components=has_ai,
            has_native_c_cpp_binaries=has_native,
            has_iot_ot_artifacts=has_iot_ot,
            has_lockfiles_or_sbom=has_sbom,
            has_env_or_secret_files=has_env,
            sink_density_per_kloc=sink_density,
            domain_affinities=affinities,
            feature_vector=feat_vec,
            estimated_risk_prior=risk_prior,
        )

    @staticmethod
    def _classify_archetype(
        *,
        has_k8s: bool,
        has_docker: bool,
        has_iac: bool,
        has_cicd: bool,
        has_ai: bool,
        has_native: bool,
        has_iot_ot: bool,
        has_web: bool,
        clouds: Set[str],
        lang_counts: Dict[str, int],
    ) -> TargetArchetype:
        if has_ai:
            return TargetArchetype.AI_AGENT_PLATFORM
        if has_iot_ot:
            return TargetArchetype.EMBEDDED_OT_FIRMWARE
        if has_native and not has_web:
            return TargetArchetype.NATIVE_SYSTEMS_BINARY
        if has_k8s or (has_docker and clouds):
            return TargetArchetype.CLOUD_NATIVE_K8S
        if has_cicd and has_iac and not has_web:
            return TargetArchetype.CI_SUPPLY_CHAIN_HEAVY
        if lang_counts.get("powershell", 0) > 0:
            return TargetArchetype.ENTERPRISE_HYBRID_AD
        if len(lang_counts) >= 4:
            return TargetArchetype.POLYGLOT_FULLSTACK
        return TargetArchetype.WEB_API_MONOLITH

    @staticmethod
    def _synthetic_enterprise_fingerprint(name: str) -> TargetFingerprint:
        affinities = {d.value: 0.70 for d in CyberDomain}
        vec = [0.6, 0.65, 0.55, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 0.5, 0.3, 0.3, 1.0, 1.0, 0.7]
        return TargetFingerprint(
            fingerprint_id=new_id("fp"),
            target_name=name,
            target_root="synthetic_enterprise_range",
            archetype=TargetArchetype.POLYGLOT_FULLSTACK,
            total_files=32,
            total_loc=4200,
            language_distribution={"python": 12, "yaml": 8, "terraform": 6, "json": 6},
            detected_frameworks=["Flask", "GraphQL", "PyJWT/OAuth"],
            detected_cloud_providers=["aws"],
            has_kubernetes=True,
            has_dockerfile=True,
            has_terraform_or_iac=True,
            has_cicd_workflows=True,
            has_openapi_or_graphql=True,
            has_ai_llm_components=True,
            has_lockfiles_or_sbom=True,
            has_env_or_secret_files=True,
            sink_density_per_kloc=14.2,
            domain_affinities=affinities,
            feature_vector=vec,
            estimated_risk_prior=0.78,
        )

    @staticmethod
    def _clamp(val: float, lo: float = 0.05, hi: float = 1.0) -> float:
        return max(lo, min(hi, val))
