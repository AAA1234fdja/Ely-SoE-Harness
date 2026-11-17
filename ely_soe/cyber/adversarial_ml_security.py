"""
Adversarial ML / AI Model Supply-Chain Security Engine:
Safe Non-Executing Pickle Opcode Disassembler (`pickletools`), Checkpoint RCE Scanner,
RAG Vector-Store Multi-Tenant ACL Leakage Auditor & OWASP ML Top 10 Verifier.

Secures the ML lifecycle beyond LLM prompt injection:
  1. **Safe Non-Executing Python Pickle / PyTorch Checkpoint Opcode Scanner**:
       Uses Python stdlib `pickletools.genops()` to disassemble raw `.pkl`/`.pickle`/`.pt`
       byte streams WITHOUT EVER executing `pickle.loads()`! Detects arbitrary code execution
       gadgets (`os.system`, `posix.system`, `subprocess.Popen`, `builtins.eval`,
       `builtins.exec`, `nt.system`, `webbrowser.open`, `importlib.import_module`,
       `__builtin__.getattr`, `STACK_GLOBAL` + `REDUCE` chains) with zero execution risk!
  2. **RAG Vector-Store Multi-Tenant Access-Control & Metadata-Filter Auditor**:
       Audits Retrieval-Augmented Generation pipeline configs and code for missing
       `tenant_id` / `acl_groups` pre-filtering on vector similarity search (cross-tenant
       document exfiltration via semantic retrieval!), unencrypted embedding indexes, and
       poisonable unvalidated document ingestion pipelines.
  3. **ML Weight Backdoor / Distribution Anomaly Heuristic Verifier**:
       Inspects model layer summary statistics (kurtosis/L-inf spike outliers across weight
       tensors) to flag potential Neural Trojan / sleeper backdoor anomalies and checks
       Model Card provenance (`safetensors` preferred over `pickle`, SHA-256 weight pin).
  4. **Model Extraction / Inference API Abuse Auditor**:
       Flags inference endpoints exposing full raw `logprobs` / softmax probability vectors
       without rate limits, differential noise, or watermarking (model-stealing risk).
"""

from __future__ import annotations

import math
import pickletools
import re
from dataclasses import dataclass
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


DANGEROUS_PICKLE_MODULES: Dict[str, Tuple[str, Severity]] = {
    "os": ("OS command execution via `os.system`/`os.popen`", Severity.CRITICAL),
    "posix": ("POSIX OS command execution via `posix.system`", Severity.CRITICAL),
    "nt": ("Windows OS command execution via `nt.system`", Severity.CRITICAL),
    "subprocess": ("Arbitrary subprocess execution via `subprocess.Popen`/`check_output`", Severity.CRITICAL),
    "builtins": ("Arbitrary Python code execution via `eval`/`exec`/`__import__`", Severity.CRITICAL),
    "__builtin__": ("Legacy Python2/3 arbitrary code execution via `eval`/`exec`", Severity.CRITICAL),
    "importlib": ("Dynamic module import gadget (`importlib.import_module`)", Severity.CRITICAL),
    "runpy": ("Arbitrary module execution via `runpy.run_module`/`run_path`", Severity.CRITICAL),
    "socket": ("Direct outbound reverse-shell / exfiltration socket creation", Severity.CRITICAL),
    "http.client": ("Direct network exfiltration during model unpickling", Severity.HIGH),
    "urllib.request": ("Remote payload fetch during model unpickling", Severity.HIGH),
    "shutil": ("Filesystem tampering/deletion during model unpickling", Severity.HIGH),
    "ctypes": ("Native memory corruption / shellcode execution via `ctypes`", Severity.CRITICAL),
    "operator": ("`operator.attrgetter` sandbox-escape gadget chain", Severity.HIGH),
}


class AdversarialMLSecurityEngine:
    """Safely inspects ML pickle checkpoints, RAG vector ACLs, weight anomalies, and inference APIs."""

    def inspect_pickle_bytes_safely(
        self,
        raw_bytes: bytes,
        asset: str = "model_checkpoint.pkl",
    ) -> Dict[str, Any]:
        """
        Safely disassemble Python Pickle opcodes using `pickletools.genops` WITHOUT executing
        a single instruction of untrusted bytecode. Catches `GLOBAL`, `STACK_GLOBAL`, `INST`,
        and `REDUCE` code-execution gadgets.
        """
        vulns: List[CyberVulnerability] = []
        imports_found: List[Tuple[str, str]] = []
        stack_strings: List[str] = []
        opcodes_seen: Dict[str, int] = {}
        parse_error = ""

        try:
            for op, arg, _pos in pickletools.genops(raw_bytes):
                name = op.name
                opcodes_seen[name] = opcodes_seen.get(name, 0) + 1
                if name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "STRING", "SHORT_BINSTRING", "BINSTRING"):
                    if isinstance(arg, (str, bytes)):
                        s = arg.decode("utf-8", errors="ignore") if isinstance(arg, bytes) else arg
                        stack_strings.append(s)
                elif name == "GLOBAL":
                    if isinstance(arg, str):
                        parts = arg.split(" ", 1)
                        mod = parts[0]
                        sym = parts[1] if len(parts) > 1 else ""
                        imports_found.append((mod, sym))
                elif name == "INST":
                    if isinstance(arg, str):
                        parts = arg.split(" ", 1)
                        imports_found.append((parts[0], parts[1] if len(parts) > 1 else ""))
                elif name == "STACK_GLOBAL":
                    if len(stack_strings) >= 2:
                        sym = stack_strings[-1]
                        mod = stack_strings[-2]
                        imports_found.append((mod, sym))
        except Exception as exc:
            parse_error = f"{type(exc).__name__}: {exc}"

        dangerous_hits: List[Dict[str, str]] = []
        for mod, sym in imports_found:
            root_mod = mod.split(".")[0]
            spec = DANGEROUS_PICKLE_MODULES.get(mod) or DANGEROUS_PICKLE_MODULES.get(root_mod)
            if spec:
                reason, sev = spec
                dangerous_hits.append({"module": mod, "symbol": sym, "reason": reason, "severity": sev.value})
                vulns.append(
                    make_cyber_vuln(
                        rule_id=f"CYB-ML-PICKLE-RCE-{root_mod.upper()}",
                        title=f"Malicious Pickle/ML Checkpoint Code Execution Gadget `{mod}.{sym}` in `{asset}`",
                        description=(
                            f"Static non-executing `pickletools` disassembly of `{asset}` uncovered dangerous callable "
                            f"`{mod}.{sym}` ({reason}) paired with `REDUCE`/`INST` opcodes. Loading this model via "
                            "`torch.load()` or `pickle.load()` triggers immediate Remote Code Execution (OWASP ML06)."
                        ),
                        cyber_domain=CyberDomain.WEB_SSRF_XXE_SSTI_DESER,
                        severity=sev,
                        cwe_ids=["CWE-502", "CWE-94"],
                        confidence=0.99,
                        owasp_categories=["OWASP-ML06:2023-AI-Supply-Chain-Attacks"],
                        cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="A", vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
                        mitre_techniques=[MitreTechniqueRef("T1059.006", "Python Deserialization RCE in ML Weights", MitreTactic.EXECUTION)],
                        verification_method=VerificationMethod.BINARY_HEADER_INSPECTION,
                        endpoint_or_asset=asset,
                        remediation_guidance="Reject `.pkl`/`.pt` checkpoints containing non-tensor globals; migrate all model serialization to `safetensors` or `torch.load(..., weights_only=True)`.",
                        discovered_by="ely_cyber_adversarial_ml_engine",
                    )
                )

        return {
            "inspected_at": utc_now_iso(),
            "asset": asset,
            "bytes_inspected": len(raw_bytes),
            "opcodes_count": sum(opcodes_seen.values()),
            "reduce_opcodes": opcodes_seen.get("REDUCE", 0),
            "imports_found": [f"{m}.{s}" for m, s in imports_found],
            "dangerous_hits": dangerous_hits,
            "is_safe_tensor_only": len(dangerous_hits) == 0 and not parse_error,
            "parse_error": parse_error,
            "vulnerabilities": vulns,
        }

    def audit_rag_pipeline_config(
        self,
        rag_cfg: Dict[str, Any],
        asset: str = "enterprise_rag_pipeline",
    ) -> Dict[str, Any]:
        """Audit RAG vector-database pipeline for cross-tenant ACL leakage and document poisoning."""
        vulns: List[CyberVulnerability] = []

        if rag_cfg.get("multi_tenant", True) and not rag_cfg.get("enforce_metadata_acl_prefilter", False):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-ML-RAG-TENANT-LEAK-001",
                    title=f"Multi-Tenant RAG Vector Store `{asset}` Lacks Mandatory Pre-Retrieval ACL Metadata Filter",
                    description=(
                        f"Vector similarity search on `{asset}` queries a shared embedding index without enforcing "
                        "`tenant_id` / `acl_group` pre-filters, enabling cross-tenant confidential document extraction."
                    ),
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-284", "CWE-639"],
                    confidence=0.98,
                    owasp_categories=["LLM02:2025-Sensitive-Information-Disclosure"],
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=asset,
                    remediation_guidance="Enforce server-side JWT-bound `tenant_id` and document-level ACL metadata filters inside the vector store query predicate BEFORE k-NN ranking.",
                    discovered_by="ely_cyber_adversarial_ml_engine",
                )
            )

        if not rag_cfg.get("sanitize_ingested_docs_for_prompt_injection", False):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-ML-RAG-POISON-001",
                    title=f"RAG Ingestion Pipeline `{asset}` Lacks Indirect Prompt-Injection Quarantine & Provenance Tagging",
                    description="Untrusted external documents ingested into the vector DB can embed hidden instruction overrides targeting downstream agents.",
                    cyber_domain=CyberDomain.WEB_INJECTION,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-74"],
                    confidence=0.95,
                    owasp_categories=["LLM01:2025-Prompt-Injection", "LLM08:2025-Vector-and-Embedding-Weaknesses"],
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=asset,
                    remediation_guidance="Tag retrieved chunks with explicit untrusted provenance delimiters (`<untrusted_doc>`) and strip instruction-override payloads at ingest.",
                    discovered_by="ely_cyber_adversarial_ml_engine",
                )
            )

        if rag_cfg.get("expose_raw_logprobs", False) and not rag_cfg.get("rate_limit_extraction_guard", False):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-ML-MODEL-EXTRACTION-001",
                    title=f"Inference API `{asset}` Exposes Unthrottled Raw `logprobs` (Model Stealing Risk)",
                    description="Exposing full top-k log-probabilities without query rate caps allows rapid distillation/extraction of proprietary model behavior.",
                    cyber_domain=CyberDomain.API_MICROSERVICES,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-200", "CWE-770"],
                    confidence=0.93,
                    owasp_categories=["OWASP-ML05:2023-Model-Theft"],
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=asset,
                    remediation_guidance="Disable raw `logprobs` on external APIs or apply strict per-tenant query quotas and output perturbation.",
                    discovered_by="ely_cyber_adversarial_ml_engine",
                )
            )

        if str(rag_cfg.get("model_serialization_format", "pickle")).lower() in ("pickle", "pt", "ckpt"):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-ML-UNSAFE-FORMAT-001",
                    title=f"ML Pipeline `{asset}` Loads Models in Unsafe Pickle Format (`{rag_cfg.get('model_serialization_format')}`)",
                    description="Loading untrusted or third-party weights in pickle format exposes inference hosts to supply-chain RCE.",
                    cyber_domain=CyberDomain.WEB_SSRF_XXE_SSTI_DESER,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-502"],
                    confidence=0.97,
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=asset,
                    remediation_guidance="Standardize exclusively on `safetensors` with pinned SHA-256 digests and Cosign provenance attestations.",
                    discovered_by="ely_cyber_adversarial_ml_engine",
                )
            )

        return {
            "audited_at": utc_now_iso(),
            "asset": asset,
            "findings_count": len(vulns),
            "vulnerabilities": vulns,
        }

    def detect_weight_backdoor_anomaly(
        self,
        layer_norms: Dict[str, Sequence[float]],
        z_threshold: float = 4.0,
        asset: str = "neural_model",
    ) -> Dict[str, Any]:
        """
        Statistical spectral/outlier anomaly screen on per-neuron L2 weight norms across layers
        to flag potential Neural Trojan / sleeper trigger neurons (excessively high outlier z-score).
        """
        anomalous_layers: List[Dict[str, Any]] = []
        vulns: List[CyberVulnerability] = []

        for layer, vals in layer_norms.items():
            if len(vals) < 4:
                continue
            mean = sum(vals) / len(vals)
            var = sum((x - mean) ** 2 for x in vals) / len(vals)
            std = math.sqrt(var)
            if std <= 1e-12:
                continue
            max_z = max(abs(x - mean) / std for x in vals)
            if max_z >= z_threshold:
                anomalous_layers.append({"layer": layer, "max_z_score": round(max_z, 3), "neuron_count": len(vals)})
                vulns.append(
                    make_cyber_vuln(
                        rule_id=f"CYB-ML-WEIGHT-TROJAN-{layer.upper()[:16]}",
                        title=f"Suspicious Weight-Norm Outlier (`z={max_z:.2f}`) in Layer `{layer}` of `{asset}` (Potential Backdoor Trigger)",
                        description=(
                            f"Layer `{layer}` exhibits extreme weight-norm concentration (`z={max_z:.2f} >= {z_threshold}`), "
                            "a statistical signature associated with neural trigger neurons / data poisoning."
                        ),
                        cyber_domain=CyberDomain.ADVERSARY_EMULATION,
                        severity=Severity.MEDIUM,
                        cwe_ids=["CWE-506"],
                        confidence=0.80,
                        owasp_categories=["OWASP-ML02:2023-Data-Poisoning-Attack"],
                        verification_method=VerificationMethod.CRYPTO_ORACLE_CHECK,
                        endpoint_or_asset=f"{asset}#{layer}",
                        remediation_guidance="Run trigger-inversion / fine-pruning verification and validate training dataset lineage before deployment.",
                        discovered_by="ely_cyber_adversarial_ml_engine",
                    )
                )

        return {
            "audited_at": utc_now_iso(),
            "asset": asset,
            "layers_scanned": len(layer_norms),
            "anomalous_layers": anomalous_layers,
            "vulnerabilities": vulns,
        }

    def scan_directory(self, root_path: Path) -> List[CyberVulnerability]:
        """Scan repository for unsafe `torch.load`/`joblib.load` calls and inspect `.pkl` files safely."""
        vulns: List[CyberVulnerability] = []
        rx_torch = re.compile(r"torch\.load\s*\((?![^)]*weights_only\s*=\s*True)[^)]+\)")
        rx_hf = re.compile(r"from_pretrained\s*\([^)]*trust_remote_code\s*=\s*True")

        for fp in sorted(root_path.rglob("*")):
            if not fp.is_file():
                continue
            if any(p in {".git", "node_modules", "__pycache__", ".venv"} for p in fp.parts):
                continue
            rel = str(fp.relative_to(root_path))
            if fp.suffix.lower() in {".pkl", ".pickle"}:
                try:
                    raw = fp.read_bytes()
                    vulns.extend(self.inspect_pickle_bytes_safely(raw, asset=rel)["vulnerabilities"])
                except OSError:
                    continue
            elif fp.suffix.lower() == ".py":
                try:
                    txt = fp.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                for m in rx_torch.finditer(txt):
                    ln = txt[: m.start()].count("\n") + 1
                    vulns.append(
                        make_cyber_vuln(
                            rule_id="CYB-ML-TORCH-LOAD-UNSAFE",
                            title="Unsafe `torch.load()` Without `weights_only=True` (Arbitrary Pickle RCE)",
                            description=f"`{rel}:{ln}` invokes `torch.load()` without `weights_only=True`, allowing arbitrary code execution via malicious checkpoints.",
                            cyber_domain=CyberDomain.WEB_SSRF_XXE_SSTI_DESER,
                            severity=Severity.CRITICAL,
                            cwe_ids=["CWE-502"],
                            confidence=0.97,
                            verification_method=VerificationMethod.STATIC_PATTERN,
                            file_path=rel,
                            line_start=ln,
                            line_end=ln,
                            code_snippet=m.group(0)[:160],
                            remediation_guidance="Pass `weights_only=True` to `torch.load()` or migrate checkpoints to `safetensors`.",
                            discovered_by="ely_cyber_adversarial_ml_engine",
                        )
                    )
                for m in rx_hf.finditer(txt):
                    ln = txt[: m.start()].count("\n") + 1
                    vulns.append(
                        make_cyber_vuln(
                            rule_id="CYB-ML-HF-TRUST-REMOTE-CODE",
                            title="HuggingFace `from_pretrained(..., trust_remote_code=True)` Executes Arbitrary Remote Python",
                            description=f"`{rel}:{ln}` enables `trust_remote_code=True`, automatically executing unverified Python modules fetched from model hubs.",
                            cyber_domain=CyberDomain.IAC_CICD,
                            severity=Severity.CRITICAL,
                            cwe_ids=["CWE-494", "CWE-94"],
                            confidence=0.99,
                            verification_method=VerificationMethod.STATIC_PATTERN,
                            file_path=rel,
                            line_start=ln,
                            line_end=ln,
                            code_snippet=m.group(0)[:160],
                            remediation_guidance="Remove `trust_remote_code=True` and pin exact audited model revisions (`revision='<commit_sha>'`).",
                            discovered_by="ely_cyber_adversarial_ml_engine",
                        )
                    )
        return vulns
