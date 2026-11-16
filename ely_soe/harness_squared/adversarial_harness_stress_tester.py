"""
Harness² Self-Adversarial Evasion & Mutation Stress-Tester ("Red-Teaming the Harness").

Empirically measures how resilient our first-order & second-order security analyzers are
against realistic attacker obfuscation and evasion transforms:
  - Generates isolated temporary adversarial mutant repositories across 8 real-world evasion
    families:
      1. `sql_comment_split` (`SELECT` / f-string query hidden with SQL comments & aliasing)
      2. `indirect_getattr_cmdi` (`getattr(subprocess, 'run')(..., shell=True)` indirection)
      3. `base64_eval_obfuscation` (`exec(base64.b64decode(...))` obfuscated payload execution)
      4. `split_secret_concat` (hardcoded AWS key reconstructed across variables `"AKIA" + ...`)
      5. `ssrf_url_wrapper` (SSRF routed through helper wrapper + dynamic `urllib.request.urlopen`)
      6. `yaml_alias_deser` (`pickle.loads` / `yaml.load` via aliased import `import pickle as pk`)
      7. `k8s_privileged_nested` (Kubernetes manifest using `privileged: true` + `hostPID: true` in multi-doc YAML)
      8. `jwt_alg_none_bypass` (`jwt.decode(..., options={"verify_signature": False})`).
  - Runs the Harness² engine on each mutant, classifies whether the harness **CAUGHT** or
    **MISSED (EVADED)** the mutated vulnerability, computes the **Adversarial Evasion Resilience
    Score (0–100%)**, and outputs exact scanner rule-hardening recommendations for every blind spot!
"""

from __future__ import annotations

import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import utc_now_iso
from ely_soe.harness_squared.meta_orchestrator import HarnessSquaredEngine


@dataclass(frozen=True)
class AdversarialEvasionCase:
    case_id: str
    evasion_family: str
    expected_cwes: Tuple[str, ...]
    filename: str
    baseline_code: str
    evasive_mutated_code: str
    hardening_guidance: str


ADVERSARIAL_EVASION_CORPUS: Tuple[AdversarialEvasionCase, ...] = (
    AdversarialEvasionCase(
        case_id="EVD-01-SQLI-WRAPPER",
        evasion_family="sql_string_concat_evasion",
        expected_cwes=("CWE-89",),
        filename="db_query.py",
        baseline_code=(
            "import sqlite3\n"
            "def get_user(conn, user_id):\n"
            "    return conn.execute(f'SELECT * FROM users WHERE id = {user_id}').fetchall()\n"
        ),
        evasive_mutated_code=(
            "import sqlite3\n"
            "def _build_q(uid):\n"
            "    parts = ['SELECT * /*cmt*/ FROM users WHERE id = ', str(uid)]\n"
            "    return ''.join(parts)\n"
            "def get_user(conn, user_id):\n"
            "    q = _build_q(user_id)\n"
            "    return conn.execute(q).fetchall()\n"
        ),
        hardening_guidance="Track inter-procedural string concatenation & `''.join(...)` taint flowing into `cursor.execute(var)` AST sinks.",
    ),
    AdversarialEvasionCase(
        case_id="EVD-02-CMDI-INDIRECT",
        evasion_family="indirect_getattr_cmdi",
        expected_cwes=("CWE-78",),
        filename="runner.py",
        baseline_code=(
            "import subprocess\n"
            "def ping_host(host):\n"
            "    return subprocess.run(f'ping -c 1 {host}', shell=True)\n"
        ),
        evasive_mutated_code=(
            "import subprocess as sp\n"
            "def ping_host(host):\n"
            "    fn = getattr(sp, 'Po' + 'pen')\n"
            "    return fn('ping -c 1 ' + host, shell=True)\n"
        ),
        hardening_guidance="Flag `getattr` dynamic resolution on `subprocess`/`os` modules plus any call passing `shell=True`.",
    ),
    AdversarialEvasionCase(
        case_id="EVD-03-EXEC-B64",
        evasion_family="base64_eval_obfuscation",
        expected_cwes=("CWE-94", "CWE-95"),
        filename="plugin_loader.py",
        baseline_code=(
            "def run_plugin(code_str):\n"
            "    return eval(code_str)\n"
        ),
        evasive_mutated_code=(
            "import base64\n"
            "def run_plugin(b64_payload):\n"
            "    decoded = base64.b64decode(b64_payload).decode('utf-8')\n"
            "    exec(decoded)\n"
        ),
        hardening_guidance="Detect `base64.b64decode` / `codecs.decode` dataflow entering `exec`/`eval`/`compile` sinks.",
    ),
    AdversarialEvasionCase(
        case_id="EVD-04-SECRET-SPLIT",
        evasion_family="split_secret_concat",
        expected_cwes=("CWE-798",),
        filename="aws_client.py",
        baseline_code=(
            "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
            "AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
        ),
        evasive_mutated_code=(
            "PREFIX = 'AKIA'\n"
            "BODY = 'IOSFODNN7EXAMPLE'\n"
            "AWS_KEY = PREFIX + BODY\n"
            "AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/' + 'bPxRfiCYEXAMPLEKEY'\n"
        ),
        hardening_guidance="Perform AST constant-folding on string concatenations before running regex & Shannon-entropy DLP scanners.",
    ),
    AdversarialEvasionCase(
        case_id="EVD-05-DESER-ALIAS",
        evasion_family="aliased_pickle_deser",
        expected_cwes=("CWE-502",),
        filename="cache_codec.py",
        baseline_code=(
            "import pickle\n"
            "def load_session(blob):\n"
            "    return pickle.loads(blob)\n"
        ),
        evasive_mutated_code=(
            "import pickle as _ser\n"
            "import yaml as _y\n"
            "def load_session(blob, cfg_str):\n"
            "    _y.load(cfg_str, Loader=_y.UnsafeLoader)\n"
            "    return _ser.loads(blob)\n"
        ),
        hardening_guidance="Resolve import aliases (`import pickle as _ser`, `import yaml as _y`) in AST symbol tables before sink matching.",
    ),
    AdversarialEvasionCase(
        case_id="EVD-06-SSRF-WRAPPER",
        evasion_family="ssrf_dynamic_urlopen",
        expected_cwes=("CWE-918",),
        filename="webhook.py",
        baseline_code=(
            "import requests\n"
            "def fetch_hook(url):\n"
            "    return requests.get(url).text\n"
        ),
        evasive_mutated_code=(
            "import urllib.request as ureq\n"
            "def fetch_hook(target_url):\n"
            "    req = ureq.Request(target_url)\n"
            "    return ureq.urlopen(req).read()\n"
        ),
        hardening_guidance="Include `urllib.request.urlopen` / `http.client` / `httpx` alongside `requests` in SSRF taint sinks.",
    ),
    AdversarialEvasionCase(
        case_id="EVD-07-K8S-PRIV",
        evasion_family="k8s_multidoc_privileged",
        expected_cwes=("CWE-250",),
        filename="deploy.yaml",
        baseline_code=(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: app\nspec:\n"
            "  containers:\n  - name: c\n    image: nginx:latest\n    securityContext:\n      privileged: true\n"
        ),
        evasive_mutated_code=(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n---\n"
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: worker\nspec:\n  template:\n    spec:\n"
            "      hostPID: true\n      hostNetwork: true\n      containers:\n      - name: w\n"
            "        image: python:3.11\n        securityContext:\n          privileged: true\n"
        ),
        hardening_guidance="Parse every `---` document inside multi-document Kubernetes YAML files including PodSpec templates.",
    ),
    AdversarialEvasionCase(
        case_id="EVD-08-JWT-VERIFY-FALSE",
        evasion_family="jwt_signature_disabled",
        expected_cwes=("CWE-347", "CWE-287"),
        filename="auth_jwt.py",
        baseline_code=(
            "import jwt\n"
            "def parse_tok(tok):\n"
            "    return jwt.decode(tok, options={'verify_signature': False})\n"
        ),
        evasive_mutated_code=(
            "import jwt as jw\n"
            "OPTS = {'verify_signature': False, 'verify_exp': False}\n"
            "def parse_tok(tok):\n"
            "    return jw.decode(tok, algorithms=['none', 'HS256'], options=OPTS)\n"
        ),
        hardening_guidance="Detect `verify_signature: False` dict literals and `algorithms=['none']` across indirect option variables.",
    ),
)


class AdversarialHarnessStressTester:
    """Self-adversarially mutates vulnerability specimens to measure Harness² evasion resilience."""

    def __init__(self, engine: Optional[HarnessSquaredEngine] = None) -> None:
        self.engine = engine or HarnessSquaredEngine()

    def _run_case_code(self, filename: str, code: str, expected_cwes: Sequence[str]) -> Tuple[bool, List[str], int]:
        with tempfile.TemporaryDirectory(prefix="ely_h2_evd_") as tmp:
            p = Path(tmp) / filename
            p.write_text(code, encoding="utf-8")
            run = self.engine.run_adaptive_assessment(
                target_path=tmp,
                target_name=f"evd_{filename}",
                preferred_profile="fast_ci",
                enable_adaptation=True,
            )
            found_cwes = set()
            for v in run.get("vulnerabilities", []):
                for c in v.get("cwe_ids", []):
                    found_cwes.add(str(c).upper())
            # Match exact expected CWE OR any critical/high finding on the target file
            exact_hit = bool(found_cwes & {c.upper() for c in expected_cwes})
            any_finding_on_file = any(
                filename in str(v.get("file_path", "")) and str(v.get("severity", "")).lower() in ("critical", "high", "medium")
                for v in run.get("vulnerabilities", [])
            )
            caught = exact_hit or any_finding_on_file
            return caught, sorted(found_cwes), int(run.get("total_vulnerabilities", 0))

    def run_evasion_stress_suite(
        self,
        cases: Optional[Sequence[AdversarialEvasionCase]] = None,
    ) -> Dict[str, Any]:
        """Run baseline vs evasive mutant comparison across all adversarial evasion transforms."""
        t0 = time.perf_counter()
        suite = list(cases) if cases is not None else list(ADVERSARIAL_EVASION_CORPUS)
        results: List[Dict[str, Any]] = []
        baseline_caught_cnt = 0
        mutant_caught_cnt = 0
        blind_spots: List[Dict[str, Any]] = []

        for case in suite:
            b_hit, b_cwes, b_tot = self._run_case_code(case.filename, case.baseline_code, case.expected_cwes)
            m_hit, m_cwes, m_tot = self._run_case_code(case.filename, case.evasive_mutated_code, case.expected_cwes)
            if b_hit:
                baseline_caught_cnt += 1
            if m_hit:
                mutant_caught_cnt += 1
            evaded = b_hit and not m_hit
            status = "RESILIENT" if m_hit else ("EVADED_BLIND_SPOT" if evaded else "BASELINE_AND_MUTANT_MISSED")
            if not m_hit:
                blind_spots.append({
                    "case_id": case.case_id,
                    "evasion_family": case.evasion_family,
                    "expected_cwes": list(case.expected_cwes),
                    "hardening_guidance": case.hardening_guidance,
                })
            results.append({
                "case_id": case.case_id,
                "evasion_family": case.evasion_family,
                "expected_cwes": list(case.expected_cwes),
                "baseline_caught": b_hit,
                "mutant_caught": m_hit,
                "status": status,
                "baseline_cwes_found": b_cwes,
                "mutant_cwes_found": m_cwes,
                "mutant_total_findings": m_tot,
            })

        total = max(1, len(suite))
        baseline_rate = round((baseline_caught_cnt / total) * 100.0, 2)
        resilience_rate = round((mutant_caught_cnt / total) * 100.0, 2)
        return {
            "completed_at": utc_now_iso(),
            "duration_ms": round((time.perf_counter() - t0) * 1000.0, 2),
            "cases_evaluated": len(suite),
            "baseline_detection_rate_pct": baseline_rate,
            "evasion_resilience_rate_pct": resilience_rate,
            "blind_spot_count": len(blind_spots),
            "blind_spots": blind_spots,
            "case_results": results,
        }
