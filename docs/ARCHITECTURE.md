# ELY Security Lab & SOE Harness — Architectural Specification

This document specifies the security invariants, threat model, cryptographic protocols, formal verification theorems, and modular data contracts governing **Ely-SoE-Harness (`v1.0.0`)**.

---

## 1. Threat Model & Trust Boundaries

Multi-agent coworking systems (such as **ELY Cowork**) expand the classic application attack surface into an adversarial **multi-principal control plane** where untrusted external text, third-party MCP servers, third-party skill plugins, shared vector/episodic memory, and partially compromised internal agents interact concurrently.

**Ely-SoE-Harness** models four explicit adversary classes:

| Adversary Class | Entry Vector | Goal | Primary Harness Defense / Test |
| :--- | :--- | :--- | :--- |
| **A1 — External Content Adversary** | Web pages, uploaded documents, git diffs, MCP tool descriptions | Indirect prompt injection -> arbitrary tool call, secret exfiltration, or lateral write | `CaMeL` provenance lattice, `RedTeamCampaign`, `AdaptiveRedTeam`, `MCPProtocolAuditor` |
| **A2 — Compromised Internal Agent (`UA-01`..`UA-08`)** | Hijacked researcher, planner, or sandboxed skill agent | Cross-workspace write, memory poisoning, IPC escalation, Auditor oracle tampering | `UntrustedAgentArena`, `FormalPolicyVerifier (T1–T6)`, `MemoryForensicsEngine` |
| **A3 — Supply-Chain / MCP Rug-Pull Actor** | Malicious skill package, typosquatted dependency, mutated MCP schema | Persistent code execution, tool shadowing, silent post-approval behavior change | `SupplyChainAuditor`, `MCPProtocolAuditor` schema pinning |
| **A4 — Dishonest / Hallucinating Security Agent** | Over-eager discovery model or compromised test runner | Inflate false positives, self-confirm unverified findings, fabricate pass verdicts, alter audit logs | `SeparationOfDutiesViolation`, `AuditorKeyring`, Oracle Integrity Challenges, `ForensicAuditLedger` |

### Hard Trust Boundary: Discovery Plane vs. Independent Auditor Plane

```text
  [ Untrusted / Semi-Trusted Discovery Plane ]             [ Trusted Independent Auditor Plane ]
  * Static & AST Taint Analyzers                           * IndependentAuditor (isolated key_id)
  * Rust Core & Supply-Chain Auditors                      * AuditorKeyring (PBKDF2 -> 5 HMAC subkeys)
  * Model Adapters (GLM 5.3, frontier models)              * Oracle Challenge Generator (nonce-bound)
  * Fuzzer, Red Team, Adaptive Red Team                    * IndependentValidator (sandbox PoC replay)
  * Rogue Agent Arena (UA-01..UA-08)                       * ForensicAuditLedger (hash chain + Merkle)
                       |                                                     |
                       | emits Finding(status=HYPOTHESIS)                    | executes isolated repro
                       +---------------------------------------------------->+ verifies oracle challenge
                                                                             | signs ValidationCertificate
                       X  FORBIDDEN: direct status=CONFIRMED                 |
                       X  FORBIDDEN: validator_id == discovered_by           |
                       X  FORBIDDEN: access to AuditorKeyring secrets        v
                                                                 Finding(status=CONFIRMED | FALSE_POSITIVE)
```

---

## 2. Cryptographic Integrity & Non-Repudiation Protocol

Implemented in `ely_soe/core/crypto_ledger.py` and enforced in `ely_soe/core/models.py`:

### 2.1 Domain-Separated Subkey Derivation (`AuditorKeyring`)

From a 256-bit master secret (ephemeral CSPRNG or PBKDF2-HMAC-SHA256 with `100,000` iterations), `AuditorKeyring` derives five cryptographic domain-separated HMAC-SHA256 subkeys:

1. `_ledger_key` (`ely-soe-ledger-hmac-v1`) — authenticates each sequential entry hash in `ForensicAuditLedger`.
2. `_cert_key` (`ely-soe-validation-cert-v1`) — signs `ValidationCertificate` payloads so only the Auditor plane can confirm or reject findings.
3. `_report_key` (`ely-soe-report-seal-v1`) — seals final `SecurityEvaluationReport` digests and Merkle checkpoints.
4. `_maturity_key` (`ely-soe-maturity-attest-v1`) — signs Ely 1.0 Pre-Release Gate attestations.
5. `_scope_key` (`ely-soe-scope-manifest-v1`) — authenticates authorized `ScopeManifesto` boundaries.

### 2.2 Tamper-Evident `ForensicAuditLedger` & Merkle Proofs

Every security lifecycle event is appended as a `LedgerEntry`:

- `entry_hash = SHA256(canonical_json({seq, timestamp, actor, event_type, payload, prev_hash}))`
- `signature = HMAC_SHA256(_ledger_key, entry_hash)`
- `prev_hash` links `seq[i]` strictly to `entry_hash[i-1]` starting from `GENESIS_HASH = "0" * 64`.
- `MerkleTree` computes deterministic binary SHA-256 Merkle roots and generates logarithmic-size inclusion proofs (`inclusion_proof(index)`) verifiable offline.
- Any single-byte mutation to any historical payload, actor, sequence number, or signature invalidates `ledger.verify()` and reports exact `tampered_indices`.

### 2.3 Finding State Machine (`Finding.apply_validation_certificate`)

```text
  HYPOTHESIS ---> VALIDATING ---> CONFIRMED ---------> MITIGATED (after verified patch)
                       |
                       +--------> FALSE_POSITIVE (verdict == NOT_REPRODUCED)
                       |
                       +--------> INCONCLUSIVE   (verdict == INCONCLUSIVE | TAMPER_DETECTED)
```

Invariants enforced at runtime (raising `SeparationOfDutiesViolation` on breach):

1. `Finding.__post_init__` forbids initializing any finding with `status == CONFIRMED` unless accompanied by a signed `ValidationCertificate`.
2. `apply_validation_certificate` rejects certificates where `cert.finding_id != self.finding_id`.
3. `apply_validation_certificate` rejects self-validation where `cert.validator_id == self.discovered_by`.
4. `apply_validation_certificate` rejects missing signatures or signatures failing `AuditorKeyring.verify_certificate`.
5. Promotion to `CONFIRMED` requires BOTH `cert.verdict == ValidationVerdict.REPRODUCED` AND `cert.oracle_integrity_verified == True`.

---

## 3. CaMeL Capability Lattice & Formal Verification Theorems (`T1`–`T6`)

Implemented in `ely_soe/core/capability_lattice.py` and verified exhaustively by `ely_soe/frontier/formal_policy_verifier.py`.

### 3.1 Provenance Trust Lattice

Every data artifact carries an immutable `ProvenanceTag` ordered along a strict 5-level lattice (higher integer = lower trust / higher taint):

```text
  SYSTEM_TRUSTED (0) < USER_VERIFIED (1) < AGENT_INTERNAL (2) < EXTERNAL_UNTRUSTED (3) < ADVERSARIAL_TAINTED (4)
```

When multiple inputs combine, effective provenance strictly takes the **join (`max` taint level)**, preventing tainted external data from laundering itself into trusted control flow (**CaMeL Control/Data Separation**).

### 3.2 Formally Verified Theorems (`FormalPolicyVerifier`)

Given any principal capability policy graph (principals, capability grants, workspace mounts, memory namespaces, IPC channels, and delegation permissions), `FormalPolicyVerifier` exhaustively model-checks six safety theorems:

| ID | Theorem | Formal Property Checked | Counterexample Output |
| :-: | :--- | :--- | :--- |
| **`T1`** | **Auditor Plane Unreachability** | No non-auditor principal directly holds `can_modify_validation`, and no transitive IPC path from any external-facing or untrusted principal reaches a principal capable of modifying validation state. | Exact IPC hop trace `[p_0 -> ... -> p_k]` |
| **`T2`** | **Workspace Non-Interference** | Distinct cross-namespace agent principals cannot share overlapping filesystem mount prefixes where at least one holds write access. | Conflicting `(principal_a, path_a, write)` vs. `(principal_b, path_b, write)` |
| **`T3`** | **Memory Namespace Non-Interference** | Untrusted or isolated principals cannot write into another principal's private memory namespace or global system memory. | Cross-namespace write pair & namespace ID |
| **`T4`** | **CaMeL Control/Data CFI** | No privileged capability (`proc_spawn`, `fs_write`, `net_egress`, `secret_read`, `audit_write`, `policy_edit`) may accept `EXTERNAL_UNTRUSTED` or `ADVERSARIAL_TAINTED` provenance without an explicit `human_approved` gate. | Taint-to-capability execution witness |
| **`T5`** | **Zero-Wildcard Least Privilege** | No principal holds unconstrained wildcard targets (`*`, `/**`, `0.0.0.0/0`, `http://*`) on privileged capabilities. | Exact `(principal, action, wildcard_target)` |
| **`T6`** | **Transitive Delegation Non-Amplification** | No external-facing principal can transitively reach a delegatable high-privilege capability (e.g., `proc_spawn`, `secret_read`, `audit_write`) via IPC/delegation chains. | Full transitive delegation chain trace |

---

## 4. Eight-Stage Atomic SOE Lifecycle (`ely_soe/soe/lifecycle.py`)

Every invocation across Modality 1 (Scheduled), Modality 2 (On-Demand), and Modality 3 (Ely 1.0 Pre-Release Gate) executes the same deterministic 8-stage pipeline:

1. **Stage 1 — Scope Validation & Scrubbed Snapshot**: Verify `ScopeManifesto` signature and target containment; compute pre-audit `main_digest = compute_directory_tree_digest(target_root)`; clone target into an ephemeral directory; run `SecretScrubber` to drop sensitive files (`.env`, private keys) and redact inline secrets.
2. **Stage 2 — Attack Surface Mapping**: `RepositoryAnalyzer` builds `AttackSurfaceGraph` (languages, files, LOC, trust boundaries, entry points, permission matrix, dependency count).
3. **Stage 3 — Risk-Ordered Audit Planning**: `AuditPlanner` builds an `AuditPlan` prioritized by attack-surface density and SQLite historical hotspot domains (`AuditHistoryStore.historical_hotspot_domains()`).
4. **Stage 4 — Multi-Engine Static + Frontier Analysis**: Executes `PythonTaintAnalyzer`, `RustCoreSecurityAnalyzer`, `CoreAgenticDomainAnalyzer`, `InfrastructureDomainAnalyzer`, `SupplyChainAuditor`, `MCPProtocolAuditor`, and `GuardrailDifferentialExplorer`. All outputs are constrained to `FindingStatus.HYPOTHESIS`.
5. **Stage 5 — Isolated Dynamic Security Lab**: Runs `CoverageGuidedFuzzer`, `RedTeamCampaign`, `AdaptiveRedTeam`, `UntrustedAgentArena (UA-01..UA-08)`, and `BlueTeamRecoveryDrill` against snapshot-derived targets inside environment-scrubbed sandboxes, streaming telemetry into `SecurityMonitor`.
6. **Stage 6 — Independent Validation & Remediation Verification**: `IndependentValidator` verifies hypotheses in clean sandboxes, challenges oracle integrity via `IndependentAuditor`, issues signed `ValidationCertificate`s (eliminating false positives), and generates/verifies remediation proposals via `DifferentialPatchVerifier`.
7. **Stage 7 — Graph Risk, Compliance Mapping & Ely 1.0 Maturity Gate**: Executes `AttackGraphAnalyzer` (Dijkstra kill chains + chokepoints), `ThreatIntelComplianceMapper` (ATLAS/OWASP/NIST/EU AI Act), `RiskScoringEngine`, and `ElyMaturityEvaluator` (9 criteria, L0–L4, release decision).
8. **Stage 8 — Forensic Sealing, Teardown & Main-Instance Verification**: Seals report digest and Merkle ledger via `AuditorKeyring`, destroys ephemeral sandbox directory (`sandbox_destroyed_verified=True`), recomputes `post_digest = compute_directory_tree_digest(target_root)` confirming `pre_digest == post_digest` (`main_instance_untouched_verified=True`), persists run to SQLite, and writes requested exports (JSON, Markdown, SARIF 2.1.0, HTML, ATLAS).

---

## 5. Benchmark Methodology (`ELY-Bench-v1.0`)

Implemented in `ely_soe/benchmark/{corpus,metrics,runner}.py`:

- **Corpus (`ElyLabCorpus`)**: 35 labeled test items spanning all 10 security domains — **25 ground-truth vulnerabilities** (spanning Critical, High, Medium across Rust, Python, MCP, memory, supply chain, and multi-agent IPC) plus **10 realistic benign decoys** (safe parameterized queries, safe `shell=False` subprocesses, validated canonical paths, pinned dependencies) designed to punish noisy scanners.
- **Comparative Matrix (`4 × 4 = 16` cells)**:
  - **Models**: `glm-5.3`, `frontier-cyber-v2`, `frontier-reasoner`, `baseline-small`
  - **Harness Profiles**: `bare_model`, `static_only`, `harness_no_validator`, `full_soe_harness`
- **Composite Metric (`Frontier Security Index`, 0–100)**:

  $$\text{Frontier Index} = 0.35 \cdot F_1 + 0.20 \cdot (1 - \text{FDR}) + 0.25 \cdot \text{ReproRate} + 0.20 \cdot \text{PatchQuality}$$

  This rewards models and harnesses that simultaneously maximize recall/precision, minimize analyst-wasting false discoveries, cryptographically prove exploitability in sandboxes, and verify clean non-regressing patches.

---

## 6. Operational Security Guidelines

1. **Production Key Management**: Pass a dedicated passphrase or KMS-provisioned key to `AuditorKeyring.from_passphrase(...)` when running CI/CD release gates so `verify-ledger` and report signatures can be independently verified offline by release governance teams.
2. **CI/CD Pre-Release Enforcement**: Invoke `python3 -m ely_soe pre-release <repo_path> --export-dir artifacts/` in release pipelines. Treat exit code `2` as a hard merge/release block until all CRITICAL/HIGH findings are remediated and all 9 maturity criteria pass.
3. **Network Binding & Sandbox Hygiene**: When launching the Web Command Center (`ely-soe serve --host 0.0.0.0 --port 8080`), always restrict `allowed_roots` to authorized repository directories so `ScopeGuard` enforces strict workspace containment on every API request.
