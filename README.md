# ELY Security Lab & Security Orchestration Engine (SOE) Harness

> **Independent Frontier Agentic Security Evaluation, Continuous Auditing & Pre-Release Maturity Gate for ELY Cowork (`v1.0.0`)**
>
> *Zero third-party runtime dependencies · Pure Python 3.11+ Standard Library · Cryptographically Signed Auditor Plane · 10 Mandatory Security Domains · 9 Ely 1.0 Maturity Criteria · 9 Frontier Research Modules · Full CLI + Web Command Center*

---

## Executive Overview

**Ely-SoE-Harness** is an end-to-end **Security Orchestration Engine (SOE)** and **Independent ELY Security Lab** engineered to verify whether a multi-agent coworking platform (such as **ELY Cowork**, built with a Rust security core, Python agent orchestrators, MCP tool gateways, shared memory stores, and sandboxed skill plugins) meets **Ely 1.0 production security maturity** before release — and continuously thereafter.

The platform is built around three foundational security theses:

1. **Strict Separation of Duties & Cryptographic Non-Repudiation**: Discovery models, static analyzers, and red-team agents may *only* emit `HYPOTHESIS` findings. No discovery actor can confirm its own findings. Only the isolated **Independent Validator / Auditor Plane** — holding an isolated `AuditorKeyring` (HMAC-SHA256 subkeys derived via PBKDF2) and executing dynamic sandbox verification with anti-cheating oracle challenges — can issue a signed `ValidationCertificate` promoting a finding to `CONFIRMED` or rejecting it as `FALSE_POSITIVE`.
2. **Zero Impact on the Main Instance (Isolated Snapshot Lifecycle)**: Every audit snapshots the target repository into an ephemeral workspace, runs `SecretScrubber` to strip sensitive credential files (`.env`, private keys, tokens) and redact inline secrets, executes all static/dynamic/fuzzing/red-team/rogue-agent campaigns inside a scrubbed subprocess sandbox (`SandboxRunner`), cryptographically verifies that the main instance tree SHA-256 is byte-for-byte untouched, and destroys the ephemeral sandbox afterward.
3. **Harness Engineering Multiplies Model Security Effectiveness**: Controlled comparative benchmarking (`ELY-Bench-v1.0`, 16-cell matrix across 4 models × 4 harness profiles over 25 ground-truth vulnerabilities + 10 false-positive decoys) proves empirically that a general-purpose model (**GLM 5.3**) equipped with the `full_soe_harness` achieves **98.04% F1**, **100.00% PoC reproducibility**, **3.85% false discovery rate**, and **96.58 Frontier Index** — outperforming bare specialized frontier cyber models (`frontier-cyber-v2` bare: **62.82 Frontier Index**) by **+33.76 points**.

---

## Measured Verification Results (Live End-to-End Runs)

All metrics below are directly reproduced by the automated test suite (`56/56` passing) and CLI commands (`ely-soe pre-release`, `ely-soe benchmark`, `ely-soe frontier policy-verify`):

### 1. Pre-Release Gate Comparison (`v0.9.0` Vulnerable vs. `v1.0.0-rc1` Hardened)

| Metric | `ely-cowork@0.9.0` (`lab_targets/ely_specimen/v0_9`) | `ely-cowork@1.0.0-rc1` (`lab_targets/ely_specimen/v1_0_hardened`) | Delta / Verdict |
| :--- | :---: | :---: | :---: |
| **Security Posture Score** | `0.00 / 100` | `100.00 / 100` | **`+100.00` (`IMPROVED`)** |
| **Ely 1.0 Maturity Score** | `19.63 / 100` (`1/9` criteria passed) | `100.00 / 100` (`9/9` criteria passed) | **`+80.37`** |
| **Release Gate Decision** | **`BLOCKED`** (CLI exit code `2`) | **`APPROVED`** (CLI exit code `0`) | **Gate Enforced** |
| **Confirmed Vulnerabilities** | `97` (`35` CRIT, `45` HIGH across all 10 domains) | `0` (`0` CRIT, `0` HIGH) | **`-97` confirmed** |
| **False Positives Rejected** | `8` filtered by Independent Validator | `0` | **Zero FP leakage** |
| **Sensitive Files Scrubbed** | `1` (`.env` excluded before sandbox) | `0` | **Zero secret exposure** |
| **Main Instance Untouched** | `True` (SHA-256 pre/post verified) | `True` (SHA-256 pre/post verified) | **100% Isolated** |
| **Sandbox Destroyed Verified** | `True` | `True` | **Zero residue** |
| **Auditor Signature Authentic** | `True` (Merkle + HMAC-SHA256) | `True` (Merkle + HMAC-SHA256) | **Tamper-evident** |

### 2. Formal Capability Policy Verification (`T1`–`T6` State-Space Model Checker)

| Policy Profile | Principals | States Checked | Theorems Proven | Counterexamples | Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Hardened Ely 1.0 CaMeL Policy** | `5` | `116` | **`6 / 6`** (`T1`–`T6`) | `0` | **PROVEN** |
| **Vulnerable v0.9 Policy** | `2` | `15` | `1 / 6` | `7` across `T1, T2, T4, T5, T6` | **DISPROVEN** |

### 3. Comparative Harness Lift Matrix (`ELY-Bench-v1.0` — 16 Cells)

| Model | Harness Profile | F1 Score | False Discovery Rate | Reproducibility | Patch Quality | Frontier Index |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `glm-5.3` | `bare_model` | `74.42%` | `11.11%` | `0.00%` | `65.00%` | `56.90` |
| `frontier-cyber-v2` | `bare_model` | `86.36%` | `0.00%` | `0.00%` | `75.00%` | `62.82` |
| `glm-5.3` | **`full_soe_harness`** | **`98.04%`** | **`3.85%`** | **`100.00%`** | **`92.00%`** | **`96.58`** |

> **Empirical Lift**: Adding `full_soe_harness` to `glm-5.3` produces **`+23.62%` F1 lift** and **`+39.72 pts` Frontier Index lift**, surpassing bare `frontier-cyber-v2` by **`+33.76 pts`**.

---

## System Architecture

```text
+---------------------------------------------------------------------------------------------------+
|                          INTERACTION & AUTOMATION INTERFACES (Layers 8–9)                         |
|   [ Web Command Center (HTTP + Live SVG Attack Graph + 8 Tabs) ]   [ ely-soe CLI (8 Commands) ]   |
+------------------------------------------------+--------------------------------------------------+
                                                 |
                                                 v
+---------------------------------------------------------------------------------------------------+
|                        SECURITY ORCHESTRATION ENGINE — SOE (Layer 5)                              |
|   Modality 1: Scheduled Continuous Audits   |  Modality 2: On-Demand Targeted Audits              |
|   Modality 3: Ely 1.0 Pre-Release Gate      |  Cross-Version Regression Diff & SQLite History     |
|                                                                                                   |
|   8-Stage Atomic Lifecycle:                                                                       |
|   1. Scope Guard & Snapshot -> 2. Attack Surface -> 3. Risk-Ordered Plan -> 4. Static + Frontier  |
|   5. Isolated Sandbox Dynamic Lab -> 6. Independent Validator -> 7. Maturity Gate -> 8. Teardown  |
+-------------------+------------------------------------+------------------------------------------+
                    |                                    |
                    v                                    v
+--------------------------------------------+  +---------------------------------------------------+
|   DISCOVERY & ANALYSIS PLANE (Layers 3,4,7)|  |     INDEPENDENT ELY SECURITY LAB (Layer 2)        |
|   * RepositoryAnalyzer & AttackSurfaceGraph|  |  * SnapshotController + SecretScrubber            |
|   * PythonTaintAnalyzer (AST intra-fn)     |  |  * SandboxRunner (scrubbed env, rlimits, timeout) |
|   * RustCoreSecurityAnalyzer               |  |  * CoverageGuidedFuzzer (invariant oracles)       |
|   * CoreAgenticDomainAnalyzer (D1–D5)      |  |  * RedTeamCampaign (multi-turn adversarial)       |
|   * InfrastructureDomainAnalyzer (D6–D10)  |  |  * AdaptiveRedTeam (iterative encoding bypasses)  |
|   * SupplyChainAuditor (SBOM/CVEs/Skills)  |  |  * UntrustedAgentArena (UA-01..UA-08 rogue agents)|
|   * 9 Frontier Research Modules:           |  |  * BlueTeamRecoveryDrill (containment + rollback) |
|     MCP Auditor · Attack Graph · Policy    |  |  * SecurityMonitor (telemetry & anomaly alerts)   |
|     Verifier · Memory Forensics · Symbolic |  |                                                   |
|     Fuzzer · Differential Patch Verifier · |  |  +---------------------------------------------+  |
|     Threat Intel Mapper · Policy Synth ·   |  |  |   ISOLATED AUDITOR / VALIDATOR PLANE        |  |
|     Purple-Team Replay                     |  |  |   * IndependentAuditor + AuditorKeyring     |  |
|                                            |  |  |   * Oracle Integrity Challenges             |  |
|   [ Emits ONLY FindingStatus.HYPOTHESIS ]  |  |  |   * Signed ValidationCertificates           |  |
+--------------------------------------------+  |  |   * Merkle-Chained ForensicAuditLedger      |  |
                                                |  +---------------------------------------------+  |
                                                +---------------------------------------------------+
                                                 |
                                                 v
+---------------------------------------------------------------------------------------------------+
|                           CRYPTOGRAPHIC & POLICY FOUNDATION (Layer 1)                             |
|  Domain Models (SeparationOfDutiesViolation) · CaMeL Capability Lattice · ScopeManifesto/Guard    |
|  MerkleTree + HMAC-SHA256 ForensicAuditLedger · Weighted Risk Scoring Engine · SOE Config Presets |
+---------------------------------------------------------------------------------------------------+
```

For full formal theorem definitions, threat model boundaries, data-flow invariants, and cryptographic constructions, see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## The 10 Mandatory Security Domains

Every audit plan covers (or filters across) all 10 mandatory security domains defined for multi-agent coworking systems:

| # | Enum Value (`SecurityDomain`) | Domain | Primary Analyzers & Lab Verification |
| :-: | :--- | :--- | :--- |
| 1 | `agent_isolation` | Multi-Agent Isolation & Sandbox Escape | `CoreAgenticDomainAnalyzer`, `UntrustedAgentArena (UA-01..UA-08)`, `FormalPolicyVerifier (T1–T2, T6)` |
| 2 | `tool_execution` | Tool / MCP Execution & Privilege Escalation | `CoreAgenticDomainAnalyzer`, `PythonTaintAnalyzer`, `MCPProtocolAuditor`, `CapabilityPolicyEngine` |
| 3 | `memory` | Shared Memory Security & Anti-Poisoning | `CoreAgenticDomainAnalyzer`, `MemoryForensicsEngine`, `UntrustedAgentArena`, `FormalPolicyVerifier (T3)` |
| 4 | `prompt_injection` | Prompt Injection & Agent Manipulation | `CoreAgenticDomainAnalyzer`, `RedTeamCampaign`, `AdaptiveRedTeam`, `GuardrailDifferentialExplorer` |
| 5 | `api_security` | API, Auth & Input/Output Validation | `CoreAgenticDomainAnalyzer`, `PythonTaintAnalyzer`, `CoverageGuidedFuzzer` |
| 6 | `filesystem` | Filesystem Scoping & Path Traversal | `InfrastructureDomainAnalyzer`, `PythonTaintAnalyzer`, `CoverageGuidedFuzzer`, `ScopeGuard` |
| 7 | `process_management` | Process Execution, Signals & Resource Limits | `InfrastructureDomainAnalyzer`, `SandboxRunner`, `DifferentialPatchVerifier` |
| 8 | `supply_chain` | Supply Chain, SBOM, Dependencies & Skills | `SupplyChainAuditor` (SBOM, CVE lookup, typosquatting, unpinned deps, untrusted skills) |
| 9 | `network` | Network Egress, SSRF & Telemetry Security | `InfrastructureDomainAnalyzer`, `SecurityMonitor`, `LeastPrivilegePolicySynthesizer` |
| 10 | `rust_core` | Rust Security Core (`unsafe`, FFI, Crypto, IPC) | `RustCoreSecurityAnalyzer`, `AttackGraphAnalyzer`, `BlueTeamRecoveryDrill` |

---

## The 9 Ely 1.0 Pre-Release Maturity Criteria

Modality 3 (`ely-soe pre-release`) evaluates the 9 mandatory maturity criteria (L0–L4 maturity rubric) and enforces strict release gating (zero confirmed CRITICAL/HIGH findings + minimum criterion thresholds):

1. **Aislamiento entre agentes** *(Multi-agent isolation & zero cross-agent blast radius)*
2. **Control granular de permisos** *(Least-privilege CaMeL capabilities, zero wildcards, tool/MCP scoping)*
3. **Protección frente a prompt injection** *(Direct, indirect, multi-turn & adaptive obfuscation resilience)*
4. **Validación de entradas y salidas** *(AST taint safety, SQLi/RCE/path traversal/SSRF elimination & fuzz cleanliness)*
5. **Seguridad del sistema de memoria** *(Namespace partitioning, provenance tagging, anti-poisoning & checkpoint rollback)*
6. **Auditoría de dependencias** *(SBOM completeness, lockfile pinning, CVE/typosquat elimination, skill verification)*
7. **Monitoreo, observabilidad y trazabilidad** *(Tamper-evident forensic ledger, structured alerts & Auditor signature validity)*
8. **Pruebas adversariales automatizadas** *(Red-team resilience ≥ 90% and 100% containment of `UA-01`..`UA-08` rogue agents)*
9. **Recuperación ante compromisos** *(Verified Blue-Team compromise containment, quarantine & clean state restoration)*

---

## The 9 Frontier Research Modules (`ely_soe/frontier/`)

| Module | File | Capabilities |
| :--- | :--- | :--- |
| **MCP Protocol Auditor** | `mcp_protocol_auditor.py` | Detects MCP tool description poisoning (hidden prompt instructions), cross-server tool shadowing, overly broad JSON schemas, and rug-pull SHA-256 schema drift against pinned hashes. |
| **Attack Graph & Blast-Radius Engine** | `attack_graph.py` | Builds directed exploit graphs from confirmed findings to crown jewels (`JEWEL:auditor_validation_plane`, etc.), runs Dijkstra max-probability kill-chain discovery, computes rogue-agent blast radius %, and identifies min-cut remediation chokepoints. |
| **Formal Capability Policy Verifier** | `formal_policy_verifier.py` | Exhaustive bounded state-space model checker proving or disproving 6 formal theorems (`T1` Auditor Unreachability, `T2` Workspace Non-Interference, `T3` Memory Non-Interference, `T4` CaMeL Control/Data Non-Interference, `T5` Zero-Wildcard Least Privilege, `T6` Transitive Delegation Non-Amplification) with concrete counterexample traces. |
| **Memory Forensics & Time-Travel** | `memory_forensics.py` | Detects cross-namespace poisoning, instruction injection in episodic/semantic memory, causal taint propagation, automated quarantine, and deterministic rollback to signed clean checkpoints. |
| **Guardrail Differential Explorer** | `symbolic_path_fuzzer.py` | Static + live differential path exploration discovering inconsistent validation boundaries, Unicode/homoglyph/encoding normalization bypasses, and policy-enforcement gaps. |
| **Differential Patch Verifier** | `differential_patch_verifier.py` | Synthesizes candidate remediations, verifies Python AST syntax validity, runs sandboxed before/after differential verification confirming the PoC is neutralized without breaking benign functional invariants. |
| **Threat Intel & Compliance Mapper** | `threat_intel_mapper.py` | Maps findings to MITRE ATLAS, OWASP Top 10 for LLM/Agentic Apps, NIST AI RMF, EU AI Act, and CWE taxonomies, and exports MITRE ATLAS Navigator JSON layers. |
| **Least-Privilege Policy Synthesizer** | `policy_synthesizer.py` | Synthesizes hardened CaMeL `CapabilityPolicyEngine` JSON specifications directly from `AttackSurfaceGraph` + confirmed findings, eliminating discovered wildcard grants and unsafe IPC edges. |
| **Purple-Team Replay Arena** | `purple_team_replay.py` | Executes deterministic comparative attack replays (`v0.9` vulnerable posture vs. `v1.0` hardened posture) across red-team and untrusted-agent suites, producing per-scenario containment matrices and executive scorecards. |

---

## Quick Start

### Requirements

- **Python 3.11+** (zero external runtime dependencies — uses only the Python Standard Library, including `sqlite3`, `http.server`, `ast`, `hmac`, `hashlib`, `unittest`).

### Optional Editable Install

```bash
pip install -e . --no-build-isolation
```

Or run directly from the repository root with `python3 -m ely_soe`:

```bash
python3 -m ely_soe --help
```

### Run the Full End-to-End Demo

Runs Pre-Release Gates on `v0.9` (blocked) and `v1.0` (approved), cross-version diff, Formal Policy Verification, and the 16-cell Comparative Benchmark:

```bash
python3 -m ely_soe demo
```

### CLI Command Reference

| Command | Description |
| :--- | :--- |
| `ely-soe audit <path> [--modality on_demand\|scheduled\|pre_release] [--profile frontier_deep] [--model glm-5.3] [--export-dir out/]` | Execute a full 8-stage isolated security audit and export JSON / Markdown / SARIF 2.1.0 / HTML / ATLAS artifacts. |
| `ely-soe pre-release <path> [--target-version 1.0.0-rc1]` | Run Modality 3 Ely 1.0 Maturity Gate. Exits `0` on `APPROVED`, `2` on `BLOCKED` (CI/CD-ready). |
| `ely-soe compare <run_id_a> <run_id_b>` | Compute cross-version regression & remediation trajectory (`IMPROVED` / `REGRESSED` / `UNCHANGED`). |
| `ely-soe benchmark [--models glm-5.3,frontier-cyber-v2,...]` | Run the 16-cell `ELY-Bench-v1.0` comparative harness lift benchmark and persist results to SQLite. |
| `ely-soe schedule add --name <n> --target <path> --interval <mins>` | Register a Modality 1 continuous scheduled audit policy (`schedule list` / `schedule run` also supported). |
| `ely-soe frontier policy-verify [--mode hardened\|vulnerable]` | Run Formal Policy Verifier (`T1`–`T6`) with counterexample output (also `mcp-audit`, `memory-forensics`, `purple-replay`, `patch-verify`, `synthesize`). |
| `ely-soe demo [--export-dir out/]` | Run the complete end-to-end showcase (`v0.9` blocked + `v1.0` approved + diff + formal proof + 16-cell benchmark). |
| `ely-soe serve [--host 0.0.0.0 --port 8080]` | Launch the live ELY Security Lab & SOE Web Command Center. |

### Ready-to-Run Verification Recipes

```bash
# 1. Pre-Release Gate against vulnerable v0.9 specimen (expected: BLOCKED, exit code 2)
python3 -m ely_soe pre-release ./lab_targets/ely_specimen/v0_9 \
  --target-name ely-cowork --target-version 0.9.0 --profile frontier_deep

# 2. Pre-Release Gate against hardened v1.0-rc1 specimen (expected: APPROVED, exit code 0)
python3 -m ely_soe pre-release ./lab_targets/ely_specimen/v1_0_hardened \
  --target-name ely-cowork --target-version 1.0.0-rc1 --profile frontier_deep \
  --export-dir artifacts/v1_0_release/

# 3. Run Formal Capability Policy Verifier on both hardened (6/6 proven) & vulnerable (7 counterexamples)
python3 -m ely_soe frontier policy-verify --mode hardened
python3 -m ely_soe frontier policy-verify --mode vulnerable

# 4. Run 12-Playbook Purple-Team Replay (v0.9 vs v1.0 resilience comparison)
python3 -m ely_soe frontier purple-replay

# 5. Execute the 16-Cell ELY-Bench v1.0 Comparative Harness Matrix
python3 -m ely_soe benchmark

# 6. Synthesize a formally verified CaMeL + Linux Seccomp + Egress Firewall Defense Bundle
python3 -m ely_soe frontier synthesize --target ./lab_targets/ely_specimen/v0_9
```

---

## Web Command Center (`ely-soe serve`)

Start the live zero-dependency interactive Command Center:

```bash
python3 -m ely_soe serve --host 0.0.0.0 --port 8080
```

### Interactive Views (8 Tabs)

1. **Executive Overview** — Real-time Posture Score, Ely 1.0 Maturity gauge, 10-Domain risk heatmap, audit run history, and one-click `v0.9` vs. `v1.0` quick launches.
2. **Audit Runner & Scope Gate** — Launch Modality 1/2/3 audits across models (`glm-5.3`, `frontier-cyber-v2`, `frontier-reasoner`, `baseline-small`) and profiles (`bare_model`, `static_only`, `harness_no_validator`, `full_soe_harness`, `frontier_deep`), with strict workspace scope enforcement (rejects out-of-scope paths with HTTP `403`).
3. **Findings & Cryptographic Certificates** — Inspect confirmed findings, CWE/OWASP/ATLAS tags, independent `ValidationCertificate` HMAC signatures, and rejected false positives.
4. **Ely 1.0 Maturity Gate** — Live 9-criterion L0–L4 scorecard, blocking criteria explanations, and cross-version diff viewer.
5. **Interactive Attack Graph (SVG)** — Live SVG kill-chain visualizer mapping Entry Points → Agents/Assets → Crown Jewels, rogue-agent blast radius %, and min-cut remediation chokepoints.
6. **Frontier Research Lab** — Run Formal Policy Verifier (`T1`–`T6`), MCP Protocol Auditor, Memory Forensics, Differential Patch Verifier, and Purple-Team Replay directly in the browser.
7. **Benchmark Arena (`ELY-Bench-v1.0`)** — Execute and visualize the 16-cell Model × Harness comparative matrix showing empirical harness lift.
8. **Continuous Scheduler & Exports** — Manage Modality 1 scheduled audit policies and download JSON, Markdown, SARIF 2.1.0, HTML Executive Reports, and MITRE ATLAS Navigator layers.

### Key REST API Endpoints

| Method & Path | Purpose |
| :--- | :--- |
| `GET /api/health` · `GET /api/overview` | Service health, overview dashboard KPIs, registered models, and store statistics |
| `GET /api/runs` · `GET /api/runs/<run_id>` | List historical runs or fetch full signed report + attack graph + maturity scorecard |
| `POST /api/audits/run` | Execute an isolated 8-stage audit (enforces `ScopeGuard` allowlist) |
| `GET /api/compare?baseline=<id>&candidate=<id>` | Cross-version finding & posture regression diff |
| `GET /api/benchmarks` · `POST /api/benchmarks/run` | List or run the 16-cell `ELY-Bench-v1.0` matrix |
| `POST /api/frontier/{policy-verify,mcp-audit,memory-forensics,guardrail-diff,policy-synthesize,purple-replay,patch-verify}` | Execute all Frontier Research Modules on demand |
| `GET /api/schedules` · `POST /api/schedules` · `POST /api/schedules/run-due` | Manage & trigger Modality 1 scheduled audits |
| `GET /api/export/<run_id>/{json,markdown,sarif,html,atlas}` | Download signed audit artifacts in 5 standard formats |
| `POST /api/demo/seed` | Seed demo workspace with `v0.9` + `v1.0` audits and comparative benchmark |

---

## Repository Structure

```text
Ely-SoE-Harness/
├── pyproject.toml                         # Zero-dep Python 3.11+ package manifest (ely-soe CLI)
├── README.md                              # Project documentation & quick-start guide
├── docs/
│   └── ARCHITECTURE.md                    # Formal threat model, theorems T1–T6, crypto & SOE specs
├── ely_soe/
│   ├── __init__.py                        # Package version & metadata
│   ├── __main__.py                        # `python3 -m ely_soe` entry point
│   ├── cli.py                             # 10-subcommand CLI with CI/CD exit codes
│   ├── core/                              # Layer 1: Models, Crypto Ledger, CaMeL Lattice, ScopeGuard, Scoring
│   ├── lab/                               # Layer 2: Snapshot, Sandbox, Monitor, Auditor, Fuzzer, Red/Blue/Rogue Agents
│   ├── analyzers/                         # Layer 3: Repo, AST Taint, Rust Core, 10 Domains, Supply Chain, Tool Registry
│   ├── harness/                           # Layer 4: Model Adapters, Planner, Analyzer, TestGen, Validator, Reporter
│   ├── soe/                               # Layer 5: 8-Stage Lifecycle, Ely 1.0 Maturity Gate, SQLite Store, Scheduler
│   ├── benchmark/                         # Layer 6: ELY-Bench-v1.0 Corpus (25 vulns + 10 decoys), Metrics, Runner
│   ├── frontier/                          # Layer 7: 9 Frontier Security Research Modules
│   └── web/                               # Layer 8: Zero-dep HTTP API Server + Interactive SPA Command Center
├── lab_targets/
│   └── ely_specimen/
│       ├── v0_9/                          # 15-file realistic vulnerable ELY Cowork v0.9 specimen
│       └── v1_0_hardened/                 # 14-file hardened ELY Cowork v1.0-rc1 reference specimen
└── tests/                                 # Layer 10: 8 comprehensive unittest modules (52/52 passing)
```

---

## Testing & Verification

Run the complete 56-test verification suite (covering every layer from cryptographic primitives and formal theorems to live HTTP API endpoints, closed-loop policy synthesis, and CLI end-to-end `demo` execution):

```bash
python3 -m unittest discover -s tests -v
```

| Test Module | Tests | Coverage |
| :--- | :---: | :--- |
| `tests/test_core_foundation.py` | `19` | Separation of Duties, `AuditorKeyring`, `MerkleTree`, `ForensicAuditLedger` tamper detection, `CaMeL` capability lattice, `ScopeGuard`, `SecretScrubber`, `RiskScoringEngine` |
| `tests/test_security_lab.py` | `9` | `SnapshotController` secret stripping & main-instance immutability, `SandboxRunner` isolation, `SecurityMonitor`, `IndependentAuditor` oracle challenges, `CoverageGuidedFuzzer`, `RedTeamCampaign`, `AdaptiveRedTeam`, `BlueTeamRecoveryDrill`, `UntrustedAgentArena (UA-01..UA-08)` |
| `tests/test_analyzers.py` | `6` | `RepositoryAnalyzer`, `PythonTaintAnalyzer`, `RustCoreSecurityAnalyzer`, `CoreAgenticDomainAnalyzer`, `InfrastructureDomainAnalyzer`, `SupplyChainAuditor`, `FrontierToolRegistry` |
| `tests/test_harness_pipeline.py` | `4` | `ModelRegistry`, `AuditPlanner`, `VulnerabilityAnalyzer` (`HYPOTHESIS`-only invariant) + `IndependentValidator` FP filtering, `SecurityReporter` (JSON/Markdown/SARIF/HTML) |
| `tests/test_soe_lifecycle_and_maturity.py` | `2` | Full 8-stage Pre-Release Gate (`v0_9` `BLOCKED` vs. `v1_0_hardened` `APPROVED` + cross-version diff), Modality 1 scheduled + Modality 2 on-demand audits |
| `tests/test_benchmark_suite.py` | `2` | `ElyLabCorpus` 10-domain integrity (25 vulns + 10 decoys), 16-cell comparative harness lift proof & SQLite persistence |
| `tests/test_frontier_modules.py` | `7` | All 9 Frontier Research Modules (`MCPProtocolAuditor`, `AttackGraphAnalyzer`, `FormalPolicyVerifier`, `MemoryForensicsEngine`, `GuardrailDifferentialExplorer`, `DifferentialPatchVerifier`, `ThreatIntelComplianceMapper`, `LeastPrivilegePolicySynthesizer`, `PurpleTeamReplayEngine`) |
| `tests/test_web_and_cli.py` | `3` | Live HTTP server, static SPA, all Frontier API endpoints, `ScopeGuard` `403` enforcement, 5-format artifact exports, CLI `frontier` & `pre-release` exit codes |
| `tests/test_end_to_end_demo_and_governance.py` | `4` | Closed-loop policy synthesis -> formal verification (`T1`–`T6`), Attack Graph UI contract, offline JSONL forensic ledger tamper detection, full `ely-soe demo` run |

---

## Security & Scope Safeguards

- **Strict Target Scoping**: `ScopeGuard` enforces cryptographically signed `ScopeManifesto` boundaries. Attempts to audit outside authorized repository roots (e.g., `/etc`, host filesystem paths, or unauthorized external networks) are blocked immediately (`HTTP 403` / `ScopeViolationError`).
- **Pre-Sandbox Secret Scrubbing**: `.env`, `*.pem`, `*.key`, `id_rsa*`, and inline API tokens/secrets are excluded or redacted from ephemeral audit snapshots before any analyzer, fuzzer, or model adapter touches the tree.
- **Zero Side Effects on Production Code**: Main-instance directory SHA-256 digests are captured pre-audit and verified post-audit; any mismatch raises a tamper alert and invalidates audit attestation.
- **Pure Defensive Evaluation**: All exploits, red-team payloads, and untrusted rogue agent probes execute exclusively inside ephemeral, environment-scrubbed local sandboxes against authorized targets and synthetic lab specimens.
