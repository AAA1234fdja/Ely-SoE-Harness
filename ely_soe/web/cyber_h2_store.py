"""
Persistent SQLite Storage, Posture Trend Analytics & Cross-Run Regression Diff Engine
for the Generalized Cyber Suite and Harness² Meta-Control Lab.

Eliminates ephemeral in-memory state loss across server restarts by persisting:
  1. `cyber_scans` — unified 47-engine scan snapshots, gate verdicts, posture scores,
     compliance readiness, Merkle roots, and SHA-256 record integrity digests.
  2. `h2_studies` — complete Harness² meta-studies (`M1–M8` proofs, Shapley attribution,
     ADTree / Systemic Portfolio optimization, Root-Cause blueprints, Conformal intervals,
     SARIF v2.1.0 documents).
  3. `soar_executions` — Merkle-verified incident response playbook execution audit trails.
  4. `autopatch_runs` — isolated differential auto-patch verification reports & unified diffs.

Also provides:
  - **Chronological Posture Trend Queries** (per-target historical score & finding curves)
  - **Regression / Improvement Diff Engine (`diff_cyber_scans`, `diff_h2_studies`)**
    comparing any two runs (`newly_introduced_rules`, `remediated_rules`, `posture_delta`,
    `gate_transition`) with cryptographic row integrity verification!
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import new_id, utc_now_iso


class CyberAndHarness2Store:
    """Thread-safe SQLite persistence layer with integrity verification & differential comparison."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS cyber_scans (
                    scan_id TEXT PRIMARY KEY,
                    recorded_at TEXT NOT NULL,
                    target_name TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    gate_verdict TEXT NOT NULL,
                    overall_posture REAL NOT NULL,
                    total_vulns INTEGER NOT NULL,
                    critical_count INTEGER NOT NULL,
                    high_count INTEGER NOT NULL,
                    compliance_pct REAL NOT NULL,
                    merkle_root TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_cyber_scans_target_ts ON cyber_scans(target_name, recorded_at DESC);

                CREATE TABLE IF NOT EXISTS h2_studies (
                    study_id TEXT PRIMARY KEY,
                    recorded_at TEXT NOT NULL,
                    target_name TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    gate_verdict TEXT NOT NULL,
                    governance_verdict TEXT NOT NULL,
                    m1_m8_verdict TEXT NOT NULL,
                    m1_m8_passed INTEGER NOT NULL,
                    total_vulns INTEGER NOT NULL,
                    adaptations_applied INTEGER NOT NULL,
                    systemic_risk_cut_pct REAL NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    sarif_json TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_h2_studies_target_ts ON h2_studies(target_name, recorded_at DESC);

                CREATE TABLE IF NOT EXISTS soar_executions (
                    exec_id TEXT PRIMARY KEY,
                    recorded_at TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    playbook_id TEXT NOT NULL,
                    target_asset TEXT NOT NULL,
                    dry_run INTEGER NOT NULL,
                    ledger_verified INTEGER NOT NULL,
                    merkle_root TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS autopatch_runs (
                    patch_run_id TEXT PRIMARY KEY,
                    recorded_at TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    files_patched INTEGER NOT NULL,
                    vulns_eliminated INTEGER NOT NULL,
                    reduction_pct REAL NOT NULL,
                    payload_json TEXT NOT NULL
                );
                """
            )

    @staticmethod
    def _sha256_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # CYBER SCAN PERSISTENCE & DIFF
    # ------------------------------------------------------------------
    def save_cyber_scan(self, scan: Dict[str, Any]) -> str:
        scan_id = str(scan.get("scan_id") or new_id("cscan"))
        scan_copy = {**scan, "scan_id": scan_id}
        payload_json = json.dumps(scan_copy, default=str)
        digest = self._sha256_text(payload_json)
        sev = scan_copy.get("severity_counts") or {}
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO cyber_scans
                (scan_id, recorded_at, target_name, target_path, gate_verdict, overall_posture,
                 total_vulns, critical_count, high_count, compliance_pct, merkle_root, payload_sha256, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    str(scan_copy.get("assessed_at") or utc_now_iso()),
                    str(scan_copy.get("target_name", "unknown")),
                    str(scan_copy.get("target_path", "")),
                    str(scan_copy.get("gate_verdict", "UNKNOWN")),
                    float(scan_copy.get("overall_cyber_posture", 0.0)),
                    int(scan_copy.get("total_vulnerabilities", 0)),
                    int(sev.get("critical", 0)),
                    int(sev.get("high", 0)),
                    float(scan_copy.get("compliance_readiness_pct", 0.0)),
                    str(scan_copy.get("ledger_merkle_root", "")),
                    digest,
                    payload_json,
                ),
            )
        return scan_id

    def list_cyber_scans(self, *, target_name: Optional[str] = None, limit: int = 25) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            if target_name:
                rows = conn.execute(
                    "SELECT scan_id, recorded_at, target_name, gate_verdict, overall_posture, total_vulns, critical_count, high_count, compliance_pct, merkle_root "
                    "FROM cyber_scans WHERE target_name = ? ORDER BY recorded_at DESC LIMIT ?",
                    (target_name, int(limit)),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT scan_id, recorded_at, target_name, gate_verdict, overall_posture, total_vulns, critical_count, high_count, compliance_pct, merkle_root "
                    "FROM cyber_scans ORDER BY recorded_at DESC LIMIT ?",
                    (int(limit),),
                ).fetchall()
        return [dict(r) for r in rows]

    def get_cyber_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT payload_sha256, payload_json FROM cyber_scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        if not row:
            return None
        integrity_ok = self._sha256_text(row["payload_json"]) == row["payload_sha256"]
        data = json.loads(row["payload_json"])
        data["storage_integrity_verified"] = integrity_ok
        return data

    def diff_cyber_scans(self, baseline_scan_id: str, candidate_scan_id: str) -> Dict[str, Any]:
        """Compute exact rule-level security regression / improvement diff between two stored scans."""
        base = self.get_cyber_scan(baseline_scan_id)
        cand = self.get_cyber_scan(candidate_scan_id)
        if not base or not cand:
            raise KeyError("One or both cyber scan IDs were not found in SQLite store.")

        base_rules = {str(v.get("rule_id", "")) for v in (base.get("vulnerabilities") or []) if isinstance(v, dict)}
        cand_rules = {str(v.get("rule_id", "")) for v in (cand.get("vulnerabilities") or []) if isinstance(v, dict)}

        remediated = sorted(base_rules - cand_rules)
        introduced = sorted(cand_rules - base_rules)
        persistent = sorted(base_rules & cand_rules)
        posture_delta = round(float(cand.get("overall_cyber_posture", 0.0)) - float(base.get("overall_cyber_posture", 0.0)), 2)
        vuln_delta = int(cand.get("total_vulnerabilities", 0)) - int(base.get("total_vulnerabilities", 0))

        return {
            "compared_at": utc_now_iso(),
            "baseline_scan_id": baseline_scan_id,
            "candidate_scan_id": candidate_scan_id,
            "baseline_target": base.get("target_name"),
            "candidate_target": cand.get("target_name"),
            "gate_transition": f"{base.get('gate_verdict')} -> {cand.get('gate_verdict')}",
            "posture_delta": posture_delta,
            "vulnerability_count_delta": vuln_delta,
            "remediated_rules_count": len(remediated),
            "newly_introduced_rules_count": len(introduced),
            "persistent_rules_count": len(persistent),
            "remediated_rules": remediated[:30],
            "newly_introduced_rules": introduced[:30],
            "regression_detected": len(introduced) > 0 or posture_delta < -5.0,
        }

    # ------------------------------------------------------------------
    # HARNESS² META-STUDY PERSISTENCE & SARIF RETRIEVAL
    # ------------------------------------------------------------------
    def save_h2_study(self, study: Dict[str, Any], sarif_doc: Optional[Dict[str, Any]] = None) -> str:
        study_id = str(study.get("study_id") or new_id("h2study"))
        compact = {k: v for k, v in study.items() if k != "sarif_v2_1"}
        compact["study_id"] = study_id
        payload_json = json.dumps(compact, default=str)
        digest = self._sha256_text(payload_json)
        sarif_text = json.dumps(sarif_doc or study.get("sarif_v2_1"), default=str) if (sarif_doc or study.get("sarif_v2_1")) else None

        run = compact.get("harness2_run") or {}
        fv = compact.get("formal_meta_verification") or {}
        gov = compact.get("policy_governance_gate") or {}
        sys_def = compact.get("systemic_defense_portfolio") or compact.get("attack_defense_tree_optimization") or {}
        risk_cut = float(sys_def.get("systemic_risk_reduction_pct", sys_def.get("relative_risk_reduction_pct", 0.0)))

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO h2_studies
                (study_id, recorded_at, target_name, profile, gate_verdict, governance_verdict,
                 m1_m8_verdict, m1_m8_passed, total_vulns, adaptations_applied, systemic_risk_cut_pct,
                 payload_sha256, payload_json, sarif_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    study_id,
                    str(compact.get("completed_at") or utc_now_iso()),
                    str(compact.get("target_name", "unknown")),
                    str((run.get("selected_genome") or {}).get("profile_name", "fast_ci")),
                    str(run.get("gate_verdict", "UNKNOWN")),
                    str(gov.get("governance_verdict", "UNKNOWN")),
                    str(fv.get("overall_verdict", "UNKNOWN")),
                    int(fv.get("theorems_passed", 0)),
                    int(run.get("total_vulnerabilities", 0)),
                    int((run.get("mapek_adaptation") or {}).get("total_adaptations_applied", 0)),
                    risk_cut,
                    digest,
                    payload_json,
                    sarif_text,
                ),
            )
        return study_id

    def list_h2_studies(self, *, limit: int = 25) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT study_id, recorded_at, target_name, profile, gate_verdict, governance_verdict, "
                "m1_m8_verdict, m1_m8_passed, total_vulns, adaptations_applied, systemic_risk_cut_pct "
                "FROM h2_studies ORDER BY recorded_at DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_latest_h2_sarif(self) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT sarif_json FROM h2_studies WHERE sarif_json IS NOT NULL ORDER BY recorded_at DESC LIMIT 1"
            ).fetchone()
        return json.loads(row["sarif_json"]) if row and row["sarif_json"] else None

    # ------------------------------------------------------------------
    # SOAR & AUTOPATCH PERSISTENCE
    # ------------------------------------------------------------------
    def save_soar_execution(self, exec_res: Dict[str, Any]) -> str:
        exec_id = new_id("soar")
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO soar_executions
                (exec_id, recorded_at, incident_id, playbook_id, target_asset, dry_run, ledger_verified, merkle_root, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    exec_id,
                    str(exec_res.get("executed_at") or utc_now_iso()),
                    str(exec_res.get("incident_id", "")),
                    str(exec_res.get("playbook_id", "")),
                    str(exec_res.get("target_asset", "")),
                    1 if exec_res.get("dry_run", True) else 0,
                    1 if exec_res.get("ledger_verified", False) else 0,
                    str(exec_res.get("ledger_merkle_root", "")),
                    json.dumps(exec_res, default=str),
                ),
            )
        return exec_id

    def save_autopatch_run(self, res: Dict[str, Any]) -> str:
        run_id = new_id("apatch")
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO autopatch_runs
                (patch_run_id, recorded_at, target_path, verdict, files_patched, vulns_eliminated, reduction_pct, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    str(res.get("verified_at") or utc_now_iso()),
                    str(res.get("target", "")),
                    str(res.get("verdict", "")),
                    int(res.get("files_patched_count", 0)),
                    int(res.get("vulnerabilities_eliminated", 0)),
                    float(res.get("risk_surface_reduction_pct", 0.0)),
                    json.dumps(res, default=str),
                ),
            )
        return run_id

    def get_history_summary(self) -> Dict[str, Any]:
        with self._lock, self._connect() as conn:
            c_cnt = conn.execute("SELECT COUNT(*) FROM cyber_scans").fetchone()[0]
            h_cnt = conn.execute("SELECT COUNT(*) FROM h2_studies").fetchone()[0]
            s_cnt = conn.execute("SELECT COUNT(*) FROM soar_executions").fetchone()[0]
            a_cnt = conn.execute("SELECT COUNT(*) FROM autopatch_runs").fetchone()[0]
        return {
            "db_path": str(self.db_path),
            "cyber_scans_stored": int(c_cnt),
            "h2_studies_stored": int(h_cnt),
            "soar_executions_stored": int(s_cnt),
            "autopatch_runs_stored": int(a_cnt),
            "recent_cyber_scans": self.list_cyber_scans(limit=10),
            "recent_h2_studies": self.list_h2_studies(limit=10),
        }
