"""
SQLite Historical Audit Store & Cross-Version Security Evolution Engine.

Persists every SOE evaluation run, finding, validation certificate, maturity
assessment, benchmark experiment, and scheduled audit policy — enabling:
  - Longitudinal tracking of Ely's security posture across releases (`v0.9` -> `v1.0-rc1`)
  - Exact fingerprint-level diffing between any two runs or versions:
      * Newly introduced vulnerabilities
      * Fixed / resolved vulnerabilities
      * Persistent unmitigated vulnerabilities
      * Regressed vulnerabilities (reappeared after being fixed!)
  - Domain-by-domain posture delta & Maturity Level trajectory
  - Historical hotspot detection fed back into `AuditPlanner`
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ely_soe.core.models import (
    BenchmarkExperimentResult,
    Finding,
    FindingStatus,
    SecurityDomain,
    SecurityEvaluationReport,
    utc_now_iso,
)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS audit_runs (
    run_id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL,
    target_name TEXT NOT NULL,
    target_version TEXT NOT NULL,
    modality TEXT NOT NULL,
    model_id TEXT NOT NULL,
    harness_profile TEXT NOT NULL,
    snapshot_digest TEXT NOT NULL,
    posture_score REAL NOT NULL,
    maturity_verdict TEXT NOT NULL,
    maturity_score REAL NOT NULL,
    confirmed_count INTEGER NOT NULL,
    false_positive_count INTEGER NOT NULL,
    critical_count INTEGER NOT NULL,
    high_count INTEGER NOT NULL,
    sandbox_destroyed INTEGER NOT NULL,
    main_untouched INTEGER NOT NULL,
    ledger_merkle_root TEXT NOT NULL,
    report_signature TEXT NOT NULL,
    report_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    target_version TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    domain TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_start INTEGER NOT NULL,
    cvss_score REAL NOT NULL,
    agentic_risk_score REAL NOT NULL,
    finding_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES audit_runs(run_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_runs_version ON audit_runs(target_name, target_version, created_at);

CREATE TABLE IF NOT EXISTS benchmark_experiments (
    experiment_id TEXT PRIMARY KEY,
    corpus_version TEXT NOT NULL,
    total_ground_truth INTEGER NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scheduled_policies (
    schedule_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    target_path TEXT NOT NULL,
    target_name TEXT NOT NULL,
    interval_minutes INTEGER NOT NULL,
    modality TEXT NOT NULL,
    model_id TEXT NOT NULL,
    harness_profile TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_run_at TEXT,
    next_run_at TEXT,
    policy_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


class AuditHistoryStore:
    """SQLite persistence layer and cross-version security evolution analyzer."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA_SQL)

    def save_report(self, report: SecurityEvaluationReport) -> None:
        stats = report.summary_stats()
        report_json = json.dumps(report.to_dict())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO audit_runs (
                    run_id, report_id, target_name, target_version, modality, model_id,
                    harness_profile, snapshot_digest, posture_score, maturity_verdict,
                    maturity_score, confirmed_count, false_positive_count, critical_count,
                    high_count, sandbox_destroyed, main_untouched, ledger_merkle_root,
                    report_signature, report_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.run_id,
                    report.report_id,
                    report.target_name,
                    report.target_version,
                    report.modality.value,
                    report.model_id,
                    report.harness_profile,
                    report.snapshot_digest,
                    float(stats["security_posture_score"]),
                    str(stats["maturity_verdict"]),
                    float(stats["maturity_score"]),
                    int(stats["confirmed_count"]),
                    int(stats["false_positive_count"]),
                    int(stats["confirmed_by_severity"]["critical"]),
                    int(stats["confirmed_by_severity"]["high"]),
                    1 if report.sandbox_destroyed_verified else 0,
                    1 if report.main_instance_untouched_verified else 0,
                    report.ledger_merkle_root,
                    report.report_signature,
                    report_json,
                    report.created_at,
                ),
            )
            for f in report.findings:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO findings (
                        finding_id, run_id, target_version, fingerprint, domain, severity,
                        status, rule_id, title, file_path, line_start, cvss_score,
                        agentic_risk_score, finding_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f.finding_id,
                        report.run_id,
                        report.target_version,
                        f.fingerprint,
                        f.domain.value,
                        f.severity.value,
                        f.status.value,
                        f.rule_id,
                        f.title,
                        f.location.file_path,
                        f.location.line_start,
                        f.cvss_score,
                        f.agentic_risk_score,
                        json.dumps(f.to_dict()),
                        f.created_at,
                    ),
                )

    def list_runs(self, limit: int = 50, target_name: Optional[str] = None) -> List[Dict[str, Any]]:
        query = (
            "SELECT run_id, report_id, target_name, target_version, modality, model_id, "
            "harness_profile, posture_score, maturity_verdict, maturity_score, confirmed_count, "
            "false_positive_count, critical_count, high_count, sandbox_destroyed, main_untouched, "
            "ledger_merkle_root, created_at FROM audit_runs "
        )
        params: List[Any] = []
        if target_name:
            query += "WHERE target_name = ? "
            params.append(target_name)
        query += "ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_report_dict(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT report_json FROM audit_runs WHERE run_id = ?", (run_id,)).fetchone()
        if not row:
            return None
        return json.loads(row["report_json"])

    def get_latest_run_for_version(self, target_version: str, target_name: Optional[str] = None) -> Optional[Dict[str, Any]]:
        query = "SELECT report_json FROM audit_runs WHERE target_version = ? "
        params: List[Any] = [target_version]
        if target_name:
            query += "AND target_name = ? "
            params.append(target_name)
        query += "ORDER BY created_at DESC LIMIT 1"
        with self._connect() as conn:
            row = conn.execute(query, params).fetchone()
        if not row:
            return None
        return json.loads(row["report_json"])

    def historical_hotspot_domains(self, target_name: Optional[str] = None, limit_runs: int = 5) -> Set[SecurityDomain]:
        """Identify domains with repeated confirmed Critical/High findings in recent runs."""
        runs = self.list_runs(limit=limit_runs, target_name=target_name)
        if not runs:
            return set()
        run_ids = [r["run_id"] for r in runs]
        placeholders = ",".join("?" for _ in run_ids)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT domain, COUNT(*) AS cnt FROM findings WHERE run_id IN ({placeholders}) "
                "AND status = 'confirmed' AND severity IN ('critical', 'high') GROUP BY domain",
                run_ids,
            ).fetchall()
        hotspots: Set[SecurityDomain] = set()
        for r in rows:
            if int(r["cnt"]) >= 1:
                try:
                    hotspots.add(SecurityDomain(r["domain"]))
                except ValueError:
                    pass
        return hotspots

    def compare_versions(self, baseline_version: str, candidate_version: str) -> Dict[str, Any]:
        """
        Compare security evolution between two Ely versions (`baseline_version` -> `candidate_version`).
        Returns newly introduced, fixed, persistent, and regressed vulnerabilities plus posture deltas.
        """
        base = self.get_latest_run_for_version(baseline_version)
        cand = self.get_latest_run_for_version(candidate_version)
        if base is None or cand is None:
            raise ValueError(
                f"Cannot compare versions: baseline({baseline_version}) found={base is not None}, "
                f"candidate({candidate_version}) found={cand is not None}"
            )
        return self.compare_report_dicts(base, cand)

    def compare_runs(self, baseline_run_id: str, candidate_run_id: str) -> Dict[str, Any]:
        base = self.get_report_dict(baseline_run_id)
        cand = self.get_report_dict(candidate_run_id)
        if base is None or cand is None:
            raise ValueError(f"Missing run(s): baseline={baseline_run_id}, candidate={candidate_run_id}")
        return self.compare_report_dicts(base, cand)

    @staticmethod
    def compare_report_dicts(base: Dict[str, Any], cand: Dict[str, Any]) -> Dict[str, Any]:
        base_confirmed = {
            f["fingerprint"]: f
            for f in base.get("findings", [])
            if f.get("status") in (FindingStatus.CONFIRMED.value, FindingStatus.REGRESSED.value)
        }
        cand_confirmed = {
            f["fingerprint"]: f
            for f in cand.get("findings", [])
            if f.get("status") in (FindingStatus.CONFIRMED.value, FindingStatus.REGRESSED.value)
        }

        base_fps = set(base_confirmed)
        cand_fps = set(cand_confirmed)

        fixed_fps = sorted(base_fps - cand_fps)
        new_fps = sorted(cand_fps - base_fps)
        persistent_fps = sorted(base_fps & cand_fps)

        base_sum = base.get("summary", {})
        cand_sum = cand.get("summary", {})

        posture_delta = round(
            float(cand_sum.get("security_posture_score", 0.0)) - float(base_sum.get("security_posture_score", 0.0)), 2
        )
        maturity_delta = round(
            float(cand_sum.get("maturity_score", 0.0)) - float(base_sum.get("maturity_score", 0.0)), 2
        )

        domain_deltas: Dict[str, Dict[str, int]] = {}
        b_dom = base_sum.get("confirmed_by_domain", {})
        c_dom = cand_sum.get("confirmed_by_domain", {})
        for d in SecurityDomain:
            bv = int(b_dom.get(d.value, 0))
            cv = int(c_dom.get(d.value, 0))
            domain_deltas[d.value] = {"baseline": bv, "candidate": cv, "delta": cv - bv}

        trajectory = (
            "IMPROVED"
            if (posture_delta > 0 and len(new_fps) == 0)
            else ("REGRESSED" if (posture_delta < 0 or len(new_fps) > len(fixed_fps)) else "STABLE")
        )

        return {
            "baseline": {
                "run_id": base.get("run_id"),
                "version": base.get("target_version"),
                "posture_score": base_sum.get("security_posture_score", 0.0),
                "maturity_score": base_sum.get("maturity_score", 0.0),
                "maturity_verdict": base_sum.get("maturity_verdict"),
                "confirmed_count": len(base_confirmed),
            },
            "candidate": {
                "run_id": cand.get("run_id"),
                "version": cand.get("target_version"),
                "posture_score": cand_sum.get("security_posture_score", 0.0),
                "maturity_score": cand_sum.get("maturity_score", 0.0),
                "maturity_verdict": cand_sum.get("maturity_verdict"),
                "confirmed_count": len(cand_confirmed),
            },
            "trajectory": trajectory,
            "posture_delta": posture_delta,
            "maturity_delta": maturity_delta,
            "fixed_count": len(fixed_fps),
            "newly_introduced_count": len(new_fps),
            "persistent_count": len(persistent_fps),
            "fixed_findings": [
                {"fingerprint": fp, "title": base_confirmed[fp]["title"], "severity": base_confirmed[fp]["severity"], "domain": base_confirmed[fp]["domain"]}
                for fp in fixed_fps
            ],
            "newly_introduced_findings": [
                {"fingerprint": fp, "title": cand_confirmed[fp]["title"], "severity": cand_confirmed[fp]["severity"], "domain": cand_confirmed[fp]["domain"]}
                for fp in new_fps
            ],
            "persistent_findings": [
                {"fingerprint": fp, "title": cand_confirmed[fp]["title"], "severity": cand_confirmed[fp]["severity"], "domain": cand_confirmed[fp]["domain"]}
                for fp in persistent_fps
            ],
            "domain_deltas": domain_deltas,
            "compared_at": utc_now_iso(),
        }

    def save_benchmark_experiment(self, result: BenchmarkExperimentResult) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO benchmark_experiments (
                    experiment_id, corpus_version, total_ground_truth, result_json, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    result.experiment_id,
                    result.corpus_version,
                    result.total_ground_truth_vulns,
                    json.dumps(result.to_dict()),
                    result.created_at,
                ),
            )

    def list_benchmarks(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT experiment_id, corpus_version, total_ground_truth, result_json, created_at "
                "FROM benchmark_experiments ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            data = json.loads(r["result_json"])
            out.append(data)
        return out

    def upsert_schedule(
        self,
        schedule_id: str,
        name: str,
        target_path: str,
        target_name: str,
        interval_minutes: int,
        modality: str,
        model_id: str,
        harness_profile: str,
        enabled: bool,
        last_run_at: Optional[str],
        next_run_at: Optional[str],
        policy_dict: Dict[str, Any],
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scheduled_policies (
                    schedule_id, name, target_path, target_name, interval_minutes,
                    modality, model_id, harness_profile, enabled, last_run_at,
                    next_run_at, policy_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    schedule_id,
                    name,
                    target_path,
                    target_name,
                    interval_minutes,
                    modality,
                    model_id,
                    harness_profile,
                    1 if enabled else 0,
                    last_run_at,
                    next_run_at,
                    json.dumps(policy_dict),
                    utc_now_iso(),
                ),
            )

    def list_schedules(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM scheduled_policies ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]
