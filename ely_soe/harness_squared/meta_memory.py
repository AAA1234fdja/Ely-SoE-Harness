"""
Harness² SQLite-Backed Cross-Run Episodic & Semantic Meta-Memory Knowledge Store.

Persists Harness² learning across invocations so the meta-harness genuinely improves
over time on similar repositories and recurring pre-release security gates:
  - **Episodic Run Archive**: target fingerprint 16-dim embeddings, selected `HarnessGenome`,
    observed reward, posture score, TTFC, critical yield, and full JSON summary
  - **Cosine-Similarity Transfer Recall (`find_similar_runs`)**: retrieves top-K nearest
    prior assessments to warm-start strategy priors on new targets
  - **Bandit State Persistence**: stores & reloads `LinUCBGenomeBandit` matrix state and
    `DomainThompsonScheduler` Beta posteriors
  - **Adaptation Rule Efficacy Ledger**: tracks every MAPE-K adaptation rule's empirical
    hit rate (`confirmed_findings_added / times_triggered`), enabling self-pruning of
    low-value adaptation rules over time!
"""

from __future__ import annotations

import json
import math
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import utc_now_iso
from ely_soe.harness_squared.models import HarnessGenome, TargetFingerprint


class MetaMemoryStore:
    """Zero-dependency SQLite episodic & semantic memory store for Harness²."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = Path(db_path) if db_path else None
        self._conn = sqlite3.connect(str(self.db_path) if self.db_path else ":memory:", check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS h2_runs (
                run_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                target_name TEXT NOT NULL,
                archetype TEXT NOT NULL,
                fingerprint_hash TEXT NOT NULL,
                feature_vector_json TEXT NOT NULL,
                genome_arm TEXT NOT NULL,
                genome_json TEXT NOT NULL,
                reward REAL NOT NULL,
                posture_score REAL NOT NULL,
                total_vulns INTEGER NOT NULL,
                critical_vulns INTEGER NOT NULL,
                adaptations_applied INTEGER NOT NULL,
                duration_ms REAL NOT NULL,
                ttfc_ms REAL,
                report_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS h2_rule_efficacy (
                rule_id TEXT PRIMARY KEY,
                times_triggered INTEGER NOT NULL DEFAULT 0,
                times_yielded_findings INTEGER NOT NULL DEFAULT 0,
                total_risk_added REAL NOT NULL DEFAULT 0.0,
                last_updated TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS h2_kv_state (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        self._conn.commit()

    def record_run(
        self,
        *,
        run_id: str,
        fingerprint: TargetFingerprint,
        genome: HarnessGenome,
        reward: float,
        posture_score: float,
        total_vulns: int,
        critical_vulns: int,
        adaptations_applied: int,
        duration_ms: float,
        ttfc_ms: Optional[float],
        report_summary: Dict[str, Any],
    ) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO h2_runs (
                run_id, created_at, target_name, archetype, fingerprint_hash,
                feature_vector_json, genome_arm, genome_json, reward, posture_score,
                total_vulns, critical_vulns, adaptations_applied, duration_ms, ttfc_ms, report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                utc_now_iso(),
                fingerprint.target_name,
                fingerprint.archetype.value,
                fingerprint.fingerprint_hash,
                json.dumps(fingerprint.feature_vector),
                genome.profile_family,
                json.dumps(genome.to_dict()),
                float(reward),
                float(posture_score),
                int(total_vulns),
                int(critical_vulns),
                int(adaptations_applied),
                float(duration_ms),
                float(ttfc_ms) if ttfc_ms is not None else None,
                json.dumps(report_summary, default=str),
            ),
        )
        self._conn.commit()

    def find_similar_runs(
        self,
        feature_vector: Sequence[float],
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """Cosine-similarity k-NN transfer recall over historical target fingerprints."""
        rows = self._conn.execute(
            "SELECT run_id, created_at, target_name, archetype, feature_vector_json, genome_arm, reward, posture_score, total_vulns, critical_vulns, duration_ms FROM h2_runs ORDER BY created_at DESC LIMIT 200"
        ).fetchall()
        scored: List[Tuple[float, Dict[str, Any]]] = []
        for row in rows:
            try:
                vec = json.loads(row["feature_vector_json"])
            except Exception:
                continue
            sim = self._cosine_similarity(feature_vector, vec)
            scored.append(
                (
                    sim,
                    {
                        "run_id": row["run_id"],
                        "created_at": row["created_at"],
                        "target_name": row["target_name"],
                        "archetype": row["archetype"],
                        "similarity": round(sim, 4),
                        "genome_arm": row["genome_arm"],
                        "reward": round(float(row["reward"]), 4),
                        "posture_score": round(float(row["posture_score"]), 2),
                        "total_vulns": int(row["total_vulns"]),
                        "critical_vulns": int(row["critical_vulns"]),
                        "duration_ms": round(float(row["duration_ms"]), 2),
                    },
                )
            )
        scored.sort(key=lambda t: (-t[0], -t[1]["reward"]))
        return [item for _, item in scored[:top_k]]

    def update_rule_efficacy(self, rule_id: str, risk_added: float) -> None:
        row = self._conn.execute(
            "SELECT times_triggered, times_yielded_findings, total_risk_added FROM h2_rule_efficacy WHERE rule_id = ?",
            (rule_id,),
        ).fetchone()
        if row:
            trig = int(row["times_triggered"]) + 1
            hit = int(row["times_yielded_findings"]) + (1 if risk_added > 0 else 0)
            tot = float(row["total_risk_added"]) + max(0.0, float(risk_added))
        else:
            trig = 1
            hit = 1 if risk_added > 0 else 0
            tot = max(0.0, float(risk_added))
        self._conn.execute(
            """
            INSERT OR REPLACE INTO h2_rule_efficacy
            (rule_id, times_triggered, times_yielded_findings, total_risk_added, last_updated)
            VALUES (?, ?, ?, ?, ?)
            """,
            (rule_id, trig, hit, tot, utc_now_iso()),
        )
        self._conn.commit()

    def get_rule_efficacy(self) -> Dict[str, Dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM h2_rule_efficacy ORDER BY total_risk_added DESC").fetchall()
        out: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            trig = max(1, int(r["times_triggered"]))
            out[r["rule_id"]] = {
                "times_triggered": int(r["times_triggered"]),
                "times_yielded_findings": int(r["times_yielded_findings"]),
                "hit_rate": round(int(r["times_yielded_findings"]) / trig, 3),
                "total_risk_added": round(float(r["total_risk_added"]), 2),
                "last_updated": r["last_updated"],
            }
        return out

    def save_kv(self, key: str, value: Any) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO h2_kv_state (key, value_json, updated_at) VALUES (?, ?, ?)",
            (key, json.dumps(value), utc_now_iso()),
        )
        self._conn.commit()

    def load_kv(self, key: str) -> Optional[Any]:
        row = self._conn.execute("SELECT value_json FROM h2_kv_state WHERE key = ?", (key,)).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row["value_json"])
        except Exception:
            return None

    def list_runs(self, limit: int = 25) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT run_id, created_at, target_name, archetype, genome_arm, reward, posture_score, total_vulns, critical_vulns, adaptations_applied, duration_ms, ttfc_ms FROM h2_runs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        row = self._conn.execute("SELECT report_json FROM h2_runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            return None
        return json.loads(row["report_json"])

    def close(self) -> None:
        self._conn.close()

    @staticmethod
    def _cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
        n = min(len(a), len(b))
        if n == 0:
            return 0.0
        dot = sum(float(a[i]) * float(b[i]) for i in range(n))
        na = math.sqrt(sum(float(a[i]) ** 2 for i in range(n)))
        nb = math.sqrt(sum(float(b[i]) ** 2 for i in range(n)))
        if na <= 1e-12 or nb <= 1e-12:
            return 0.0
        return max(0.0, min(1.0, dot / (na * nb)))
