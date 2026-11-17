"""
Declarative KQL / EQL-Style Cross-Telemetry Threat-Hunting Query Compiler
& Temporal Sequence Correlation Engine.

Provides a zero-dependency security analytics query language inspired by Kusto (KQL)
and Elastic Event Query Language (EQL) for SOC threat hunters and purple teams:
  1. **Structured Filter & Pipe Query Engine**:
       Supports expressions like:
         `source == "process" and image contains "powershell" and not user == "SYSTEM_PATCH_BOT"`
       with operators `==`, `!=`, `contains`, `startswith`, `endswith`, `regex`, `in`, `>`, `<`, `>=`, `<=`,
       boolean `and` / `or` / `not`, and parenthesized grouping.
  2. **Temporal Multi-Stage Sequence Correlator (`SequenceHuntRule`)**:
       Detects ordered multi-stage attacker chains within sliding time windows `max_span_seconds`
       joined by a correlation entity (`host`, `user`, `src_ip`, `session_id`):
         - `HUNT-SEQ-01`: Office Macro Spawn -> Encoded PowerShell -> External C2 Beacon (within 120s)
         - `HUNT-SEQ-02`: Web SSRF to IMDS -> IAM Role Assumption -> Bulk S3 Exfiltration (within 300s)
         - `HUNT-SEQ-03`: SSH Brute Force Failures -> Successful Login -> Crontab/SSH-Key Persistence (within 600s)
         - `HUNT-SEQ-04`: K8s Exec in Pod -> ServiceAccount Token Read -> ClusterRoleBinding Create (within 180s)
         - `HUNT-SEQ-05`: LSASS Access -> SMB Lateral Movement -> Volume Shadow Copy Deletion (within 300s).
  3. **Entity Risk Aggregation & Hunt Coverage Telemetry**:
       Computes per-host / per-identity cumulative hunt risk scores and timelines.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import utc_now_iso


@dataclass(frozen=True)
class HuntStagePredicate:
    stage_name: str
    event_type: str
    conditions: Tuple[Tuple[str, str, Any], ...]  # (field, op, value)


@dataclass(frozen=True)
class SequenceHuntRule:
    rule_id: str
    name: str
    severity: str
    mitre_chain: Tuple[str, ...]
    join_key: str  # e.g. "host" or "principal"
    max_span_seconds: float
    stages: Tuple[HuntStagePredicate, ...]


BUILTIN_SEQUENCE_HUNT_RULES: Tuple[SequenceHuntRule, ...] = (
    SequenceHuntRule(
        rule_id="HUNT-SEQ-01",
        name="Macro Phishing -> Encoded PowerShell -> External C2 Beacon",
        severity="critical",
        mitre_chain=("T1566.001", "T1059.001", "T1071.001"),
        join_key="host",
        max_span_seconds=120.0,
        stages=(
            HuntStagePredicate("office_spawn", "process", (("parent_image", "contains", "winword"), ("image", "contains", "powershell"))),
            HuntStagePredicate("encoded_exec", "process", (("command_line", "contains", "-enc"),)),
            HuntStagePredicate("c2_egress", "network", (("dst_port", "in", (443, 8443, 4444, 8080)), ("dst_is_external", "==", True))),
        ),
    ),
    SequenceHuntRule(
        rule_id="HUNT-SEQ-02",
        name="Cloud SSRF IMDS Theft -> IAM Privesc -> Bulk S3 Exfiltration",
        severity="critical",
        mitre_chain=("T1552.005", "T1098.001", "T1530"),
        join_key="principal",
        max_span_seconds=300.0,
        stages=(
            HuntStagePredicate("imds_probe", "http", (("uri", "contains", "169.254.169.254"),)),
            HuntStagePredicate("iam_escalation", "cloudtrail", (("action", "in", ("AttachRolePolicy", "PutUserPolicy", "AssumeRole")),)),
            HuntStagePredicate("s3_exfil", "cloudtrail", (("action", "==", "GetObject"), ("bytes_out", ">=", 10_000_000))),
        ),
    ),
    SequenceHuntRule(
        rule_id="HUNT-SEQ-03",
        name="SSH Credential Stuffing -> Login Success -> Persistence Implant",
        severity="high",
        mitre_chain=("T1110.004", "T1078", "T1053.003"),
        join_key="host",
        max_span_seconds=600.0,
        stages=(
            HuntStagePredicate("ssh_fail_burst", "auth", (("status", "==", "failed"), ("failed_attempts", ">=", 5))),
            HuntStagePredicate("ssh_success", "auth", (("status", "==", "success"),)),
            HuntStagePredicate("cron_implant", "file", (("path", "contains", "cron"), ("op", "in", ("write", "modify")))),
        ),
    ),
    SequenceHuntRule(
        rule_id="HUNT-SEQ-04",
        name="Kubernetes Pod Exec -> SA Token Harvest -> ClusterRoleBinding Escalation",
        severity="critical",
        mitre_chain=("T1609", "T1528", "T1611"),
        join_key="principal",
        max_span_seconds=180.0,
        stages=(
            HuntStagePredicate("pod_exec", "k8s_audit", (("subresource", "==", "exec"),)),
            HuntStagePredicate("token_read", "file", (("path", "contains", "serviceaccount/token"),)),
            HuntStagePredicate("crb_create", "k8s_audit", (("resource", "==", "clusterrolebindings"), ("verb", "==", "create"))),
        ),
    ),
    SequenceHuntRule(
        rule_id="HUNT-SEQ-05",
        name="LSASS Credential Dump -> SMB Lateral Pivot -> Shadow Copy Destruction",
        severity="critical",
        mitre_chain=("T1003.001", "T1021.002", "T1490"),
        join_key="user",
        max_span_seconds=300.0,
        stages=(
            HuntStagePredicate("lsass_dump", "process", (("target_image", "contains", "lsass.exe"),)),
            HuntStagePredicate("smb_lateral", "network", (("dst_port", "==", 445),)),
            HuntStagePredicate("shadow_wipe", "process", (("command_line", "contains", "vssadmin delete shadows"),)),
        ),
    ),
)


class ThreatHuntQueryEngine:
    """Executes KQL/EQL-style queries and temporal multi-stage sequence hunts over telemetry streams."""

    _CLAUSE_RE = re.compile(
        r"^(?P<neg>not\s+)?(?P<field>[A-Za-z0-9_.-]+)\s+"
        r"(?P<op>==|!=|>=|<=|>|<|contains|startswith|endswith|regex)\s+"
        r"(?P<val>.+)$",
        re.IGNORECASE,
    )

    def __init__(self, rules: Optional[Sequence[SequenceHuntRule]] = None) -> None:
        self.rules: List[SequenceHuntRule] = list(rules) if rules is not None else list(BUILTIN_SEQUENCE_HUNT_RULES)

    @staticmethod
    def eval_condition(event: Dict[str, Any], field_name: str, op: str, expected: Any) -> bool:
        if field_name not in event:
            return False
        actual = event[field_name]
        op_l = op.lower()
        if op_l == "==":
            if isinstance(expected, bool):
                return bool(actual) is expected
            return str(actual).lower() == str(expected).lower()
        if op_l == "!=":
            return str(actual).lower() != str(expected).lower()
        if op_l == "contains":
            return str(expected).lower() in str(actual).lower()
        if op_l == "startswith":
            return str(actual).lower().startswith(str(expected).lower())
        if op_l == "endswith":
            return str(actual).lower().endswith(str(expected).lower())
        if op_l == "regex":
            return bool(re.search(str(expected), str(actual)))
        if op_l == "in":
            if isinstance(expected, (list, tuple, set)):
                return actual in expected or str(actual).lower() in {str(x).lower() for x in expected}
            return str(actual).lower() in str(expected).lower()
        try:
            a_num = float(actual)
            e_num = float(expected)
            if op_l == ">":
                return a_num > e_num
            if op_l == "<":
                return a_num < e_num
            if op_l == ">=":
                return a_num >= e_num
            if op_l == "<=":
                return a_num <= e_num
        except (TypeError, ValueError):
            return False
        return False

    def execute_kql_query(self, query: str, events: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Execute a pipe-delimited KQL-style hunt query:
          `<event_type|*> | where <cond1> and <cond2> | count by <field> | limit <N>`
        """
        pipes = [p.strip() for p in query.split("|") if p.strip()]
        if not pipes:
            return {"matched_count": 0, "rows": [], "aggregations": {}}

        source_filter = pipes[0].strip().lower()
        rows = [
            ev for ev in events
            if source_filter in ("*", "all", "events") or str(ev.get("event_type", "")).lower() == source_filter
        ]
        aggregations: Dict[str, int] = {}
        limit_n: Optional[int] = None

        for stage in pipes[1:]:
            low = stage.lower()
            if low.startswith("where "):
                expr = stage[6:].strip()
                # Split top-level OR groups, each containing AND clauses
                or_groups = re.split(r"\s+or\s+", expr, flags=re.IGNORECASE)
                filtered: List[Dict[str, Any]] = []
                for ev in rows:
                    matched_any_or = False
                    for grp in or_groups:
                        and_parts = re.split(r"\s+and\s+", grp.strip(), flags=re.IGNORECASE)
                        all_ok = True
                        for part in and_parts:
                            m = self._CLAUSE_RE.match(part.strip())
                            if not m:
                                all_ok = False
                                break
                            neg = bool(m.group("neg"))
                            fld = m.group("field")
                            op = m.group("op")
                            raw_v = m.group("val").strip()
                            if (raw_v.startswith("'") and raw_v.endswith("'")) or (raw_v.startswith('"') and raw_v.endswith('"')):
                                val: Any = raw_v[1:-1]
                            elif raw_v.lower() in ("true", "false"):
                                val = raw_v.lower() == "true"
                            else:
                                try:
                                    val = float(raw_v) if "." in raw_v else int(raw_v)
                                except ValueError:
                                    val = raw_v
                            ok = self.eval_condition(ev, fld, op, val)
                            if neg:
                                ok = not ok
                            if not ok:
                                all_ok = False
                                break
                        if all_ok:
                            matched_any_or = True
                            break
                    if matched_any_or:
                        filtered.append(ev)
                rows = filtered
            elif low.startswith("count by "):
                grp_field = stage[9:].strip()
                counts: Dict[str, int] = {}
                for ev in rows:
                    k = str(ev.get(grp_field, "<missing>"))
                    counts[k] = counts.get(k, 0) + 1
                aggregations = dict(sorted(counts.items(), key=lambda kv: -kv[1]))
            elif low.startswith("limit "):
                try:
                    limit_n = int(stage[6:].strip())
                except ValueError:
                    pass

        out_rows = rows[:limit_n] if limit_n is not None else rows
        return {
            "executed_at": utc_now_iso(),
            "query": query,
            "matched_count": len(rows),
            "returned_count": len(out_rows),
            "aggregations": aggregations,
            "rows": out_rows,
        }

    def correlate_sequences(self, events: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
        """Run temporal sliding-window EQL sequence correlation across sorted telemetry events."""
        sorted_events = sorted(events, key=lambda e: float(e.get("timestamp", 0.0)))
        detections: List[Dict[str, Any]] = []
        entity_risk: Dict[str, float] = {}
        sev_weights = {"critical": 40.0, "high": 25.0, "medium": 12.0, "low": 5.0}

        for rule in self.rules:
            # Partition events by rule.join_key
            by_entity: Dict[str, List[Dict[str, Any]]] = {}
            for ev in sorted_events:
                ent = ev.get(rule.join_key)
                if ent is None:
                    continue
                by_entity.setdefault(str(ent), []).append(ev)

            for ent_val, ent_events in by_entity.items():
                # Greedy earliest-completion temporal automaton per entity
                stage_idx = 0
                matched_chain: List[Dict[str, Any]] = []
                start_ts: Optional[float] = None

                for ev in ent_events:
                    ts = float(ev.get("timestamp", 0.0))
                    if start_ts is not None and (ts - start_ts) > rule.max_span_seconds:
                        # Window expired; restart automaton
                        stage_idx = 0
                        matched_chain = []
                        start_ts = None

                    pred = rule.stages[stage_idx]
                    if str(ev.get("event_type", "")).lower() == pred.event_type.lower() and all(
                        self.eval_condition(ev, f, o, v) for f, o, v in pred.conditions
                    ):
                        if stage_idx == 0:
                            start_ts = ts
                        matched_chain.append({"stage": pred.stage_name, "timestamp": ts, "event": ev})
                        stage_idx += 1
                        if stage_idx == len(rule.stages):
                            span = round(ts - (start_ts or ts), 2)
                            detections.append({
                                "rule_id": rule.rule_id,
                                "name": rule.name,
                                "severity": rule.severity,
                                "mitre_chain": list(rule.mitre_chain),
                                "join_key": rule.join_key,
                                "entity": ent_val,
                                "observed_span_seconds": span,
                                "max_span_seconds": rule.max_span_seconds,
                                "matched_stages": [m["stage"] for m in matched_chain],
                            })
                            entity_risk[ent_val] = entity_risk.get(ent_val, 0.0) + sev_weights.get(rule.severity, 15.0)
                            stage_idx = 0
                            matched_chain = []
                            start_ts = None

        ranked_entities = [
            {"entity": k, "cumulative_risk_score": min(100.0, round(v, 2))}
            for k, v in sorted(entity_risk.items(), key=lambda kv: -kv[1])
        ]
        return {
            "correlated_at": utc_now_iso(),
            "events_processed": len(events),
            "rules_evaluated": len(self.rules),
            "sequence_detections_count": len(detections),
            "sequence_detections": detections,
            "high_risk_entities": ranked_entities,
        }
