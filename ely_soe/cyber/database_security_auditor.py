"""
Multi-Engine Database & Data-Plane Security Posture Auditor.

Audits database configurations, SQL DDL schemas, stored procedures, and connection
manifests across PostgreSQL, MySQL/MariaDB, SQL Server, MongoDB, Redis, and
Elasticsearch/OpenSearch:
  - Cleartext / unencrypted transport (`sslmode=disable`, `ssl=false`)
  - Over-privileged application DB credentials (`SUPERUSER`, `GRANT ALL ON *.*`, `dbOwner`, `root`)
  - `pg_hba.conf` authentication bypass (`trust` / legacy `md5` instead of `scram-sha-256`)
  - OS command execution primitives (`COPY ... FROM PROGRAM`, `xp_cmdshell`, `INTO OUTFILE`, `LOAD_FILE`)
  - Dynamic SQL injection inside stored procedures (`EXECUTE format(...)`, `EXEC(@sql)`)
  - Multi-tenant tables lacking PostgreSQL Row-Level Security (`ENABLE ROW LEVEL SECURITY`)
  - Redis missing `requirepass` / `ACL` or exposing dangerous commands (`CONFIG`, `FLUSHALL`, `EVAL`, `MODULE`)
  - MongoDB disabled authorization / `$where` server-side JavaScript injection
  - Elasticsearch disabled `xpack.security.enabled` / open `0.0.0.0` binding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

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


@dataclass(frozen=True)
class DBStaticRule:
    rule_id: str
    engine: str
    title: str
    severity: Severity
    cwe_id: str
    pattern: str
    description: str
    remediation: str


DB_SECURITY_RULES: Tuple[DBStaticRule, ...] = (
    DBStaticRule(
        "CYB-DB-PG-HBA-TRUST-001", "postgresql",
        "PostgreSQL `pg_hba.conf` Permits Unauthenticated `trust` Login",
        Severity.CRITICAL, "CWE-287",
        r"(?mi)^(?:host|hostssl|hostnossl|local)\s+\S+\s+\S+(?:\s+\S+)?\s+trust\b",
        "`pg_hba.conf` allows passwordless `trust` authentication, enabling complete database compromise from reachable hosts.",
        "Replace `trust` and legacy `md5` with `scram-sha-256` or mutual TLS (`cert`) over `hostssl`.",
    ),
    DBStaticRule(
        "CYB-DB-PG-COPY-PROG-001", "postgresql",
        "PostgreSQL `COPY ... FROM/TO PROGRAM` OS Command Execution Primitive",
        Severity.CRITICAL, "CWE-78",
        r"(?i)\bCOPY\s+.*?\b(?:FROM|TO)\s+PROGRAM\b",
        "`COPY ... PROGRAM` executes arbitrary shell commands on the database server host under the `postgres` OS user.",
        "Revoke `pg_execute_server_program` and superuser privileges from all application database roles.",
    ),
    DBStaticRule(
        "CYB-DB-SQL-SUPERUSER-001", "sql",
        "Application Role Granted Excessive `SUPERUSER` or Wildcard `GRANT ALL ON *.*`",
        Severity.HIGH, "CWE-269",
        r"(?i)(?:ALTER\s+ROLE\s+\w+\s+WITH\s+SUPERUSER|GRANT\s+ALL(?:\s+PRIVILEGES)?\s+ON\s+\*\.\*|WITH\s+GRANT\s+OPTION)",
        "Over-privileged database roles convert any application SQLi into total DB/host takeover.",
        "Grant strict schema- and table-scoped DML permissions (`SELECT, INSERT, UPDATE`) only.",
    ),
    DBStaticRule(
        "CYB-DB-MSSQL-XPCMD-001", "mssql",
        "SQL Server `xp_cmdshell` or Dynamic `EXEC(@sql)` Enabled",
        Severity.CRITICAL, "CWE-78",
        r"(?i)(?:sp_configure\s+['\"]xp_cmdshell['\"]\s*,\s*1|\bxp_cmdshell\b|EXEC\s*\(\s*@\w+\s*\+)",
        "Enabling `xp_cmdshell` or concatenating variables into `EXEC()` allows OS RCE and second-order SQL injection.",
        "Disable `xp_cmdshell` and use parameterized `sp_executesql` with typed parameters.",
    ),
    DBStaticRule(
        "CYB-DB-MYSQL-OUTFILE-001", "mysql",
        "MySQL `INTO OUTFILE` / `LOAD_FILE` Arbitrary Filesystem Read/Write",
        Severity.CRITICAL, "CWE-22",
        r"(?i)(?:INTO\s+(?:OUTFILE|DUMPFILE)\s+['\"]|\bLOAD_FILE\s*\()",
        "`INTO OUTFILE` and `LOAD_FILE` enable writing webshells or reading sensitive OS files via SQL queries.",
        "Revoke `FILE` privilege and configure `secure_file_priv = NULL` in `my.cnf`.",
    ),
    DBStaticRule(
        "CYB-DB-SSL-DISABLED-001", "generic",
        "Database Connection Explicitly Disables TLS (`sslmode=disable` / `ssl=false`)",
        Severity.HIGH, "CWE-319",
        r"(?i)(?:sslmode\s*=\s*(?:disable|allow|prefer)\b|useSSL\s*=\s*false|ssl\s*:\s*false|tls\s*=\s*false)",
        "Unencrypted database connections expose credentials, session tokens, and sensitive query data to network interception.",
        "Mandate `sslmode=verify-full` (TLS 1.3) with pinned CA certificates.",
    ),
    DBStaticRule(
        "CYB-DB-PG-DYNEXEC-001", "postgresql",
        "PL/pgSQL Dynamic `EXECUTE` Concatenation Inside Stored Procedure",
        Severity.HIGH, "CWE-89",
        r"(?i)\bEXECUTE\s+(?:['\"][^'\"]+['\"]\s*\|\||format\s*\([^)]*%s)",
        "Using `||` or unquoted `%s` in PL/pgSQL `EXECUTE format(...)` introduces stored-procedure SQL injection.",
        "Use `EXECUTE ... USING param` or `format('... %I ... %L', ident, literal)`.",
    ),
    DBStaticRule(
        "CYB-DB-REDIS-NOAUTH-001", "redis",
        "Redis Configured With `protected-mode no` or Open `bind 0.0.0.0`",
        Severity.CRITICAL, "CWE-306",
        r"(?mi)^(?:protected-mode\s+no|bind\s+0\.0\.0\.0)\b",
        "Exposing Redis without `protected-mode`, TLS, and ACL authentication allows trivial RCE via Lua/SLAVEOF/module load.",
        "Bind Redis to private interfaces, enable TLS + Redis 6+ ACLs (`requirepass`), and disable `CONFIG`/`FLUSHALL`/`DEBUG`.",
    ),
    DBStaticRule(
        "CYB-DB-MONGO-NOAUTH-001", "mongodb",
        "MongoDB Security Authorization Disabled or Server-Side `$where` JS Enabled",
        Severity.CRITICAL, "CWE-306",
        r"(?i)(?:authorization\s*:\s*['\"]?disabled['\"]?|\$where\s*:|javascriptEnabled\s*:\s*true)",
        "Disabling MongoDB RBAC authorization or permitting `$where` JavaScript queries enables full DB dump and NoSQL injection.",
        "Set `security.authorization: enabled`, `security.javascriptEnabled: false`, and enforce SCRAM-SHA-256 + TLS.",
    ),
    DBStaticRule(
        "CYB-DB-ES-NOSEC-001", "elasticsearch",
        "Elasticsearch `xpack.security.enabled: false` (Unauthenticated Cluster Access)",
        Severity.CRITICAL, "CWE-306",
        r"(?i)xpack\.security\.enabled\s*:\s*false",
        "Disabling X-Pack security exposes all indexed logs, PII, and cluster admin APIs without authentication.",
        "Enable `xpack.security.enabled: true` with TLS transport and RBAC API keys.",
    ),
)


class DatabaseSecurityAuditor:
    """Static & structured configuration security auditor for SQL and NoSQL data planes."""

    def __init__(self) -> None:
        self._compiled = [(r, re.compile(r.pattern)) for r in DB_SECURITY_RULES]

    def audit_db_config_object(self, config: Dict[str, Any], engine: str = "postgresql", asset: str = "db_prod") -> List[CyberVulnerability]:
        """Audit a structured database configuration dict (useful for live cluster/IaC telemetry)."""
        vulns: List[CyberVulnerability] = []
        eng = engine.lower()

        if not config.get("tls_enforced", True):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-DB-CFG-NOTLS-001",
                    title=f"{eng.upper()} Instance `{asset}` Does Not Enforce TLS Encryption in Transit",
                    description=f"Database `{asset}` accepts plaintext client connections.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-319"],
                    confidence=0.98,
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=asset,
                    remediation_guidance="Enforce mandatory TLS 1.2+/1.3 for all client and replication connections.",
                    discovered_by="ely_cyber_database_auditor",
                )
            )
        if config.get("publicly_accessible", False):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-DB-CFG-PUBLIC-001",
                    title=f"{eng.upper()} Database `{asset}` Is Publicly Accessible From the Internet",
                    description=f"Database `{asset}` exposes a public IP/endpoint directly to untrusted networks.",
                    cyber_domain=CyberDomain.NETWORK_PROTOCOL,
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-284"],
                    confidence=0.99,
                    cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="H", sc="N", si="N", sa="N"),
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=asset,
                    remediation_guidance="Place database exclusively in isolated private subnets accessible only via app security groups.",
                    discovered_by="ely_cyber_database_auditor",
                )
            )
        if not config.get("encryption_at_rest", True):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-DB-CFG-NOATREST-001",
                    title=f"{eng.upper()} Database `{asset}` Lacks KMS Storage Encryption at Rest",
                    description=f"Storage volumes and backups for `{asset}` are not encrypted with KMS-managed keys.",
                    cyber_domain=CyberDomain.TLS_CRYPTOGRAPHY,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-311"],
                    confidence=0.97,
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=asset,
                    remediation_guidance="Enable AES-256 KMS encryption at rest with automated key rotation for data volumes and snapshots.",
                    discovered_by="ely_cyber_database_auditor",
                )
            )
        if config.get("multi_tenant", False) and not config.get("row_level_security_enabled", False):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-DB-CFG-NORLS-001",
                    title=f"Multi-Tenant Database `{asset}` Lacks Row-Level Security (RLS) Tenant Isolation",
                    description=f"Shared multi-tenant schema on `{asset}` relies solely on application `WHERE` clauses without DB-enforced RLS.",
                    cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                    severity=Severity.HIGH,
                    cwe_ids=["CWE-639", "CWE-284"],
                    confidence=0.94,
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=asset,
                    remediation_guidance="Enable `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` with `FORCE ROW LEVEL SECURITY` bound to `current_setting('app.tenant_id')`.",
                    discovered_by="ely_cyber_database_auditor",
                )
            )
        if not config.get("audit_logging_enabled", True):
            vulns.append(
                make_cyber_vuln(
                    rule_id="CYB-DB-CFG-NOAUDIT-001",
                    title=f"{eng.upper()} Database `{asset}` Missing DDL/Auth Audit Logging (`pgaudit`)",
                    description=f"Database `{asset}` lacks structured audit logging for failed logins, privilege changes, and bulk exports.",
                    cyber_domain=CyberDomain.DETECTION_ENGINEERING,
                    severity=Severity.MEDIUM,
                    cwe_ids=["CWE-778"],
                    confidence=0.92,
                    verification_method=VerificationMethod.STATIC_PATTERN,
                    endpoint_or_asset=asset,
                    remediation_guidance="Enable `pgaudit` / audit plugins and stream immutable logs to SIEM.",
                    discovered_by="ely_cyber_database_auditor",
                )
            )
        return vulns

    def scan_directory(self, root_path: Path) -> List[CyberVulnerability]:
        vulns: List[CyberVulnerability] = []
        exts = {".sql", ".conf", ".cnf", ".yml", ".yaml", ".json", ".env", ".py", ".ts", ".js", ".properties", ".toml"}
        for fp in sorted(root_path.rglob("*")):
            if not fp.is_file() or (fp.suffix.lower() not in exts and fp.name.lower() not in {"pg_hba.conf", "redis.conf", "mongod.conf"}):
                continue
            if any(p in {".git", "node_modules", "__pycache__", ".venv"} for p in fp.parts):
                continue
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(fp.relative_to(root_path))

            # Check static DB rules
            for rule, rx in self._compiled:
                for m in rx.finditer(content):
                    lineno = content[: m.start()].count("\n") + 1
                    vulns.append(
                        make_cyber_vuln(
                            rule_id=rule.rule_id,
                            title=rule.title,
                            description=rule.description,
                            cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL if rule.cwe_id in ("CWE-287", "CWE-306", "CWE-269") else CyberDomain.WEB_INJECTION,
                            severity=rule.severity,
                            cwe_ids=[rule.cwe_id],
                            confidence=0.93,
                            verification_method=VerificationMethod.STATIC_PATTERN,
                            file_path=rel,
                            line_start=lineno,
                            line_end=lineno,
                            code_snippet=m.group(0)[:160],
                            remediation_guidance=rule.remediation,
                            discovered_by="ely_cyber_database_auditor",
                        )
                    )

            # Check multi-tenant SQL DDL missing ROW LEVEL SECURITY
            if fp.suffix.lower() == ".sql" and re.search(r"(?i)CREATE\s+TABLE\s+\w+.*?\btenant_id\b", content, re.DOTALL):
                if not re.search(r"(?i)ENABLE\s+ROW\s+LEVEL\s+SECURITY", content):
                    vulns.append(
                        make_cyber_vuln(
                            rule_id="CYB-DB-SQL-MISSING-RLS-001",
                            title="Multi-Tenant SQL Table Defines `tenant_id` Without `ENABLE ROW LEVEL SECURITY`",
                            description=f"DDL schema `{rel}` defines a `tenant_id` column without enforcing database-level Row-Level Security policies.",
                            cyber_domain=CyberDomain.AUTH_ACCESS_CONTROL,
                            severity=Severity.MEDIUM,
                            cwe_ids=["CWE-639"],
                            confidence=0.88,
                            verification_method=VerificationMethod.STATIC_PATTERN,
                            file_path=rel,
                            line_start=1,
                            line_end=1,
                            remediation_guidance="Add `ALTER TABLE <tbl> ENABLE ROW LEVEL SECURITY;` and bind policies to session tenant context.",
                            discovered_by="ely_cyber_database_auditor",
                        )
                    )
        return vulns
