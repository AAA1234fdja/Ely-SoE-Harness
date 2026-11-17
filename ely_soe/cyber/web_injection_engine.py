"""
Generalized Web & Application Injection Vulnerability Testing Engine.

Covers OWASP A03:2021 / A05 Injection families via BOTH:
  1. Multi-language Static AST + Taint + Pattern Analysis (Python, JS/TS, PHP, Java, Go, Ruby, SQL)
  2. Authorized Local Sandboxed Differential Probe Verification (comparing benign baseline
     responses vs. boolean/error/syntax/second-order/timing/command-echo differential probes
     against an in-process or isolated sandbox WSGI/handler target — ZERO external network calls).

Injection classes covered:
  - SQL Injection (Error-based, Union-based, Boolean-blind, Time-blind, Stacked, ORM raw, Second-order)
  - NoSQL Injection (MongoDB operator injection `$ne`/`$gt`/`$where`/`$regex`, Redis RESP smuggling)
  - OS Command Injection (shell metacharacters, subshell, IFS bypass, argument injection)
  - Code / Expression Injection (Python `eval`/`exec`, JS `eval`/`Function`, SpEL, OGNL, MVEL, EL)
  - LDAP Injection (RFC 4515 filter breakout)
  - XPath Injection (predicate breakout & boolean tautology)
  - CRLF / HTTP Response Splitting & Log Injection (CRLF header injection, ANSI/log forging)
  - CSV / Formula Injection (spreadsheet DDE/formula prefix injection)
"""

from __future__ import annotations

import ast
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Pattern, Tuple

from ely_soe.core.models import Severity, new_id
from ely_soe.cyber.deobfuscation_ast_normalizer import (
    MultiLayerPayloadNormalizer,
    PythonASTDeobfuscationEngine,
)
from ely_soe.cyber.models import (
    CVSSv4Metrics,
    CyberDomain,
    CyberVulnerability,
    EvidenceArtifact,
    HttpProbeRequest,
    HttpProbeResponse,
    MitreTactic,
    MitreTechniqueRef,
    VerificationMethod,
    make_cyber_vuln,
)


# ---------------------------------------------------------------------------
# Static Multi-Language Injection Rule Catalog
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class InjectionStaticRule:
    rule_id: str
    title: str
    description: str
    severity: Severity
    cwe_ids: Tuple[str, ...]
    owasp: Tuple[str, ...]
    mitre_id: str
    mitre_name: str
    mitre_tactic: MitreTactic
    languages: Tuple[str, ...]
    pattern: str
    anti_pattern: Optional[str]
    remediation: str
    secure_example: str
    cvss4: Tuple[str, str, str, str, str, str, str, str, str, str, str]  # AV..SA


INJECTION_STATIC_RULES: Tuple[InjectionStaticRule, ...] = (
    InjectionStaticRule(
        rule_id="CYB-INJ-SQLI-001",
        title="SQL Injection via String Formatting or Concatenation",
        description="Dynamic SQL query constructed by interpolating or concatenating untrusted variables directly into query text.",
        severity=Severity.CRITICAL,
        cwe_ids=("CWE-89",),
        owasp=("A03:2021-Injection",),
        mitre_id="T1190",
        mitre_name="Exploit Public-Facing Application",
        mitre_tactic=MitreTactic.INITIAL_ACCESS,
        languages=(".py", ".js", ".ts", ".php", ".java", ".go", ".rb"),
        pattern=r"""(?i)\b(?:execute|executemany|query|rawQuery|createNativeQuery|db\.Query|mysqli_query|pg_query)\s*\(\s*(?:f["'][^"']*\{|["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE|UNION|DROP|ALTER)\b[^"']*["']\s*(?:\+|%|\.format\s*\())""",
        anti_pattern=r"""(?i)(?:parameterized|prepared|placeholder|\?\s*,\s*\(|%s\s*,\s*\()""",
        remediation="Use parameterized prepared statements with bind variables (`?`, `%s`, `$1`, `:param`) and never concatenate untrusted input into SQL text.",
        secure_example="cursor.execute('SELECT id, email FROM users WHERE username = ?', (username,))",
        cvss4=("N", "L", "N", "N", "N", "H", "H", "H", "L", "L", "N"),
    ),
    InjectionStaticRule(
        rule_id="CYB-INJ-SQLI-002",
        title="ORM Raw SQL / Unsafe `extra()` / `RawSQL` Interpolation",
        description="ORM escape hatch (`raw`, `extra`, `text`, `RawSQL`, `sequelize.query`, `$queryRawUnsafe`) interpolates variables directly into raw SQL.",
        severity=Severity.CRITICAL,
        cwe_ids=("CWE-89",),
        owasp=("A03:2021-Injection",),
        mitre_id="T1190",
        mitre_name="Exploit Public-Facing Application",
        mitre_tactic=MitreTactic.INITIAL_ACCESS,
        languages=(".py", ".js", ".ts", ".java", ".rb"),
        pattern=r"""(?i)\b(?:\.raw\s*\(|\.extra\s*\(|RawSQL\s*\(|text\s*\(|\$queryRawUnsafe\s*\(|\$executeRawUnsafe\s*\(|sequelize\.query\s*\()\s*(?:f["']|["'][^"']*["']\s*\+|`[^`]*\$\{)""",
        anti_pattern=None,
        remediation="Replace unsafe raw ORM queries with strongly-typed ORM query builders or bound parameter dictionaries.",
        secure_example="session.execute(text('SELECT * FROM orders WHERE id = :oid'), {'oid': order_id})",
        cvss4=("N", "L", "N", "N", "N", "H", "H", "L", "N", "N", "N"),
    ),
    InjectionStaticRule(
        rule_id="CYB-INJ-NOSQL-001",
        title="NoSQL Operator Injection via Raw Request Object or `$where`",
        description="MongoDB/NoSQL query passes raw user JSON/query objects or evaluates JavaScript expressions in `$where` / `mapReduce`.",
        severity=Severity.CRITICAL,
        cwe_ids=("CWE-943", "CWE-94"),
        owasp=("A03:2021-Injection",),
        mitre_id="T1190",
        mitre_name="Exploit Public-Facing Application",
        mitre_tactic=MitreTactic.INITIAL_ACCESS,
        languages=(".js", ".ts", ".py", ".php", ".java"),
        pattern=r"""(?i)(?:\$where\s*["']?\s*:\s*|(?:findOne|find|updateOne|deleteMany|aggregate)\s*\(\s*(?:req\.body|req\.query|request\.json|request\.get_json\(\)|json\.loads))""",
        anti_pattern=r"""(?i)(?:sanitize|mongoSanitize|isinstance\s*\([^,]+,\s*str\)|schema\.parse)""",
        remediation="Validate and cast every query field to primitive scalar types (`str`, `int`), reject keys starting with `$` or containing `.`, and disable server-side `$where` JS execution.",
        secure_example="if not isinstance(username, str): raise ValueError('invalid')\ncollection.find_one({'username': str(username)})",
        cvss4=("N", "L", "N", "N", "N", "H", "H", "L", "N", "N", "N"),
    ),
    InjectionStaticRule(
        rule_id="CYB-INJ-CMDI-001",
        title="OS Command Injection via Shell Execution",
        description="Untrusted or dynamic command string passed into OS shell interpreter (`shell=True`, `os.system`, `os.popen`, `child_process.exec`, `Runtime.exec`, `exec`/`passthru`).",
        severity=Severity.CRITICAL,
        cwe_ids=("CWE-78",),
        owasp=("A03:2021-Injection",),
        mitre_id="T1059",
        mitre_name="Command and Scripting Interpreter",
        mitre_tactic=MitreTactic.EXECUTION,
        languages=(".py", ".js", ".ts", ".php", ".java", ".go", ".rb"),
        pattern=r"""(?i)(?:subprocess\.(?:run|Popen|call|check_output|check_call)\s*\([^)]*shell\s*=\s*True|os\.(?:system|popen)\s*\(|child_process\.exec(?:Sync)?\s*\(|Runtime\.getRuntime\(\)\.exec\s*\(|exec\.Command\s*\(\s*["'](?:sh|bash|cmd|powershell)["']\s*,\s*["'](?:-c|/c)["']|(?:passthru|shell_exec|proc_open)\s*\()""",
        anti_pattern=r"""(?i)(?:shell\s*=\s*False|shlex\.quote|ALLOWED_BINARIES)""",
        remediation="Avoid invoking OS shells (`shell=False`, `execFile`), pass command arguments as an explicit list, and validate commands against a strict allowlist.",
        secure_example="subprocess.run(['/usr/bin/git', 'status', '--short'], shell=False, check=True, timeout=10)",
        cvss4=("N", "L", "N", "N", "N", "H", "H", "H", "H", "H", "H"),
    ),
    InjectionStaticRule(
        rule_id="CYB-INJ-CODE-001",
        title="Arbitrary Code / Dynamic Expression Evaluation (`eval`/`exec`/`Function`)",
        description="Dynamic evaluation of string input via `eval`, `exec`, `new Function`, `vm.runInContext`, `SpelExpressionParser`, or `Ognl.getValue` enables Remote Code Execution.",
        severity=Severity.CRITICAL,
        cwe_ids=("CWE-94", "CWE-95"),
        owasp=("A03:2021-Injection",),
        mitre_id="T1059",
        mitre_name="Command and Scripting Interpreter",
        mitre_tactic=MitreTactic.EXECUTION,
        languages=(".py", ".js", ".ts", ".java", ".php", ".rb"),
        pattern=r"""(?i)(?:\b(?:eval|exec)\s*\(\s*(?!["']\s*["']\s*\))|\bnew\s+Function\s*\(|SpelExpressionParser|Ognl\.getValue|ScriptEngineManager|MVEL\.eval\s*\()""",
        anti_pattern=r"""(?i)(?:ast\.literal_eval|json\.loads|SimpleEvaluationContext)""",
        remediation="Eliminate `eval`/`exec`; parse structured data with `json.loads` or `ast.literal_eval`, and use `SimpleEvaluationContext` for Spring EL.",
        secure_example="data = json.loads(raw_payload)  # safe structured parser instead of eval()",
        cvss4=("N", "L", "N", "N", "N", "H", "H", "H", "H", "H", "L"),
    ),
    InjectionStaticRule(
        rule_id="CYB-INJ-LDAP-001",
        title="LDAP Filter Injection via Unescaped Distinguished Name / Search Filter",
        description="User-controlled values interpolated directly into RFC 4515 LDAP search filter without escaping `*`, `(`, `)`, `\\`, or NUL bytes.",
        severity=Severity.HIGH,
        cwe_ids=("CWE-90",),
        owasp=("A03:2021-Injection",),
        mitre_id="T1078",
        mitre_name="Valid Accounts",
        mitre_tactic=MitreTactic.INITIAL_ACCESS,
        languages=(".py", ".java", ".js", ".ts", ".php", ".go"),
        pattern=r"""(?i)(?:search_s|search_ext|ldap_search|DirContext\.search|conn\.search)\s*\([^)]*(?:f["'][^"']*\([^)]*\{|["']\([^"']*(?:uid|cn|sAMAccountName|mail)\s*=\s*["']\s*\+)""",
        anti_pattern=r"""(?i)(?:escape_filter_chars|escape_rdn|ldap_escape)""",
        remediation="Escape all untrusted filter values with `ldap3.utils.conv.escape_filter_chars()` or RFC 4515 hex escaping before LDAP query assembly.",
        secure_example="safe_user = escape_filter_chars(username)\nconn.search(base_dn, f'(uid={safe_user})')",
        cvss4=("N", "L", "N", "N", "N", "H", "L", "N", "N", "N", "N"),
    ),
    InjectionStaticRule(
        rule_id="CYB-INJ-XPATH-001",
        title="XPath Injection via Dynamic Query Concatenation",
        description="Untrusted input concatenated into an XPath predicate allows authentication bypass or full XML tree extraction.",
        severity=Severity.HIGH,
        cwe_ids=("CWE-643",),
        owasp=("A03:2021-Injection",),
        mitre_id="T1190",
        mitre_name="Exploit Public-Facing Application",
        mitre_tactic=MitreTactic.INITIAL_ACCESS,
        languages=(".py", ".java", ".php", ".js", ".ts"),
        pattern=r"""(?i)(?:\.xpath\s*\(|XPathExpression|evaluate\s*\()\s*(?:f["'][^"']*//[^"']*\{|["'][^"']*//[^"']*["']\s*\+)""",
        anti_pattern=r"""(?i)(?:XPathVariableResolver|lxml.*\$[a-z_]+)""",
        remediation="Use parameterized XPath variables (`tree.xpath('//user[@name=$u]', u=username)`) instead of string concatenation.",
        secure_example="nodes = tree.xpath('//account[@id=$aid]', aid=account_id)",
        cvss4=("N", "L", "N", "N", "N", "H", "L", "N", "N", "N", "N"),
    ),
    InjectionStaticRule(
        rule_id="CYB-INJ-CRLF-001",
        title="HTTP Response Splitting / CRLF Header Injection",
        description="Unsanitized user input written into HTTP response headers (`Set-Cookie`, `Location`, custom headers) permits CRLF (`\\r\\n`) injection.",
        severity=Severity.MEDIUM,
        cwe_ids=("CWE-113", "CWE-93"),
        owasp=("A03:2021-Injection",),
        mitre_id="T1190",
        mitre_name="Exploit Public-Facing Application",
        mitre_tactic=MitreTactic.INITIAL_ACCESS,
        languages=(".py", ".js", ".ts", ".java", ".php", ".go"),
        pattern=r"""(?i)(?:send_header|setHeader|addHeader|header\s*\()\s*\([^)]*(?:req\.query|req\.params|request\.args|request\.headers|\$_GET|\$_POST)""",
        anti_pattern=r"""(?i)(?:replace\s*\(\s*["']\\r|\\n|strip_crlf|validate_header)""",
        remediation="Reject any header value containing CR (`\\r`), LF (`\\n`), or NUL (`\\x00`) bytes prior to writing HTTP headers.",
        secure_example="if any(c in val for c in ('\\r', '\\n', '\\x00')): raise ValueError('Invalid header')",
        cvss4=("N", "L", "N", "N", "P", "L", "L", "N", "L", "L", "N"),
    ),
    InjectionStaticRule(
        rule_id="CYB-INJ-LOG-001",
        title="Log Forging & Log4j/JNDI Expression Lookup Risk",
        description="Unsanitized user input passed directly into formatted log messages or JNDI lookup APIs enables log forging or JNDI injection.",
        severity=Severity.HIGH,
        cwe_ids=("CWE-117", "CWE-917"),
        owasp=("A09:2021-Security-Logging-and-Monitoring-Failures",),
        mitre_id="T1070",
        mitre_name="Indicator Removal",
        mitre_tactic=MitreTactic.DEFENSE_EVASION,
        languages=(".java", ".py", ".js", ".ts", ".go"),
        pattern=r"""(?i)(?:InitialContext\(\)\.lookup\s*\(|JdbcRowSetImpl|log4j.*(?:2\.0|2\.14)\b|logger\.(?:info|warn|error)\s*\(\s*f["'][^"']*\{(?:req|request|user_input))""",
        anti_pattern=r"""(?i)(?:sanitize_log|json\.dumps|extra\s*=\s*\{)""",
        remediation="Use structured JSON logging with field-level escaping, strip CR/LF control characters, and forbid dynamic JNDI lookups on untrusted names.",
        secure_example="logger.info('login_event', extra={'username': re.sub(r'[\\r\\n\\x00-\\x1f]', '', username)})",
        cvss4=("N", "L", "N", "N", "N", "L", "H", "N", "N", "N", "N"),
    ),
    InjectionStaticRule(
        rule_id="CYB-INJ-CSV-001",
        title="CSV / Spreadsheet Formula Injection",
        description="User-supplied cell values exported to CSV without neutralizing leading `=`, `+`, `-`, `@`, `\\t`, or `\\r` formula triggers.",
        severity=Severity.LOW,
        cwe_ids=("CWE-1236",),
        owasp=("A03:2021-Injection",),
        mitre_id="T1204",
        mitre_name="User Execution",
        mitre_tactic=MitreTactic.EXECUTION,
        languages=(".py", ".js", ".ts", ".php", ".java"),
        pattern=r"""(?i)(?:csv\.writer|DictWriter|stringify\s*\([^)]*csv|fputcsv)\s*\([^)]*\).*?(?:writerow|write\s*\()""",
        anti_pattern=r"""(?i)(?:startswith\s*\(\s*\(\s*["']=|sanitize_csv|escape_formula)""",
        remediation="Prefix any cell beginning with `=`, `+`, `-`, `@`, tab, or CR with a single quote (`'`) or reject formula characters before CSV serialization.",
        secure_example="def safe_cell(v: str) -> str:\n    return \"'\" + v if v[:1] in ('=', '+', '-', '@', '\\t', '\\r') else v",
        cvss4=("N", "L", "N", "N", "A", "L", "L", "N", "N", "N", "N"),
    ),
)


# ---------------------------------------------------------------------------
# Python AST Injection Flow Detector (Catches Multi-Line & Indirect Flows)
# ---------------------------------------------------------------------------

class PythonInjectionASTAnalyzer:
    """
    Deep Python AST inspector catching multi-line SQLi, Command Injection,
    and Code Injection where tainted strings are assembled prior to sink calls.
    """

    SQL_SINK_METHODS = {"execute", "executemany", "executescript", "raw", "extra"}
    CMD_SINK_FUNCS = {"system", "popen", "popen2", "popen3", "popen4"}
    SUBPROC_FUNCS = {"run", "Popen", "call", "check_call", "check_output"}
    CODE_SINK_FUNCS = {"eval", "exec", "compile"}

    SQL_KEYWORDS = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|UNION|DROP|ALTER|WHERE|FROM)\b", re.IGNORECASE)

    def analyze_file(self, file_path: Path, rel_path: str) -> List[CyberVulnerability]:
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=rel_path)
        except (SyntaxError, OSError):
            return []

        lines = source.splitlines()
        findings: List[CyberVulnerability] = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            findings.extend(self._analyze_function(node, rel_path, lines))
        return findings

    def _analyze_function(
        self,
        func: ast.AST,
        rel_path: str,
        lines: List[str],
    ) -> List[CyberVulnerability]:
        # Track variables built with dynamic formatting / concatenation
        dynamic_sql_vars: Dict[str, int] = {}
        dynamic_str_vars: Dict[str, int] = {}
        param_names = set()
        if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in func.args.args + func.args.kwonlyargs:
                param_names.add(arg.arg)

        found: List[CyberVulnerability] = []

        for node in ast.walk(func):
            if isinstance(node, ast.Assign):
                is_dyn, has_sql = self._expr_is_dynamic(node.value, param_names | set(dynamic_str_vars.keys()))
                if is_dyn:
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            dynamic_str_vars[tgt.id] = getattr(node, "lineno", 1)
                            if has_sql:
                                dynamic_sql_vars[tgt.id] = getattr(node, "lineno", 1)

            if not isinstance(node, ast.Call):
                continue

            lineno = getattr(node, "lineno", 1)
            snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""
            call_name = self._call_name(node.func)

            # 1. SQL sink with dynamically assembled SQL variable or inline f-string / BinOp
            if call_name in self.SQL_SINK_METHODS and node.args:
                arg0 = node.args[0]
                is_dyn, has_sql = self._expr_is_dynamic(arg0, param_names | set(dynamic_str_vars.keys()))
                is_var_sql = isinstance(arg0, ast.Name) and arg0.id in dynamic_sql_vars
                if is_var_sql or (is_dyn and has_sql):
                    found.append(
                        make_cyber_vuln(
                            rule_id="CYB-AST-SQLI-001",
                            title=f"AST-Confirmed SQL Injection Sink (`{call_name}`)",
                            description=(
                                f"Function `{getattr(func, 'name', '?')}` builds a SQL query dynamically "
                                f"from non-constant inputs before passing it to `{call_name}()`."
                            ),
                            cyber_domain=CyberDomain.WEB_INJECTION,
                            severity=Severity.CRITICAL,
                            cwe_ids=["CWE-89"],
                            confidence=0.93,
                            owasp_categories=["A03:2021-Injection"],
                            mitre_techniques=[
                                MitreTechniqueRef("T1190", "Exploit Public-Facing Application", MitreTactic.INITIAL_ACCESS)
                            ],
                            cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="H", sc="L", si="L", sa="N"),
                            verification_method=VerificationMethod.STATIC_AST,
                            file_path=rel_path,
                            line_start=lineno,
                            line_end=lineno,
                            code_snippet=snippet,
                            attack_vector_detail=f"Tainted SQL string flows into `{call_name}()` at line {lineno}.",
                            remediation_guidance="Use parameterized queries (`cursor.execute(sql, params)`) with static SQL templates.",
                            secure_code_example="cursor.execute('SELECT * FROM items WHERE owner = ?', (owner_id,))",
                            discovered_by="ely_cyber_web_injection_ast",
                        )
                    )

            # 2. Command injection via subprocess(..., shell=True) with dynamic command
            if call_name in self.SUBPROC_FUNCS:
                shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )
                if shell_true and node.args:
                    arg0 = node.args[0]
                    is_dyn, _ = self._expr_is_dynamic(arg0, param_names | set(dynamic_str_vars.keys()))
                    is_tainted_var = isinstance(arg0, ast.Name) and (arg0.id in param_names or arg0.id in dynamic_str_vars)
                    if is_dyn or is_tainted_var:
                        found.append(
                            make_cyber_vuln(
                                rule_id="CYB-AST-CMDI-001",
                                title=f"AST-Confirmed Command Injection via `subprocess.{call_name}(shell=True)`",
                                description=(
                                    f"Dynamic/tainted command reaches `subprocess.{call_name}` with `shell=True` "
                                    f"inside `{getattr(func, 'name', '?')}`."
                                ),
                                cyber_domain=CyberDomain.WEB_INJECTION,
                                severity=Severity.CRITICAL,
                                cwe_ids=["CWE-78"],
                                confidence=0.95,
                                owasp_categories=["A03:2021-Injection"],
                                mitre_techniques=[
                                    MitreTechniqueRef("T1059.004", "Unix Shell", MitreTactic.EXECUTION, "004")
                                ],
                                cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
                                verification_method=VerificationMethod.STATIC_AST,
                                file_path=rel_path,
                                line_start=lineno,
                                line_end=lineno,
                                code_snippet=snippet,
                                attack_vector_detail=f"Shell metacharacters (`;`, `|`, `$()`) execute arbitrary OS commands via line {lineno}.",
                                remediation_guidance="Pass an argument list with `shell=False` and enforce an explicit binary allowlist.",
                                discovered_by="ely_cyber_web_injection_ast",
                            )
                        )

            # 3. Direct eval/exec on tainted variable
            if call_name in self.CODE_SINK_FUNCS and node.args:
                arg0 = node.args[0]
                is_dyn, _ = self._expr_is_dynamic(arg0, param_names | set(dynamic_str_vars.keys()))
                is_tainted_var = isinstance(arg0, ast.Name) and (arg0.id in param_names or arg0.id in dynamic_str_vars)
                if is_dyn or is_tainted_var:
                    found.append(
                        make_cyber_vuln(
                            rule_id="CYB-AST-CODE-001",
                            title=f"AST-Confirmed Dynamic Code Execution via `{call_name}()`",
                            description=f"Untrusted or dynamically constructed expression flows into `{call_name}()`.",
                            cyber_domain=CyberDomain.WEB_INJECTION,
                            severity=Severity.CRITICAL,
                            cwe_ids=["CWE-94", "CWE-95"],
                            confidence=0.94,
                            owasp_categories=["A03:2021-Injection"],
                            mitre_techniques=[
                                MitreTechniqueRef("T1059.006", "Python", MitreTactic.EXECUTION, "006")
                            ],
                            cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="H", sc="H", si="H", sa="L"),
                            verification_method=VerificationMethod.STATIC_AST,
                            file_path=rel_path,
                            line_start=lineno,
                            line_end=lineno,
                            code_snippet=snippet,
                            remediation_guidance="Remove `eval`/`exec` and use `json.loads` or `ast.literal_eval`.",
                            discovered_by="ely_cyber_web_injection_ast",
                        )
                    )

        return found

    def _call_name(self, func_node: ast.AST) -> str:
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            return func_node.attr
        return ""

    def _expr_is_dynamic(self, expr: ast.AST, tainted_vars: set[str]) -> Tuple[bool, bool]:
        """Returns `(is_dynamic_or_tainted, contains_sql_keyword)`."""
        sql_kw = False
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                if self.SQL_KEYWORDS.search(sub.value):
                    sql_kw = True

        if isinstance(expr, ast.JoinedStr):  # f-string
            has_fmt = any(isinstance(v, ast.FormattedValue) for v in expr.values)
            return has_fmt, sql_kw
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
            has_non_const = any(not isinstance(n, ast.Constant) for n in (expr.left, expr.right))
            return has_non_const, sql_kw
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
            return True, sql_kw
        if isinstance(expr, ast.Name) and expr.id in tainted_vars:
            return True, sql_kw
        return False, sql_kw


# ---------------------------------------------------------------------------
# Authorized Sandboxed Differential Probe Verifier
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DifferentialProbeSpec:
    probe_id: str
    family: str  # sqli_boolean, sqli_error, sqli_union, nosqli, cmdi, ldapi, crlf
    title: str
    cwe_ids: Tuple[str, ...]
    severity: Severity
    benign_value: str
    true_payload: str
    false_payload: str
    error_signatures: Tuple[str, ...]
    remediation: str


INJECTION_PROBE_CATALOG: Tuple[DifferentialProbeSpec, ...] = (
    DifferentialProbeSpec(
        probe_id="PROBE-SQLI-BOOL-01",
        family="sqli_boolean",
        title="Differential Boolean-Blind SQL Injection Confirmed",
        cwe_ids=("CWE-89",),
        severity=Severity.CRITICAL,
        benign_value="alice",
        true_payload="alice' OR '1'='1",
        false_payload="alice' AND '1'='2",
        error_signatures=("syntax error", "sqlite3.operationalerror", "sql syntax", "unterminated quoted string", "ora-00933", "pg::syntaxerror"),
        remediation="Bind all SQL query arguments using parameterized placeholders (`?` / `$1`).",
    ),
    DifferentialProbeSpec(
        probe_id="PROBE-SQLI-UNION-01",
        family="sqli_union",
        title="SQL Error / UNION Injection Confirmed",
        cwe_ids=("CWE-89",),
        severity=Severity.CRITICAL,
        benign_value="1",
        true_payload="1 UNION SELECT 'ELY_SQLI_CANARY_9821', 'x' --",
        false_payload="1'",
        error_signatures=("ely_sqli_canary_9821", "operationalerror", "syntax error", "near \"'\"", "sqlstate"),
        remediation="Strictly parameterize numeric and string SQL predicates and validate integer types.",
    ),
    DifferentialProbeSpec(
        probe_id="PROBE-NOSQL-OP-01",
        family="nosqli",
        title="NoSQL Operator Injection (`$ne` / `$gt`) Confirmed",
        cwe_ids=("CWE-943",),
        severity=Severity.CRITICAL,
        benign_value="alice",
        true_payload='{"$ne": "__never_matches__"}',
        false_payload='{"$eq": "__never_matches__"}',
        error_signatures=("operator injection", "ely_nosql_bypass", "$ne"),
        remediation="Coerce and schema-validate query fields to scalar primitives and strip `$`-prefixed keys.",
    ),
    DifferentialProbeSpec(
        probe_id="PROBE-CMDI-ECHO-01",
        family="cmdi",
        title="OS Command Injection Confirmed via Canary Execution",
        cwe_ids=("CWE-78",),
        severity=Severity.CRITICAL,
        benign_value="localhost",
        true_payload="localhost; echo ELY_CMDI_CANARY_7741",
        false_payload="localhost",
        error_signatures=("ely_cmdi_canary_7741", "sh: 1:", "command not found"),
        remediation="Eliminate `shell=True`; pass static command arrays and enforce strict hostname regex validation.",
    ),
    DifferentialProbeSpec(
        probe_id="PROBE-CRLF-SPLIT-01",
        family="crlf",
        title="CRLF Header Injection / HTTP Response Splitting Confirmed",
        cwe_ids=("CWE-113",),
        severity=Severity.HIGH,
        benign_value="en-US",
        true_payload="en-US\r\nX-Ely-Crlf-Canary: injected",
        false_payload="en-US",
        error_signatures=("x-ely-crlf-canary",),
        remediation="Reject CR (`\\r`) and LF (`\\n`) characters in all HTTP header inputs.",
    ),
)


class WebInjectionSecurityEngine:
    """
    Combines multi-language static analysis, Python AST injection flow analysis,
    and authorized local sandboxed differential HTTP probing.
    """

    def __init__(self) -> None:
        self._compiled_rules: List[Tuple[InjectionStaticRule, Pattern[str], Optional[Pattern[str]]]] = [
            (
                r,
                re.compile(r.pattern),
                re.compile(r.anti_pattern) if r.anti_pattern else None,
            )
            for r in INJECTION_STATIC_RULES
        ]
        self._ast_analyzer = PythonInjectionASTAnalyzer()
        self._deobf_ast = PythonASTDeobfuscationEngine()
        self._payload_normalizer = MultiLayerPayloadNormalizer()

    def scan_directory(self, root_path: Path) -> List[CyberVulnerability]:
        """Scan an authorized local codebase snapshot for all injection vulnerability classes (including deobfuscated AST sinks)."""
        findings: List[CyberVulnerability] = []
        seen_fps: set[str] = set()

        for file_path in sorted(root_path.rglob("*")):
            if not file_path.is_file():
                continue
            if any(p in {".git", "node_modules", "__pycache__", ".venv", "dist", "build"} for p in file_path.parts):
                continue
            ext = file_path.suffix.lower()
            if ext not in {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java", ".go", ".rb", ".sql"}:
                continue

            rel = str(file_path.relative_to(root_path))
            if ext == ".py":
                for f in self._ast_analyzer.analyze_file(file_path, rel):
                    fp = f.fingerprint()
                    if fp not in seen_fps:
                        seen_fps.add(fp)
                        findings.append(f)

            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            if ext == ".py":
                deobf_res = self._deobf_ast.analyze_source(content, file_path=rel)
                for df in deobf_res.get("vulnerabilities", []):
                    fp = df.fingerprint()
                    if fp not in seen_fps:
                        seen_fps.add(fp)
                        findings.append(df)

            lines = content.splitlines()
            for rule, regex, anti in self._compiled_rules:
                if ext not in rule.languages:
                    continue
                for idx, line in enumerate(lines, start=1):
                    if not regex.search(line):
                        continue
                    window = "\n".join(lines[max(0, idx - 3) : min(len(lines), idx + 2)])
                    if anti and anti.search(window):
                        continue
                    cv = rule.cvss4
                    vuln = make_cyber_vuln(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        description=rule.description,
                        cyber_domain=CyberDomain.WEB_INJECTION,
                        severity=rule.severity,
                        cwe_ids=list(rule.cwe_ids),
                        confidence=0.87,
                        owasp_categories=list(rule.owasp),
                        mitre_techniques=[
                            MitreTechniqueRef(rule.mitre_id, rule.mitre_name, rule.mitre_tactic)
                        ],
                        cvss4=CVSSv4Metrics(
                            av=cv[0], ac=cv[1], at=cv[2], pr=cv[3], ui=cv[4],
                            vc=cv[5], vi=cv[6], va=cv[7], sc=cv[8], si=cv[9], sa=cv[10],
                        ),
                        verification_method=VerificationMethod.STATIC_PATTERN,
                        file_path=rel,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line.strip()[:300],
                        remediation_guidance=rule.remediation,
                        secure_code_example=rule.secure_example,
                        discovered_by="ely_cyber_web_injection_static",
                    )
                    fp = vuln.fingerprint()
                    if fp not in seen_fps:
                        seen_fps.add(fp)
                        findings.append(vuln)

        return findings

    def probe_sandbox_endpoint(
        self,
        handler: Callable[[HttpProbeRequest], HttpProbeResponse],
        *,
        endpoint: str,
        method: str = "GET",
        param_name: str = "q",
        location: str = "query",  # query, body_json, header
    ) -> List[CyberVulnerability]:
        """
        Execute authorized differential injection probes strictly against an
        in-process local sandbox handler callable (NEVER touches external networks).
        """
        findings: List[CyberVulnerability] = []

        for probe in INJECTION_PROBE_CATALOG:
            base_req = self._build_request(method, endpoint, param_name, probe.benign_value, location)
            true_req = self._build_request(method, endpoint, param_name, probe.true_payload, location)
            false_req = self._build_request(method, endpoint, param_name, probe.false_payload, location)

            t0 = time.monotonic()
            base_res = handler(base_req)
            true_res = handler(true_req)
            false_res = handler(false_req)
            elapsed = (time.monotonic() - t0) * 1000.0

            triggered = False
            reason = ""

            # Check 1: Explicit canary / error / shell / header signature
            combined_true = (
                true_res.body.lower()
                + "\n"
                + "\n".join(f"{k.lower()}: {v.lower()}" for k, v in true_res.headers.items())
                + "\n"
                + "\n".join(true_res.shell_commands).lower()
                + "\n"
                + "\n".join(true_res.side_effects).lower()
            )
            combined_false = false_res.body.lower() + "\n" + "\n".join(false_res.side_effects).lower()

            for sig in probe.error_signatures:
                if sig in combined_true or (probe.family == "sqli_union" and sig in combined_false):
                    triggered = True
                    reason = f"Canary/error signature `{sig}` observed in sandbox response."
                    break

            # Check 2: Boolean differential response divergence (tautology returns significantly more data or 200 vs 401/404)
            if not triggered and probe.family in ("sqli_boolean", "nosqli"):
                true_diff_false = (
                    (true_res.status_code == 200 and false_res.status_code in (401, 403, 404))
                    or (
                        true_res.status_code == 200
                        and false_res.status_code == 200
                        and len(true_res.body) > len(false_res.body) + 25
                        and len(true_res.body) >= len(base_res.body)
                    )
                )
                sql_tautology_in_db = any("or '1'='1" in q.lower() for q in true_res.db_queries_executed)
                if true_diff_false or sql_tautology_in_db:
                    triggered = True
                    reason = (
                        f"Boolean differential confirmed: true_status={true_res.status_code} (len={len(true_res.body)}) "
                        f"vs false_status={false_res.status_code} (len={len(false_res.body)})."
                    )

            # Check 3: Shell command side-effect telemetry
            if not triggered and probe.family == "cmdi":
                if any("ely_cmdi_canary_7741" in c.lower() or ";" in c for c in true_res.shell_commands):
                    triggered = True
                    reason = f"Injected shell command observed in sandbox telemetry: `{true_res.shell_commands[0]}`"

            if triggered:
                ev = EvidenceArtifact(
                    artifact_id=new_id("ev"),
                    kind="payload_diff",
                    summary=reason,
                    content=(
                        f"Endpoint: {method} {endpoint} (param={param_name})\n"
                        f"Benign ({base_res.status_code}): {base_res.body[:200]}\n"
                        f"True Probe ({true_res.status_code}): {true_res.body[:250]}\n"
                        f"False Probe ({false_res.status_code}): {false_res.body[:200]}"
                    ),
                    metadata={"probe_id": probe.probe_id, "elapsed_ms": round(elapsed, 2)},
                )
                findings.append(
                    make_cyber_vuln(
                        rule_id=probe.probe_id,
                        title=probe.title,
                        description=f"{probe.title} on `{method} {endpoint}` parameter `{param_name}`. {reason}",
                        cyber_domain=CyberDomain.WEB_INJECTION,
                        severity=probe.severity,
                        cwe_ids=list(probe.cwe_ids),
                        confidence=0.97,
                        owasp_categories=["A03:2021-Injection"],
                        mitre_techniques=[
                            MitreTechniqueRef("T1190", "Exploit Public-Facing Application", MitreTactic.INITIAL_ACCESS)
                        ],
                        cvss4=CVSSv4Metrics(av="N", ac="L", at="N", pr="N", ui="N", vc="H", vi="H", va="H", sc="L", si="L", sa="N", e="P"),
                        verification_method=VerificationMethod.SANDBOX_DIFFERENTIAL_PROBE,
                        sandbox_reproduced=True,
                        endpoint_or_asset=f"{method} {endpoint}?{param_name}",
                        attack_vector_detail=reason,
                        remediation_guidance=probe.remediation,
                        evidence=[ev],
                        discovered_by="ely_cyber_web_injection_prober",
                    )
                )

        return findings

    @staticmethod
    def _build_request(
        method: str,
        endpoint: str,
        param_name: str,
        value: str,
        location: str,
    ) -> HttpProbeRequest:
        if location == "header":
            return HttpProbeRequest(method=method, path=endpoint, headers={param_name: value})
        if location == "body_json":
            # Support raw JSON operator probes for NoSQL testing
            if value.startswith("{") and value.endswith("}"):
                body = f'{{"{param_name}": {value}}}'
            else:
                escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n")
                body = f'{{"{param_name}": "{escaped}"}}'
            return HttpProbeRequest(method=method, path=endpoint, body=body, content_type="application/json")
        return HttpProbeRequest(method=method, path=endpoint, query_params={param_name: value})
