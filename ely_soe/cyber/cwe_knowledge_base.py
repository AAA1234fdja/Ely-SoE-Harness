"""
Comprehensive CWE Top-55+ Security Knowledge Graph & Multi-Language Secure Remediation Engine.

Provides structured, machine-actionable vulnerability intelligence used across:
  - `GeneralizedCyberOrchestrator` enrichment & executive remediation guides
  - `CVSSv4` baseline vector & EPSS fallback priors
  - `Harness²` adaptive workflow drilldown selection (mapping observed CWEs -> secondary verification engines)
  - Multi-language secure-code patch recipes (Python, JavaScript/TypeScript, Go, Java, C/C++, Terraform, Kubernetes).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ely_soe.cyber.models import CyberDomain


@dataclass(frozen=True)
class CWEKnowledgeEntry:
    cwe_id: str
    name: str
    cyber_domain: CyberDomain
    parent_cwe: str
    default_cvss4: str
    epss_prior: float
    owasp_refs: Tuple[str, ...]
    mitre_refs: Tuple[str, ...]
    root_cause: str
    exploit_mechanics: str
    detection_indicators: Tuple[str, ...]
    defense_in_depth: Tuple[str, ...]
    secure_recipes: Dict[str, str]  # language -> secure code snippet
    verification_oracle: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cwe_id": self.cwe_id,
            "name": self.name,
            "cyber_domain": self.cyber_domain.value,
            "parent_cwe": self.parent_cwe,
            "default_cvss4": self.default_cvss4,
            "epss_prior": self.epss_prior,
            "owasp_refs": list(self.owasp_refs),
            "mitre_refs": list(self.mitre_refs),
            "root_cause": self.root_cause,
            "exploit_mechanics": self.exploit_mechanics,
            "detection_indicators": list(self.detection_indicators),
            "defense_in_depth": list(self.defense_in_depth),
            "secure_recipes": dict(self.secure_recipes),
            "verification_oracle": self.verification_oracle,
        }


CWE_KNOWLEDGE_CATALOG: Tuple[CWEKnowledgeEntry, ...] = (
    CWEKnowledgeEntry(
        "CWE-89", "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
        CyberDomain.WEB_INJECTION, "CWE-943", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N", 0.78,
        ("A03:2021-Injection",), ("T1190",),
        "Untrusted input concatenated into dynamic SQL strings alters query parse tree structure.",
        "Attacker injects boolean tautologies, UNION SELECT queries, or stacked statements to dump/alter DB tables.",
        ("SQL syntax errors in HTTP 500 responses", "Boolean 1=1 vs 1=2 differential length shifts", "Anomalous UNION/SLEEP queries"),
        ("Parameterized prepared statements", "Least-privilege DB roles without FILE/SUPER", "Strict ORM bind variables", "WAF SQL grammar inspection"),
        {
            "python": "cursor.execute('SELECT id, email FROM users WHERE username = ?', (username,))",
            "javascript": "await pool.query('SELECT id, email FROM users WHERE username = $1', [username]);",
            "go": "db.QueryContext(ctx, \"SELECT id, email FROM users WHERE username = $1\", username)",
            "java": "PreparedStatement ps = conn.prepareStatement(\"SELECT id FROM users WHERE username = ?\"); ps.setString(1, username);",
        },
        "Differential boolean/error SQLi probe must produce identical non-500 safe empty result.",
    ),
    CWEKnowledgeEntry(
        "CWE-78", "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)",
        CyberDomain.WEB_INJECTION, "CWE-77", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 0.85,
        ("A03:2021-Injection",), ("T1059.004", "T1190"),
        "Passing untrusted arguments to `/bin/sh -c` (`shell=True`, `os.system`, `child_process.exec`).",
        "Shell metacharacters (`;`, `|`, `$(...)`, backticks) execute arbitrary OS commands under service UID.",
        ("Unexpected child shells spawned by web worker PID", "Shell metacharacters in HTTP params"),
        ("Pass argv list with `shell=False`", "Strict regex allowlist on arguments", "Drop container capabilities & use seccomp"),
        {
            "python": "subprocess.run(['/usr/bin/ping', '-c', '1', '--', validated_host], shell=False, check=True, timeout=5)",
            "javascript": "execFile('/usr/bin/ping', ['-c', '1', '--', validatedHost], { shell: false, timeout: 5000 });",
            "go": "exec.CommandContext(ctx, \"/usr/bin/ping\", \"-c\", \"1\", \"--\", validatedHost).Output()",
        },
        "Injecting `; echo CANARY` or `$(id)` must not spawn a shell or alter stdout.",
    ),
    CWEKnowledgeEntry(
        "CWE-79", "Improper Neutralization of Input During Web Page Generation (Cross-Site Scripting)",
        CyberDomain.WEB_CLIENT_PROTOCOL, "CWE-74", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:H/SI:H/SA:N", 0.65,
        ("A03:2021-Injection",), ("T1189",),
        "Unescaped untrusted data rendered into HTML, attribute, URL, or DOM JavaScript contexts.",
        "Attacker executes arbitrary JavaScript in victim origin to hijack sessions, perform CSRF, or exfiltrate DOM state.",
        ("Unescaped `<svg/onload>` / `<script>` reflection in `text/html`", "DOM sink writes to `innerHTML`"),
        ("Context-aware auto-escaping templates", "Strict nonce-based CSP without `unsafe-inline`", "`HttpOnly` session cookies"),
        {
            "python": "return html.escape(user_query, quote=True)",
            "javascript": "element.textContent = userQuery; // Never element.innerHTML = userQuery",
            "go": "tmpl := htmltemplate.Must(htmltemplate.New(\"p\").Parse(\"<p>{{.}}</p>\"))",
        },
        "Probing with `\"><svg/onload=canary()>` must return HTML-entity encoded output.",
    ),
    CWEKnowledgeEntry(
        "CWE-918", "Server-Side Request Forgery (SSRF)",
        CyberDomain.WEB_SSRF_XXE_SSTI_DESER, "CWE-441", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:H/SA:N", 0.82,
        ("A10:2021-Server-Side-Request-Forgery", "API7:2023-SSRF"), ("T1552.005", "T1190"),
        "Server initiates outbound HTTP/TCP requests to user-controlled URLs without resolving & validating destination IP.",
        "Attacker pivots to `169.254.169.254` Cloud IMDS, internal Kubernetes APIs, Redis, or loopback admin endpoints.",
        ("Outbound requests from web tier to `169.254.169.254` or RFC 1918 IPs", "Octal/hex/IPv6-mapped IP URL inputs"),
        ("DNS resolution + strict block of loopback/RFC1918/link-local IPs", "Disable HTTP redirects", "Mandate IMDSv2 hop-limit=1", "Egress firewall proxy"),
        {
            "python": "ip = ipaddress.ip_address(socket.getaddrinfo(host, None)[0][4][0]); assert ip.is_global",
            "go": "dialer.Control = rejectPrivateAndLinkLocalIPs",
        },
        "Submitting `http://169.254.169.254`, `http://2130706433`, and `http://[::ffff:127.0.0.1]` must return HTTP 400/403.",
    ),
    CWEKnowledgeEntry(
        "CWE-502", "Deserialization of Untrusted Data",
        CyberDomain.WEB_SSRF_XXE_SSTI_DESER, "CWE-913", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 0.88,
        ("A08:2021-Software-and-Data-Integrity-Failures",), ("T1190", "T1059.006"),
        "Reconstructing native objects from untrusted binary/YAML/Java/pickle streams invokes arbitrary `__reduce__`/gadget chains.",
        "Attacker supplies crafted pickle/Java/YAML gadget payload triggering immediate Remote Code Execution.",
        ("`pickle.loads`, `yaml.load`, `ObjectInputStream`, `torch.load` without `weights_only=True`"),
        ("Replace with JSON/Protobuf schema parsers", "Use `yaml.safe_load`", "Use `safetensors` for ML weights", "Cryptographically sign state blobs"),
        {
            "python": "data = json.loads(raw_payload)  # or yaml.safe_load(raw_yaml)",
            "java": "ObjectMapper mapper = new ObjectMapper(); mapper.deactivateDefaultTyping();",
        },
        "Submitting a benign pickle/YAML `!!python/object` probe must be rejected without execution.",
    ),
    CWEKnowledgeEntry(
        "CWE-611", "Improper Restriction of XML External Entity Reference (XXE)",
        CyberDomain.WEB_SSRF_XXE_SSTI_DESER, "CWE-610", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:H/SC:L/SI:N/SA:N", 0.74,
        ("A05:2021-Security-Misconfiguration",), ("T1190", "T1005"),
        "XML parser allows `<!DOCTYPE>` and external `SYSTEM`/`PUBLIC` entities.",
        "Attacker reads local `/etc/passwd`, triggers SSRF, or causes Billion Laughs exponential memory exhaustion.",
        ("XML requests containing `<!DOCTYPE` or `<!ENTITY`"),
        ("Disable DTD & external entity resolution (`defusedxml`, `disallow-doctype-decl=true`)", "Prefer JSON APIs"),
        {
            "python": "import defusedxml.ElementTree as ET; root = ET.fromstring(xml_payload)",
            "java": "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);",
        },
        "Submitting `<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]>` must raise parser security error.",
    ),
    CWEKnowledgeEntry(
        "CWE-639", "Authorization Bypass Through User-Controlled Key (IDOR / BOLA)",
        CyberDomain.AUTH_ACCESS_CONTROL, "CWE-285", "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 0.72,
        ("A01:2021-Broken-Access-Control", "API1:2023-Broken-Object-Level-Authorization"), ("T1078",),
        "Endpoint looks up object by client-supplied ID without verifying authenticated actor owns or has ACL on that object.",
        "Authenticated User A enumerates `/api/v1/users/1002` or `/orders/9941` to read/modify User B's confidential records.",
        ("Sequential object ID enumeration across distinct tenant records returning HTTP 200"),
        ("Enforce `WHERE id = ? AND owner_id = current_user.id` at data-access layer", "Use opaque UUIDv4/ULIDs + centralized ABAC policy"),
        {
            "python": "record = db.fetch_one('SELECT * FROM orders WHERE id = ? AND tenant_id = ?', (order_id, ctx.tenant_id))",
            "javascript": "const doc = await Order.findOne({ _id: req.params.id, ownerId: req.user.id });",
        },
        "Requesting User B's object with User A's bearer token must return HTTP 403 or 404.",
    ),
    CWEKnowledgeEntry(
        "CWE-347", "Improper Verification of Cryptographic Signature (JWT `alg:none` / Key Confusion)",
        CyberDomain.AUTH_ACCESS_CONTROL, "CWE-345", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:L/SA:N", 0.79,
        ("A07:2021-Identification-and-Authentication-Failures",), ("T1550.001",),
        "JWT verifier trusts header `alg`/`jku`/`kid` or skips signature verification.",
        "Attacker forges `alg:none` or RS256-to-HS256 key-confusion admin JWTs to hijack any account.",
        ("Bearer tokens with empty signature segment or mismatched `alg` accepted with HTTP 200"),
        ("Pin explicit `algorithms=['RS256']` or `['EdDSA']`", "Reject `alg:none`", "Validate `iss`, `aud`, `exp`, `nbf`"),
        {
            "python": "claims = jwt.decode(token, public_key, algorithms=['EdDSA'], audience='api', issuer='auth.ely')",
            "javascript": "jwt.verify(token, publicKey, { algorithms: ['RS256'], audience: 'api' });",
        },
        "Forged `alg:none` token and weak-secret HS256 token must both be rejected with HTTP 401.",
    ),
    CWEKnowledgeEntry(
        "CWE-22", "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal / ZipSlip)",
        CyberDomain.WEB_SSRF_XXE_SSTI_DESER, "CWE-706", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 0.80,
        ("A01:2021-Broken-Access-Control",), ("T1005", "T1190"),
        "Constructing file paths with `../` sequences without resolving canonical `realpath` against base root.",
        "Attacker reads `/etc/passwd`, SSH keys, or overwrites cron/authorized_keys via archive ZipSlip.",
        ("URL/archive entries containing `../`, `%2e%2e`, or absolute leading `/`"),
        ("Resolve `target = (base / name).resolve()` and assert `target.is_relative_to(base.resolve())`"),
        {
            "python": "dest = (base_dir / user_name).resolve(); assert dest.is_relative_to(base_dir.resolve())",
            "go": "clean := filepath.Clean(filepath.Join(base, name)); if !strings.HasPrefix(clean, base + string(os.PathSeparator)) { return ErrTraversal }",
        },
        "Submitting `../../../../etc/passwd` and encoded `..%2f` must fail with HTTP 400/403.",
    ),
    CWEKnowledgeEntry(
        "CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine (SSTI)",
        CyberDomain.WEB_SSRF_XXE_SSTI_DESER, "CWE-94", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 0.81,
        ("A03:2021-Injection",), ("T1190",),
        "Passing user input as the template source string (`render_template_string(user_input)`) rather than template data context.",
        "Attacker evaluates `{{7*7}}` and traverses Python MRO `__subclasses__()` to invoke OS commands.",
        ("Mathematical expression `{{7*7}}` evaluating to `49` in response body"),
        ("Never build template strings from user input; pass user data strictly as context variables into static template files"),
        {
            "python": "return render_template('greeting.html', user_name=user_input)  # Never render_template_string(user_input)",
        },
        "Sending `{{7*7}}` must render literal `{{7*7}}`, never `49`.",
    ),
    CWEKnowledgeEntry(
        "CWE-444", "Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)",
        CyberDomain.WEB_CLIENT_PROTOCOL, "CWE-436", "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N", 0.68,
        ("A04:2021-Insecure-Design",), ("T1557",),
        "Front-end reverse proxy and back-end origin disagree on `Content-Length` vs `Transfer-Encoding` boundaries.",
        "Attacker smuggles a second hidden HTTP request into another user's socket to poison caches or steal auth headers.",
        ("Simultaneous `Content-Length` + `Transfer-Encoding` headers", "Obfuscated `Transfer-Encoding` whitespace/case"),
        ("Enforce end-to-end HTTP/2 without H2->H1 downgrade", "Reject ambiguous CL+TE requests with HTTP 400"),
        {"nginx": "ignore_invalid_headers on; underscores_in_headers off;"},
        "Sending simultaneous `Content-Length` and `Transfer-Encoding: chunked` must return HTTP 400.",
    ),
    CWEKnowledgeEntry(
        "CWE-798", "Use of Hard-coded Credentials / Secrets",
        CyberDomain.AUTH_ACCESS_CONTROL, "CWE-259", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N", 0.76,
        ("A07:2021-Identification-and-Authentication-Failures",), ("T1552.001",),
        "Embedding static API tokens, cloud access keys, DB passwords, or private keys in source or IaC.",
        "Anyone with repo, image, or CI artifact read access compromises cloud/DB production immediately.",
        ("High-entropy tokens matching AWS/GitHub/Stripe/PEM patterns in source or git history"),
        ("Inject secrets at runtime via KMS/Vault/OIDC workload identity", "Block commits with pre-commit secret scanning"),
        {"python": "api_key = os.environ['SERVICE_API_KEY']  # Mounted via Vault/KMS secret injector"},
        "Repository secret scanner + git diff scanner must return 0 live high-entropy credentials.",
    ),
    CWEKnowledgeEntry(
        "CWE-269", "Improper Privilege Management (Cloud IAM / AD / RBAC Escalation)",
        CyberDomain.CLOUD_IAM, "CWE-284", "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 0.77,
        ("A01:2021-Broken-Access-Control",), ("T1098.003", "T1078.004"),
        "Over-permissive IAM roles (`iam:PassRole` + `lambda:CreateFunction`, wildcard `*:*`, K8s `cluster-admin`, AD `WriteDacl`).",
        "Low-privilege identity chains indirect permissions to attain Cloud Account Root, Cluster-Admin, or Domain Admin.",
        ("Shortest-path reachability from non-admin identity to Tier-0/Admin in IAM/AD/RBAC graph"),
        ("Enforce Permission Boundaries / SCPs", "Apply least-privilege synthesized IAM policies", "Eliminate wildcard trust policies"),
        {"terraform": "resource \"aws_iam_policy\" \"scoped\" { policy = jsonencode({ Statement = [{ Effect = \"Allow\", Action = [\"s3:GetObject\"], Resource = [aws_s3_bucket.app.arn] }] }) }"},
        "IAM/AD graph solver must confirm 0 escalation paths from low-privilege principals to Tier-0/Admin.",
    ),
    CWEKnowledgeEntry(
        "CWE-250", "Execution with Unnecessary Privileges (Privileged Container / HostPath Breakout)",
        CyberDomain.KUBERNETES_CONTAINER, "CWE-269", "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 0.71,
        ("A05:2021-Security-Misconfiguration",), ("T1611",),
        "Container runs as UID 0, `privileged: true`, shares host PID/Net/IPC namespaces, or mounts `/var/run/docker.sock`.",
        "Attacker with in-container RCE escapes directly to host Linux node and harvests all sibling pods and cloud node credentials.",
        ("Pod spec with `privileged: true`, `hostPID: true`, `CAP_SYS_ADMIN`, or writable rootfs"),
        ("Enforce Pod Security Standards `restricted`", "Drop `ALL` capabilities", "Set `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `seccompProfile: RuntimeDefault`"),
        {"kubernetes": "securityContext:\n  runAsNonRoot: true\n  readOnlyRootFilesystem: true\n  allowPrivilegeEscalation: false\n  capabilities:\n    drop: [\"ALL\"]"},
        "K8s manifest auditor and Seccomp auditor must report 0 critical privilege-escalation findings.",
    ),
    CWEKnowledgeEntry(
        "CWE-327", "Use of a Broken or Risky Cryptographic Algorithm",
        CyberDomain.TLS_CRYPTOGRAPHY, "CWE-693", "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N", 0.55,
        ("A02:2021-Cryptographic-Failures",), ("T1557", "T1040"),
        "Use of MD5/SHA-1 for signatures/passwords, DES/3DES/RC4/AES-ECB, or SSLv3/TLS 1.0/1.1.",
        "Enables chosen-prefix signature collision, ciphertext pattern leakage, POODLE/SWEET32 decryption, or offline hash cracking.",
        ("Code calling `hashlib.md5`/`sha1` on passwords, `AES.MODE_ECB`, or TLS handshake accepting RC4/TLSv1.0"),
        ("Use Argon2id/scrypt for passwords", "Use AES-256-GCM or ChaCha20-Poly1305 AEAD", "Enforce TLS 1.3 + SHA-256/384"),
        {"python": "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; ct = AESGCM(key).encrypt(nonce, pt, aad)"},
        "TLS handshake parser & crypto static auditor must report 0 broken ciphers or weak hash primitives.",
    ),
    CWEKnowledgeEntry(
        "CWE-787", "Out-of-bounds Write (Stack/Heap Buffer Overflow)",
        CyberDomain.BINARY_MEMORY_SAFETY, "CWE-119", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 0.86,
        ("A06:2021-Vulnerable-and-Out-of-Date-Components",), ("T1203", "T1068"),
        "Unbounded writes (`strcpy`, `sprintf`, `gets`, unchecked memcpy/index) corrupt adjacent stack frames or heap metadata.",
        "Attacker hijacks instruction pointer (ROP/JOP) or overwrites function pointers to achieve native RCE.",
        ("C/C++ calls to `strcpy`/`gets`/`sprintf`", "ELF/PE binaries missing NX, PIE, Stack Canary, Full RELRO"),
        ("Migrate memory-critical parsers to Rust", "Use bounds-checked `snprintf`/`strlcpy`", "Compile with `-fstack-protector-strong -D_FORTIFY_SOURCE=3 -Wl,-z,relro,-z,now -fPIE`"),
        {"c": "snprintf(dst, sizeof(dst), \"%s\", src); // Always pass explicit destination buffer size", "rust": "let safe_slice = buf.get(..len).ok_or(ParseError::Bounds)?;"},
        "Binary header checksec must confirm PIE + NX + Canary + Full RELRO and 0 unsafe unbounded copy calls.",
    ),
    CWEKnowledgeEntry(
        "CWE-416", "Use After Free (UAF)",
        CyberDomain.BINARY_MEMORY_SAFETY, "CWE-825", "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 0.83,
        ("A06:2021-Vulnerable-and-Out-of-Date-Components",), ("T1203",),
        "Dereferencing heap memory pointer after `free()`/`delete` when attacker can reallocate controlled object into freed slot.",
        "Attacker sprays controlled vtable/struct data into reclaimed heap chunk to hijack control flow.",
        ("Intra-procedural pointer use after `free(ptr)` without immediate `ptr = NULL`"),
        ("Nullify freed pointers immediately", "Use RAII `std::unique_ptr` or Rust ownership", "Test with ASan (`-fsanitize=address`)"),
        {"c": "free(ptr); ptr = NULL;", "cpp": "auto obj = std::make_unique<Session>();"},
        "Intra-file UAF analyzer and ASan fuzzing campaign must report 0 post-free dereferences.",
    ),
    CWEKnowledgeEntry(
        "CWE-829", "Inclusion of Functionality from Untrusted Control Sphere (CI/CD & Supply-Chain)",
        CyberDomain.IAC_CICD, "CWE-494", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 0.82,
        ("A08:2021-Software-and-Data-Integrity-Failures",), ("T1195.002",),
        "Unpinned GitHub Actions tags (`@main`/`@v3`), `pull_request_target` untrusted checkout, typosquatted packages, or `curl | sh`.",
        "Compromised upstream tag or malicious fork PR executes inside privileged CI runner and steals release/cloud signing tokens.",
        ("Workflow actions not pinned to 40-char commit SHA", "`pull_request_target` + `actions/checkout` PR ref", "Typosquatted lockfile packages"),
        ("Pin all actions to immutable 40-char SHA", "Set minimal workflow `permissions:`", "Verify SLSA v1.0 provenance + lockfile hashes"),
        {"yaml": "permissions:\n  contents: read\nsteps:\n  - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11"},
        "CI/CD & Supply-Chain auditors must report 0 unpinned actions, 0 Pwn-Request patterns, and 0 typosquats.",
    ),
    CWEKnowledgeEntry(
        "CWE-306", "Missing Authentication for Critical Function (OT/ICS, API, Redis/Mongo)",
        CyberDomain.FIRMWARE_IOT_OT, "CWE-287", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 0.84,
        ("A07:2021-Identification-and-Authentication-Failures", "API2:2023-Broken-Authentication"), ("T0855", "T1190"),
        "Network/API/OT control service exposes privileged administrative or actuator write commands without authentication.",
        "Attacker directly sends Modbus coil writes, MQTT publish commands, or Redis `CONFIG SET` over network.",
        ("Open unauthenticated Redis/Elasticsearch/MQTT/Modbus/GraphQL mutations"),
        ("Enforce mutual TLS (X.509) + RBAC authentication", "Bind internal services to loopback/private mesh with strict NetworkPolicies"),
        {"yaml": "auth:\n  required: true\n  mode: mtls_x509_rbac"},
        "Unauthenticated request to admin/control endpoint must return HTTP 401/403 or TLS handshake rejection.",
    ),
    CWEKnowledgeEntry(
        "CWE-74", "Improper Neutralization of Special Elements in Output Used by a Downstream Component (Prompt & Injection)",
        CyberDomain.ADVERSARY_EMULATION, "CWE-707", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:N", 0.75,
        ("LLM01:2025-Prompt-Injection", "A03:2021-Injection"), ("AML.T0051", "T1059"),
        "Lack of structural separation between trusted control instructions and untrusted external data in LLM/agent pipelines.",
        "Untrusted document/prompt hijacks agent tool invocations, exfiltrates context secrets, or emits weaponized outputs.",
        ("Canary secret leaked in completion", "Forbidden tool called from untrusted RAG context"),
        ("Enforce CaMeL control/data privilege separation", "Capability Lattice tool authorization", "Output schema validation & secret scrubbing"),
        {"python": "decision = capability_lattice.evaluate(tool_name, args, provenance=TrustLevel.UNTRUSTED_DATA)"},
        "AI/LLM red-team harness must achieve 100% block rate across all 15 OWASP LLM 2025 probes.",
    ),
)


class CWEKnowledgeBase:
    """Queryable CWE security knowledge graph and multi-language remediation recipe provider."""

    def __init__(self, entries: Sequence[CWEKnowledgeEntry] = CWE_KNOWLEDGE_CATALOG) -> None:
        self._by_id: Dict[str, CWEKnowledgeEntry] = {e.cwe_id.upper(): e for e in entries}

    def get(self, cwe_id: str) -> Optional[CWEKnowledgeEntry]:
        key = cwe_id.upper()
        if not key.startswith("CWE-"):
            key = f"CWE-{key}"
        return self._by_id.get(key)

    def by_domain(self, domain: CyberDomain) -> List[CWEKnowledgeEntry]:
        return [e for e in self._by_id.values() if e.cyber_domain == domain]

    def by_mitre(self, technique_id: str) -> List[CWEKnowledgeEntry]:
        t = technique_id.upper()
        return [e for e in self._by_id.values() if any(m.upper().startswith(t) for m in e.mitre_refs)]

    def get_remediation_bundle(self, cwe_ids: Sequence[str], preferred_lang: str = "python") -> Dict[str, Any]:
        matched: List[Dict[str, Any]] = []
        for cid in cwe_ids:
            entry = self.get(cid)
            if entry:
                recipe = entry.secure_recipes.get(preferred_lang) or next(iter(entry.secure_recipes.values()), "")
                matched.append(
                    {
                        "cwe_id": entry.cwe_id,
                        "name": entry.name,
                        "root_cause": entry.root_cause,
                        "defense_in_depth": list(entry.defense_in_depth),
                        "preferred_recipe": recipe,
                        "verification_oracle": entry.verification_oracle,
                    }
                )
        return {"requested_cwes": list(cwe_ids), "resolved_count": len(matched), "remediation_guides": matched}

    def list_all(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._by_id.values()]
