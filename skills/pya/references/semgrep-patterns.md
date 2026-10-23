# Semgrep-Inspired Detection Patterns

## Purpose

These patterns describe WHAT to look for conceptually using semantic reasoning: the approach Semgrep pioneered, which our AI agents can take further by understanding intent, not just structure. When semgrep is installed, PYA runs it with `--metrics=off` and local rules only; a tool that did not run is reported as "not run", never as "clean".

## Core Philosophy

Semgrep's power comes from understanding code semantics. Our AI agents implement the same principles:

1. **Trace data flow**: Follow variables from source (user input) to sink (dangerous function)
2. **Understand equivalence**: `import X as Y` means Y IS X; aliased functions are the same function
3. **Match across statements**: A variable assigned on line 5 used on line 50 is the same data
4. **Detect absence**: Missing sanitization between source and sink IS the vulnerability
5. **Context-aware**: `eval()` in a test file is not the same risk as `eval()` in a route handler
6. **Framework-literate**: ORM `.filter()` is NOT the same as raw SQL string concatenation

## Pattern 1: Taint Analysis (Source → Sink)

The most important detection pattern. For each vulnerability:

```text
SOURCE (untrusted data enters) → [SANITIZER missing?] → SINK (dangerous operation)
```

### Sources (Where User Data Enters)

| Framework | Source Expressions |
|-----------|-------------------|
| Express/Node | `req.params.*`, `req.query.*`, `req.body.*`, `req.headers.*`, `req.cookies.*` |
| Django | `request.GET.*`, `request.POST.*`, `request.FILES.*`, `request.META.*`, `request.body` |
| Flask | `request.args.*`, `request.form.*`, `request.json.*`, `request.data` |
| FastAPI | Function parameters with `Query()`, `Path()`, `Body()`, `Header()` |
| Spring | `@RequestParam`, `@PathVariable`, `@RequestBody`, `HttpServletRequest.getParameter()` |
| Rails | `params[:]`, `request.env[]`, `cookies[]` |
| Go net/http | `r.URL.Query()`, `r.FormValue()`, `r.Body`, `r.Header.Get()` |
| ASP.NET | `Request.Query[]`, `Request.Form[]`, `Request.Body` |
| Generic | `stdin`, `argv`, `os.environ`, `process.env`, file contents from user upload |
| GitHub Actions | `github.event.*` text fields, `github.head_ref`, `inputs.*`, downloaded `workflow_run` artifacts |
| LLM apps | Model completions, tool-call arguments, retrieved documents, web pages and tool results fed to the model |

### Sinks (Where Data Becomes Dangerous)

| Vulnerability | Sink Functions |
|--------------|---------------|
| SQL Injection | `execute()`, `query()`, `raw()`, `cursor.execute(f"...")`, template literals in SQL |
| Command Injection | `exec()`, `system()`, `spawn()`, `Popen(shell=True)`, backtick operators |
| Path Traversal | `open()`, `readFile()`, `include()`, `require()`, `sendFile()` |
| XSS | `innerHTML`, `document.write()`, `v-html`, `dangerouslySetInnerHTML`, `mark_safe()` |
| SSRF | `fetch()`, `requests.get()`, `http.Get()`, `HttpClient()`, `urllib.request.urlopen()` |
| Deserialization | `pickle.loads()`, `unserialize()`, `ObjectInputStream.readObject()`, `YAML.load()` |
| Code Injection | `eval()`, `exec()`, `Function()`, `compile()`, `setTimeout(string)` |
| Open Redirect | `redirect()`, `location.href =`, `res.redirect()`, `header("Location: ")` |
| LDAP Injection | `ldap_search()`, `SearchRequest()` with string concat |
| Template Injection | `render_template_string()`, `Velocity.evaluate()`, `new Template()` |
| Prompt Injection | System-prompt or instruction fields built from untrusted text (see `agentic-security.md` AG-11) |
| Improper Output Handling | Model output into `eval`, shell, SQL, `innerHTML`, file paths (LLM05) |

### Sanitizers (What Breaks the Taint Chain)

| For | Sanitizer |
|-----|-----------|
| SQL Injection | Parameterized queries, prepared statements, ORM query builders |
| XSS | HTML encoding, `escape()`, `htmlspecialchars()`, template auto-escaping |
| Command Injection | Allowlist of commands, array form (no shell), `shlex.quote()` |
| Path Traversal | `realpath()` + prefix check, `os.OpenRoot()` (Go 1.24+), allowlist |
| SSRF | URL allowlist, deny private ranges (10.*, 172.16-31.*, 192.168.*, 127.*) |
| Open Redirect | Same-origin check, path-only redirects, allowlisted domains |

## Pattern 2: Absence Detection (Missing Controls)

**This is the AI advantage**: static tools can't detect what's NOT there.

```text
FOR EACH route/endpoint/handler:
  □ Authentication check present? (middleware, decorator, guard)
  □ Authorization check present? (ownership, role, permission)
  □ Input validation before processing? (type, range, format)
  □ Rate limiting on sensitive operations? (login, signup, reset)
  □ CSRF protection on state-changing methods? (POST, PUT, DELETE)
  □ Audit logging for security-relevant actions? (admin ops, data access)

IF ANY is missing → Generate finding with appropriate severity
```

### What To Look For

| Missing Control | How to Detect | Severity |
|----------------|---------------|----------|
| Auth on data endpoint | Route handler accesses DB without auth check | HIGH |
| Authz on resource access | Uses resource ID from request without ownership check | HIGH |
| Input validation | Request params used directly without type/format check | MEDIUM |
| Rate limiting on login | Auth endpoint without rate limit middleware | HIGH |
| CSRF on mutations | POST/PUT/DELETE handler without CSRF token check | MEDIUM |
| Audit logging on admin | Admin operation without logging who did what | MEDIUM |

## Pattern 3: Dangerous Function + Dynamic Input

```text
DETECT: dangerous_function(expression_containing_user_variable)
WHERE: user_variable traces back to untrusted source
AND: no sanitizer in the path

Confidence: HIGH if source is directly from request
Confidence: MEDIUM if source is from database (stored input)
Confidence: LOW if source origin is unclear
```

## Pattern 4: Crypto Anti-Patterns

| Pattern | Detection | CWE |
|---------|-----------|-----|
| MD5/SHA1 for passwords | `hashlib.md5`, `crypto.createHash('md5')`, `MessageDigest.getInstance("MD5")` | CWE-327 |
| ECB mode | `AES.new(key, AES.MODE_ECB)`, `Cipher.getInstance("AES/ECB/")` | CWE-327 |
| Hardcoded IV/nonce | Static byte array used as IV, `iv = b'\x00' * 16` | CWE-329 |
| Weak key size | RSA < 2048, AES < 128, EC < 256 | CWE-326 |
| Math.random for security | `Math.random()`, `random.random()`, `rand()`, `mt_rand()` for tokens/keys | CWE-338 |
| Non-constant-time comparison | `==` for secret/token comparison, `strcmp()` for HMAC | CWE-208 |
| Disabled cert verification | `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true` | CWE-295 |
| Stale or vendored trust store | `verify="vendor/cacert.pem"`, `sslcertificates` to a repo file, `REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE` to a vendored bundle | CWE-295 |

## Pattern 5: Race Condition Detection

```text
DETECT check-then-act WITHOUT atomicity:

Pattern A: Balance/quantity check → deduction
  if user.balance >= amount:     # CHECK
    user.balance -= amount       # ACT: NOT atomic!
  Fix: Use database transaction with SELECT FOR UPDATE

Pattern B: File existence check → operation
  if os.path.exists(path):       # CHECK
    data = open(path).read()     # ACT: TOCTOU!
  Fix: Try/except, or use os.OpenRoot() (Go)

Pattern C: Permission check → action (separate operations)
  if user.can_access(resource):  # CHECK (may change between lines)
    resource.delete()            # ACT
  Fix: Atomic operation with database constraints

INDICATORS of race conditions:
- Concurrent access patterns (goroutines, threads, async without await)
- Shared mutable state without locks/transactions
- Time delay between check and action
- Financial operations without serializable transactions
```

## Pattern 6: Secrets in Code

### High-Confidence Patterns (known formats)

```text
AWS Access Key:    AKIA[A-Z0-9]{16}
AWS Secret Key:    [A-Za-z0-9/+=]{40} (in context of AWS config)
GitHub Token:      gh[opsr]_[A-Za-z0-9]{36,}   (gho_ = OAuth, e.g. GitHub CLI; also look in logs and proxy request bodies)
GitHub App Token:  ghu_[A-Za-z0-9]{36}
Stripe Live:       sk_live_[A-Za-z0-9]{24,}
Stripe Test:       sk_test_[A-Za-z0-9]{24,}  (lower severity)
Slack Token:       xox[baprs]-[A-Za-z0-9-]+
JWT:               eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+
Private Key:       -----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----
Google API Key:    AIza[A-Za-z0-9_-]{35}
Twilio:            SK[a-f0-9]{32}
SendGrid:          SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}
```

### Medium-Confidence Patterns (heuristic)

```text
password\s*[=:]\s*["'][^"']{8,}["']     # password assignment (non-empty, non-placeholder)
api[_-]?key\s*[=:]\s*["'][^"']{16,}["'] # API key assignment
secret\s*[=:]\s*["'][^"']{8,}["']       # generic secret
token\s*[=:]\s*["'][^"']{16,}["']       # token assignment
```

### Exclude (reduce false positives)

- Files: `*_test.*`, `*.spec.*`, `*.example`, `*.sample`, `*.md`
- Values: `"changeme"`, `"placeholder"`, `"your-key-here"`, `"xxx"`, `"TODO"`, empty strings
- Context: Hash comparisons, documentation strings, mock/fixture data

## Pattern 7: Framework Security Bypass Detection

When code EXPLICITLY bypasses built-in security, confidence goes to HIGH:

| Bypass | Framework | What it disables |
|--------|-----------|-----------------|
| `dangerouslySetInnerHTML` | React | XSS protection (auto-escaping) |
| `mark_safe()` | Django | Template auto-escaping |
| `v-html` | Vue | Content escaping |
| `bypassSecurityTrust*()` | Angular | DomSanitizer |
| `\| safe` filter | Jinja2 | Auto-escaping |
| `{% autoescape off %}` | Django/Jinja2 | Block-level escaping |
| `@csrf_exempt` | Django | CSRF protection |
| `[AllowAnonymous]` | ASP.NET | Authentication requirement |
| `verify=False` | Python requests | TLS certificate validation |
| `rejectUnauthorized: false` | Node.js | TLS certificate validation |
| `InsecureSkipVerify: true` | Go | TLS certificate validation |
| `NODE_TLS_REJECT_UNAUTHORIZED=0` | Node.js env | All TLS validation |
| `--no-verify` | git hooks | Pre-commit safety checks |
| `nosec` / `nolint:gosec` | Bandit/gosec | Security linter suppression |

**Rule**: When a bypass is detected, check WHY. If the surrounding context doesn't justify it (e.g., test code, local dev, explicit security decision with comment), flag it at HIGH confidence.

## Pattern 8: Information Disclosure

```text
DETECT:
- Stack traces in HTTP responses (framework debug mode)
- Version headers (Server, X-Powered-By)
- Database error messages exposed to users
- Internal IP addresses in responses
- Source code paths in error messages
- Verbose logging of request/response bodies containing PII
- GraphQL introspection enabled in production
- API documentation endpoints (Swagger) without auth
- .git directory accessible via web
- .env file accessible via web
```

## Application Priority

When reviewing code, apply patterns in this order (highest impact first):

1. **Injection** (Pattern 1 + 3): RCE/data breach risk
2. **Authentication/Authorization** (Pattern 2): access control failure
3. **Secrets** (Pattern 6): immediate credential compromise
4. **Crypto** (Pattern 4): data protection failure
5. **Framework Bypass** (Pattern 7): intentional insecurity
6. **Race Conditions** (Pattern 5): logic/financial exploitation
7. **Information Disclosure** (Pattern 8): reconnaissance aid
