# Dockerfile Security Patterns

## Critical Issues

| Pattern | Risk | Severity | Fix |
|---------|------|----------|-----|
| No `USER` directive (runs as root) | Container root = host escalation path | HIGH | Add `USER nonroot:nonroot` after install |
| `FROM image:latest` | Unpinned, supply chain risk | MEDIUM | Pin: `FROM image@sha256:abc123...` |
| `COPY .env .` or `ADD credentials/` | Secrets baked into layers (retrievable) | CRITICAL | Use BuildKit `--mount=type=secret` |
| `ARG PASSWORD=secret` | Visible in `docker history` output | HIGH | Use runtime env or secrets mount |
| `RUN apt-get install` without `--no-install-recommends` | Bloated attack surface | LOW | Add flag + `rm -rf /var/lib/apt/lists/*` |
| `EXPOSE 22` | SSH in container = anti-pattern | MEDIUM | Remove, use `docker exec` |
| `ADD http://url/file` | Unverified remote content | HIGH | `curl` + checksum verification |
| Missing `HEALTHCHECK` | No health visibility | LOW | Add HEALTHCHECK instruction |
| `RUN chmod 777 /app` | World-writable filesystem | MEDIUM | Use 644 (files) / 755 (dirs) |
| `COPY . .` without `.dockerignore` | May include .git, .env, secrets | HIGH | Create `.dockerignore` |
| `FROM` an end-of-life runtime (`node:20`, `php:8.1` and older) | No security fixes | HIGH | Move to a supported line |
| `FROM python:3.11*` / `python:3.12*` and the image installs packages with its bundled pip | Old pip with its own vendored CA bundle | MEDIUM (HIGH if it fetches packages over an untrusted network) | Upgrade pip in the image first, or use a newer Python line |
| Vendored CA bundle copied into the image (`cacert.pem`, `ca-bundle.crt`) or `REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE` pointing at one | Trust store frozen at build time | MEDIUM | Use the distro `ca-certificates` package and rebuild |
| `RUN echo "import ..." > .../site-packages/*.pth` or `COPY sitecustomize.py` | Python startup-hook persistence (T1546.018) | CRITICAL | Remove; see `threat-intelligence.md` |

## Dangerous Patterns with Examples

### Secrets in Build

```dockerfile
# CRITICAL: Secret visible in layer history
ARG DB_PASSWORD
RUN echo "password=$DB_PASSWORD" > /app/config

# SAFE: BuildKit secret mount (not stored in layer)
RUN --mount=type=secret,id=db_pass cat /run/secrets/db_pass > /app/config
```

### Running as Root

```dockerfile
# DANGEROUS: No USER = root (and node:20 is end-of-life)
FROM node:20
COPY . /app
CMD ["node", "server.js"]

# SAFE: Non-root user on a supported line
FROM node:24
RUN groupadd -r app && useradd -r -g app app
COPY --chown=app:app . /app
USER app
CMD ["node", "server.js"]
```

### Unpinned Dependencies

```dockerfile
# DANGEROUS: Version drift, potential supply chain attack
FROM node:latest
RUN npm install

# SAFE: Pinned base (supported line, digest) + lock file
FROM node:24-alpine@sha256:<digest>
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
```

### Multi-stage Leak

```dockerfile
# DANGEROUS: Build stage secrets leak if not discarded
FROM node:24 AS build
COPY .npmrc .  # Contains auth token!
RUN npm ci

FROM node:24-alpine
COPY --from=build /app/node_modules ./node_modules
# .npmrc is NOT in final image, but IS in build cache
```

## Base Images, Runtime Lines and Trust Stores

Version floors for specific CVEs live in the feed. These rules are permanent.

| Check | Report when | Skip when | Source |
|---|---|---|---|
| End-of-life runtime | `FROM node:20*`, `node:25*` (Node 20.x and 25.x reached end of life on 2026-04-30 and 2026-06-01), `FROM php:8.1*` or older, `engines.node` pinned to an EOL line | A distro image documents backported security fixes for that line | Node release schedule https://github.com/nodejs/Release (D§6); PHP EOL branches get no official releases (D§3: https://www.bleepingcomputer.com/news/security/php-ships-emergency-patches-for-critical-php2shell-flaws/) |
| Python 3.11 / 3.12 images keep old pip | `FROM python:3.11*` or `3.12*` and `pip install` runs without first upgrading pip | The Dockerfile runs `python -m pip install --upgrade pip` (ideally from a hash-pinned wheel) before other installs, or uses `uv` | Python will not bump pip on 3.11/3.12; the official 3.11/3.12 images stay on the old pip (D§5: https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576/) |
| Stale image after a CA distrust | Images built before a CA distrust event and never rebuilt (no scheduled rebuild workflow, base pinned by digest with no update automation) | Renovate/Dependabot digest updates or a scheduled rebuild exist | Rebuild Docker images and CI runners after CA fixes (D§5, D§13: https://docs.docker.com/engine/release-notes/) |
| Long-running PHP-FPM after patching | Compose or k8s config with no restart or rollout on image update | Rolling deploys replace workers | Stale-state bugs live in long-running workers (D§3) |

## Docker Daemon and Container Runtime

| Pattern | Risk | Severity | Fix |
|---------|------|----------|-----|
| `"insecure-registries"` in `daemon.json` (or `--insecure-registry`) | Image pulls over HTTP or without TLS verification; DNS tricks can force the insecure fallback | HIGH | Remove; use TLS registries with trusted certs (insecure-registry fallback CVE context: D§13, https://github.com/moby/moby/security/advisories/GHSA-7cfq-22r6-qp73) |
| `sudo podman run` / rootful podman of third-party or untrusted images in scripts, Makefiles or CI | Rootful runtime bugs become host compromise; a crafted image annotation made rootful `podman run` ignore sandbox flags | HIGH | Run untrusted images rootless (D§16: https://github.com/containers/podman/security/advisories/GHSA-2cvf-wqm6-wr9g) |
| Docker socket mounted into containers | Container-to-host escape | CRITICAL | Remove or use a socket proxy with an allowlist |

```yaml
# DANGEROUS: daemon.json
{ "insecure-registries": ["registry.internal:5000", "0.0.0.0/0"] }
```

```bash
# DANGEROUS: rootful run of an image from an untrusted source
sudo podman run --rm docker.io/someone/tool:latest
# SAFE: rootless, pinned digest, no extra privileges
podman run --rm --security-opt=no-new-privileges docker.io/someone/tool@sha256:<digest>
```

## Docker Compose Security

| Pattern | Risk | Fix |
|---------|------|-----|
| `privileged: true` | Full host access | Remove, use capabilities |
| `volumes: /var/run/docker.sock:/var/run/docker.sock` | Docker escape | Remove unless required |
| `ports: "3306:3306"` (binds 0.0.0.0) | DB exposed to network | Use `127.0.0.1:3306:3306` |
| Missing `mem_limit` / `cpus` | Resource exhaustion | Set limits |
| `network_mode: host` | No network isolation | Use bridge/custom network |
| `env_file: .env` committed to git | Secrets in VCS | Add .env to .gitignore |
| `ports: "445:445"` or `"139:139"` (SMB), or ksmbd-tools installed in an image | SMB exposed; in-kernel ksmbd has had unauthenticated RCE reports (HIGH) | Do not expose SMB; prefer Samba in a container behind a VPN (D§17: https://threatlandscape.io/blog/ksmbd-zdi-can-33774-33549-unpatched-rce) |

## .dockerignore Required Entries

```text
.git
.env
.env.*
*.pem
*.key
id_rsa*
credentials/
secrets/
node_modules
.npm
__pycache__
*.pyc
```

## Best Practices Checklist

- [ ] Multi-stage build (separate build/runtime)
- [ ] Base image pinned to digest
- [ ] Runs as non-root user
- [ ] .dockerignore excludes secrets and dev files
- [ ] No secrets in ARG, ENV, or COPY
- [ ] Minimal packages installed
- [ ] HEALTHCHECK defined
- [ ] No unnecessary EXPOSE
- [ ] Base image on a supported runtime line
- [ ] pip upgraded before installs on python:3.11/3.12 images
- [ ] No vendored CA bundles; images rebuilt on a schedule
- [ ] No `insecure-registries`; untrusted images run rootless
- [ ] Scanned (osv-scanner, Trivy or equivalent) before push
