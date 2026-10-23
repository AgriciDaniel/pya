# JavaScript / TypeScript Security Patterns

## Dangerous Functions

| Function | Risk | CWE | Severity | Safe Alternative |
|----------|------|-----|----------|-----------------|
| `eval(userInput)` | Code injection | CWE-94 | CRITICAL | `JSON.parse()`, static analysis |
| `new Function(code)` | Code injection | CWE-94 | CRITICAL | Predefined functions |
| `setTimeout(string, ms)` | Code injection | CWE-94 | HIGH | `setTimeout(fn, ms)` |
| `setInterval(string, ms)` | Code injection | CWE-94 | HIGH | `setInterval(fn, ms)` |
| `child_process.exec(cmd)` | Command injection | CWE-78 | CRITICAL | `execFile()` with array args |
| `child_process.execSync(cmd)` | Command injection | CWE-78 | CRITICAL | `execFileSync()` |
| `innerHTML = userInput` | XSS | CWE-79 | HIGH | `textContent`, DOM API |
| `document.write(data)` | XSS | CWE-79 | HIGH | DOM manipulation |
| `outerHTML = userInput` | XSS | CWE-79 | HIGH | `textContent` |
| `vm.runInNewContext(code)` | Sandbox escape | CWE-94 | CRITICAL | Isolated workers, `vm2` |
| `require(userInput)` | Arbitrary module load | CWE-94 | CRITICAL | Static imports, allowlist |
| `RegExp(userInput)` | ReDoS | CWE-1333 | MEDIUM | Validate/sanitize pattern, `re2` |
| `Math.random()` for tokens, secrets, IDs, PKCE verifiers | Predictable secrets | CWE-338 | CRITICAL (auth values), MEDIUM otherwise | `crypto.randomBytes()`, `crypto.randomUUID()`, `crypto.getRandomValues()` |

## Prototype Pollution (JavaScript-Unique Critical Threat)

```javascript
// DANGEROUS: Deep merge with user input
const _ = require('lodash');
_.merge(config, req.body);
// If req.body = {"__proto__": {"isAdmin": true}}
// ALL objects now have isAdmin = true

// DANGEROUS: Recursive property assignment
function deepSet(obj, path, value) {
  const keys = path.split('.');
  // If path = "__proto__.polluted" → prototype pollution
}

// SAFE: Use Object.create(null) for dictionaries
const safeMap = Object.create(null);

// SAFE: Filter __proto__, constructor, prototype from keys
const FORBIDDEN = ['__proto__', 'constructor', 'prototype'];
```

**Impact**: Prototype pollution can escalate to RCE via `child_process.fork()` exploitation or bypass security checks globally.

## Framework-Specific Vulnerabilities

### React

| Pattern | Risk | Fix |
|---------|------|-----|
| `dangerouslySetInnerHTML={{__html: userInput}}` | XSS | Sanitize with DOMPurify |
| `href={userInput}` with `javascript:` protocol | XSS | Validate URL scheme |
| Server components leaking secrets to client | Data exposure | Check `"use client"` boundaries |
| `useEffect` with unsanitized URL fetch | SSRF | Validate URLs server-side |

### Next.js

| Pattern | Risk | Fix |
|---------|------|-----|
| `getServerSideProps` returning sensitive data | Data leak to client | Filter response |
| API routes without auth middleware | Unauthorized access | Add auth check |
| `next.config.js` headers misconfiguration | Missing security headers | Add security headers |
| `rewrites()` to internal services | SSRF | Validate destination |
| Server Actions (`'use server'`) without auth or input validation | Every exported action is a public POST endpoint | Check session and authorization inside each action; validate arguments with a schema |
| `images.dangerouslyAllowSVG: true` | SVG reaches the image optimizer and its native decoder (sharp/librsvg); XSS if served inline | Leave it off; if required, set `contentDispositionType: 'attachment'` and a strict `contentSecurityPolicy` |
| `images.remotePatterns` with wildcards (`hostname: '**'`) | Optimizer fetches arbitrary hosts (SSRF, untrusted images to native decoders) | List exact hosts |
| `'use cache'` functions returning binary data (typed arrays, `Buffer`) or caching per-user data without user-specific keys | Cache deserialization bugs; cross-user data leaks | Return plain serializable data; key caches by user where data is per-user |

**Advisory context (versions in the feed):** Next.js's Oct 14, 2026 release fixed an RCE in `use cache`
functions returning typed arrays (GHSA-673q-mjm6-r5xr), an RCE via SVG in Image Optimization through
sharp/librsvg (CVE-2026-96889, GHSA-2464-fhr4-w9xw), and a Server Actions DoS (GHSA-p3m5-59mp-jv5r).
Two had no CVE and did not show in `npm audit`, so dependency checks use OSV/GHSA data (D§7:
https://github.com/vercel/next.js/security/advisories/GHSA-673q-mjm6-r5xr,
https://github.com/vercel/next.js/security/advisories/GHSA-2464-fhr4-w9xw,
https://thehackernews.com/2026/10/nextjs-ships-out-of-band-patch-for-two.html). A lockfile can
keep an old `sharp` even after upgrading `next`; check `sharp` separately (D§7).

```javascript
// VULNERABLE: next.config.js
module.exports = { images: { dangerouslyAllowSVG: true, remotePatterns: [{ protocol: 'https', hostname: '**' }] } };
// SAFE
module.exports = { images: { remotePatterns: [{ protocol: 'https', hostname: 'images.example.com' }] } };

// VULNERABLE: server action with no authorization
'use server';
export async function deleteProject(id) { await db.project.delete({ where: { id } }); }
// SAFE
'use server';
export async function deleteProject(id) {
  const user = await requireUser();
  const parsed = z.string().uuid().parse(id);
  await db.project.delete({ where: { id: parsed, ownerId: user.id } });
}
```

### Express.js

| Pattern | Risk | Fix |
|---------|------|-----|
| No `helmet` middleware | Missing security headers | `app.use(helmet())` |
| `express.static()` serving `.env` | Secret exposure | Configure dotfiles: 'deny' |
| `res.send(userInput)` | XSS | Use template engine with escaping |
| `req.query` in SQL without parameterization | SQLi | Use parameterized queries |
| `cors({origin: '*', credentials: true})` | Auth bypass | Specify exact origins |

### Vue.js

| Pattern | Risk | Fix |
|---------|------|-----|
| `v-html="userInput"` | XSS | Use `{{ }}` interpolation (auto-escaped) |
| `v-bind:href="userInput"` | XSS via javascript: | Validate URL scheme |

### Angular

| Pattern | Risk | Fix |
|---------|------|-----|
| `bypassSecurityTrustHtml(input)` | XSS | Let DomSanitizer work |
| `bypassSecurityTrustScript(input)` | Code injection | Remove bypass |
| `[innerHTML]="userInput"` | XSS (partial sanitization) | Use interpolation |

## TLS in Node.js HTTP Clients (undici, fetch)

| Pattern | Risk | Fix |
|---------|------|-----|
| `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0` | TLS validation disabled | Remove; use `NODE_EXTRA_CA_CERTS` for private CAs |
| Custom `tls`/`connect` options passed to an undici `Agent`, `Pool` or `ProxyAgent` (`ca`, `checkServerIdentity`, pinned certs) | If the client drops these options (as a 2026 undici bug did, CVE-2026-109383), validation silently falls back or is bypassed | Keep undici current (floors in the feed); add a test that a bad certificate is rejected |
| `checkServerIdentity: () => undefined` | Hostname verification disabled | Remove |
| Cross-origin redirects followed with caching enabled | Cache poisoning across origins (undici CVE-2026-109829) | Disable redirect following for cached requests or validate origin |

Source for the undici advisories: D§6, https://github.com/nodejs/undici/security/advisories .

```javascript
// VULNERABLE: relies on custom TLS options without a test that they apply
const agent = new Agent({ connect: { ca: fs.readFileSync('pinned-ca.pem'), checkServerIdentity: () => undefined } });
// SAFE: default validation plus private CA via env, and a test that a bad cert fails
// NODE_EXTRA_CA_CERTS=/etc/ssl/private-ca.pem node server.js
const res = await fetch('https://internal.example.com/api');
```

## Install Scripts and npm v12

npm v12 (GA 2026-07-08) no longer runs dependency `preinstall`, `install`, `postinstall` (and implicit
`node-gyp rebuild`) scripts unless they are allowed. Projects opt packages back in with the
`allowScripts` field in `package.json` (written by `npm approve-scripts`) or the `allow-scripts` config
in `.npmrc`. v12 also defaults `--allow-git` and `--allow-remote` to `none`
(https://github.blog/changelog/2026-06-24-upcoming-breaking-changes-for-npm-v12/,
https://github.com/npm/cli/releases/tag/v12.0.0).

| Check | Report when | Skip when | Severity |
|---|---|---|---|
| Scripts re-enabled broadly | `allowScripts` in `package.json` or `allow-scripts` in `.npmrc` allows all packages, uses wildcards, or names packages with no native build need | The allowlist names a few packages with native builds (for example `esbuild`, `sharp`) at pinned versions | MEDIUM; HIGH if an allowed package is in the feed |
| Git and remote deps re-enabled | `.npmrc` sets `allow-git` or `allow-remote` to allow all | Specific, reviewed sources | MEDIUM |
| Old npm in CI | CI or Dockerfile pins an npm older than v12 while installing third-party packages, with no `--ignore-scripts` | `npm ci --ignore-scripts` is used | LOW |
| Install hooks in the project's own dependencies | A dependency's `preinstall`/`postinstall` makes network calls or reads `~/.npmrc`, `~/.config/gh`, cloud credentials | none | CRITICAL (see `threat-intelligence.md`) |

Keeping npm v12's default of disabled dependency scripts is the recommended posture (D§12:
https://brco.dev/insights/updates/npm-supply-chain-attacks-2026/).

## TypeScript-Specific Issues

| Pattern | Risk | Fix |
|---------|------|-----|
| `as AdminUser` type assertion | Bypasses type safety at compile time, no runtime check | Runtime validation (Zod, io-ts) |
| `any` type on security-critical data | Disables type checking entirely | Use strict types |
| `@ts-ignore` above security code | Hides type errors that may indicate bugs | Fix the type error |
| `JSON.parse(data) as SecureType` | No runtime validation of parsed data | Use Zod schema validation |
| Non-null assertion `user!.isAdmin` | Crashes if null, may bypass checks | Proper null checking |

## Dependency Risks

| Package | Issue | Alternative |
|---------|-------|-------------|
| `lodash` (older versions) | Prototype pollution in merge/set/defaultsDeep | Update or use `lodash.merge` with frozen proto |
| `minimist` | Prototype pollution | `yargs`, `commander` |
| `qs` (older versions) | Prototype pollution via nested objects | Update to latest |
| `express-fileupload` | Path traversal if `mv()` used with user filename | Sanitize filename |
| `jsonwebtoken` | Algorithm confusion if not specifying algorithms | Always set `algorithms: ['RS256']` |
| `axios` | SSRF if user controls URL | Validate URL, deny private ranges |

## Common Anti-Patterns

```javascript
// DANGEROUS: Template literal SQL
const user = await db.query(`SELECT * FROM users WHERE id = '${req.params.id}'`);
// SAFE:
const user = await db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);

// DANGEROUS: Path traversal
const file = path.join('/uploads', req.query.filename);
// SAFE:
const safeName = path.basename(req.query.filename); // Strip directory traversal
const file = path.join('/uploads', safeName);

// DANGEROUS: Open redirect
res.redirect(req.query.returnUrl);
// SAFE:
const url = new URL(req.query.returnUrl, 'https://myapp.com');
if (url.origin === 'https://myapp.com') res.redirect(url.pathname);
```
