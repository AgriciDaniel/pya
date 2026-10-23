# Ruby Security Patterns

## Dangerous Functions

| Function | Risk | CWE | Severity | Safe Alternative |
|----------|------|-----|----------|-----------------|
| `system(user_input)` | Command injection | CWE-78 | CRITICAL | `system(cmd, arg1, arg2)` array form |
| `exec(user_input)` | Command injection | CWE-78 | CRITICAL | `exec([cmd, cmd], arg)` |
| `` `#{user_input}` `` | Command injection | CWE-78 | CRITICAL | Array form system calls |
| `%x{#{user_input}}` | Command injection | CWE-78 | CRITICAL | Array form system calls |
| `eval(user_input)` | Code injection | CWE-94 | CRITICAL | Avoid entirely |
| `send(user_input, ...)` | Arbitrary method call | CWE-94 | HIGH | Allowlist of methods |
| `constantize(user_input)` | Arbitrary class instantiation | CWE-470 | HIGH | Allowlist of classes |
| `Marshal.load(data)` | Deserialization RCE | CWE-502 | CRITICAL | `JSON.parse()` |
| `YAML.load(data)` | Deserialization RCE | CWE-502 | CRITICAL | `YAML.safe_load()` |
| `IO.read(user_path)` | Path traversal | CWE-22 | HIGH | Validate path prefix |
| `open(user_input)` | Command injection via pipe | CWE-78 | CRITICAL | `File.open()` (no pipe support) |

## Ruby on Rails Vulnerabilities

| Pattern | Risk | Severity | Fix |
|---------|------|----------|-----|
| `params.permit!` or no strong params | Mass assignment | HIGH | Whitelist with `params.require(:x).permit(:a, :b)` |
| `raw(user_input)` in view | XSS | HIGH | Use `<%= %>` (auto-escaped) |
| `.html_safe` on user input | XSS | HIGH | Let Rails auto-escape |
| `render inline: user_input` | Template injection/XSS | CRITICAL | Use template files |
| `find_by_sql("... #{params[:id]}")` | SQL injection | CRITICAL | Use parameterized: `where(id: params[:id])` |
| `where("name = '#{params[:name]}'")` | SQL injection | CRITICAL | `where(name: params[:name])` or `where("name = ?", params[:name])` |
| `redirect_to params[:url]` | Open redirect | MEDIUM | `redirect_to` with path only, validate host |
| `send_file params[:path]` | Path traversal | HIGH | Validate against allowed directory |
| `ActiveRecord::Base.connection.execute(sql)` | SQL injection if interpolated | CRITICAL | Use ActiveRecord query interface |
| Missing `protect_from_forgery` | CSRF | MEDIUM | Enabled by default, don't disable |

## Common Anti-Patterns

```ruby
# DANGEROUS: SQL injection via string interpolation
User.where("email = '#{params[:email]}'")

# SAFE: Hash conditions (parameterized)
User.where(email: params[:email])

# SAFE: Placeholder (parameterized)
User.where("email = ?", params[:email])

# DANGEROUS: open() with pipe character
open("|#{user_input}") # Executes as command if starts with |

# SAFE: File.open (no pipe support)
File.open(validated_path, "r")

# DANGEROUS: Kernel#open with user URL (SSRF)
open(user_url).read # Can read local files too!

# SAFE: Use URI and restrict
uri = URI.parse(user_url)
raise "Invalid" unless uri.is_a?(URI::HTTPS)
```

## Dependency Security

```bash
# Check for known vulnerabilities
bundle audit check --update

# Key vulnerable gems (historical):
# - nokogiri (XXE, buffer overflow) - keep updated
# - rails (multiple CVEs per year) - keep updated
# - devise (auth bypass in older versions)
# - paperclip (deprecated, path traversal) - use ActiveStorage
# - rest-client (backdoor in 2019 incident)
```
