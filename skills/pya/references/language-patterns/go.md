# Go Security Patterns

## Dangerous Functions

| Function | Risk | CWE | Severity | Safe Alternative |
|----------|------|-----|----------|-----------------|
| `exec.Command("sh", "-c", userInput)` | Command injection | CWE-78 | CRITICAL | `exec.Command(binary, args...)` without shell |
| `fmt.Sprintf` into SQL | SQL injection | CWE-89 | CRITICAL | `db.Query(sql, params...)` |
| `math/rand` for security | Predictable randomness | CWE-330 | HIGH | `crypto/rand` |
| `filepath.Clean(userInput)` for security | Does NOT prevent traversal | CWE-22 | HIGH | `os.OpenRoot()` (Go 1.24+) |
| `template.HTML(userInput)` | XSS bypass | CWE-79 | HIGH | `html/template` auto-escaping |
| `text/template` for HTML | No auto-escaping | CWE-79 | HIGH | `html/template` |
| `http.ListenAndServe` (no TLS) | Unencrypted traffic | CWE-319 | MEDIUM | `http.ListenAndServeTLS` |
| `==` for secret comparison | Timing attack | CWE-208 | MEDIUM | `subtle.ConstantTimeCompare()` |
| `ioutil.ReadAll(r.Body)` without limit | DoS via large body | CWE-770 | MEDIUM | `io.LimitReader(r.Body, maxSize)` |

## Go-Specific Vulnerabilities

### Path Traversal Misconception

```go
// DANGEROUS: filepath.Clean does NOT prevent traversal!
cleanPath := filepath.Clean(userInput)
data, _ := os.ReadFile(filepath.Join(baseDir, cleanPath))
// userInput = "../../../../etc/passwd" → filepath.Clean returns "../../../../etc/passwd"

// SAFE (Go 1.24+): os.OpenRoot
root, _ := os.OpenRoot("/var/data")
file, err := root.Open(userInput) // Cannot escape /var/data

// SAFE (pre-1.24): Resolve and verify prefix
absPath, _ := filepath.Abs(filepath.Join(baseDir, userInput))
if !strings.HasPrefix(absPath, baseDir) {
    return errors.New("path traversal attempt")
}
```

### Race Conditions (Data Races on Multiword Values)

```go
// DANGEROUS: Data race on interface value
var handler http.Handler // interface = pointer + type (two words)
go func() { handler = maliciousHandler }() // Write
handler.ServeHTTP(w, r) // Read: may read half-updated value!

// DANGEROUS: Data race on slice
var users []User
go func() { users = append(users, newUser) }() // Write
for _, u := range users {} // Read: undefined behavior

// SAFE: Use sync.Mutex or channels
var mu sync.Mutex
mu.Lock()
handler = newHandler
mu.Unlock()
```

### Goroutine Leaks & Resource Exhaustion

```go
// DANGEROUS: Goroutine leak (no cancellation)
func handler(w http.ResponseWriter, r *http.Request) {
    go func() {
        for { // Infinite loop: goroutine never stops
            doWork()
        }
    }()
}

// SAFE: Use context for cancellation
func handler(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    go func() {
        for {
            select {
            case <-ctx.Done():
                return
            default:
                doWork()
            }
        }
    }()
}
```

## Framework Patterns

### net/http

| Pattern | Risk | Fix |
|---------|------|-----|
| `http.DefaultServeMux` in production | Global mux, route hijacking | Create dedicated `http.NewServeMux()` |
| Missing `r.Body.Close()` | Resource leak | `defer r.Body.Close()` |
| No request size limit | DoS | `http.MaxBytesReader()` |
| `http.Redirect` with user URL | Open redirect | Validate URL, path-only redirect |

### Gin / Echo / Fiber

| Pattern | Risk | Fix |
|---------|------|-----|
| `c.HTML()` with `text/template` | XSS (no auto-escape) | Use `html/template` |
| `c.Param()` in file path | Path traversal | Validate, use `filepath.Base()` |
| Missing CORS configuration | Overly permissive | Configure explicit origins |
| `c.Bind()` to struct with unexported fields | Mass assignment | Use explicit binding tags |

## Crypto Patterns

```go
// DANGEROUS: math/rand for tokens
token := fmt.Sprintf("%d", rand.Int()) // Predictable!

// SAFE: crypto/rand
b := make([]byte, 32)
crypto_rand.Read(b)
token := base64.URLEncoding.EncodeToString(b)

// DANGEROUS: Timing-vulnerable comparison
if userToken == secretToken { // Timing attack possible

// SAFE: Constant-time comparison
if subtle.ConstantTimeCompare([]byte(userToken), []byte(secretToken)) == 1 {
```

## Dependency Risks

| Pattern | Risk | Fix |
|---------|------|-----|
| No `go.sum` file | Dependency tampering | Run `go mod tidy` |
| `replace` directives pointing to local paths | Build inconsistency | Remove for production |
| Old `golang.org/x/crypto` | Known CVEs | Update regularly |
| `go get` without version pinning | Version drift | Use exact versions in go.mod |
