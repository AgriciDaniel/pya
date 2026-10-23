# C# / .NET Security Patterns

## Dangerous Functions

| Function | Risk | CWE | Severity | Safe Alternative |
|----------|------|-----|----------|-----------------|
| `BinaryFormatter.Deserialize()` | RCE via deserialization | CWE-502 | CRITICAL | `System.Text.Json`, Protobuf |
| `Process.Start(userInput)` | Command injection | CWE-78 | CRITICAL | Allowlist commands, use ProcessStartInfo |
| `SqlCommand(sql + input)` | SQL injection | CWE-89 | CRITICAL | `SqlParameter` / parameterized queries |
| `Assembly.Load(userInput)` | Arbitrary code loading | CWE-470 | CRITICAL | Allowlist assemblies |
| `Activator.CreateInstance(userType)` | Arbitrary instantiation | CWE-470 | HIGH | Type allowlist |
| `XmlSerializer(Type.GetType(input))` | Type confusion | CWE-502 | HIGH | Fixed type serializers |
| `ObjectStateFormatter` | Deserialization | CWE-502 | CRITICAL | Avoid (ASP.NET ViewState) |
| `LosFormatter` | Deserialization | CWE-502 | CRITICAL | Avoid |
| `XmlDocument.Load()` (default) | XXE | CWE-611 | HIGH | Set `XmlResolver = null` |
| `File.ReadAllText(userPath)` | Path traversal | CWE-22 | HIGH | Validate path prefix |
| `HttpUtility.HtmlEncode` missing | XSS | CWE-79 | HIGH | Use Razor auto-encoding |
| `DirectorySearcher.Filter = "..." + input` | LDAP injection | CWE-90 | HIGH | Escape special chars, parameterized filter |
| `new DESCryptoServiceProvider()` | Weak crypto (deprecated) | CWE-327 | HIGH | `Aes.Create()` with 256-bit key |
| `MD5.Create()` for password hashing | Weak hash for auth | CWE-327 | HIGH | `Rfc2898DeriveBytes` or `BCrypt.Net` |

## ASP.NET Core Vulnerabilities

| Pattern | Risk | Severity | Fix |
|---------|------|----------|-----|
| `Html.Raw(userInput)` | XSS | HIGH | Use `@Model.Value` (auto-encoded) |
| `FromSqlRaw($"... {input}")` | SQL injection | CRITICAL | `FromSqlInterpolated()` or parameters |
| `[AllowAnonymous]` on sensitive endpoints | Auth bypass | HIGH | Remove, verify auth requirement |
| Missing `[ValidateAntiForgeryToken]` | CSRF | MEDIUM | Add to POST/PUT/DELETE actions |
| `cors.AllowAnyOrigin().AllowCredentials()` | Credential theft | HIGH | Specify exact origins |
| `app.UseDeveloperExceptionPage()` in prod | Info disclosure | MEDIUM | Only in Development environment |
| Missing `[Authorize]` on controllers | Unauthorized access | HIGH | Add authorization |
| `ModelState` not checked before action | Invalid data processing | MEDIUM | Check `ModelState.IsValid` |
| `IFormFile` without validation | Malicious upload | HIGH | Validate type, size, scan content |

## Deserialization (Critical Threat)

```csharp
// CRITICAL: BinaryFormatter is ALWAYS dangerous
// Microsoft has deprecated it; do not use for ANY untrusted data
BinaryFormatter bf = new BinaryFormatter();
object obj = bf.Deserialize(untrustedStream); // RCE!

// Also dangerous:
// - NetDataContractSerializer
// - ObjectStateFormatter
// - LosFormatter
// - SoapFormatter
// - DataContractSerializer (with known types from untrusted source)

// SAFE: System.Text.Json
var obj = JsonSerializer.Deserialize<MyType>(jsonString);

// SAFE: Protobuf
var obj = ProtoBuf.Serializer.Deserialize<MyType>(stream);
```

## Entity Framework Security

```csharp
// DANGEROUS: Raw SQL with interpolation
var users = context.Users
    .FromSqlRaw($"SELECT * FROM Users WHERE Name = '{input}'")
    .ToList();

// SAFE: FromSqlInterpolated (parameterizes automatically)
var users = context.Users
    .FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {input}")
    .ToList();

// SAFE: LINQ (always parameterized)
var users = context.Users.Where(u => u.Name == input).ToList();
```

## ViewState Security (ASP.NET WebForms)

```csharp
// ViewState without MAC validation = deserialization attack vector
// Ensure in web.config:
// <pages enableViewStateMac="true" />
// <machineKey validation="HMACSHA256" />

// CVE-2020-0688: Pre-auth RCE via ViewState when machine key is known
// Always use unique, random machine keys in production
```

## Dependency Risks

| Package | Issue | Fix |
|---------|-------|-----|
| Newtonsoft.Json with `TypeNameHandling` | Deserialization RCE | Set `TypeNameHandling.None` or use System.Text.Json |
| Old ASP.NET MVC (< 5.2.7) | Various CVEs | Update to ASP.NET Core |
| `System.Drawing` on server | DoS via image parsing | Use `ImageSharp` or `SkiaSharp` |
| Log4net (older versions) | Configuration injection | Update |
