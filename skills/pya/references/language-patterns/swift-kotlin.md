# Swift & Kotlin (iOS/Android) Security Patterns

## Swift (iOS): Dangerous Patterns

| Pattern | Risk | CWE | Severity | Fix |
|---------|------|-----|----------|-----|
| `URLSession` without certificate pinning | MitM attacks | CWE-295 | HIGH | Implement `URLSessionDelegate` pinning |
| `UserDefaults` for secrets | Data accessible without auth | CWE-922 | HIGH | Use Keychain with `kSecAttrAccessible` |
| `UIWebView` (deprecated) | JavaScript injection, no security | CWE-79 | HIGH | Use `WKWebView` |
| `WKWebView` + `evaluateJavaScript(userInput)` | Code injection | CWE-94 | CRITICAL | Sanitize or avoid |
| `NSCoding`/`NSKeyedUnarchiver` from untrusted | Deserialization | CWE-502 | HIGH | Use `Codable` with JSON |
| `FileManager` without Data Protection | Files readable when locked | CWE-311 | MEDIUM | Set `.completeFileProtection` |
| Clipboard read without notification | Data leakage | CWE-200 | LOW | Minimize clipboard usage |
| Hardcoded API keys in source | Credential exposure | CWE-798 | HIGH | Use Info.plist or server-side |
| `allowsArbitraryLoads = true` in ATS | Allows HTTP | CWE-319 | MEDIUM | Remove, use HTTPS only |
| `canOpenURL` without validation | URL scheme hijacking | CWE-939 | MEDIUM | Validate scheme |

### Keychain Security

```swift
// DANGEROUS: Storing secrets in UserDefaults
UserDefaults.standard.set(apiKey, forKey: "secret") // Readable in backup!

// SAFE: Keychain with biometric protection
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccessControl as String: SecAccessControlCreateWithFlags(
        nil, .biometryCurrentSet, .privateKeyUsage, nil
    )!,
    kSecValueData as String: secretData
]
SecItemAdd(query as CFDictionary, nil)
```

### WKWebView JavaScript Bridge

```swift
// DANGEROUS: Exposing native functions to web content
webView.configuration.userContentController.add(self, name: "nativeHandler")
// If web content is untrusted, attacker can call native functions!

// SAFE: Validate origin before processing messages
func userContentController(_ controller: WKUserContentController,
                           didReceive message: WKScriptMessage) {
    guard message.frameInfo.isMainFrame,
          message.frameInfo.securityOrigin.host == "trusted.com" else { return }
}
```

---

## Kotlin (Android): Dangerous Patterns

| Pattern | Risk | CWE | Severity | Fix |
|---------|------|-----|----------|-----|
| `WebView.addJavascriptInterface(obj, "bridge")` | JS→Native RCE (API < 17) | CWE-94 | CRITICAL | Target API 17+, use `@JavascriptInterface` |
| `ContentProvider` without permissions | Data leak to any app | CWE-284 | HIGH | Add `android:permission` |
| Implicit `Intent` with sensitive data | Data intercepted by other apps | CWE-927 | HIGH | Use explicit intents |
| `SharedPreferences` for secrets | Readable without root (backup) | CWE-922 | HIGH | Use EncryptedSharedPreferences |
| `SQLiteDatabase.rawQuery(sql + input)` | SQL injection | CWE-89 | CRITICAL | Use parameterized queries |
| `Runtime.getRuntime().exec(cmd)` | Command injection | CWE-78 | CRITICAL | Avoid shell commands |
| `android:exported="true"` without checks | Component hijacking | CWE-926 | HIGH | Add intent-filter or permission check |
| `android:allowBackup="true"` | Data extraction via backup | CWE-312 | MEDIUM | Set false or encrypt |
| `android:debuggable="true"` in release | Debug access in production | CWE-489 | HIGH | Remove for release builds |
| `TrustManager` accepting all certs | MitM | CWE-295 | CRITICAL | Use default TrustManager |

### Android WebView Security

```kotlin
// CRITICAL: JavaScript interface on older APIs
webView.addJavascriptInterface(MyBridge(), "Android")
// On API < 17: ALL public methods callable from JS → RCE!
// On API 17+: Only @JavascriptInterface methods exposed

// DANGEROUS: Loading untrusted URLs with JS enabled
webView.settings.javaScriptEnabled = true
webView.loadUrl(userProvidedUrl) // Attacker's page can access bridge!

// SAFE: Restrict to specific domains
webView.webViewClient = object : WebViewClient() {
    override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
        return request.url.host != "trusted.example.com"
    }
}
```

### Encrypted Storage

```kotlin
// DANGEROUS: Plain SharedPreferences
getSharedPreferences("secrets", MODE_PRIVATE).edit()
    .putString("token", authToken).apply() // Readable in backups!

// SAFE: EncryptedSharedPreferences
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
val prefs = EncryptedSharedPreferences.create(
    context, "secrets", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
```

## Common Mobile Issues (Both Platforms)

| Issue | Detection | Severity |
|-------|-----------|----------|
| Certificate pinning absent | No SSL pinning implementation | HIGH |
| Root/jailbreak detection absent | No integrity checks | MEDIUM |
| Debug logging in release | `print()`/`Log.d()` with sensitive data | MEDIUM |
| Biometric auth bypass | Auth result not verified server-side | HIGH |
| Deep link handling without validation | `://` scheme handlers accepting any input | MEDIUM |
| Screenshot prevention missing | No `FLAG_SECURE` / `isSecureTextEntry` | LOW |
