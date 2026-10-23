# C/C++ Security Patterns

## Banned Functions (CERT C, Microsoft SDL)

| Function | Risk | CWE | Severity | Safe Alternative |
|----------|------|-----|----------|-----------------|
| `gets()` | Buffer overflow (unconditional) | CWE-120 | CRITICAL | `fgets(buf, size, stdin)` |
| `strcpy(dst, src)` | Buffer overflow | CWE-120 | CRITICAL | `strncpy()`, `strlcpy()`, `std::string` |
| `strcat(dst, src)` | Buffer overflow | CWE-120 | CRITICAL | `strncat()`, `strlcat()`, `std::string` |
| `sprintf(buf, fmt, ...)` | Buffer overflow | CWE-120 | CRITICAL | `snprintf(buf, size, fmt, ...)` |
| `printf(userInput)` | Format string attack | CWE-134 | CRITICAL | `printf("%s", userInput)` |
| `scanf("%s", buf)` | Buffer overflow | CWE-120 | HIGH | `scanf("%99s", buf)` with width |
| `malloc()` without null check | Null pointer deref | CWE-476 | MEDIUM | Check return value |
| `free(ptr); use(ptr)` | Use-after-free | CWE-416 | CRITICAL | Set ptr = NULL after free |
| `free(ptr); free(ptr)` | Double-free | CWE-415 | CRITICAL | Set ptr = NULL after free |
| `memcpy` without bounds check | Buffer overflow | CWE-120 | HIGH | Verify size <= dst capacity |
| `alloca(userSize)` | Stack overflow | CWE-121 | HIGH | Use `malloc` with size limit |
| `system(cmd)` | Command injection | CWE-78 | CRITICAL | `execve()` with array |
| `atoi(str)` | No error checking, UB on overflow | CWE-190 | MEDIUM | `strtol()` with error check |

## Memory Safety Patterns

### Buffer Overflow

```c
// DANGEROUS
char buf[64];
strcpy(buf, user_input); // No bounds check!

// SAFE
char buf[64];
strncpy(buf, user_input, sizeof(buf) - 1);
buf[sizeof(buf) - 1] = '\0';
```

### Use-After-Free

```c
// DANGEROUS
char *ptr = malloc(100);
free(ptr);
strcpy(ptr, "data"); // UB: use after free!

// SAFE
char *ptr = malloc(100);
free(ptr);
ptr = NULL; // Prevent accidental reuse
```

### Integer Overflow

```c
// DANGEROUS: Integer overflow in allocation size
size_t count = user_count; // e.g., 0xFFFFFFFF
size_t size = count * sizeof(struct Item); // Overflow → tiny allocation!
struct Item *items = malloc(size); // Under-allocated buffer

// SAFE: Check for overflow before multiplication
if (count > SIZE_MAX / sizeof(struct Item)) {
    return ERROR_OVERFLOW;
}
```

### Format String

```c
// CRITICAL: User controls format string
printf(user_input); // Can read/write arbitrary memory!
// Attacker sends: "%x%x%x%x%n" → writes to stack address

// SAFE: Always use format specifier
printf("%s", user_input);
```

## C++ Modern Mitigations

| Pattern | What it prevents | Use |
|---------|-----------------|-----|
| `std::unique_ptr<T>` | Use-after-free, double-free, leaks | Single ownership |
| `std::shared_ptr<T>` | Same + shared ownership | Shared ownership |
| `std::string` | Buffer overflow in strings | String handling |
| `std::array<T, N>` | Out-of-bounds (with `.at()`) | Fixed arrays |
| `std::vector<T>` | Buffer overflow (with `.at()`) | Dynamic arrays |
| `std::span<T>` (C++20) | Bounds-checked view | Array views |
| RAII pattern | Resource leaks | All resource management |
| `[[nodiscard]]` | Ignored error returns | Error-critical functions |

## Compiler Protections

Enable these flags for hardened builds:

```text
-fstack-protector-strong    # Stack canaries
-D_FORTIFY_SOURCE=2         # Runtime buffer overflow detection
-Wformat-security           # Format string warnings
-Werror=format-security     # Format strings as errors
-fPIE -pie                  # Position-independent executable (ASLR)
-Wl,-z,relro,-z,now         # Full RELRO (GOT protection)
-fsanitize=address          # AddressSanitizer (dev/test)
-fsanitize=undefined        # UBSanitizer (dev/test)
```

## CERT C Coding Standard (Key Rules)

| Rule | Description | Detection |
|------|-------------|-----------|
| ARR30-C | Don't form out-of-bounds pointers | Array access without bounds check |
| ARR38-C | Guarantee library functions don't overflow | Verify destination size |
| STR31-C | Guarantee storage for strings + null | Size calculations for string operations |
| MEM30-C | Don't access freed memory | Use-after-free patterns |
| MEM35-C | Allocate sufficient memory | Integer overflow in size calculation |
| INT30-C | Unsigned integer wrapping | Arithmetic without overflow check |
| INT32-C | Signed integer overflow is UB | Signed arithmetic near limits |
| FIO30-C | Exclude user input from format strings | printf/sprintf with user data as format |
| ENV33-C | Don't call system() | system() usage |
