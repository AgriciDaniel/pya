# Rust Security Patterns

## The Unsafe Audit

> 80%+ of Rust vulnerability reports involve `unsafe` code.
> 20% of crates contain at least one `unsafe` block.
> 34% of crates call into crates that use `unsafe`.

## Dangerous Patterns

| Pattern | Risk | CWE | Severity | Fix |
|---------|------|-----|----------|-----|
| `unsafe { *raw_ptr }` | Use-after-free, null deref | CWE-416/476 | CRITICAL | Verify lifetime, use safe refs |
| `std::mem::transmute` | Type confusion, UB | CWE-843 | CRITICAL | Use `From`/`Into` traits |
| `std::mem::uninitialized()` | Reading uninitialized memory | CWE-908 | CRITICAL | Use `MaybeUninit` |
| FFI without `catch_unwind` | Unwinding across FFI = UB | CWE-758 | HIGH | Wrap FFI calls with `catch_unwind` |
| `Box::from_raw` without matching `into_raw` | Double-free | CWE-415 | CRITICAL | Match ownership transfers |
| `slice::from_raw_parts` with wrong length | Buffer overflow | CWE-120 | CRITICAL | Verify bounds |
| `unsafe impl Send/Sync` | Data race | CWE-362 | HIGH | Verify thread safety manually |

## Unsafe Audit Methodology

When reviewing Rust code, focus EXCLUSIVELY on:

1. **Every `unsafe` block**: What invariant does it rely on? Is that invariant guaranteed?
2. **Every FFI boundary**: Does ownership transfer correctly? Is unwinding handled?
3. **Every `unsafe impl`**: Is the safety contract actually upheld?
4. **Every raw pointer dereference**: Is the pointer guaranteed non-null and valid?

### Common Unsafe Soundness Holes

```rust
// DANGEROUS: Lifetime extension via transmute
unsafe {
    let static_ref: &'static str = std::mem::transmute(local_string.as_str());
    // local_string may be dropped → dangling reference!
}

// DANGEROUS: Aliasing violation
unsafe {
    let ptr = &mut data as *mut T;
    let ref1 = &*ptr;
    let ref2 = &mut *ptr; // UB: mutable + immutable reference coexist!
}

// DANGEROUS: FFI ownership mismatch
extern "C" {
    fn c_function(ptr: *mut Data); // Does C free this? Or do we?
}
// Double-free if both Rust and C try to free
```

## Safe Rust Issues (No `unsafe` Required)

| Pattern | Risk | Severity | Fix |
|---------|------|----------|-----|
| `panic!()` in library code | DoS, unexpected termination | MEDIUM | Return `Result`, handle errors |
| `.unwrap()` on user input | Panic on malformed input | MEDIUM | Use `?` or match |
| Unbounded recursion | Stack overflow | MEDIUM | Add depth limit or use iteration |
| `format!` with user input in SQL | SQL injection (via diesel raw) | HIGH | Use diesel query builder |
| `Command::new("sh").arg("-c").arg(user_input)` | Command injection | CRITICAL | Use `Command::new(binary).args(vec)` |
| Regex without timeout | ReDoS | MEDIUM | Use `regex` crate (guarantees linear time) |

## Dependency Security

```toml
# Check for known vulnerabilities:
# cargo install cargo-audit
# cargo audit

# Check for unsafe usage in dependencies:
# cargo install cargo-geiger
# cargo geiger
```

| Concern | Detection | Fix |
|---------|-----------|-----|
| Yanked crates in Cargo.lock | `cargo audit` | Update dependencies |
| Unmaintained dependencies | `cargo audit` with `--deny unmaintained` | Find alternatives |
| Excessive unsafe in deps | `cargo geiger` | Evaluate or replace |
| Build scripts (`build.rs`) with network access | Manual review | Audit build scripts |

## Crypto Patterns

```rust
// DANGEROUS: Using rand (not crypto-safe) for secrets
use rand::Rng;
let token: u64 = rand::thread_rng().gen(); // NOT cryptographically secure!

// SAFE: Use rand with OsRng or rand_chacha
use rand::rngs::OsRng;
let mut key = [0u8; 32];
OsRng.fill_bytes(&mut key);
```
