# Shell / Bash Security Patterns

## The Cardinal Sin: Unquoted Variables

```bash
# DANGEROUS: Unquoted variable → word splitting + glob expansion
cd $DIR                    # If DIR="/tmp; rm -rf /", executes rm!
rm $FILE                   # If FILE="* .txt", expands glob!
if [ $VAR = "test" ]      # If VAR is empty, syntax error; if contains spaces, breaks

# SAFE: Always double-quote variables
cd "$DIR"
rm "$FILE"
if [ "$VAR" = "test" ]
```

## Dangerous Patterns

| Pattern | Risk | CWE | Severity | Safe Alternative |
|---------|------|-----|----------|-----------------|
| `eval "$user_input"` | Command injection | CWE-78 | CRITICAL | Never eval user input |
| `$($user_input)` | Command substitution injection | CWE-78 | CRITICAL | Validate/allowlist commands |
| `` `$user_input` `` | Same as above (backtick form) | CWE-78 | CRITICAL | Avoid backticks entirely |
| `source "$user_file"` | Arbitrary code execution | CWE-94 | CRITICAL | Validate file path/contents |
| `/tmp/myapp.$$` | Predictable temp file (symlink attack) | CWE-377 | HIGH | `mktemp` |
| `curl URL \| bash` | Pipe-to-shell (supply chain) | CWE-94 | CRITICAL | Download, verify hash, then execute |
| `export PATH=./bin:$PATH` | PATH injection | CWE-426 | HIGH | Use absolute paths |
| Unquoted `$@` in scripts | Argument injection | CWE-78 | HIGH | Use `"$@"` (quoted) |
| `echo $secret` | Secret in process list | CWE-200 | MEDIUM | `printf '%s' "$secret"` |
| `read` without `-r` | Backslash interpretation | CWE-78 | LOW | `read -r variable` |

## Command Injection Vectors

```bash
# DANGEROUS: User input in command
grep "$user_input" /var/log/app.log
# If user_input = "-r /etc/passwd #" → reads passwd!

# SAFE: Use -- to end options, or restrict input
grep -- "$user_input" /var/log/app.log
# Better: Validate input matches expected pattern
if [[ "$user_input" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    grep -- "$user_input" /var/log/app.log
fi

# DANGEROUS: Filename in command (may start with -)
for file in *; do
    cat $file  # If filename is "-rf", interpreted as flag!
done

# SAFE: Prefix with ./
for file in ./*; do
    cat "$file"
done
```

## Temp File Security

```bash
# DANGEROUS: Predictable temp file → symlink attack
TMPFILE="/tmp/myapp.$$"     # PID is predictable!
echo "data" > "$TMPFILE"    # Attacker symlinks /tmp/myapp.1234 → /etc/passwd

# SAFE: mktemp creates unique file with restrictive permissions
TMPFILE=$(mktemp) || exit 1
echo "data" > "$TMPFILE"
trap 'rm -f "$TMPFILE"' EXIT  # Clean up on exit

# SAFE: Temp directory
TMPDIR=$(mktemp -d) || exit 1
trap 'rm -rf "$TMPDIR"' EXIT
```

## ShellCheck References

| Code | Issue | Fix |
|------|-------|-----|
| SC2086 | Double quote to prevent globbing/splitting | Quote `"$var"` |
| SC2046 | Quote to prevent word splitting | Quote `"$(command)"` |
| SC2091 | Remove surrounding $() to avoid execution | Don't execute command output |
| SC2059 | Don't use variables in printf format string | `printf '%s' "$var"` |
| SC2034 | Variable appears unused | Check for typos |
| SC2155 | Declare and assign separately | `local var; var=$(cmd)` |
| SC2164 | Use `cd ... \|\| exit` for error handling | `cd "$dir" \|\| exit 1` |
| SC2068 | Double quote array expansions | `"${array[@]}"` |

## Safe Script Header

```bash
#!/usr/bin/env bash
set -euo pipefail  # Exit on error, undefined vars, pipe failures
IFS=$'\n\t'        # Safer word splitting (only newline and tab)

# Validate all inputs before use
validate_input() {
    local input="$1"
    if [[ ! "$input" =~ ^[a-zA-Z0-9_.-]+$ ]]; then
        echo "ERROR: Invalid input: $input" >&2
        exit 1
    fi
}
```

## CI/CD Script Security

```bash
# DANGEROUS: GitHub Actions script injection
echo "Processing: $PR_TITLE"  # PR_TITLE may contain $(malicious_command)

# SAFE: Use printf, never expand untrusted in command position
printf 'Processing: %s\n' "$PR_TITLE"

# DANGEROUS: curl pipe to shell in CI
curl -fsSL https://install.example.com | bash

# SAFER: Download, verify, then execute
curl -fsSL -o installer.sh https://install.example.com
echo "expected_sha256  installer.sh" | sha256sum -c -
bash installer.sh
```

## Heredoc Injection

```bash
# DANGEROUS: Unquoted heredoc delimiter allows variable expansion
cat << EOF > config.txt
password=$USER_INPUT   # If USER_INPUT contains $(rm -rf /), it executes!
EOF

# SAFE: Quote the delimiter to prevent expansion
cat << 'EOF' > config.txt
password=$USER_INPUT   # Literal text, no expansion
EOF
```

## Key Principles

1. **Always quote variables**: `"$var"`, `"$@"`, `"$(cmd)"`
2. **Use `set -euo pipefail`** at the top of every script
3. **Use `mktemp`** for temporary files
4. **Use `[[ ]]`** instead of `[ ]` (no word splitting inside `[[ ]]`)
5. **Use `printf`** instead of `echo` for data (no escape interpretation)
6. **Validate all external input** with regex pattern matching
7. **Use absolute paths** for commands (`/usr/bin/grep` not `grep`)
8. **Never use `eval`** with any variable that could contain user input
