# Sample flex-perms Configuration

This directory contains focused sample permission rules for Claude Code tools using the flex-perms system. These rules provide a minimal but effective starter set focusing on the most obviously problematic cases.

## Directory Structure

```
sample-flex-perms/
├── deny/     # Block truly dangerous operations
├── ask/      # Prompt for potentially sensitive operations  
└── allow/    # Explicitly permit common safe operations
```

Current rules cover essential tools:
- `WebFetch` - Prevent access to cloud metadata services
- `Bash` - Block dangerous system commands (sudo, destructive rm, curl|shell)
- `Read/Write/Edit` - Protect SSH private keys and prevent directory traversal
- `Grep` - Block searches for private key patterns

## Rule Files

Rule files use INI format with sections for info and clause(s). File names follow the pattern: `description.rule`

## Key Security Rules

**Directory Traversal Protection**: Files containing `dotdot` patterns like `(^|/)\.\.(/|$)` prevent assistants from quietly accessing files outside permitted directories using paths like `../../../etc/passwd` without making the intent obvious to users.

**Private Key Protection**: SSH and GPG private key patterns block access to cryptographic secrets while allowing public keys.

**System Command Safety**: Bash rules prevent privilege escalation (sudo), destructive operations (rm -rf /), and code injection (curl|bash).

## Philosophy

These rules are designed to be:
- **Minimal**: Only the most obviously problematic cases
- **Justifiable**: Easy to understand and agree with
- **Practical**: Won't block legitimate development work

## Usage

To use these rules:

1. Copy this directory to `$HOME/.claude/flex-perms/`
2. Modify the regular expressions to match your security requirements
3. Add or remove rules as needed for your environment

## Testing

Test rules using the flex-check.sh tool:

```bash
# Test a specific URL
echo '{"tool_name":"WebFetch","tool_input":{"url":"https://github.com"}}' | ./flex-check.py

# Run with these rules directly
FLEX_CHECK_PERM_DIRS="sample-flex-perms" ./flex-check.py
```
See individual tool documentation for more details on specific rule sets.
