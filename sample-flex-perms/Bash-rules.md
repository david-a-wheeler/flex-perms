# Bash Command Rules

## Deny Rules
- `^((/usr)?/bin/)?sudo[ \t]+` - Blocks `sudo`, `/bin/sudo`, `/usr/bin/sudo`
- `^((/usr)?/bin/)?rm[ \t]+-rf[ \t]+/` - Blocks `rm -rf /` (filesystem destruction)
- `^((/usr)?/bin/)?(curl|wget)[ \t]+.*\|[ \t]*(sh|bash|dash|ksh)` - Blocks download-and-execute

Pattern `[ \t]+` matches spaces/tabs (not newlines). Optional path prefixes catch full command paths.

## Adding Rules
Create `.rule` files with INI format:
- `deny/Bash/name.rule`
- `ask/Bash/name.rule`
- `allow/Bash/name.rule`
