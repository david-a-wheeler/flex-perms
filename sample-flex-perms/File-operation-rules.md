# File Operation Rules

## Deny Rules
- `/\.ssh/id_[^.]*$` - SSH private keys (matches `id_rsa`, not `id_rsa.pub`)
- `/\.ssh/.*_rsa$` - RSA private keys (matches `key_rsa`, not `key_rsa.pub`)  
- `(^|/)\.\.(/|$)` - Directory traversal (`../file`, `/path/../file`, `/path/..`)

## Ask Rules  
- `/etc/` - System config directories
- `~/.config/` - User config directories
- `/\.claude` - Claude Code config

## Allow Rules
- `\.(md|txt)$` - Markdown and text files

## Adding Rules
Create `.rule` files with INI format:
- `deny/Read/name.rule`
- `ask/Write/name.rule`
- `allow/Edit/name.rule`
