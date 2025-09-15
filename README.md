# flex-perms project

This `flex-perms` project implements an easy-to-use and flexible
fine-grained security control system for controlling AI code assistants,
particularly Claude Code.

## Goals

`Flex-perms` is designed to be:

* easy to install
* easy to use
* highly flexible
* easy to review

Every rule is a separate file, so you can easily share what you've developed.

## TL;DR

Install per [INSTALL.md](./INSTALL.md). You can then create rule files.

Here's an example rule file you could store in file
`~/.claude/flex-perms/deny/WebFetch/no-pastebin-binaries.rule`:

~~~~ini
# Demo of a .rule file. Put it in a "deny" directory
[info]
reason = Dangerous request.
author = Could B. YourName

# A rule matches if ANY of its clauses match ("OR"),
# and a clause matches only if ALL its conditions match ("AND").

# Block access to SSH private keys and config
[clause.ssh_keys]
tool_input.command = /(\.ssh\/(id_|identity|config)|\/etc\/ssh\/)/

# Don't download .exe from pastebin
[clause.pastebin_binary]
tool_input.url = /^https?:\/\/pastebin\.com\.?\/.*\.(bin|exe)(\/|$)/

# Don't modify config files while running production. All lines must match.
[clause.production_blackout]
env.ENVIRONMENT = ^production$
tool_name = ^(Write|Edit)$
tool_input.file_path = (config|\.json$)
~~~~

A rule file is named `NAME.rule`. It has a required `[info]` section and one or more `[clause.ID]` sections. Clauses contain one or more conditions in the form `field_path = Python_regex`.”

## Brief summary

Permissions are defined in **permission directories** like `.claude/flex-perms/` (project-specific permissions) and `~/.claude/flex-perms/` (user-specific permissions for all projects), which are checked in order.

Each permission directory is organized as:

```
{PERM}/{TOOL}/{NAME}.rule
```

Where:

* PERM: `deny` (forbid this event), `ask` (ask for user permission), or `allow`
  (immediately permit without asking the user)
* TOOL: A toolname (e.g., `WebFetch`, `Edit`, or `Bash`)

Inside that are individual `NAME.rule` files defining a rule.
An example of a rule file might be
`.claude/flex-perms/deny/Bash/sudo.rule`.

Each permission directory is checked in turn. In each permission directory, the rules in `deny` are checked first, then `ask`, then `allow`. Within a rule, a rule matches if any of its clauses match ("OR" semantics), and a clause matches if all its conditions match ("AND" semantics).

## Installing

See [INSTALL.md](./INSTALL.md).
Your assistant should be able to follow its directions.

## Guide

For more information see [GUIDE.md](./GUIDE.md).

## Non-goals

No system like this can perfectly prevent attacks.
This system is intended to be part of an overall risk reduction approach
so that you can use assistants while managing risk.
Nothing can prevent all risks, but you can take steps to manage them.
