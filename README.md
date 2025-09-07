# flex-perms project

This `flex-perms` project implements a flexible fine-grained security control
system for controlling AI code assistants, particularly Claude Code.

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
`~/.claude/flex-perms/deny/Bash/no-dd.rule`:

~~~~ini
# Demo of a rule
[info]
reason = Running the `dd` command is forbidden.

# A rule matches if ANY of its clauses match,
# and a clause matches if ALL its conditions match.
# Here we have one clause named `clause.dd`, and it has one condition.

[clause.dd]
tool_input.command = ^((/usr)?/bin/)?dd[ \t]+
~~~~

As you can guess, a rule file is named `NAME.rule`. It has a required `[info]` section and one or more `[clause.ID]` sections. Clauses contain one or more conditions in the form `field_path = Python_regex`.”

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
