# flex-perms project

This `flex-perms` project is designed to
provide a simple mechanism to implement very flexible security controls
on AI assistants. Its goal is to make it eaier to use agentic AI assistants
to develop code, and permitting them to automatically run many safe
commands, while blocking the assistant or forcing the assistant to ask
about performing certain actions. The goal is to make using the
assistant more secure, by enabling the assistant to do more things
automatically while still retaining control over it.

We currently focused on supporting Claude Code.
We hope to eventually support other AI assistants as well.

## Goals

`Flex-perms` is designed to be:

* easy to review: it's so simple that you can easily determine it's safe
* easy to install: it provides a simple file to install it
* easy to maintain: its structure makes how to use it obvious
* easy to share: it supports many subdirectories with many files, instead of
  a single large JSON file. This makes it easy to share configuration
  fragments with others
* flexible: Code's built-in system can restrict a domain,
  but it can't restrict on specific URL or filename patterns, or consider
  multiple values. We can.

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

## Brief summary

The `flex-perms` system enables people to easily implement fine-grained
permission control over Claude Code and perhaps other AI code assistants.

Its permissions are defined in **permission directories** like `.claude/flex-perms/` (project-specific permissions) and `~/.claude/flex-perms/` (user-specific permissions for all projects), which are checked in order.  These contain optional subdirectories named `deny` (forbid this event), `ask` (ask for user permission), and `allow`. Each of these subdirectories can contain one or more **ToolName** directories for tools (like `WebFetch`, `Edit`, or `Bash`), and inside each tool directory are individual `NAME.rule` files defining specific rules. For example, `.claude/flex-perms/deny/Bash/sudo.rule`.

Each `NAME.rule` file has a required `[info]` section and one or more `[clause.ID]` sections. Clauses contain one or more conditions in the form `field_path = Python_regex`.”

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
