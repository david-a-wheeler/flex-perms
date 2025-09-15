# Guide to flex-perms

## Brief summary

The `flex-perms` system enables people to easily implement fine-grained
permission control over Claude Code and perhaps other AI code assistants.

Its permissions are defined in **permission directories** like `.claude/flex-perms/` (project-specific permissions) and `~/.claude/flex-perms/` (user-specific permissions for all projects), which are checked in order.  These contain optional subdirectories named `deny` (forbid this event), `ask` (ask for user permission), and `allow`. Each of these subdirectories can contain one or more **ToolName** directories for tools (like `WebFetch`, `Edit`, or `Bash`), and inside each tool directory are individual `NAME.rule` files defining specific rules. For example, `.claude/flex-perms/deny/Bash/sudo.rule`.

Each `NAME.rule` file has a required `[info]` section and one or more `[clause.ID]` sections. Clauses contain one or more conditions in the form `field_path = Python_regex` (you don't need to quote the regular expressions, making them easy to use).

Each permission directory is checked in turn. In each permission directory, the rules in `deny` are checked first, then `ask`, then `allow`. Within a rule, a rule matches if any of its clauses match ("OR" semantics), and a clause matches if all its conditions match ("AND" semantics).

A "policy" is the collection of decisions that would be made in the current context, based on the current permission directory list (in order). It represents the potential outcomes for events under the current configuration. Note: some parts of a policy can be project and/or user-specific.

## Detailed Description

To use `flex-perms`, you add a `hook` so the assistant will call
the program `flex-check.py` on an event
(typically the `PreToolUse` event). From then on, when the assistant
wants to determine if it's allowed to do something, it will send an
request event to `flex-check.py`, and receive a reply with
its decision. A decision can be one of three permission types
(deny, ask, allow). A decision can also be "undecided" (meaning that
other systems are free to make a decision).

### List of permission directories

The permission decision is made by consulting a sequence of
"permission directories" in order. Once a permission type is determined,
that's the decision and the rest of the directories aren't evaluated.

By default these permission directories are, in priority order:

* `{ENTERPRISE}/flex-perms` (organization-wide enforced rules)
* `$FLEX_CHECK_EXTRA_DIR` (if the environment variable is defined;
  this enables you to easily add a permission directory to specific processes)
* `./.claude/local/flex-perms` (project-level, your overrides)
* `./.claude/flex-perms` (project-level, everyone on the project)
* `$HOME/.claude/flex-perms` (user-level, applies to all projects you work on)
* `{ENTERPRISE}/default/flex-perms` (organization-wide defaults, checked
  after the other directories are checked first)

The value of `{ENTERPRISE}` depends on the operating system:

* Windows: `C:/ProgramData/Claude Code`
* MacOS: `/Library/Application Support/Claude Code`
* Unix/Linux: `/etc/claude-code`

### Permission directory structure

Within each permission directory is a subdirectory structure with
rule files:

```
{PERM}/{TOOL}/{NAME}.rule
```

Where:

- `{PERM}` is the permission type: `deny`, `ask`, or `allow`
- `{TOOL}` is the Claude Code tool name (WebFetch, Edit, Write, Bash, etc.)
- `{NAME}` is a user-chosen descriptive name
- `.rule` suffix indicates a rule definition

Directories and subdirectories that aren't present are ignored.

For example, in a permission directory, if the rule defined in
`deny/WebFetch/malware.rule` matched the information in
an event using the `WebFetch` tool, a `deny` decision would result.

When using a permissions directory, the rules are applied in order:

* `deny`: If any rule matches, then the event is denied.
* `ask`: If any rule matches, then the user is asked for confirmation before
  execution.
* `allow`: If any rule matches, the action is permitted without
  requiring user confirmation.

Note the precedence order: `deny`, then `ask`, then `allow`.

### Rule files

A `.rule` file is in INI format, a common text file format for configuration.
It has an `[info]` section and one or more `[clause.ID]` sections.
For a rule to match at runtime, at least one clause must match the event,
and for a clause to match, all of the clause's conditions must match.

In these INI format files,
any line beginning with '#' is ignored as a line comment.
INI files have sections identified on a line as `[SECTION_NAME]`,
and each section contains 1+ key/value pairs defined by `key = value`.
Values may continue on 1+ following lines by being indented.
The '#' has no special meaning if it is not the first character.
Trailing whitespace on a line, and blank lines, are ignored.

A rule file contains one `[info]`
section with at least `reason = {REASON TEXT}`
that provides a relatively short (about one sentence) textual
reason for the decision that is defined by this rule.
The `info` section may optionally include the keys `author`, `description`,
`timestamp`, and `flags`.
There's no `name` key because the filename provides that.

A rule file must also contain 1+ `[clause.ID]` sections, each uniquely named
where `ID` is any alphanumeric sequence.
Each `[clause]` section has a set of one or more `conditions` defined
in the form `key = value`, where each `key` is unique in a `[clause]`.

A rule *matches* an event if *any* clause in the rule matches the event
("OR" semantics).
A clause *matches* an event if *all* its conditions match the event
("AND" semantics).

When a rule is being evaluated to determine if it matches an event,
the clauses and conditions are evaluated in the order of the file.

### Conditions

A rule file clause contains one or more `condition`s.
A `condition` has a key and a value (with `=` between them).

The `condition` key optionally begins with `!` and is followed by a field path.
The `!` negates the condition (`!tool_input.url = foo` will match when
`foo` is *not* present in `tool_input.url`).
The optional `!` is followed by a `field path`.
Common tools and field paths to use for the condition are:

* WebFetch: `tool_input.url`
* Edit: `tool_input.file_path`
* Bash: `tool_input.command`

The `value` in a condition is a Python regular expression that describes
the text pattern to match.

Don't quote them with `"`; a `"` matches itself.
A letter or digit matches itself.
A `^` matches the beginning of the string, `\Z` matches the end of the string,
`$` matches the end of the string optionally preceded by one newline
(often not what you want), and `[A-Z]` matches the one uppercase
Latin letter (A through Z inclusive).
A dot matches any one character exception newline; write `\.` or `[.]`
to match a literal dot.
You can use options like `(AA|BB|CC)` to match `AA`, `BB`, or `CC`.
If you don't use `^`, `$`, or `\Z`, it will match anywhere in the input.

### Regular expressions

Again, the `value` in a condition is a Python regular expression (regex)
that describes the text pattern to match.
Don't quote them with `"`; a `"` matches itself.

In a regular expression pattern,
a letter or digit matches itself.
A `^` matches the beginning of the string, `\Z` matches the end of the string,
`$` matches the end of the string optionally preceded by one newline
(often not what you want), and `[A-Z]` matches the one uppercase
Latin letter (A through Z inclusive).
A dot matches any one character exception newline; write `\.` or `[.]`
to match a literal dot.
You can use options like `(AA|BB|CC)` to match `AA`, `BB`, or `CC`.
If you don't use `^`, `$`, or `\Z`, it will match anywhere in the input.

### Regular expression flags

By default a regex rule uses the default Python regular expression `re` rules.
If you set `info` section key `flags`, you change the interpretation
for this entire rul.
The `flags` value is a comma-separated list of re flag modifiers;
any whitespace around commas is ignored.
You can use the short or longnames, your choice.

Here are some useful ones, as described by the
[Python3 re library](https://docs.python.org/3/library/re.html).
We give the longname first and the shortname in parentheses.
You can use either, but we recommend using the longname:

* ASCII (A): Make `\w`, `\W`, `\b`, `\B`, `\d`, `\D`, `\s` and `\S`
  perform ASCII-only matching instead of full Unicode matching.
* IGNORECASE (I): Perform case-insensitive matching; expressions like
  [A-Z] will also match lowercase letters. Full Unicode matching (such
  as Ü matching ü) also works unless the ASCII flag is used to disable
  non-ASCII matches.
* MULTILINE (M): When specified, the pattern character '^' matches at the
  beginning of the string and at the beginning of each line (immediately
  following each newline); and the pattern character '$' matches at the end
  of the string and at the end of each line (immediately preceding each
  newline). By default, '^' matches only at the beginning of the string,
  and '$' only at the end of the string and immediately before the newline
  (if any) at the end of the string.
* DOTALL (S): Make the '.' special character match any character at all,
  including a newline; without this flag, '.' will match anything except
  a newline.
* VERBOSE (X): This flag allows you to write long regular expressions that
  look nicer and are more readable by allowing you to visually separate
  logical sections of the pattern and add comments. Whitespace within the
  pattern is ignored, except when in a character class, or when preceded by
  an unescaped backslash, or within tokens like *?, (?: or (?P<...>. For
  example, (? : and * ? are not allowed. When a line contains a # that is
  not in a character class and is not preceded by an unescaped backslash,
  all characters from the leftmost such # through the end of the line
  are ignored.

### Permission directory options

You can define an `options.json` configuration file inside a permission
directory, which will configure it further.

#### Defining one rule for multiple tools

The key `see` in the `options.json` file lets you define one rule
for multiple tools. The key, if present, must be a
a map of tool name(s) to a a comma-separated
list of other tool names (as strings) to consult.

For example, if this is in `.claude/flex-perms/options.json` then
many named tools will also check the rules for a
pseudo-tool named `FileAccess`.:

**Format:**
```json
{
  "see": {
    "Read": ["FileAccess"],
    "Edit": ["FileAccess"],
    "Write": ["FileAccess"],
    "Grep": ["FileAccess"]
  }
}
```

This can be followed to arbitrary levels, but avoid cycles.

#### Support in rules for environment variable matching

You can inject selected environment variables into rules for dynamic security policies. This is useful for environment-specific configurations while maintaining security by only exposing explicitly listed variables.

#### Configuring which environment variables are visible

Add an `env` array to your `options.json` file to specify which environment variables should be available to rules:

```json
{
  "env": ["HOME", "PATH", "ALLOWED_TOKEN"],
}
```

#### How environment variable matching works

1. When an `options.json` file contains an `env` array, flex-perms reads the specified environment variables
2. These variables are injected into the request JSON under an `env` key
3. Rules can then reference those environment variables using field path syntax: `env.VARIABLE_NAME = PATTERN`
4. Only variables explicitly listed in the `env` array are accessible to rules
5. Possibly-missing environment variables can be handled with optional field paths (`env.VAR?`)

#### Example of matching on environment variable values

**File: `~/.claude/flex-perms/deny/WebFetch/env-security.rule`**

```ini
[info]
reason = Special ALLOWED_TOKEN values and access from production is forbidden.

[clause.1]
# Deny any requests if ALLOWED_TOKEN is set to "secure123"
env.ALLOWED_TOKEN? = ^secure123\Z

[clause.2]
tool_input.url = ^https://api\.example\.com(/|\Z)
# Block access to this URL if DEBUG_MODE is set to "production"
env.DEBUG_MODE? = ^production$
```

### Controlling the system with environment variables

Some environment variables can configure this system itself.
You shouldn't normally need them, but here they are:

* `FLEX_CHECK_PERM_DIRS`: List of permission directories, newline-separated
  (newline separation easily handles spaces, backslashes, and other nonsense).
  If set it overrides the default.
* `FLEX_CHECK_PERMS`: If set, inserted as an added *second* permission
  directory after environment permission directory.
  This simulates command line arguments.
* `FLEX_CHECK_LOGFILE`: If set, this is the path to a log file for recording
  permission requests and responses in JSONL format (JSON Lines).
  Each log entry is written as a single JSON object on one line with the format:
  `{"request": {...}, "response": {...}}`
  This format is fault-tolerant (crashes don't corrupt previous entries) and
  supports streaming processing.
* `FLEX_CHECK_DEBUG`: Set to `true` to enable verbose debug output
  to stderr showing rule processing steps. You can also enable with the
  `--debug` flag to `flex-check.py`

### Special capabilities

The following are other special capabilities not usually needed.

* A field path is a sequence of one or more field names, each optionally
  followed by '?', separated by `.`. The `?` indicates it's *not* an
  error if the field name is not present. Normally that's an error, so
  that misspelled field names won't cause rules to be misinterpreted.
  E.g., `tool_input.foo?` means that `foo` is not required
  in the request.
* Field names in field paths are case-sensitive.
  We detect and report on case errors, so case errors are easily fixed.
* JSON data is normally turned into a string for regex matching.
  However, JSON `null` (Python `None`) is dangerous to handle that way.
  If you need to match them, use `]NULL[` to match `null`, and
  `]NOT_NULL[` to match anything other than `null`. These are intentionally
  not legal regex patterns, to ensure they can't be mistaken for anything else.

### Terminology Reference

| Term | Definition / Meaning | Example |
|------|-------------------|---------|
| **Permission Directory** | A directory containing rules that define allowed, denied, or ask decisions. Can include `deny`, `ask`, and `allow` subdirectories. | `/etc/claude-code/flex-perms` |
| **Permission Directory List** | Ordered list of permission directories consulted when evaluating a request. | |
| **Rule** | A single `.rule` INI file containing an `[info]` section and 1+ `[clause]` sections. | `deny/WebFetch/malware.rule` |
| **Policy** | The collection of decisions that would be made in the current context, based on the current permission directory list (in order). It represents the potential outcomes for events under the current configuration. Note that changing the current directory can change the active policy because some policies are project-specific. | “The policy indicates that WebFetch requests to `example.com` are denied, Bash commands matching `rm -rf` are asked for confirmation, and other edits are allowed.” |
| **Info Section `[info]`** | Required section in a rule. Contains metadata about the rule. Must include `reason`. Optional: `author`, `description`, `timestamp`, `flags`. | `[info]`<br>reason = Block known malware<br>author = Alice<br>flags = IGNORECASE |
| **Clause `[clause.ID]`** | A named grouping of one or more conditions within a rule. OR semantics across clauses. | `[clause.length]`<br>min = ^.{8,128}$ |
| **Condition** | Atomic key/value test inside a clause. AND semantics across conditions within a clause. Key is a field path, value is a Python regex. Optional negation with `!` in the key. | `!tool_input.url = ^https://example\.com/.*$` |
| **Field Path** | A dot-separated path of names for JSON navigation; may include `?` after a name for optional fields. Case-sensitive. | `tool_input.file_path?` |
| **Decision** | Outcome of evaluating a rule for an event: `deny`, `ask`, or `allow`, or `undecided`. | `deny` |
| **Subsection ID** | Alphanumeric identifier for a clause. Optional; used as `[clause.ID]`. Must be unique within a rule. | `[clause.complexity]` |
| **Regex Flags** | Settings applied to the conditions’ regex evaluations. Stored in `[info]` as `flags`. | `flags = IGNORECASE,VERBOSE` |

## Library

You can use the program as a Python library by importing it.

Its class name is `FlexCheck` and it accepts a number of keyword
options (all optional):

* `perm_dirs`: List [str]. A list of permission directory paths.
* `logfile`: str. A path to a file for logging (in JSONL format)
* `extra_dir`: str. A path to an "extra" permission directory to place second.
* `debug: bool`. If true, generate debug info on stderr during rule processing.

## Rationale

The built-in permission system of Claude Code has many
frustrating limitations. For example, it can accept or reject on a
domain name for `WebFetch`, but that doesn't make sense for many sites
like `github.com`, where trustworthiness varies.
E.g., in an issue or pull request, anyone can post anything, including attacks,
while other areas are canonical and highly trustworthy.

This library tries to provide a flexible alternative, building
on constructs many developers already know.

Here are some key points:

* It builds on the Claude Code configuration directory order
  (enterprise, etc.). We added a lowest-priority "enterprise default"
  because some will want that capability.
* It uses regular expressions for pattern-matching, which are flexible
  and widely-understood.
* It uses INI format. Unlike JSON, INI doesn't require
  quirky escaping for regexes. Unlike YAML, there aren't footguns on quoting.
  It also has built-in Python support.
* It uses JSON paths to specify values, so it can immediately analyze
  anything in the JSON event.
* You can analyze environment variables, but they must be expressly requested.
  This reduces the risk of unintentional leakage.

## Possible future directions

This might in future gain:

* "include". An `[include]` section lists what to import, and it
  loads the corresponding file(s) from the permission directories'
  `includes` directory.
* "substitution". A `[substitutions]` section lists keys and their
  substitutions. Before processing a regular expression, the substitutions
  are applied in order. This enables use of predefined regular expressions
  in larger expressions.
* "ALL" tool. After trying out the rules for a tool and its "see" groups,
  try out rules for the pseudo ALL tool. Rules here are *always* tried.
  Note that conditions in these rules
  will often need to use `?`, e.g., `tool_input.url?`
* "test". Add self-test clauses. E.g., `[test.NAME.hit]` if the test
  data should match this rule, and `[test.NAME.miss]` if it should not.
  We want people to be able to insert spaces, newlines, etc., so we'll
  want to interpret backslashes in the values. Something like:

~~~~ini
[test.1.hit]
tool_name: Bash
tool_input.command: sudo\nrm -rf /
~~~~
