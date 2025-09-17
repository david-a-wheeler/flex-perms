# Proposed changes

Here are proposed changes to the current system:

* "include". Identify rules to import.
  It loads the corresponding file(s) from the permission directories'
  `includes` directory.
* "substitutions". A `[substitutions]` section lists keys and their
  substitutions. Before processing a regular expression, the substitutions
  are applied in order. This enables use of predefined regular expressions
  in larger expressions.
* "ALL" tool. A pseudo-tool named ALL; rules for ALL are *always* tried
  after the "see" options.
* Self-test sections.

Below is a proposed design, with commentary. I express this in
present tense so we can use this text as documentation if we accept it.

* * *

## Substitutions

A rule file can define substitutions.
These create named and potentially reusable sub-patterns.
These substitutions can be local to only this rule
or be exported to rules that include them.

A rule file can have an optional `[substitutions.local]` and an
optional `[substitutions.external]` section
The `local` substitutions can only be used within this rule; the
`external` substitutions can be used transitively by other rules that include
this rule. A `[substitutions]` section isn't allowed, for clarity.

The substitution keys are used as a string substitute
inside a regex before using that transformed regex.
A later regex can use any previously-defined
substitution, and this can be effectively transitive.
To reduce the risk of accidental substitutions, substitution keys
must be at least 5 characters long.
This means `FILE` isn't allowed, but `${FILE}`, `$(FILE)`, and
`%FILE%` are allowed.
We recommend names with some surrounding punctuation to make it clear
a substitution is intended, without being prescriptive on the specific
punctuation.

After a rule has been loaded, its `includes` directives are processed.
Those included rules may export substitutions; if they do, they are
loaded into the "current external substitutions" list and the
"current local substitutions" list (they start with identical contents).
If there are no includes directives, or they don't export anything,
these two lists are empty lists.

The substitution key/value pairs are then processed in the order of the file.
That is, if both substitutions.local and substitutions.external exist, they
are processed in file order, and then their key/value pairs are processed
in order.
If a key being processed is already present in the
"current local substitutions" list, the rule is malformed.
As a consequence, you can't use the same key in any substitution section;
preventing redefinition counters some errors.
The value of the key/value pair undergoes "regex processing"
(described below).
The key and resulting processed regex is then appended to the list of
"current local substitutions". If it's defined in a .external
section, the key/value pair is
also appended to the "current external substitutions".

"Regex processing" takes a regex and applying the substitutions, in
current local substitutions list, in *reverse* order
(most recently defined backwards).
Note that this means that local substitutions can use substitution patterns
previously processed, even in `substitutions.external` sections, since the
current local substitutions list includes all substitutions in the
current external substitutions list.
The substitutions are a "global substitution" of exactly the key.
Inside a regex a key reference can appear 0 or more times and it will
be replaced with its value (it's a `/g` substitution).
There's no special syntax for replacement text in the regex.
That is, there's no required
`${...}` or similar syntax to indicate a replacement.
Every time the key *literally* appears in a regular expression,
it is replaced, without any special syntax to trigger a replacement.
This avoids the need to specially escape a regular expression that
doesn't use the replacement marker.

When the debug mode is enabled, each key is written with its value before
and after regex processing to simplify debugging.

Finally, when each condition is being loaded
(after processing the substitutions), its regex also undergoes
regex processing before use. As a result, it's easier to define regexes.
If the debug mode is on, any condition where regex processing changes the
regex being used is written to stderr.

Note that circularity of substitutions isn't possible. Processing always
uses a sequence of substitutions in a strict order.

Rationale: We require `substitutions.local` and `substitutions.external`
so that if we later need to support multiple sections, we can add an
optional third `.ID` parameter. If we allowed only `substitutions` then
it wouldn't be obvious if the second parameter `external` was making it
external or was a section with ID of `external`.

Rationale: We use "reverse order" of currently-active substitutions so that
if there is a `FILE` definition, and a later definition of `FILES` that uses
FILE, a reference to `FILES` will not accidentally use `FILE` instead.
We could do "longest key first" but I fear that might be confusing and
lead to unexpected matches. The substitutions most recently added
will also tend to be closest to their uses, and are more likely to be
what was intended.

Rationale: We do regex processing of substitutions as we read them in,
not later when the conditions are applied. That way, if a substitution
includes a text sequence that will *later* be defined, the later definition
can't affect its meaning. Any regex substitution's meaning will be
completely defined and frozen when it's processed in the rule that defines it.

Rationale: The checking of the key against the current local substitutions
ensures that the name of a substitution
key is unique among all substitution sections in this rule *and*
all external substitutions that were transitively
imported from `includes` sections.

Rationale: There's no namespace isolation for substitutions, however,
users can use long names to do essentially the same thing.

Here's an example, which matches a chmod command with one or more files,
as well a cp command with exactly two files:

~~~~ini
[substitutions]
$(FILE) = [A-Za-z0-9.,_-/]+
$[FILES] = $(FILE)([ \t]+$(FILE))*
SMILEY = :-\)

[clause.1]
tool_input.command = /^chmod[ \t]+[ugo=+-rwx0-9]+[ \t]+$[FILES]$/

[clause.2]
tool_input.command = /^cp[ \t]+$(FILE)[ \t]+$(FILE)$/

[clause.3]
tool_input.command = /^echo[ \t].*SMILEY/
~~~~

### Substitution design notes

*NOTE*: There are alternative ways we could have processed this:

* All regex substitutions could only occur when a condition regex is used.
  Then, and only then, could the substitutions occur.
  Then the internal stored format would be clear
  (it's just the value provided).
  However, this could mean that a later substitution might interfere
  with the interpretation of an earlier rule depending on the processing order.
  It would also be harder to detect
  a badly-written substitution regex pattern like `$[FOO] = [abc`.
  (though we *could* do the substitutions just to check on it).
  A downside of substituting as-we-go is that we can't easily see the
  "underlying" pattern during debugging - all processed values are pre-expanded.

The substitution keys are processed in reverse order (last first), so
later substitution definitions can use earlier ones.

To prevent hard-to-find errors:

* The key is replaced *exactly*, including any "variable" markers.
  We decided to *not* use a defining syntax like `FILES = ...` with a later
  special substitution syntax like `${FILES}`, because that approach
  would imply that the substitution syntax in other cases like
  `${something_else}` should also invoke a substitution.
  This alternative would imply the need to do complex escaping when
  *not* using a substitution.  Instead, we let the user control
  exactly what is substituted, so the user
  can choose a key (and substitution) that's most convenient for that user.
  That means we can't detect misspelled substitutions, but we don't
  expect that to be a serious problem, especially since this approach
  means the user doesn't have to create as many escapes.
* When the substitution section is read in, each line is processed in order,
  replacing all previous substitutions in their order. Then, when a
  condition is processed, all of the existing substitutions are replaced.
  This means later substitutions can reuse earlier ones, but
  not the other way around and there's no endless looping.
  I think this gives the most "natural" approach when combined with
  include files.
* Each substitution value must *itself* be a legal regular expression
  after applying all the later defined substitutions defined after it
  in the rule file.
  This is checked when the substitutions are first loaded (by compiling it).
  A rule with an illegal substitution is misformed.

## Include files

The `[info]` section supports an optional `includes` key.
If present, its value is a whitespace-separated list of rule file names
(including `.rule`).
These rule files will be loaded in sequence from the permission
directory's `includes` subdirectory.

Technical details:
The requesting rule is malformed
if an included file doesn't exist or can't be read.
The file can have directory separators (`/`), but cannot cause a final
path to escape the "includes" directory.
If there's a continuation line, a newline is silently
inserted before each continuation line, so you can conveniently create
a long list of rule file names without long lines.

An included rule file is processed similarly to normal rule files
(leading `#` is a comment,
trailing whitespace is removed). In principle
it has no *required* sections.
It can include substitutions and clauses.
It *must* include an `info` section with `reason` if this rule file has
one or more `clause` sections.
(A "primary" file must 1+ clauses, and that requirement triggers this rule.)
Included files may include other files, transitively, but won't
include a file that's already included (preventing endless loops
and making it easy to create utility rules).

Here is an example:

~~~~ini
# File includes/file.rule

# Substitutions have NO special substitution syntax, the %..% is arbitrary
[substitutions]
%FILE% = [A-Za-z0-9.,_-/]+

# File includes/files.rule
[info]
reason = No weird mysudo use.
includes = file.rule

# Substitutions have NO special substitution syntax. Notice we use
# $..$ here and %..% in another.
[substitutions]
$FILES$ = %FILE%([ \t]+%FILE%)*

[clause.1]
user_input.command = /^mysudo\s+$FILES$( *: *%FILE%)*/

# File demo.rule
[info]
reason = demo.
includes = files.rule

# Clauses have separate namespaces, they can reuse names.
[clause.1]
user_input.command = /^theirsudo\s+$FILES$( *: *%FILE%)*/
~~~~

Here is pseudocode:

~~~~
process_rule_file(file) -> decision, external_substitutions, pattern settings:
  - load file (INI format) into memory
  - remove "#" comments and trailing whitespace, identify sections and their key/values.
  - If there's an info.includes, run process_rule_file(file) sequentially on each, retrieving their external_substitutions and pattern settings.
  - compute list of external substitutions by appending all returned included external substitutions in order
  - compute list of local substitutions by starting with external subsitutions and appending all substitution sections in our file in order
  - process all clauses: for each condition, if we need to apply the regex, first apply the local substitutions to the regex patterns in reverse order, then apply the regex to determine if its value matches. Once a clause triggers, we have a decision and we don't need to process anything else
  - if no clause matched, we'll return a decision of none, a "new external substitutions" list of keys (the external substitutions,  appended with our file's sections with names `substitution.external[.ID]` (in order)), and the pattern parameters we used.
  
~~~~

Included rule files are loaded first, in sequence, before current
(the including file's)
rule's substitutions and applying its current clauses.

Note that the included files' use of substitutions are never affected by
those that included them, so a clause author doesn't need to worry
that an including file will create a substitution that would change
its meaning.
On the negative side, this means an including file can't "pass in"
substitutions to the files it includes.
On the positive side, this means that an including file can't set
a substitution that creates a subtle misinterpreation
of a clause in an included file.

As substitutions are read from the corresponding `[substitutions]` sections,
they are *added* to the list of substitutions
that will be applied by the including file (transitively), and
all previous substitutions (including from included files) are applied.
A rule is malformed if a substitution key is duplicated in any of the
transitively including requestors.
Users can prevent duplicated keys by using unlikely-to-be-reused
keys for substitutions, and we do detect the problem.

Once an included file is loaded and its included files are resolved,
any `clause`s it defines are applied *before* returning to the caller.

Externally-visible substitutions should be documented so that the
correct flags will be used for them.

The system passes the files included so far, and will ignore files
already included on a particular branch. This prevents circular dependencies
from causing an infinite loop. There's a limited number of files, and
generally only files in `includes/` will be included, so there's no need to
limit the depth count as well.

## "ALL" tool

Sometimes you want to define a pattern and apply it across *many*
tools, in an easy way.

Proposed solution: a pseudo "ALL" tool (a tool subdirectory named "ALL"
for each possible decision).
After trying out the rules for a tool and *all* "see" groups (transitively),
the system will try the rules for the pseudo ALL tool. Rules for the ALL tool
are *always* tried if all the other tools don't have a match.

Note that conditions in these rules
will often need to use `?`. At least `tool_input.url?` and maybe
`tool_input?.url?` (not sure which).

## Self-test support

Since rules can be complex, it's best to have self-test support.

Sections in a rule may be named `[test.NAME.RESULT]`.
where `RESULT` is `hit`  if the test data given in the section
should match this rule, and `miss` if the data in this section should not.
We want people to be able to insert spaces, newlines, etc., so the value
will be backslash interpreted (that is, \n becomes newline, a backslash
space or \020 becomes space, etc.)
Something like:

~~~~ini
...
[test.1.hit]
tool_name: Bash
tool_input.command: /sudo\nrm -rf \//
~~~~

Similarly, we want people to be able to test individual named
substitutions, to ensure the name meets their expectations.
Current thinking is to use
section name `testname.NAME` to test substitution named NAME,
where each key is the pattern and its value is `hit` or `miss`.
Again, the values are backslash-encoded so `\n` can represent a newline.

In the backslash endcoding, leading and trailng whitespace is removed
before decoding the backslashes, but *not* after decoding, so it's possible
to create values that end in newlines, spaces, and so on.

~~~~ini
...
[nametest.${FILE}.hit]
1 = foo.pdf
2 = A grand\r\nold "time"
~~~~
