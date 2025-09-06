# Installing flex-perms for Claude Code

flex-perms provides flexible permission control for Claude Code tools through directory-based rules and regex pattern matching.

## Step 1: Choose Installation Location

**Recommended**: Install to `$HOME/.claude/`

In most cases, if you're using Claude Code, we suggest installing the flex-perms program in `$HOME/.claude`. This gives you sensible defaults across all projects while allowing project-specific overrides when needed, and you won't need to reinstall for each project.

**Alternatives for special purposes**:
- **Project-only**: Install in `.claude/` within a specific project directory for running flex-perms *only* for that project.
- **System-wide**: Install in `/etc/claude-code/` (requires admin access) to affect all users on the system.

You can install the `flex-perms` *program* in `$HOME/.claude` and still have rules specific to a project.

## Step 2: Install Python3

Install Python3. Most users probably already have it.

## Step 3: Install Files

Presuming that you'll install to `~/.claude`:

1. **Copy the sample rules**:
   ```bash
   cp -r sample-flex-perms/ ~/.claude/flex-perms/
   ```

2. **Copy the executable script**:
   ```bash
   cp flex-check.py ~/.claude/
   chmod +x ~/.claude/flex-check.py
   ```

3. **Configure the hook**:
   Add a hook configuration to file `~/.claude/settings.json`:

   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "*",
           "hooks": [
             {
               "type": "command",
               "command": "~/.claude/flex-check.py"
             }
           ]
         }
       ]
     }
   }
   ```

   - **If the file doesn't exist**: Create it with the complete JSON structure as shown above.
   - **If the file exists**: Add the `"hooks"` section to the existing JSON object if there's no "hooks" section. Then add the contents of "hooks". If it's after something else at the same layer, remember to add a ',' separator before the new item.

## Step 3: Verify Installation

Test the installation by running Claude Code in a directory and attempting a denied operation. For example, try:
- Running `sudo ls` (should be blocked)
- Reading a file like `~/.ssh/id_rsa` (should be blocked)
- Editing a `.md` file (should be allowed)

## Customizing Rules

After installation, you can:

- **Add rules**: Create new `.rule` files in `~/.claude/flex-perms/{deny,ask,allow}/ToolName/NAME.rule`
- **Remove rules**: Delete unwanted rule files
- **Override per-project**: Copy `~/.claude/flex-perms/` to a project's `.claude/flex-perms/` and modify

Each rule file uses INI format with info sections and clauses that match against multiple tool input parameters.

## Troubleshooting

- **Hook not working**: Check `settings.json` syntax and file paths
- **Rules not applying**: Verify file permissions and that `flex-check.py` is executable
- **Debug issues**: Set `FLEX_CHECK_LOGFILE=/tmp/flex-check.log` to see rule evaluation log and restart the assistant.

For more details, see the project documentation.
