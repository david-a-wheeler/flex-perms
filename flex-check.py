#!/usr/bin/env python3
"""
flex-check.py: Flexible permission checks for AI code assistant (Claude Code)
Usage: flex-check.py (via stdin for hooks)

by David A. Wheeler
"""

# SPDX-License-Identifier: MIT

import configparser
import json
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

class FlexCheck:
    """Main flex-check implementation."""

    # Allowed keys in [info] section of rule files
    ALLOWED_INFO_KEYS = {
        'reason', 'author', 'description', 'timestamp'
    }

    class FileAccessError(Exception):
        """Internal exception for file access errors during rule processing."""
        def __init__(self, file_path: str, operation: str):
            self.file_path = file_path
            self.operation = operation
            super().__init__(f"Failed to {operation} {file_path}")

    class MalformedRuleError(Exception):
        """Internal exception for malformed rule files."""
        def __init__(self, file_path: str, message: str):
            self.file_path = file_path
            self.message = message
            super().__init__(f"Malformed rule {file_path}: {message}")

    class RuleValidationError(Exception):
        """Internal exception for rule validation errors."""
        pass

    def __init__(self, perm_dirs: List[str] = None, logfile: str = None,
                 extra_dir: str = None, debug: bool = False):
        """Initialize FlexCheck permission system.

        Args:
            perm_dirs: List of permission directories to search (in order).
                      If None, uses default directories based on Claude Code
                      configuration paths (enterprise -> project -> user).
            logfile: Path to log file for request/response logging. If None,
                    no logging is performed. Required when debug=True.
            extra_dir: Additional permission directory inserted after the first
                      (enterprise) directory. Useful for testing or additional
                      rule sources.
            debug: Enable debug output to stderr with detailed rule processing
                  information.
        """
        self.perm_dirs: List[str] = (
            perm_dirs if perm_dirs is not None else self.default_perm_dirs()
        )

        # Insert extra_dir after the first (enterprise) directory if provided
        if extra_dir and self.perm_dirs:
            self.perm_dirs.insert(1, extra_dir)
        elif extra_dir: # No other permission dirs, use extra_dir if provided
            self.perm_dirs = [extra_dir]

        self.logfile: str = logfile
        self.debug: bool = debug

    def debug_msg(self, message: str) -> None:
        """Print debug message to stderr if debug mode is enabled."""
        if self.debug:
            print(f"DEBUG: {message}", file=sys.stderr)

    @staticmethod
    def detect_enterprise_dir() -> str:
        """Detect enterprise directory based on operating system."""
        if os.name == "nt":  # Windows
            return "C:/ProgramData/Claude Code"
        elif os.uname().sysname == "Darwin":  # macOS
            return "/Library/Application Support/Claude Code"
        else:  # Unix/Linux
            return "/etc/claude-code"

    @staticmethod
    def default_config_dirs() -> List[str]:
        """Get default Claude Code configuration directories."""
        # Set default directories in precedence order
        enterprise_dir = FlexCheck.detect_enterprise_dir()
        # We added this - we think Claude should support this too
        enterprise_defaults = f"{enterprise_dir}/defaults"

        return [
            enterprise_dir,
            './.claude/local',
            './.claude',
            os.path.expanduser('~/.claude'),
            enterprise_defaults
        ]

    @staticmethod
    def default_perm_dirs() -> List[str]:
        """Get default flex-perms directories in precedence order."""
        config_dirs = FlexCheck.default_config_dirs()
        return [os.path.join(config_dir, "flex-perms")
                for config_dir in config_dirs]

    def parse_field_path(self, path: str) -> List[Tuple[str, bool]]:
        """Parse field path into list of (key, is_optional) tuples.

        Args:
            path: Field path like "parent.child?" or "field"

        Returns:
            List of (key, is_optional) tuples for each path component
        """
        components = []
        for key in path.strip('.').split('.'):
            is_optional = key.endswith('?')
            actual_key = key[:-1] if is_optional else key
            components.append((actual_key, is_optional))
        return components

    def navigate_json_path(self, data: dict, components: List[Tuple[str, bool]],
                           original_path: str) -> Tuple[any, bool]:
        """Navigate through JSON data using parsed field path components.

        Args:
            data: JSON data to navigate
            components: List of (key, is_optional) tuples from parse_field_path
            original_path: Original field path for error messages

        Returns:
            (value, is_missing_optional): Value at end of path, and whether
                this represents a missing optional field

        Raises:
            RuleValidationError: Field validation errors (case mismatch, missing fields)
        """
        current_data = data
        for key, is_optional in components:
            if isinstance(current_data, dict):
                # Try case-sensitive match first
                if key in current_data:
                    current_data = current_data[key]
                    continue

                # Case-sensitive failed, try case-insensitive
                for dict_key in current_data.keys():
                    if dict_key.lower() == key.lower():
                        # Found case mismatch - raise error
                        raise self.RuleValidationError(f"Field path '{original_path}': rule uses '{key}' but JSON has '{dict_key}'")

                # No match at all
                if is_optional:
                    return (None, True)  # Optional field missing - signal skip
                else:
                    raise self.RuleValidationError(f"Required field path component '{key}' not found in path '{original_path}'")
            else:
                current_data = current_data[key]
        return (current_data, False)

    def convert_json_value(self, value: any, missing_optional: bool = False) -> Tuple[bool, Optional[str]]:
        """Convert JSON value to string for regex matching.

        Args:
            value: JSON value
            missing_optional: True if this represents a missing optional field

        Returns:
            (True, str) - Field exists with non-null value (converted to string)
            (True, None) - Field exists with JSON null value
            (False, None) - Optional field missing (should skip)
        """
        if missing_optional:
            return (False, None)  # Optional field missing - skip

        # Convert JSON values to strings for regex matching
        if value is None:  # This is JSON null
            return (True, None)
        elif isinstance(value, bool):
            return (True, "true" if value else "false")
        else:
            return (True, str(value))

    def extract_json_value(self, json_str: str, path: str
                          ) -> Tuple[bool, Optional[str]]:
        """Extract JSON value using field path with optional field support.

        Field path syntax:
            - "field_path" - Required field path
                (raises RuleValidationError if missing)
            - "field_path?" - Optional field path
                (returns (False, None) if missing)
            - "parent.child?" - Optional nested field path
            - "parent?.child" - Child of optional parent field path

        Returns (field_exists, converted_value):
            - Optional field missing → (False, None)
            - JSON null → (True, None)
            - JSON boolean → (True, "true"|"false")
            - JSON string|number → (True, string)

        Raises:
            RuleValidationError - Field path validation errors
        """
        try:
            data = json.loads(json_str)
            components = self.parse_field_path(path)
            value, is_missing_optional = self.navigate_json_path(
                data, components, path)

            return self.convert_json_value(value, is_missing_optional)
        except self.RuleValidationError:
            raise  # Re-raise our exceptions
        except (KeyError, TypeError):
            raise self.RuleValidationError(
                f"Invalid path or data structure: '{path}'")

    def log_request_response(self, request: str, response: str) -> None:
        """Log request and response JSON to logfile in JSONL format if set.

        Each log entry is written as a single JSON object on one line.
        Format: {"request": {...}, "response": {...}}
        """
        if not self.logfile:
            return

        try:
            log_entry = {
                "request": json.loads(request),
                "response": json.loads(response)
            }

            with open(self.logfile, 'a', encoding='utf-8') as f:
                json.dump(log_entry, f, separators=(',', ':'))
                f.write('\n')
        except (json.JSONDecodeError, OSError):
            # Ignore logging errors
            pass

    def parse_rule_file(self, rule_path: str
                       ) -> Tuple[str, List[Dict[str, str]]]:
        """Parse a .rule file and return (reason, clauses)."""
        try:
            with open(rule_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except OSError:
            raise self.FileAccessError(rule_path, "read rule file")

        # Preprocess: remove comment lines (lines starting with #)
        lines = []
        for line in content.splitlines():
            if not line.lstrip().startswith('#'):
                lines.append(line.rstrip())  # Remove trailing whitespace

        preprocessed_content = '\n'.join(lines)

        # Check for duplicate sections
        section_pattern = re.compile(r'^\s*\[([^\]]+)\]')
        sections = []
        for line in lines:
            match = section_pattern.match(line)
            if match:
                sections.append(match.group(1))

        duplicates = [s for s in set(sections) if sections.count(s) > 1]
        if duplicates:
            raise self.MalformedRuleError(rule_path,
                f"Duplicate sections: {duplicates}")

        # Parse with configparser
        try:
            config = configparser.ConfigParser(
                interpolation=None,
                inline_comment_prefixes=(),
                comment_prefixes=()
            )
            # Preserve case sensitivity for option names (field paths)
            config.optionxform = str
            config.read_string(preprocessed_content)
        except configparser.Error as e:
            raise self.MalformedRuleError(rule_path, f"INI parsing error: {e}")

        # Extract reason
        if 'info' not in config:
            raise self.MalformedRuleError(rule_path, "Missing [info] section")

        info_section = config['info']

        # Validate that only allowed keys are present in info section
        invalid_keys = set(info_section.keys()) - self.ALLOWED_INFO_KEYS
        if invalid_keys:
            raise self.MalformedRuleError(rule_path, f"Invalid keys in [info] section: {sorted(invalid_keys)}. Allowed keys: {sorted(self.ALLOWED_INFO_KEYS)}")

        if 'reason' not in info_section:
            raise self.MalformedRuleError(rule_path,
                "Missing 'reason' in [info] section")

        reason = info_section['reason']

        # Extract clauses in file order
        clauses = []
        for section_name in config.sections():
            if section_name == 'info':
                continue
            if section_name.startswith('clause.'):
                clause = dict(config[section_name].items())
                if not clause:
                    raise self.MalformedRuleError(rule_path, f"Empty clause section [{section_name}]")
                clauses.append(clause)

        if not clauses:
            raise self.MalformedRuleError(rule_path, "No clause sections found")

        return reason, clauses

    # Map of single-character regex flags to their corresponding re module constants
    REGEX_FLAG_MAP = {
        'i': re.IGNORECASE,
        'm': re.MULTILINE,
        's': re.DOTALL,
        'x': re.VERBOSE,
        'a': re.ASCII
    }

    def parse_slashed_regex(self, pattern: str) -> Tuple[str, int]:
        """Parse /regex/flags format and return (regex, flags).

        Args:
            pattern: Either a regular pattern or /regex/flags format

        Returns:
            (regex_pattern, flags_int): Extracted regex and compiled flags

        Raises:
            ValueError: If /regex/flags format is malformed
        """
        # Parse /regex/flags format
        if not pattern.strip().startswith('/') or pattern.count('/') < 2:
            raise ValueError(f"Malformed /regex/flags pattern: {pattern}")

        # Find the last '/' to separate regex from flags
        last_slash = pattern.rfind('/')
        regex_part = pattern[1:last_slash]  # Remove leading /
        flags_part = pattern[last_slash + 1:]  # Remove trailing /

        # Convert single-character flags to regex flags
        flags = 0
        for flag_char in flags_part:
            if flag_char in self.REGEX_FLAG_MAP:
                flags |= self.REGEX_FLAG_MAP[flag_char]
            else:
                raise ValueError(f"Unknown regex flag '{flag_char}' in pattern: {pattern}")

        return regex_part, flags

    def _is_special_pattern(self, pattern: str) -> bool:
        """Check if pattern is a special null-matching pattern."""
        return pattern in ("]NULL[", "]NOT_NULL[", "/]NULL[/", "/]NOT_NULL[/")

    def _evaluate_null_pattern(self, pattern: str, value: any, negated: bool) -> bool:
        """Evaluate special null-matching patterns."""
        if pattern in ("]NULL[", "/]NULL[/"):
            return (value is None) != negated
        elif pattern in ("]NOT_NULL[", "/]NOT_NULL[/"):
            return (value is not None) != negated
        else:
            # Regular pattern vs JSON null never matches (except when negated)
            return negated

    def evaluate_condition(self, field_path: str, pattern: str, json_input: str) -> bool:
        """Evaluate a single condition against JSON input.

        Args:
            field_path: Field path (may include ! prefix for negation)
            pattern: Pattern to match (regex, ]NULL[, or ]NOT_NULL[)
            json_input: JSON string to evaluate against

        Returns:
            True if condition passes, False if it fails
        """
        # Check for negation prefix
        negated = field_path.startswith('!')
        if negated:
            field_path = field_path[1:]  # Remove the ! prefix

        # Extract field path value from JSON
        field_exists, value = self.extract_json_value(json_input, field_path)

        if not field_exists:
            # Optional field is missing - handle based on negation
            if negated:
                # Negated + missing = clause fails (we wanted "not X" but X is absent)
                self.debug_msg(f"Field path '!{field_path}': missing optional field - FAILED")
                return False
            else:
                # Non-negated + missing = condition passes (ignore missing optional fields)
                self.debug_msg(f"Field path '{field_path}': missing optional field - SKIPPED")
                return True

        # Evaluate pattern against the field value
        if self._is_special_pattern(pattern) or value is None:
            match_result = self._evaluate_null_pattern(pattern, value, negated)
        else:
            # Regular regex matching for non-null values
            try:
                regex_pattern, regex_flags = self.parse_slashed_regex(pattern)
                match_result = (
                    bool(re.search(regex_pattern, value, regex_flags)) != negated
                )
            except (re.error, ValueError) as e:
                self._debug_condition_result(field_path, pattern, value, False, negated, f"invalid regex/flags: {e}")
                return False

        self._debug_condition_result(field_path, pattern, value, match_result, negated)
        return match_result

    def _debug_condition_result(self, field_path: str, pattern: str, value: any,
                               passed: bool, negated: bool, error_msg: str = None) -> None:
        """Log debug message for condition evaluation result."""
        prefix = '!' if negated else ''
        if error_msg:
            result = f"FAILED ({error_msg})"
        else:
            result = 'PASSED' if passed else 'FAILED'
        self.debug_msg(f"Field path '{prefix}{field_path}': pattern '{pattern}' vs value '{value}' - {result}")

    def evaluate_clause(self, clause: Dict[str, str], json_input: str) -> bool:
        """Check if a clause matches the JSON input.

        Field path negation:
            - !field.path = pattern - Inverts the match result (matches when pattern DOESN'T match)
            - !field.path? = pattern - For optional field paths: missing field path = no match, present field path = inverted match
            - Works with all pattern types (regular regex, ]NULL[, ]NOT_NULL[)

        Special pattern handling:
            - ]NULL[ - Matches only JSON null values (illegal regex syntax prevents accidents)
            - ]NOT_NULL[ - Matches only non-null values (any actual value)
            - Regular patterns - Match string-converted values, JSON null never matches

        Optional field path handling:
            - Field paths with ? suffix are optional and skipped if missing
            - All other field paths are required and cause clause failure if missing
            - Clause passes if all present required field paths and optional field paths match their patterns
        """
        self.debug_msg(f"Evaluating clause with {len(clause)} conditions")

        for field_path, pattern in clause.items():
            if not self.evaluate_condition(field_path, pattern, json_input):
                return False

        self.debug_msg(f"All conditions processed - clause PASSED")
        return True  # All conditions matched

    def process_rule_file(self, rule_path: str, json_input: str) -> Optional[str]:
        """Process a .rule file and return match details if found."""
        self.debug_msg(f"Processing rule file: {rule_path}")

        try:
            reason, clauses = self.parse_rule_file(rule_path)
            self.debug_msg(f"Rule file parsed: {len(clauses)} clauses found")

            # Test clauses in file order
            for i, clause in enumerate(clauses):
                self.debug_msg(f"Testing clause {i+1}/{len(clauses)} in {rule_path}")
                if self.evaluate_clause(clause, json_input):
                    # Build match description
                    field_descriptions = []
                    for field_path, pattern in clause.items():
                        # Handle negation prefix for description
                        display_path = field_path
                        actual_path = field_path
                        if field_path.startswith('!'):
                            actual_path = field_path[1:]

                        found, value = self.extract_json_value(json_input, actual_path)
                        if found:
                            field_descriptions.append(f"{display_path}:{value}")
                        # Skip optional fields that weren't found

                    match_desc = f"clause {i+1} ({', '.join(field_descriptions)})"
                    result = f"{reason} {rule_path} - {match_desc}"
                    self.debug_msg(f"Rule file {rule_path}: MATCHED - {result}")
                    return result
                else:
                    self.debug_msg(f"Clause {i+1} in {rule_path}: did not match")

            self.debug_msg(f"Rule file {rule_path}: no clauses matched")
            return None  # No clauses matched

        except self.RuleValidationError as e:
            # Rule validation error causes deny with error details
            error_result = f"Security policy file error: {e} in {rule_path}"
            self.debug_msg(f"Rule file {rule_path}: VALIDATION ERROR - {error_result}")
            return error_result
        except self.MalformedRuleError as e:
            # Malformed rule causes deny with error details
            error_result = f"Security policy file error: {e.message} - {e.file_path}"
            self.debug_msg(f"Rule file {rule_path}: MALFORMED - {error_result}")
            return error_result

    def regex_match_in_perm_dir(self, perm_dir: str, perm_type: str,
                                perm_options: Dict, tool_name: str, json_input: str) -> Optional[str]:
        """Match rule files in permission directory for tool and permission type.

        Returns: rule_file:match_details if match found, else None
        """
        rule_dir = os.path.join(perm_dir, perm_type, tool_name)

        # Check for direct tool rules first
        if os.path.isdir(rule_dir):
            try:
                rule_files = [f for f in os.listdir(rule_dir) if f.endswith('.rule')]
            except OSError:
                raise self.FileAccessError(rule_dir, "list directory")

            for rule_file in rule_files:
                rule_path = os.path.join(rule_dir, rule_file)
                if not os.path.isfile(rule_path):
                    continue

                if result := self.process_rule_file(rule_path, json_input):
                    return result

        # Check for multi-tool rules using "see" key
        if "see" in perm_options and isinstance(perm_options["see"], dict):
            see_dict = perm_options["see"]
            if tool_name in see_dict and isinstance(see_dict[tool_name], list):
                # Recursively check other tool names specified in the "see" list
                for other_tool_name in see_dict[tool_name]:
                    if isinstance(other_tool_name, str):
                        if result := self.regex_match_in_perm_dir(perm_dir, perm_type, perm_options, other_tool_name, json_input):
                            return result

        return None

    def inject_env_vars(self, json_input: str, env_var_names: List[str]) -> str:
        """Inject selected environment variables into request JSON."""
        try:
            data = json.loads(json_input)
        except json.JSONDecodeError:
            return json_input

        # Add env dictionary with selected environment variables
        env_dict = {}
        for env_name in env_var_names:
            env_value = os.environ.get(env_name)
            if env_value is not None:
                env_dict[env_name] = env_value

        # Only add env key if there are environment variables to add
        if env_dict:
            data['env'] = env_dict

        return json.dumps(data)

    def find_match(self, tool_name: str, json_input: str) -> Optional[Tuple[str, str]]:
        """Find first matching rule across all perm dirs in precedence order.

        Returns: (perm_type, match_details) or None if no match
        """
        for perm_dir in self.perm_dirs:
            # Load options.json if it exists
            options_path = os.path.join(perm_dir, "options.json")
            perm_options = {}
            if os.path.isfile(options_path):
                try:
                    with open(options_path, 'r', encoding='utf-8') as f:
                        perm_options = json.load(f)
                except (OSError, json.JSONDecodeError):
                    # If options.json is malformed or unreadable, use empty dict
                    perm_options = {}

            # Inject environment variables if specified in options
            current_json_input = json_input
            if 'env' in perm_options and isinstance(perm_options['env'], list):
                current_json_input = self.inject_env_vars(json_input, perm_options['env'])

            for perm_type in ["deny", "ask", "allow"]:
                try:
                    if match := self.regex_match_in_perm_dir(perm_dir, perm_type, perm_options, tool_name, current_json_input):
                        return (perm_type, match)
                except self.FileAccessError as e:
                    # File access error - return deny with error details
                    error_reason = f"Security policy file access error: Failed to {e.operation} - {e.file_path}"
                    return ("deny", error_reason)

    def build_response(self, decision: str, match_details: str) -> Dict:
        """Build hook response for permission decisions."""

        decision_templates = {
            "deny": {
                "reason_template": "Access blocked by security policy - matched rule: {match_details}",
                "extra_fields": {
                    "continue": False,
                    "stopReason": "flex-perms: Request blocked by deny rule"
                }
            },
            "ask": {
                "reason_template": "flex-perms: Request requires permission - matched rule: {match_details}",
                "extra_fields": {}
            },
            "allow": {
                "reason_template": "flex-perms: Request permitted by allow rule - matched rule: {match_details}",
                "extra_fields": {}
            }
        }

        template = decision_templates[decision]

        base_output = {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": template["reason_template"].format(match_details=match_details)
        }

        response = template["extra_fields"].copy()
        response["hookSpecificOutput"] = base_output

        return response


    def run(self) -> None:
        """Parse JSON input from stdin and return permission decision as JSON."""
        try:
            json_input = sys.stdin.read()
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)

        try:
            data = json.loads(json_input)
            tool_name = data.get('tool_name', '')
        except json.JSONDecodeError:
            self.log_request_response(json_input, "{}")
            sys.exit(5)  # Match shell version error code

        if not tool_name:
            self.log_request_response(json_input, "{}")
            sys.exit(0)

        result = self.find_match(tool_name, json_input)

        if result:
            decision, match_details = result
            response = self.build_response(decision, match_details)
        else:
            # No match - defer to Claude's built-in permission system
            self.log_request_response(json_input, "{}")
            sys.exit(0)

        response_json = json.dumps(response, separators=(',', ': '), indent=2)
        self.log_request_response(json_input, response_json)
        print(response_json)

def main():
    """Main entry point."""
    # Check for --debug argument
    debug_arg = False
    if len(sys.argv) > 1 and sys.argv[1] == '--debug':
        debug_arg = True
        sys.argv.pop(1)  # Remove --debug from args

    perm_dirs = None
    if os.environ.get('FLEX_CHECK_PERM_DIRS'):
        perm_dirs_str = os.environ['FLEX_CHECK_PERM_DIRS']
        perm_dirs = re.split(r'\r?\n', perm_dirs_str.strip())
    logfile = os.environ.get('FLEX_CHECK_LOGFILE')
    extra_dir = os.environ.get('FLEX_CHECK_EXTRA_DIR')

    # Enable debug if --debug argument or FLEX_CHECK_DEBUG=true
    debug = debug_arg or os.environ.get('FLEX_CHECK_DEBUG', '').lower() == 'true'

    flex_check = FlexCheck(perm_dirs=perm_dirs, logfile=logfile, extra_dir=extra_dir, debug=debug)
    flex_check.run()

if __name__ == '__main__':
    main()
