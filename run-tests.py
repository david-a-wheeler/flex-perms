#!/usr/bin/env python3
"""
test-flex-check.py: Test suite for flex-check.py
Usage: test-flex-check.py [COMMAND]

by David A. Wheeler
"""

import difflib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


TEST_CASES = [
    # WebFetch tests - only use directories needed for each test
    ("01_deny_malicious", {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://evil.com/malware"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/flex-perms"}),
    ("02_allow_github", {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://github.com/user/repo"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/flex-perms"}),
    ("03_ask_unknown", {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://unknown.example.com/test"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/flex-perms"}),
    ("04_defer_unmatched", {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://totally-unmatched.example.org"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/flex-perms"}),
    ("05_default_allow", {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://default.example.com/path"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/flex-perms-default"}),
    ("06_filename_escaping", {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://naughty.example.com/path"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/flex-perms"}),

    # Bash tests
    ("07_bash_sudo_deny", {
        "tool_name": "Bash",
        "command": "sudo ls"
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/flex-perms"}),
    ("08_bash_ls_defer", {
        "tool_name": "Bash",
        "command": "ls -la"
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/flex-perms"}),

    # Edge cases - these don't need specific rule dirs since they test basic functionality
    ("09_no_tool_name", {
        "some_other_field": "value"
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/flex-perms"}),
    ("10_empty", {}, {"FLEX_CHECK_PERM_DIRS": "configtest/flex-perms"}),
    ("11_malformed", '{"tool_name":"WebFetch","tool_input":{"url":"https://test.com"', {"FLEX_CHECK_PERM_DIRS": "configtest/flex-perms"}),
    ("12_complex_path", {
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://github.com/anthropic/claude",
            "nested": {"deep": "value"}
        }
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/flex-perms"}),

    # No-logging tests
    ("13_no_logging_unset", {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://github.com/user/repo"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/flex-perms", "FLEX_CHECK_LOGFILE": None}),  # Unset the variable
    ("14_no_logging_empty", {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://github.com/user/repo"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/flex-perms", "FLEX_CHECK_LOGFILE": ""}),  # Set to empty string

    # File access error tests. These will fail on Windows.
    ("15_unreadable_rule", {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://github.com/user/repo"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/flex-perms-unreadable"}),
    ("16_unlistable_dir", {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://github.com/user/repo"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/flex-perms-unlistable"}),

    # FLEX_CHECK_EXTRA_DIR test
    ("17_extra_dir_test", {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://extra-dir-test.com/path"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/flex-perms", "FLEX_CHECK_EXTRA_DIR": "configtest/extra-dir"}),

    # Multi-rule test - both conditions must match
    ("18_multi_rule_match", {
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://api.secure.com/endpoint",
            "headers": {"Authorization": "Bearer abc123token"}
        }
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/multi-rule-test"}),

    # Multi-rule test - only one condition matches (should defer)
    ("19_multi_rule_partial", {
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://api.secure.com/endpoint",
            "headers": {"Authorization": "InvalidAuth"}
        }
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/multi-rule-test"}),

    # options.json test - Edit tool should use FileAccess rules
    ("20_options_edit_fileaccess", {
        "tool_name": "Edit",
        "tool_input": {"file_path": "/etc/passwd"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/flex-perms"}),

    # options.json test - Read tool should use FileAccess rules
    ("21_options_read_fileaccess", {
        "tool_name": "Read",
        "tool_input": {"file_path": "/etc/passwd"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/flex-perms"}),

    # options.json test - Write tool should use FileAccess rules
    ("22_options_write_fileaccess", {
        "tool_name": "Write",
        "tool_input": {"file_path": "/etc/passwd"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/flex-perms"}),

    # Case mismatch test - should detect and report case errors
    ("23_case_mismatch_error", {
        "tool_name": "WebFetch",
        "tool_input": {"headers": {"Authorization": "Bearer abc123token"}}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/case-mismatch-test"}),

    # Optional field tests
    ("24_optional_field_present", {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://api.test.com/endpoint", "headers": {"Authorization": "Bearer token123"}}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/optional-fields-test"}),

    ("25_optional_field_missing", {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://api.test.com/endpoint"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/optional-fields-test"}),

    # Required field missing test
    ("26_required_field_missing", {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://api.test.com/endpoint"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/required-field-test"}),

    # JSON null value tests
    ("27_null_value_with_null_pattern", {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://null-test.com/endpoint", "headers": {"auth_field": None}}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/null-test"}),

    ("28_string_value_with_null_pattern", {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://null-test.com/endpoint", "headers": {"auth_field": "Bearer token"}}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/null-test"}),

    ("29_missing_optional_with_null_pattern", {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://null-test.com/endpoint"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/null-test"}),

    ("30_null_value_with_not_null_pattern", {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://not-null-test.com/endpoint", "headers": {"auth_field": None}}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/not-null-test"}),

    ("31_string_value_with_not_null_pattern", {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://not-null-test.com/endpoint", "headers": {"auth_field": "Bearer token"}}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/not-null-test"}),

    # JSON boolean value tests
    ("32_boolean_true_false_match", {
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://boolean-test.com/endpoint",
            "settings": {"enabled": True, "method": False}
        }
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/boolean-test"}),

    ("33_boolean_false_true_nomatch", {
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://boolean-test.com/endpoint",
            "settings": {"enabled": False, "method": True}
        }
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/boolean-test"}),

    # Field path negation tests
    ("34_negation_match", {
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://negation-test.com/endpoint",
            "headers": {
                "authorization": "Bearer unsafe-token",
                "user_agent": "MaliciousBrowser"
            }
        }
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/negation-test"}),

    ("35_negation_no_match", {
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://negation-test.com/endpoint",
            "headers": {
                "authorization": "Bearer safe-token",
                "user_agent": "SafeBrowser"
            }
        }
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/negation-test"}),

    # Negated optional field tests
    ("36_negated_optional_missing", {
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://optional-negation-test.com/endpoint"
        }
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/negation-optional-test"}),

    ("37_negated_optional_present_match", {
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://optional-negation-test.com/endpoint",
            "headers": {"auth": "not-secret"}
        }
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/negation-optional-test"}),

    ("38_negated_optional_present_no_match", {
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://optional-negation-test.com/endpoint",
            "headers": {"auth": "secret"}
        }
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/negation-optional-test"}),

    # Negated null pattern tests
    ("39_negated_null_with_value", {
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://null-negation-test.com/endpoint",
            "headers": {"auth": "Bearer token123"}
        }
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/negation-null-test"}),

    ("40_negated_null_with_null", {
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://null-negation-test.com/endpoint",
            "headers": {"auth": None}
        }
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/negation-null-test"}),

    # Environment variable tests
    ("41_env_vars_with_match", {
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://env-test.com/endpoint"
        }
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/env-test", "TEST_VAR": "secret"}),

    ("42_env_vars_without_test_var", {
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://env-test.com/endpoint"
        }
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/env-test"}),  # No TEST_VAR set

    ("43_env_vars_empty_list", {
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://env-test.com/endpoint"
        }
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/env-test-empty"}),

    ("44_env_vars_with_wrong_value", {
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://env-test.com/endpoint"
        }
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/env-test", "TEST_VAR": "not-secret"}),

    # Regex flags tests - test per-file flag scoping
    ("30_flags_ignore_case_match", {
        "tool_name": "Edit",
        "tool_input": {"file_path": "test"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/test-flags"}),

    ("31_flags_ignore_case_nomatch", {
        "tool_name": "Edit",
        "tool_input": {"file_path": "TEST"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/test-flags"}),

    ("32_flags_verbose_match", {
        "tool_name": "Edit",
        "tool_input": {"file_path": "test  file"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/test-flags"}),

    ("33_flags_both_match", {
        "tool_name": "Edit",
        "tool_input": {"file_path": "sensitive  FILE"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/test-flags"}),

    ("34_flags_no_flags_exact", {
        "tool_name": "Edit",
        "tool_input": {"file_path": "ExactCase"}
    }, {"FLEX_CHECK_PERM_DIRS": "configtest/test-flags"}),
]


def fail(message):
    """Report error and exit."""
    sys.stderr.write(f"{message}\n")
    sys.exit(1)


def show_first_failure_diff(test_name, test_case, expected_content, actual_content):
    """Show detailed diff for first test failure only."""
    print(f"\n{'='*60}")
    print(f"FIRST FAILURE DETAILS: {test_name}")
    print(f"{'='*60}")

    # Extract test case components
    if len(test_case) == 2:
        _, json_data = test_case
        env_vars = {}
    else:
        _, json_data, env_vars = test_case

    # Context information
    print(f"Input: {json.dumps(json_data, indent=2)}")
    if env_vars:
        # Show non-default environment variables
        filtered_env = {k: v for k, v in env_vars.items()
                       if k not in ['FLEX_CHECK_PERM_DIRS', 'FLEX_CHECK_LOGFILE']}
        if filtered_env:
            print(f"Environment: {json.dumps(filtered_env, indent=2)}")
        if 'FLEX_CHECK_PERM_DIRS' in env_vars:
            print(f"Permission dirs: {env_vars['FLEX_CHECK_PERM_DIRS']}")

    print(f"\nExpected vs Actual (leading '-'=actual lacks expected result):")

    # Generate unified diff
    diff_lines = list(difflib.unified_diff(
        expected_content.splitlines(keepends=True),
        actual_content.splitlines(keepends=True),
        fromfile="baseline/expected",
        tofile="results/actual",
        lineterm=""
    ))

    if not diff_lines:
        print("(No differences found in diff generation)")
        return

    # Show diff with reasonable line limit
    MAX_LINES = 40
    displayed_lines = diff_lines[:MAX_LINES]

    for line in displayed_lines:
        print(line.rstrip())  # Keep full line content

    if len(diff_lines) > MAX_LINES:
        print(f"... (diff truncated - showing first {MAX_LINES} of {len(diff_lines)} lines)")
        print(f"    Full diff available: test-results/{test_name}.result vs baseline/{test_name}.result")

    print(f"{'='*60}\n")


def setup_permissions():
    """Set up permissions for file access error tests."""
    # We set up permissions when we run tests because git doesn't reliably record them.
    # Create the necessary directories and files first, then set permissions.
    try:
        # On Windows, we can't make files truly unreadable with chmod,
        # so these tests will not work as expected on Windows
        if os.name != 'nt':  # Not Windows
            # Create unreadable test structure
            unreadable_dir = Path("configtest/flex-perms-unreadable/allow/WebFetch")
            unreadable_dir.mkdir(parents=True, exist_ok=True)
            unreadable_file = unreadable_dir / "unreadable.tool_input.url.rule"
            unreadable_file.write_text("# Unreadable test rule\n")

            # Create unlistable test structure
            unlistable_dir = Path("configtest/flex-perms-unlistable/allow/WebFetch")
            unlistable_dir.mkdir(parents=True, exist_ok=True)

            # Make rule file unreadable (remove all permissions)
            os.chmod(str(unreadable_file), 0)
            # Make directory unlistable (remove all permissions)
            os.chmod(str(unlistable_dir), 0)
    except OSError:
        pass  # Ignore errors during setup


def cleanup_permissions():
    """Reset permissions for unreadable/unlistable test files back to normal."""
    # This makes it easier to work with the test files after running tests,
    # since they would otherwise remain unreadable/unlistable.
    try:
        if os.name != 'nt':  # Not Windows
            # Reset rule file to readable (owner read/write, group/other read)
            unreadable_file = Path("configtest/flex-perms-unreadable/allow/WebFetch/unreadable.tool_input.url.rule")
            if unreadable_file.exists():
                os.chmod(str(unreadable_file), 0o644)

            # Reset directory to listable (owner read/write/execute, group/other read/execute)
            unlistable_dir = Path("configtest/flex-perms-unlistable/allow/WebFetch")
            if unlistable_dir.exists():
                os.chmod(str(unlistable_dir), 0o755)
    except OSError:
        pass  # Ignore errors during cleanup


def run_test_case(test_case):
    """Run a single test case and save result."""
    # Unpack test case tuple
    if len(test_case) == 2:
        test_name, json_data = test_case
        env_vars = None
    else:
        test_name, json_data, env_vars = test_case

    # Set up environment
    env = os.environ.copy()
    # Default value(s) - will be overridden by individual test cases
    env["FLEX_CHECK_PERM_DIRS"] = "configtest/flex-perms"
    env["FLEX_CHECK_LOGFILE"] = ".test_log"

    if env_vars:
        for key, value in env_vars.items():
            if value is None:
                # Unset the environment variable
                env.pop(key, None)
            else:
                env[key] = value

    # Prepare JSON input
    if isinstance(json_data, str):
        json_input = json_data
    else:
        json_input = json.dumps(json_data, indent=2)

    # Run the test
    try:
        result = subprocess.run(
            ["./flex-check.py"], input=json_input, text=True,
            capture_output=True, env=env, timeout=30
        )
        output = result.stdout + result.stderr
        exit_code = result.returncode
    except Exception as e:
        output = str(e)
        exit_code = 1

    # Read log content
    log_content = ""
    log_file = Path(".test_log")
    if log_file.exists():
        try:
            log_content = log_file.read_text()
            log_file.unlink()  # Clean up log file after reading
        except:
            log_content = "Error reading log file"

    # Save result directly
    results_dir = Path("test-results")
    results_dir.mkdir(exist_ok=True)
    result_file = results_dir / f"{test_name}.result"
    # Format log section properly
    if log_content.strip():
        log_section = f"log_start\n{log_content}log_end\n"
    else:
        log_section = "log_start\nlog_end\n"

    result_file.write_text(f"test_name: {test_name}\n"
                          f"exit_code: {exit_code}\n"
                          f"stdout_start\n{output}\nstdout_end\n"
                          f"{log_section}")


def accept_results():
    """Copy results from test-results directory to baseline."""
    source_path = Path("test-results")
    target_path = Path("baseline")

    if not source_path.exists():
        fail("Test results directory not found. Run tests first.")

    print("Accepting results from test-results to baseline")

    # Remove target directory if it exists
    if target_path.exists():
        shutil.rmtree(target_path)

    # Copy source to target
    shutil.copytree(source_path, target_path)

    # Count accepted files
    accepted_files = list(target_path.glob("*.result"))
    print(f"Accepted {len(accepted_files)} test results")


def run_and_test(pattern=None):
    """Run test cases and compare each result to baseline.

    Args:
        pattern: If provided, only run tests whose names contain this substring.
    """
    baseline_dir = Path("baseline")

    if not baseline_dir.exists():
        fail("No baseline results found. Run 'accept' command first to create baseline.")

    # Filter test cases if pattern provided
    test_cases_to_run = TEST_CASES
    if pattern:
        test_cases_to_run = [tc for tc in TEST_CASES if pattern in tc[0]]
        if not test_cases_to_run:
            fail(f"No tests match pattern: {pattern}")

    if pattern:
        print(f"Running test cases matching '{pattern}' with flex-check.py")
        print(f"Found {len(test_cases_to_run)} matching test(s)")
    else:
        print("Running all test cases with flex-check.py")
    print("Results will be saved to: test-results")
    print(f"Comparing against baseline results in: {baseline_dir}")

    passed = 0
    failed = 0
    first_failure_shown = False

    for test_case in test_cases_to_run:
        # Run the test
        run_test_case(test_case)
        test_name = test_case[0]  # Get test name from tuple

        # Compare result to baseline
        result_file = Path("test-results") / f"{test_name}.result"
        baseline_file = baseline_dir / f"{test_name}.result"

        if not baseline_file.exists():
            print(f"MISSING: {test_name} - no baseline")
            failed += 1

            # Show diff for first failure (missing baseline)
            if not first_failure_shown:
                print(f"\n{'='*60}")
                print(f"FIRST FAILURE DETAILS: {test_name}")
                print(f"{'='*60}")
                print("Missing baseline file - this is a new test")
                print(f"Actual result content:")
                print(result_file.read_text())
                print(f"{'='*60}\n")
                first_failure_shown = True

        elif result_file.read_text() == baseline_file.read_text():
            print(f"PASS: {test_name}")
            passed += 1
        else:
            print(f"FAIL: {test_name} - differs from baseline")
            failed += 1

            # Show diff for first failure
            if not first_failure_shown:
                expected_content = baseline_file.read_text()
                actual_content = result_file.read_text()
                show_first_failure_diff(test_name, test_case, expected_content, actual_content)
                first_failure_shown = True

    print(f"\nTest Results: {passed} passed, {failed} failed")

    if failed == 0:
        print("All tests passed! ✓")
        success = True
    else:
        print(f"{failed} test(s) failed! ✗")
        success = False

    # Show Windows-specific note about unreadable/unlistable tests
    if os.name == 'nt':  # Windows
        print("\nNote: On Windows, tests 15_unreadable_rule and 16_unlistable_dir")
        print("are not expected to pass due to Windows' different permission system.")
        print("This is a limitation of the test framework; the functionality should work fine.")

    # Reset permissions back to normal for easier file management
    cleanup_permissions()

    return success


def show_usage():
    """Show usage information."""
    script = sys.argv[0]
    print(f"""Usage: {script} [COMMAND] [PATTERN]

Commands:
    test [PATTERN] - Run tests and compare to baseline (default)
                     If PATTERN provided, only run tests matching pattern
    accept         - Accept current test results as new baseline
    help           - Show this help message

Examples:
    {script}             # Run all tests
    {script} test        # Run all tests
    {script} test deny   # Run tests containing 'deny' in name
    {script} accept      # Accept current results as baseline
""")


def main():
    """Main entry point."""
    args = sys.argv[1:]

    # Determine command and pattern
    command = "test"
    pattern = None

    if not args:
        command = "test"
    elif args[0] in ['test', 'accept', 'help', '--help', '-h']:
        command = args[0]
        # Check for pattern after test command
        if command == "test" and len(args) > 1:
            pattern = args[1]
    else:
        show_usage()
        fail(f"Unknown command: {args[0]}")

    if command in ['help', '--help', '-h']:
        show_usage()
        return

    if not Path("./flex-check.py").is_file():
        fail("flex-check.py not found in current directory")

    if command == "test":
        setup_permissions()
        success = run_and_test(pattern)
        sys.exit(0 if success else 1)
    elif command == "accept":
        accept_results()
    else:
        show_usage()
        fail(f"Unknown command: {command}")


if __name__ == '__main__':
    main()
