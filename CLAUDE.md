# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the flex-perms project - a security control system for AI assistants, primarily focused on Claude Code. It provides flexible permissions management through a Python script and directory-based rule structures.

## Architecture

The project implements a simple hook-based permission system:

- **flex-check.py**: Main shell script that evaluates permissions
- **Rule Structure**: Directory-based organization with `deny`, `ask`, and `allow` rule classes
- **Tool Integration**: Designed to hook into Claude Code's permission system via hooks

## Core Components

- `flex-check.py`: POSIX shell script that processes permission requests via stdin JSON
- Rule directories: Organized by permission type (deny/ask/allow), then tool name.
- Configuration discovery: Uses `$FLEX_CHECK_PERM_DIRS` directories containing deny/ask/allow subdirectories

## Implementation Requirements

When working on shell scripts in this project:

- Use Python3
- The result must be "clearly correct" and succinct

## Implementation approach

Plan in detail, and review the plan, before acting.
Make small incremental changes.

## Current Status

The project is fully functional - the main `flex-check.sh` script provides flexible permission control for Claude Code tools through directory-based rules and regex pattern matching.

## Testing

To run the test suite, run:

./run-tests.py [COMMAND] [PATTERN]

Commands:
    test [PATTERN] - Run tests and compare to baseline (default)
                     If PATTERN provided, only run tests matching pattern
    accept         - Accept current test results as new baseline (baseline/)
    help           - Show this help message

Examples:
    ./run-tests.py             # Run all tests
    ./run-tests.py test deny   # Run tests containing 'deny' in name

## Key Documentation References

- Claude Code hooks: https://docs.anthropic.com/en/docs/claude-code/hooks
- Claude Code security: https://docs.anthropic.com/en/docs/claude-code/security

The file `INFO.md` provides more references and details.
Keep that file up-to-date as new relevant information and information
sources are discovered.
