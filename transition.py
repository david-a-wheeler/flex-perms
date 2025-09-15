#!/usr/bin/env python3

import sys
import re
import os

def convert_rule_file(filepath):
    """Convert old regex format to new /regex/flags format while preserving comments"""

    with open(filepath, 'r') as f:
        lines = f.readlines()

    flags = ""
    current_section = None
    output_lines = []

    for line in lines:
        stripped = line.strip()

        # Track current section
        if stripped.startswith('[') and stripped.endswith(']'):
            current_section = stripped.lower()
            if current_section == '[info]':
                output_lines.append(line)
                continue

        # Extract flags from [info] section
        if current_section == '[info]' and stripped.startswith('flags'):
            match = re.match(r'flags\s*=\s*(.+)', stripped)
            if match:
                flags = match.group(1).strip().strip('\'"')
                # Skip this line - we're removing flags
                continue

        # Convert regex patterns in clause sections
        if current_section and current_section.startswith('[clause.'):
            # Look for assignment lines that aren't already /regex/ format
            if '=' in line and not re.search(r'=\s*/.*/', line):
                match = re.match(r'(\s*[^=]+\s*=\s*)([\'"]?)(.+?)\2\s*$', line)
                if match:
                    prefix, quote, value = match.groups()
                    # Convert to /regex/flags format
                    output_lines.append(f"{prefix}/{value}/{flags}\n")
                    continue

        # Keep all other lines (including comments) unchanged
        output_lines.append(line)

    return output_lines

def main():
    if len(sys.argv) < 2:
        print("Usage: transition.py file1.rule [file2.rule ...]", file=sys.stderr)
        sys.exit(1)

    for filepath in sys.argv[1:]:
        if not os.path.exists(filepath):
            print(f"Warning: {filepath} not found", file=sys.stderr)
            continue

        try:
            converted_lines = convert_rule_file(filepath)

            # Write back to file
            with open(filepath, 'w') as f:
                f.writelines(converted_lines)

            print(f"Converted {filepath}")

        except Exception as e:
            print(f"Error processing {filepath}: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()