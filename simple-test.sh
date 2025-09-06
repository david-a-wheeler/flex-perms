#!/bin/sh
FLEX_CHECK_PERM_DIRS="sample-flex-perms"
export FLEX_CHECK_PERM_DIRS
echo '{"tool_name":"WebFetch","tool_input":{"url":"https://169.254.169.254"}}' | ./flex-check.py
