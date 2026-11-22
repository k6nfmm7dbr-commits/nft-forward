#!/usr/bin/env bash
# Print true only when the whole push changes nothing outside documentation.
set -euo pipefail
event=${1:-}
before=${2:-}
after=${3:-}
if [[ "$event" == push && "$before" =~ ^[0-9a-f]{40}$ && "$before" != 0000000000000000000000000000000000000000 && "$after" =~ ^[0-9a-f]{40}$ ]] \
  && git cat-file -e "$before^{commit}" 2>/dev/null \
  && git cat-file -e "$after^{commit}" 2>/dev/null \
  && git diff --quiet "$before" "$after" -- . \
    ':(exclude)docs/**' ':(exclude)README.md' ':(exclude)CHANGELOG.md' ':(exclude)FUTURE_IMPROVEMENTS.md'; then
  printf 'true\n'
else
  printf 'false\n'
fi
