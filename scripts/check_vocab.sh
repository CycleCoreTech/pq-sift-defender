#!/usr/bin/env bash
# Public-artifact discipline gate (generic security baseline).
#
# Blocks commits containing common secret patterns, large files, or any
# pattern listed in the optional `_internal/vocab_patterns.txt` file
# (gitignored). The internal pattern file is the project-specific extension
# layer; this script holds only the generic security baseline.
#
# Bypass per-line: append "# noqa: vocab" or "<!-- noqa: vocab -->".
# Emergency global bypass: SKIP=vocab git commit ...
set -euo pipefail

# Generic security baseline (universal patterns).
PATTERNS=(
  # Secret / API key shapes
  'sk-ant-[A-Za-z0-9_-]{20,}'
  'sk_live_[A-Za-z0-9]{10,}'
  'sk_test_[A-Za-z0-9]{10,}'
  'whsec_[A-Za-z0-9]{20,}'
  'pq_live_[A-Za-z0-9]{10,}'
  'AKIA[0-9A-Z]{16}'
  'AWS_ACCESS_KEY_ID\s*='
  'AWS_SECRET_ACCESS_KEY\s*='
  'AVNS_[A-Za-z0-9]{20,}'
  'AIzaSy[A-Za-z0-9_-]{30,}'
  'sk-or-v1-[A-Za-z0-9]{20,}'
  'AGE-SECRET-KEY-[0-9A-Z]{50,}'
  'gho_[A-Za-z0-9]{30,}'
  'ghp_[A-Za-z0-9]{30,}'
  'github_pat_[A-Za-z0-9_]{40,}'
  're_[A-Za-z0-9]{20,}'
  'BEGIN RSA PRIVATE KEY'
  'BEGIN OPENSSH PRIVATE KEY'
  'BEGIN PRIVATE KEY'
  'BEGIN EC PRIVATE KEY'
)

# Load project-specific extensions from gitignored file if present.
EXTRA_PATTERNS_FILE="_internal/vocab_patterns.txt"
EXTRA_PATTERNS=()
if [ -f "$EXTRA_PATTERNS_FILE" ]; then
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    case "$line" in '#'*) continue ;; esac
    EXTRA_PATTERNS+=("$line")
  done < "$EXTRA_PATTERNS_FILE"
fi

ALL_PATTERNS=("${PATTERNS[@]}" "${EXTRA_PATTERNS[@]}")

fail=0
for f in "$@"; do
  case "$f" in
    *.lock|*.png|*.jpg|*.jpeg|*.gif|*.pdf|*.mp4|*.webm|*.svg|*.ico) continue ;;
    scripts/check_vocab.sh|scripts/check_pre_push.sh) continue ;;
    .pre-commit-config.yaml) continue ;;
    _internal/*) continue ;;
  esac
  [ -f "$f" ] || continue

  for pat in "${ALL_PATTERNS[@]}"; do
    if echo "$f" | grep -Eqi "$pat"; then
      echo "BLOCK [filename]: $f matches /$pat/i" >&2
      fail=1
    fi
  done

  while IFS= read -r line_with_no; do
    lineno="${line_with_no%%:*}"
    line="${line_with_no#*:}"
    case "$line" in *'noqa: vocab'*) continue ;; esac
    for pat in "${ALL_PATTERNS[@]}"; do
      if echo "$line" | grep -Eqi "$pat"; then
        echo "BLOCK [$f:$lineno]: matches /$pat/i" >&2
        echo "  > $line" >&2
        fail=1
      fi
    done
  done < <(grep -nE '.' "$f" 2>/dev/null || true)

  size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)
  if [ "$size" -gt 1048576 ]; then
    echo "BLOCK [$f]: large file (${size} bytes; max 1MB)" >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "" >&2
  echo "Commit blocked. Fix or append '# noqa: vocab'." >&2
  echo "Emergency: SKIP=vocab git commit ..." >&2
  exit 1
fi
exit 0
