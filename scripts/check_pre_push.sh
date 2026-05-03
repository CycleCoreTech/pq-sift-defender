#!/usr/bin/env bash
# Pre-push defense-in-depth gate.
#
# Scans the full diff range about to be pushed and blocks if any pattern
# from the baseline list (or the optional `_internal/vocab_patterns.txt`)
# appears in commit content or commit messages.
#
# Override (use with caution): git push --no-verify
set -euo pipefail

PATTERNS=(
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

EXTRA_PATTERNS_FILE="_internal/vocab_patterns.txt"
if [ -f "$EXTRA_PATTERNS_FILE" ]; then
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    case "$line" in '#'*) continue ;; esac
    PATTERNS+=("$line")
  done < "$EXTRA_PATTERNS_FILE"
fi

while read local_ref local_sha remote_ref remote_sha; do
  if [ "$remote_sha" = "0000000000000000000000000000000000000000" ]; then
    range="$local_sha"
  else
    range="$remote_sha..$local_sha"
  fi

  diff_text=$(git diff "$range" 2>/dev/null || true)
  [ -z "$diff_text" ] && continue

  for pat in "${PATTERNS[@]}"; do
    match=$(echo "$diff_text" | grep -nE "$pat" | head -3 || true)
    if [ -n "$match" ]; then
      echo "" >&2
      echo "PRE-PUSH BLOCK: pattern '$pat' in push range $range" >&2
      echo "$match" >&2
      echo "" >&2
      echo "Override (use with caution): git push --no-verify" >&2
      exit 1
    fi
  done

  msgs=$(git log --format=%B "$range" 2>/dev/null || true)
  [ -z "$msgs" ] && continue
  for pat in "${PATTERNS[@]}"; do
    if echo "$msgs" | grep -Eqi "$pat"; then
      echo "" >&2
      echo "PRE-PUSH BLOCK: pattern '$pat' in commit messages of $range" >&2
      exit 1
    fi
  done
done

exit 0
