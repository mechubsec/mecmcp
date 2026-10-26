#!/usr/bin/env bash
# Docs gate for docs/OAUTH.md: flags and reason codes must match the code both ways.
set -euo pipefail
cd "$(dirname "$0")/.."
doc=docs/OAUTH.md
fail=0

# Flags as written inside fenced blocks (a line starting `--oauth-...`).
doc_flags=$(awk '/^ *```/{f=!f; next} f' "$doc" | grep -oE '^ *--oauth-[a-z-]+' | tr -d ' ' | sort -u)
# Flags the CLI defines: `pub oauth_x:` fields in OAuthResourceArgs.
cli_flags=$(grep -oE '^ +pub oauth_[a-z_]+:' crates/mecmcp-runtime/src/cli.rs | sed -E 's/ +pub /--/; s/:$//; s/_/-/g' | sort -u)
[ -n "$cli_flags" ] || { echo "no oauth flags found in cli.rs"; exit 1; }
[ -n "$doc_flags" ] || { echo "no oauth flags found in fenced blocks of $doc"; exit 1; }
if [ "$doc_flags" != "$cli_flags" ]; then
  echo "flag mismatch between $doc (<) and cli.rs (>):"
  diff <(echo "$doc_flags") <(echo "$cli_flags") || true
  fail=1
fi

# Reason codes: first column of the reason table, split on '/'.
doc_codes=$(sed -n '/^| Reason | Usually means/,/^$/p' "$doc" | grep -oE '^\| `[^|]+`' \
  | grep -oE '[a-z_]+' | sort -u)
for code in $doc_codes; do
  [ "$code" = unmapped_scope ] && src=crates/mecmcp-transport/src || src="crates/mecmcp-oidc/src crates/mecmcp-transport/src"
  # shellcheck disable=SC2086
  grep -rqE "\"$code\"" $src || { echo "doc names reason with no producer: $code"; fail=1; }
done
# Every code the transport itself produces must be documented.
for code in $(grep -hoE '(Invalid|Unavailable)\("[a-z_]+"\)' crates/mecmcp-transport/src/oauth_resource/mod.rs | grep -oE '"[a-z_]+"' | tr -d '"' | sort -u) unmapped_scope; do
  echo "$doc_codes" | grep -qx "$code" || { echo "code produced but not documented: $code"; fail=1; }
done
# Every oidc reason code must be documented.
for code in $(grep -oE '=> "[a-z_]+"' crates/mecmcp-oidc/src/error.rs | grep -oE '"[a-z_]+"' | tr -d '"' | sort -u); do
  case $code in nonce_missing|nonce_mismatch|authorized_party_mismatch) continue ;; esac
  echo "$doc_codes" | grep -qx "$code" || { echo "oidc code not documented: $code"; fail=1; }
done

# The scope-map example must be valid JSON with version 1 (the loader test pins its shape).
python3 - "$doc" <<'PY' || fail=1
import json, re, sys
text = open(sys.argv[1]).read()
block = re.search(r'```json\n(\{\s*"version".*?\n\})\n\s*```', text, re.S)
sys.exit(0 if block and json.loads(block.group(1))["version"] == 1 else 1)
PY
exit $fail
