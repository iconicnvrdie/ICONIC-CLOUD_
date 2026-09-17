#!/usr/bin/env bash
# Packs install-qwen.sh + qwen-filter binary into one self-contained
# curl|bash installable: qwen-filter-install.sh
set -euo pipefail
cd "$(dirname "$0")"

for f in install-qwen.sh qwen-filter; do
  [ -f "$f" ] || { echo "missing: $f" >&2; exit 1; }
done

B64="$(base64 -w0 qwen-filter)"
MARKER="$(grep -n '^QWEN_EMBEDDED_BASE64=$' install-qwen.sh | head -1 | cut -d: -f1)"
[ -n "$MARKER" ] || { echo "marker line not found in install-qwen.sh" >&2; exit 1; }

{
  head -n "$((MARKER - 1))" install-qwen.sh
  printf "QWEN_EMBEDDED_BASE64='%s'\n" "$B64"
  tail -n +"$((MARKER + 1))" install-qwen.sh
} > qwen-filter-install.sh

chmod 0755 qwen-filter-install.sh
echo "Packed qwen-filter-install.sh ($(du -h qwen-filter-install.sh | cut -f1))"