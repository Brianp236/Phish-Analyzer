#!/usr/bin/env bash
# Run from the repo root before every push. Exits non-zero if anything sensitive is staged or present.
set -u
fail=0
red() { printf '\033[31m%s\033[0m\n' "$*"; }

echo "Checking for files that must never be committed..."
for f in $(git ls-files 2>/dev/null; git diff --cached --name-only 2>/dev/null); do
  case "$f" in
    secrets.env|*token.json|*client_secret*.json|emails/*|quarantine/*|released/*|attachments/*|logs/*|link_screenshots/*|*.exe|*.quarantined)
      red "  BLOCKED file tracked: $f"; fail=1 ;;
    *.eml)
      [[ "$f" == samples/* ]] || { red "  BLOCKED email file: $f"; fail=1; } ;;
  esac
done

echo "Scanning tracked files for keys and personal data..."
files=$(git ls-files 2>/dev/null || find . -type f -not -path './.git/*')
patterns=(
  '[a-f0-9]{64}"?\s*$'            # VirusTotal API key style (64 hex) assigned on a line
  'VT_API_KEY\s*=\s*"?[a-f0-9]{20,}'
  'ya29\.[A-Za-z0-9_-]{20,}'      # Google access token
  '1//[A-Za-z0-9_-]{20,}'         # Google refresh token
  'GOCSPX-[A-Za-z0-9_-]{10,}'     # Google client secret
  '"refresh_token"\s*:\s*"[^"]+'   # a filled-in token.json
  'limewire\.com/d/[A-Za-z0-9]+#' # live share link with its key
  'fishinthewater'
  '@gmail\.com'
  '192\.168\.[0-9]+\.[0-9]+'
  '100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]+\.[0-9]+'   # Tailscale addresses
)
for p in "${patterns[@]}"; do
  hits=$(echo "$files" | xargs -r grep -nIE "$p" 2>/dev/null | grep -vE '^(./)?check_secrets.sh:' | grep -vE '192\.168\.122\.|100\.64\.0\.0/10|100\.101\.102\.103')   # known-safe examples
  if [ -n "$hits" ]; then red "  Pattern '$p':"; echo "$hits" | sed 's/^/    /'; fail=1; fi
done

if [ $fail -eq 0 ]; then echo "Clean. Safe to push."; else red "Fix the items above before pushing."; fi
exit $fail
