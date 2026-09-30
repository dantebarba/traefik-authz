#!/bin/sh
# Fail when the repository would publish personal or secret data.
#
#   scripts/scan-secrets.sh                 scan every tracked file
#   scripts/scan-secrets.sh --range A..B    scan the lines added in A..B and those commits' identities
#
# Only generic patterns live here. Strings specific to one person or network go, one per line,
# in "$TRAEFIK_AUTHZ_ENV_DIR/forbidden-strings.txt", which never enters this repository.
# Commit messages are checked against both; commit identities only against SCAN_ALLOWED_EMAIL, an
# extended regex (default: noreply addresses), since a noreply address may embed a user name.
set -eu

range=""
[ "${1:-}" = --range ] && range=$2
log_range=$range
empty_tree=$(git hash-object -t tree /dev/null)
case $range in "$empty_tree.."*) log_range=${range#"$empty_tree.."} ;; esac

allowed_email=${SCAN_ALLOWED_EMAIL:-'noreply'}
repo_root=$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")
private_list="${TRAEFIK_AUTHZ_ENV_DIR:-$(dirname "$repo_root")/$(basename "$repo_root")-env}/forbidden-strings.txt"
self="scripts/scan-secrets.sh"

patterns='[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}
(^|[^0-9.])10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}
(^|[^0-9.])192\.168\.[0-9]{1,3}\.[0-9]{1,3}
(^|[^0-9.])172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}
(^|[^0-9.])100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}
[a-z0-9-]+\.ts\.net
/home/[a-z][a-z0-9_-]*/
/Users/[A-Za-z][A-Za-z0-9_-]*/
gh[pousr]_[A-Za-z0-9]{20,}
glpat-[A-Za-z0-9_-]{20,}
sk-[A-Za-z0-9_-]{20,}
xox[abpr]-[A-Za-z0-9-]{10,}
AKIA[0-9A-Z]{16}
-----BEGIN [A-Z ]*PRIVATE KEY-----'
allowed='@example\.|@users\.noreply\.github\.com|noreply@|git@github\.com|user@host'

content() {
  if [ -n "$range" ]; then
    git diff --no-color --unified=0 "$range" -- . ":(exclude)$self" | sed -n 's/^+[^+]/&/p'
  else
    git ls-files -z | grep -zv "^$self\$" | xargs -0 grep -I -H -n '' 2>/dev/null || true
  fi
}

found=0
hits=$(content | grep -E -f /dev/fd/3 3<<EOF_PATTERNS | grep -Eiv "$allowed" || true
$patterns
EOF_PATTERNS
)
if [ -n "$hits" ]; then
  echo "scan-secrets: generic personal or secret data found:" >&2
  echo "$hits" | cut -c1-200 >&2
  found=1
fi

if [ -f "$private_list" ]; then
  private=$(grep -v '^[[:space:]]*$' "$private_list" | grep -v '^#' || true)
  if [ -n "$private" ]; then
    hits=$( { content; [ -z "$range" ] || git log --format='%B' "$log_range"; } | grep -F -i -f /dev/fd/3 3<<EOF_PRIVATE || true
$private
EOF_PRIVATE
)
    if [ -n "$hits" ]; then
      echo "scan-secrets: strings from the private list found (values not shown): $(echo "$hits" | cut -d: -f1 | sort -u | tr '\n' ' ')" >&2
      found=1
    fi
  fi
else
  echo "scan-secrets: no private list at $private_list; generic patterns only" >&2
fi

if [ -n "$range" ]; then
  bad=$(git log --format='%ae%n%ce' "$log_range" | sort -u | grep -Ev "$allowed_email" || true)
  if [ -n "$bad" ]; then
    echo "scan-secrets: commits in $range use a non-allowed identity; set user.email for this repository" >&2
    found=1
  fi
fi

exit $found
