#!/usr/bin/env bash
# The maintainers' allowlist, made safe the way Bitcoin Core's contrib/verify-commits does
# it: walk the first-parent chain from a pinned TRUSTED ROOT commit to <ref>, and require
# every commit on it to be signed by a key allowed at its PARENT - contrib/verify-commits/
# allowed_signers (SSH) and keys/*.asc (OpenPGP) as they were in the parent commit - so a
# change to the allowlist is vouched for by a key already in it, and a commit signed by a
# key nobody trusted yet (GitHub's web-flow key on a button merge, a stranger's) fails.
# Merges are commits like any other: the maintainer who made the merge signs it, and that
# signature vouches for everything the merge brings in. Second parents are not walked.
#
#   contrib/verify-commits/verify-commits.sh <ref>
#     exit 0 and print the allowlist at <ref> (one `ssh <principal> <key>` or
#     `openpgp <fingerprint> <file>` line each), or exit 1 naming the first bad commit.
#
# The root is the one trust anchor outside the repository: $ROSE_TRUSTED_ROOT, else the
# file ~/.config/rose/trusted-root. It must be an ancestor of <ref>, and its own allowlist
# is trusted as pinned. A deployment repository runs this over the
# product commit it records, with the root it pins beside its own.
#
# Needs git 2.34+ (SSH signature verification), ssh-keygen, and gpg for OpenPGP keys.
set -euo pipefail
cd "$(dirname "$0")/../.."
ref=${1:?ref}
dir=contrib/verify-commits
root=${ROSE_TRUSTED_ROOT:-}
[ -n "$root" ] || root=$(cat "$HOME/.config/rose/trusted-root" 2>/dev/null || true)
[ -n "$root" ] || { echo "error: no trusted root (ROSE_TRUSTED_ROOT, or ~/.config/rose/trusted-root)" >&2; exit 1; }
root=$(git rev-parse --verify "$root^{commit}") || exit 1
tip=$(git rev-parse --verify "$ref^{commit}") || exit 1
git merge-base --is-ancestor "$root" "$tip" || { echo "error: trusted root ${root:0:9} is not an ancestor of $ref" >&2; exit 1; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

# The allowlist as of <commit>: the SSH signers file and the OpenPGP keys, exported to a
# directory of their own. Prints `ssh`/`openpgp` lines; an empty print is an empty list.
allowlist_at() { # allowlist_at <commit> <dir>
  local c=$1 d=$2 f; mkdir -p "$d/keys"
  git show "$c:$dir/allowed_signers" > "$d/allowed_signers" 2>/dev/null || : > "$d/allowed_signers"
  git ls-tree -r --name-only "$c" -- "$dir/keys/" 2>/dev/null | while read -r f; do
    case $f in *.asc) git show "$c:$f" > "$d/keys/$(basename "$f")";; esac
  done
  grep -v '^[[:space:]]*#' "$d/allowed_signers" | awk 'NF >= 3 {print "ssh", $1, $NF}'
  for f in "$d"/keys/*.asc; do
    [ -e "$f" ] || continue
    gpg --show-keys --with-colons "$f" 2>/dev/null | awk -F: -v f="$(basename "$f")" '$1=="fpr"{print "openpgp", $10, f; exit}'
  done
}

# Is <commit> signed by a key in the allowlist exported to <dir>? git picks the signature
# format from the commit itself; the SSH check consults only the exported signers file,
# the OpenPGP check only a throwaway keyring holding the exported keys.
signed_by_allowed() { # signed_by_allowed <commit> <dir> -> prints the signer
  local c=$1 d=$2 status fpr
  export GNUPGHOME="$d/gnupg"; mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
  for f in "$d"/keys/*.asc; do [ -e "$f" ] && gpg --batch --quiet --import "$f" 2>/dev/null || true; done
  status=$(git -c gpg.program=gpg -c gpg.ssh.allowedSignersFile="$d/allowed_signers" verify-commit --raw "$c" 2>&1 || true)
  unset GNUPGHOME
  # OpenPGP: VALIDSIG carries the primary key's fingerprint last, and only an imported
  # (allowed) key can produce it. SSH: git prints ssh-keygen's verdict, `Good "git"
  # signature for <principal> with <type> key <fingerprint>`, and only a key in the
  # signers file gets one; a key missing from it is "No principal matched".
  fpr=$(printf '%s\n' "$status" | awk '$1=="[GNUPG:]" && $2=="VALIDSIG" {print $NF; exit}')
  if [ -n "$fpr" ]; then echo "openpgp $fpr"; return 0; fi
  principal=$(printf '%s\n' "$status" | sed -n 's/^Good "git" signature for \([^ ]*\) with .* key \(.*\)$/\1 (\2)/p' | head -1)
  if [ -n "$principal" ]; then echo "ssh $principal"; return 0; fi
  if [ -z "$status" ]; then echo "  no signature" >&2; else printf '%s\n' "$status" | grep -v '^\[GNUPG:\]' | sed 's/^/  /' >&2; fi
  return 1
}

# Oldest first, first-parent only, the root excluded (its allowlist is the pinned trust).
for c in $(git rev-list --first-parent --reverse "$root..$tip"); do
  parent=$(git rev-parse "$c^1")
  d="$tmp/$parent"
  if [ ! -d "$d" ]; then mkdir -p "$d"; allowlist_at "$parent" "$d" > "$d/list"; fi
  if [ ! -s "$d/list" ]; then
    echo "error: no allowlist at $(git rev-parse --short "$parent"), the parent of $(git rev-parse --short "$c"): the trusted root must be at or after the commit that added $dir" >&2
    exit 1
  fi
  if ! signer=$(signed_by_allowed "$c" "$d" 2> "$tmp/why"); then
    echo "error: $(git rev-parse --short "$c") ($(git log -1 --format='%an, %s' "$c" | cut -c1-70)) is not signed by a key allowed at its parent:" >&2
    cat "$tmp/why" >&2
    sed 's/^/  allowed then: /' "$d/list" >&2
    exit 1
  fi
  echo "ok: $(git rev-parse --short "$c") signed by $signer" >&2
done
allowlist_at "$tip" "$tmp/tip"
