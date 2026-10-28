# verify-commits

The maintainers' signing keys, in the tree, and the script that makes the list trustworthy
from one pin outside it. It is what a deployment repository checks the product commit it
builds against (its `product_commit`), with the
same rule that repository applies to its own keys.

| File | What |
|---|---|
| `allowed_signers` | SSH signing keys, OpenSSH `allowed_signers` format: `<principal> namespaces="git" <type> <key>`. |
| `keys/*.asc` | OpenPGP public keys, one armored file each. |
| `verify-commits.sh [--chain] <ref>` | The two checks below. Prints the list at `<ref>`. |

The **trusted root** is a commit you pin outside the repository (`ROSE_TRUSTED_ROOT`, or
`~/.config/rose/trusted-root`): its allowlist, and its copy of the script, are trusted as is.
Pin a commit whose list you have checked out of band; the script refuses a root from before
the list existed.

Two rules:

1. **The allowlist is vouched for.** On the first-parent chain from the root to `<ref>`,
   every commit that changes `contrib/verify-commits/` is signed by a key that was in the
   list at its parent. So a key is only ever added, removed or rotated by a key already
   trusted, and the merge button, which signs with GitHub's key, cannot land such a change:
   the maintainer merges it on their own machine (`git merge -S`). Every other commit on the
   chain is not examined: it may be merged by the button, pushed unsigned, or come from
   anyone with push access.
2. **The commit you ship is signed.** `<ref>` itself is signed by a key in the allowlist as
   of `<ref>`. That one signature vouches for everything on the line since the last signed
   commit, which is why a deployment records only such a commit: after merging with the
   button, ship by pushing a signed commit (an empty one will do) and recording that.

`--chain` runs rule 1 alone. CI runs that on every push to `btc` and every pull request
(`.github/workflows/verify-commits.yml`) once the repository variable `ROSE_TRUSTED_ROOT` is
set; until then the job reports that it is unset and passes. A branch therefore fails CI only
when it changes the allowlist in a commit nobody trusted signed, which is when you want to
hear about it early.

```sh
ROSE_TRUSTED_ROOT=<sha> contrib/verify-commits/verify-commits.sh origin/btc           # both rules
ROSE_TRUSTED_ROOT=<sha> contrib/verify-commits/verify-commits.sh --chain origin/btc   # the allowlist only
```

To add a maintainer: append their SSH key to `allowed_signers` (`ssh-keygen -Y` needs the
`namespaces="git"` option) or their armored OpenPGP public key under `keys/`, in a commit
signed by a key already listed, merged signed. To rotate, the same, removing the old one.
Changes to the script itself and this file count as allowlist changes too.
