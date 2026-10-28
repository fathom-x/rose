# verify-commits

The maintainers' signing keys, in the tree, and the script that makes the list trustworthy
from one pin outside it. It is what a deployment repository checks the product commit it
builds against (its `product_commit`), the way
Bitcoin Core's `contrib/verify-commits/` is what its release process trusts.

| File | What |
|---|---|
| `allowed_signers` | SSH signing keys, OpenSSH `allowed_signers` format: `<principal> namespaces="git" <type> <key>`. |
| `keys/*.asc` | OpenPGP public keys, one armored file each. |
| `verify-commits.sh <ref>` | Every commit on the first-parent chain from the trusted root to `<ref>` is signed by a key that was in the list at its parent. Prints the list at `<ref>`. |

The **trusted root** is a commit you pin outside the repository (`ROSE_TRUSTED_ROOT`, or
`~/.config/rose/trusted-root`): its allowlist is trusted as is, and every later change to
the list is vouched for by a key already in it. Pin the commit that adds a key you have
checked out of band; the script refuses a root from before the list existed.

The rule it enforces: **a commit on a release branch is signed by a maintainer**, merges
included. The merge button on GitHub signs with GitHub's key, which is never in the list,
so `main` and `btc` advance by fast-forward or by merges a maintainer made and signed on
their own machine (`git merge -S`). Before the root, history is whatever it was; the script
does not look there.

```sh
ROSE_TRUSTED_ROOT=<sha> contrib/verify-commits/verify-commits.sh origin/main
```

CI runs it on every push to `btc` (`.github/workflows/verify-commits.yml`) once the repository variable
`ROSE_TRUSTED_ROOT` is set; until then the job reports that it is unset and passes.

To add a maintainer: append their SSH key to `allowed_signers` (`ssh-keygen -Y` needs the
`namespaces="git"` option) or their armored OpenPGP public key under `keys/`, in a commit
signed by a key already listed. To rotate, the same, removing the old one.
