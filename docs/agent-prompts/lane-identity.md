# Lane identity — set it with environment variables, never `git config`

Every commit in this repository is currently authored `AumOS Wave-1 <aumos@local>`,
from `user.name` and `user.email` in `.git/config`. With four lanes committing, author
attribution is useless: you cannot tell from the log which agent wrote what.

## Do not fix this with `git config`

The obvious fix is wrong here, and dangerously so:

```bash
git config user.name "GLM 5.3 Flash"     # DO NOT DO THIS
```

**Linked worktrees share `.git/config`.** `git rev-parse --git-common-dir` and
`--git-dir` both resolve to the same `.git` for every worktree in this repo, and
`extensions.worktreeConfig` is not enabled. So a `git config user.name` run inside
*any* worktree rewrites the identity for *every* lane at once — and with four lanes
running, they would race each other, each silently relabeling the others' commits.

That converts an attribution problem into a correctness problem.

## Do this instead — environment variables, per process

```bash
export GIT_AUTHOR_NAME="GLM 5.3 Flash (zcode)"
export GIT_AUTHOR_EMAIL="glm@local"
export GIT_COMMITTER_NAME="GLM 5.3 Flash (zcode)"
export GIT_COMMITTER_EMAIL="glm@local"
```

Set both pairs. Author and committer default separately, and `git commit -s` derives
the DCO `Signed-off-by` trailer from the **committer**, so setting only the author
pair leaves the sign-off saying `AumOS Wave-1`.

These are per-process. They override config, touch no shared file, and cannot race.
Verify before your first commit:

```bash
git var GIT_AUTHOR_IDENT && git var GIT_COMMITTER_IDENT
```

## Values per lane

| Lane | Name | Email |
|---|---|---|
| GLM 5.3 Flash, zcode | `GLM 5.3 Flash (zcode)` | `glm@local` |
| MiniMax M3 | `MiniMax M3` | `minimax@local` |
| Claude Code, Opus 5 | `Claude Code (Opus 5)` | `claude@local` |

Leave `.git/config` alone. `AumOS Wave-1 <aumos@local>` stays the repository default,
which is what an unset lane falls back to — and a commit still authored that way is a
useful signal that a lane forgot to set its identity.

## Attribution when identity was not set

For everything committed before this was in place, author is not a discriminator. Use
branch names, or reconstruct the interleaving by timestamp:

```bash
git reflog --date=iso
```

That remains the only reliable record of who did what and when in a shared tree.
