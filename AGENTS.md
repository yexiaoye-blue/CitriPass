<!-- codebase-memory-mcp:start -->
For structural codebase exploration, use the installed `codebase-memory` skill.
<!-- codebase-memory-mcp:end -->

## Project skills

For Rust code changes and review, read `vault-core/.agents/skills/rust-best-practices/SKILL.md`, `vault-core/.agents/skills/rust-engineer/SKILL.md`, and their relevant references. For Rust tests, read `vault-core/.agents/skills/rust-testing/SKILL.md`. For system architecture and dependency boundaries, read `vault-core/.agents/skills/clean-architecture/SKILL.md`. For commit messages, read `vault-core/.agents/skills/git-commit/SKILL.md` and use Conventional Commits. They are project-local, pinned copies; see `vault-core/.agents/skills/SOURCES.md`. Apply guidance pragmatically: CitriPass security invariants and explicit user instructions take precedence. Do not weaken KDFs or replace cryptographic algorithms to improve benchmark results or coverage targets. Use release measurements and regression tests for core changes.

## Delivery contract

- Create one `feature/<feature-name>` branch from the current `master` or `main` for each feature. Keep all fixes, tests, documentation, and review changes for that feature on the same branch.

- Keep feature branches pure. Do not merge, rebase, cherry-pick, or copy commits from `develop`, `master`, `main`, or other feature branches into them. Merge the feature branch into `develop` or another environment through a PR/MR.

- Do not sync environment branches into feature branches. This prohibition is absolute for `develop`, `master`, `main`, `release/*`, and other environment/integration branches; user authorization to merge a feature into an environment branch does not authorize the reverse operation.

- Resolve MR conflicts locally before creating the MR, but never by mutating the original feature branch. Create a temporary integration branch from the latest target branch, apply the feature commits there, resolve conflicts there, and submit the integration branch to the target branch.

- Before creating or updating an MR, fetch both source and target branches and verify all of the following: the source worktree is clean; the local source SHA equals the remote source SHA; the target remote is current; a `git merge-tree` preflight has no unresolved conflicts; and the source history contains no merge/rebase from an environment branch.

- CodeUp/remote UI conflict resolution is forbidden on feature branches. Do not use an online “resolve conflicts” action that creates a merge commit on the source branch. If the source branch changes after MR creation, stop, report the new SHA, and do not continue until the branch-integrity check passes.

- After creating or updating an MR, re-fetch the source branch and confirm its SHA is unchanged. If conflict resolution needs a commit, it must be on the temporary integration branch or target-side integration branch, never on the original feature branch.

- Do not reset, force-push, or rewrite a feature branch to repair contamination without explicit, separate authorization. Preserve the original feature tip first and document the recovery plan.

- Do not commit or force-push to `master`, `main`, or `develop`. Keep commits focused and do not push or create a PR/MR without authorization.
