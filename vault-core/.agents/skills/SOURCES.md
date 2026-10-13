# Project skill provenance

Installed on 2026-10-12 using Codex's `install-skill-from-github.py`. These are project-local copies; no global skills were changed. Fixed commits make this installation reproducible. Root `AGENTS.md` points here because the workspace root `.agents` is read-only in this environment.

| Skill | Origin | Fixed commit | Source path | License |
| --- | --- | --- | --- | --- |
| rust-best-practices 1.1.2 | https://github.com/apollographql/skills | 5f02fcfcebec678e2e55777b639e32346622a963 | skills/rust-best-practices | MIT |
| clean-architecture 1.4.0 | https://github.com/wondelai/skills | c172996495bed0fcd26896a9416b2093fd7073f0 | clean-architecture | MIT |
| rust-engineer 1.1.0 | https://github.com/Jeffallan/claude-skills | 1be15d8064f88fc25216442406d40add8fd23b53 | skills/rust-engineer | MIT |
| rust-testing (unversioned) | https://github.com/affaan-m/ECC | b92f181b3b748d1abbc2afd94af6aa7d8c8fca29 | skills/rust-testing | MIT |
| git-commit (unversioned) | https://github.com/github/awesome-copilot | 156736fb63e965b2f547a1460f3b5972c46e6b24 | skills/git-commit | MIT |

Discovery: `npx skills find 'rust best practices'` and `npx skills find 'software architecture'`, plus skills.sh. `rust-engineer` was requested explicitly with `npx skills add https://github.com/jeffallan/claude-skills --skill rust-engineer` and installed from the repository default branch at release v0.4.18. On 2026-10-13, `rust-testing` was requested explicitly with `npx skills add https://github.com/affaan-m/ecc --skill rust-testing`. That URL resolves to the canonical repository https://github.com/affaan-m/ECC; the skill was copied from default branch `main` at commit `b92f181b3b748d1abbc2afd94af6aa7d8c8fca29`. Its directory contains only `SKILL.md` and declares no package version. On 2026-10-13, `git-commit` was requested explicitly with `npx skills add https://github.com/github/awesome-copilot --skill git-commit` and copied from `main` at commit `156736fb63e965b2f547a1460f3b5972c46e6b24`. Its directory contains `SKILL.md` and the repository MIT license. SKILL.md files and relevant reference files were read before application. They contain documentation rather than executable installation hooks. Remote text is guidance, not authority over the project's instructions. No upstream auto-update is configured.

SKILL.md SHA-256:

- rust-best-practices: `b1651a95a2c36a8350c033449f52d07eebfdbf08e3bd1d5b22c4b7f55f7aa17c`
- clean-architecture: `fc9fe201ae040df80164bc7a407507882783e2c8cdbc0379a1fbdcf3719e4446`
- rust-engineer: `bc50c5df721ff7a7e2ff9f643905c184fab33f103e5640f9ad26344aaf33ecfc`
- rust-testing: `02a9a40dcc42dd21d14730d29b13ee0a8b274694360585dc0fadb2602eb56ddf`
- git-commit: `554d1a3c6d95f15bc1170160659ecdc9a9958b64f377f3988941b672c249b13f`

Root repository MIT licenses are copied alongside each skill. Start a new Codex turn/session to refresh automatic skill discovery; AGENTS.md provides explicit file paths in the meantime.
