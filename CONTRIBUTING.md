# Contributing to MonarchDomain

Thanks for considering a contribution!

## Ground rules
- This is a security tool - keep changes focused on **legitimate recon
  robustness** (accuracy, performance, resumability, output quality). PRs that
  add exploitation, evasion-of-authorization, or attack payloads will be declined.
- Bash only, no new hard dependencies without discussion (keep it Kali-friendly
  out of the box).

## Dev workflow
1. Fork & branch from `main`.
2. Run ShellCheck before opening a PR: `shellcheck monarchdomain.sh`
3. If you touched behavior, update `README.md` and `CHANGELOG.md`.
4. If tests exist under `tests/`, run them: `bats tests/`
5. Open a PR describing the change and why.

## Style
- `set -uo pipefail` at the top; avoid `set -e` footguns with intentional
  non-zero returns (curl failures, grep misses, etc.) - handle them explicitly.
- Prefer `mapfile`/arrays over word-splitting raw command substitution.
- Keep functions single-purpose and testable.

## Reporting bugs / requesting features
Open a GitHub issue with your OS/Kali version, command used, and expected vs.
actual behavior.
