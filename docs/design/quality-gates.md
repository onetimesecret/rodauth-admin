# Design: quality gates

Decided 2026-09-05. The checks this repo runs, where each one runs, and what
is deliberately left ungated.

## The layers

| Layer | What runs | When | Bypass |
|---|---|---|---|
| **editor** | RuboCop, via your editor's integration | as you type | trivial |
| **pre-commit hook** | trailing whitespace, end-of-file, merge markers, private keys, large files (1000kb), YAML, no-commit-to-main, RuboCop on staged Ruby, actionlint, gitleaks | `git commit` | `--no-verify` |
| **pre-push hook** | `bin/ci` — lint, try, rspec | `git push` | `--no-verify` |
| **CI** | `lint`, `test`, `test-postgres`, `hygiene`, `secrets`, `audit` | PR and push to main | none |
| **branch rule** | the GitHub "Defaults" ruleset on `main`: no deletion, no force-push, PR required, and — once the operator adds the required-status-checks rule (see the PR that introduced this doc) — the six CI checks required | merge | none |

Each layer is faster and weaker than the one below it. The hooks exist to
save a round trip, not to be the gate; every hook is re-run in CI (RuboCop by
the `lint` job, gitleaks by the `secrets` job over the full history, the rest
by `hygiene` over `pre-commit run --all-files`), so a `--no-verify` push costs
time, not correctness. gitleaks is the one hook `hygiene` cannot re-run: its
entry scans the *staged* diff and CI stages nothing, so it is skipped there
and given a job of its own.

Install the hooks with `bin/setup`, which runs `bundle install` and then
`pre-commit install --install-hooks --hook-type pre-commit --hook-type pre-push`.
If `pre-commit` is not on PATH it warns and continues (`uv tool install
pre-commit` or `pip install pre-commit`); the actionlint and gitleaks hooks
build from Go. Run them by hand with `pre-commit run --all-files` and
`pre-commit run --hook-stage pre-push`.

## One entry point

`bin/ci` is the single definition of "the checks". Stages: `lint` (RuboCop),
`try` (tryouts), `rspec`, and `audit` (bundler-audit). No arguments runs
lint, try, rspec in that order and stops at the first failure; `audit` is out
of the default set because it refreshes the advisory database over the
network.

`rake test`, the pre-push hook and every CI job invoke `bin/ci`. There is no
second command line to keep in sync: the workflow file names a stage, never a
tool. That is the whole point — a check spelled out in `ci.yml` is a check a
developer cannot reproduce locally with one word, and it drifts the first time
someone adds a flag on one side only.

CI job ids are the check names (`lint`, `test`, `test-postgres`, `hygiene`,
`secrets`, `audit`). Adding a `name:` to a job renames the check and silently
breaks the required-checks rule; don't.

## RACK_ENV is the opt-in for a provisioned database

direnv exports `RACK_ENV=development` and `ADMIN_DATABASE_URL` (your real
local authdb) into every shell in the checkout. So "`ADMIN_DATABASE_URL` is
set" cannot mean "a database was provisioned for this run".

The rule, applied identically by `bin/ci` and by `spec/support/spec_mode.rb`:
inherited `ADMIN_DATABASE_URL*` count only when the caller also set
`RACK_ENV=test` *before* `bin/ci` or `rspec` started. Otherwise `bin/ci`
unsets the three URLs for the `try` and `rspec` stages and the suite builds
its own scratch SQLite under `Dir.tmpdir`. Without this, `bin/ci` setting
`RACK_ENV=test` itself would turn every dev shell into a "provisioned" run
pointed at the developer's real authdb.

This is load-bearing in CI, not just a local nicety: the `test-postgres` lane
sets `RACK_ENV: test` alongside the three URLs. Had it set only the URLs,
`bin/ci` would have stripped them and the lane would have quietly tested
SQLite while claiming to prove the grants. The scratch-guard name rule still
applies on top — the database name must match `(^|_)(test|ci|scratch)($|_)`
— because the suite truncates account tables through the migrator credential.

## What is not gated, and why

- **A coverage threshold.** SimpleCov prints one `Coverage: NN.N% (a/b lines)`
  line at the end of the suite, and CI lifts that line into the job summary;
  nothing fails on it. A number that is a gate gets gamed with tests that
  assert nothing.
  Revisit if coverage drifts down across several PRs without anyone noticing
  on the PR page.
- **Type checking (RBS/Sorbet).** ~1.4k lines of Roda and Sequel, both of
  which are heavy on runtime metaprogramming; the annotation cost is larger
  than the bug class it would catch here. Revisit if the app grows past the
  point where a reader cannot hold the data shapes in their head.
- **ERB linting.** Four views, all server-rendered, all covered by the
  front-door specs. Revisit when the view layer grows a helper library.
- **A Ruby version matrix.** The deploy target is one Ruby, pinned in
  `.ruby-version`; a matrix would test configurations nobody runs. Revisit
  when a Ruby upgrade is scheduled, and then as a temporary second lane.

Two things that *are* gated and easy to miss: the app under test is wrapped
in `Rack::Lint` in the RSpec suite, so a Rack 3 protocol violation fails the
suite (there are none today); and every `uses:` in the workflows is pinned to
a full commit SHA, kept current by Dependabot (weekly, one grouped PR per
ecosystem, `deps` commit prefix).

## Adding a check

Add a `bin/ci` stage, or add a pre-commit hook. Never add a bare command to
`ci.yml`.

- **A stage** if it is a Ruby-level check over the project (a new linter, a
  second test runner). Two places in `bin/ci`: the `STAGES` string (which
  drives both the validation and `usage`) and the `case` in `stage_command()`,
  the only place a command line lives. Add it to `DEFAULT_STAGES` as well
  unless it needs the network or a service — then give it its own CI job the
  way `audit` has one.
- **A hook** if it is file-scoped, cheap and language-agnostic (formatting,
  secrets, config linting). The `hygiene` job picks it up for free, because
  it runs the whole config over every file.

Either way the local hook and the CI job stay identical without anyone
maintaining two lists.

## Files

- `bin/ci` — the stages.
- `bin/setup` — bundle plus hook installation.
- `.pre-commit-config.yaml` — the hooks and the stage split.
- `.github/workflows/ci.yml` — the six jobs; the four Ruby ones call `bin/ci`.
- `.github/dependabot.yml` — gem and action bumps.
- `spec/support/spec_mode.rb` — the RACK_ENV opt-in rule, unit-tested.
