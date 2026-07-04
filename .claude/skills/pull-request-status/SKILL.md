---
name: pull-request-status
description: Monitor the status of a pull request — its GitHub Actions checks (build/test), review and mergeable state, and SonarCloud pull-request analysis (quality gate + new-code issues and hotspots). Use when the user asks about PR status, whether a PR is green/mergeable, failing checks/build on a PR, or SonarCloud issues on a PR.
---

# Pull-request status: GitHub checks + review state + SonarCloud PR analysis

Project constants:

- GitHub repo: `alkampfergit/DotNetCoreCryptography` (public — unauthenticated REST works)
- SonarCloud project key: `alkampfergit_DotNetCoreCryptography`, organization: `alkampfergit-github`
- SonarCloud project: https://sonarcloud.io/project/overview?id=alkampfergit_DotNetCoreCryptography

## 0. Resolve the pull request

Everything below keys off the PR number and its head commit. Resolve them once:

```
# PR for the current branch (or pass an explicit number the user gave you)
gh pr view --json number,headRefName,baseRefName,headRefOid,state,isDraft
# ...or find the PR for a specific branch:
gh pr list --head <branch> --json number,headRefName,baseRefName,state
```

Keep `PR_NUMBER`, `HEAD_SHA` (`headRefOid`), and `BASE` (`baseRefName`) for reuse. If there is no
open PR for the branch, say so and fall back to branch status (SonarCloud `branch=<branch>` params,
`gh run list --branch <branch>`).

## 1. GitHub: checks + review + mergeability (one call)

`statusCheckRollup` returns every check/status on the PR head in a single call — this is the
fastest way to see build/test health:

```
gh pr view <PR_NUMBER> --json number,title,state,isDraft,mergeable,mergeStateStatus,reviewDecision,statusCheckRollup
```

- `mergeable`: `MERGEABLE` / `CONFLICTING` / `UNKNOWN`.
- `mergeStateStatus`: `CLEAN`, `BLOCKED`, `BEHIND`, `DIRTY`, `UNSTABLE` (failing/pending checks).
- `reviewDecision`: `APPROVED` / `CHANGES_REQUESTED` / `REVIEW_REQUIRED`.
- `statusCheckRollup[]`: each entry has `name`/`context`, `status` (`QUEUED|IN_PROGRESS|COMPLETED`)
  and `conclusion` (`SUCCESS|FAILURE|NEUTRAL|CANCELLED|SKIPPED|TIMED_OUT`) or a check-run `state`.

The PR is green when every completed check is `SUCCESS`/`NEUTRAL`/`SKIPPED` and none are pending.

Drill into a failed workflow run for the diagnosis (build/test failures):

```
gh run list --branch <headRefName> --limit 10
gh run view <run-id> --log-failed         # only when a run failed
```

This repo's key workflows: **BuildAndPublish** (build + test matrix on ubuntu & windows, runs on
push), **SonarCloud** and **CodeQL** (run on the `pull_request` event). Test results are published
as a per-OS report (dorny/test-reporter) and TRX artifacts on the BuildAndPublish run; skipped
tests (e.g. the Azure Key Vault integration test without credentials) surface as `::warning::`
annotations.

Fallback when `gh` is missing/unauthenticated (repo is public) — check runs for the head commit:

```
curl -s "https://api.github.com/repos/alkampfergit/DotNetCoreCryptography/commits/<HEAD_SHA>/check-runs"
```

Note: the "SonarCloud Code Analysis" check reports the quality gate — it can be `failure` while the
build itself is green. Diagnose that via SonarCloud (below), not via run logs.

## 2. SonarCloud pull-request analysis

Delegate the SonarCloud querying to the generic **`sonarcloud`** agent (Task tool,
`subagent_type: "sonarcloud"`). That agent holds all the API mechanics; this skill only supplies
*this project's* real parameters:

- `projectKey`: `alkampfergit_DotNetCoreCryptography`
- `organization`: `alkampfergit-github`
- `pullRequest`: `<PR_NUMBER>` — pass the PR number so it queries the **PR analysis** (new-code
  findings), NOT the branch. No token needed (public project).

Ask it for the PR quality gate, all open issues, and all security hotspots. Example prompt:

> Project key `alkampfergit_DotNetCoreCryptography`, organization `alkampfergit-github`,
> pullRequest `<PR_NUMBER>`. Report the quality gate status, all open issues (grouped by severity
> with file:line), and all TO_REVIEW security hotspots.

For **whole-project / branch** health (no open PR, or the user asks about the project overall),
launch the same agent with `branch=<branch>` or with no scope selector (default branch) instead of
`pullRequest`.

The agent returns the quality gate status, issues grouped by severity as
`severity type rule — file:line — message`, and hotspots. If it reports empty PR data, see the
caveat at the bottom.

## 3. Reporting

Lead with the headline: **PR #N is mergeable / blocked** — then, in order:

1. **Checks** — status per workflow (BuildAndPublish / SonarCloud / CodeQL), with failing run
   links and, for build/test failures, the failing test name(s) from `--log-failed`.
2. **Review state** — `reviewDecision` and `mergeStateStatus` (e.g. `BEHIND` ⇒ needs a rebase).
3. **SonarCloud** — PR quality gate status, then issues grouped by severity with `file:line`.
   For each issue say whether it is (a) fixable in code, or (b) a candidate to dismiss — but never
   dismiss without the user's explicit approval.

Known context: this library intentionally retains legacy v1 crypto paths (obsolete APIs,
PBKDF2-SHA1@1000 in `EncryptionUtils.DeriveKeyAndIv`) for backward-compatible *decryption only*.
Sonar findings that merely point at that retained legacy code are usually dismissable as
"won't fix"; findings on new code are not.

Dismissing an issue requires a SonarCloud token with 'Administer Issues' permission and the user's
explicit approval per issue. The `sonarcloud` agent has the `do_transition` / `add_comment`
mechanics — hand it the issue key, transition (`wontfix` or `falsepositive`), and justification once
the user approves. Without a token, tell the user which issues to dismiss and why, and let them do
it in the UI.

## Caveat: no PR data in SonarCloud

If section 2 returns empty for a PR that has run, the CI likely submitted a *branch* analysis
instead of a *pull-request* one. `sonar.branch.name` and `sonar.pullrequest.*` are mutually
exclusive; `sonarcloud.ps1` sends `sonar.pullrequest.key/branch/base` on the `pull_request` event
and `sonar.branch.name` otherwise. Also verify the SonarCloud project is bound to the GitHub repo
(SonarCloud GitHub App) and that Automatic Analysis is OFF, or the CI scan is ignored.
