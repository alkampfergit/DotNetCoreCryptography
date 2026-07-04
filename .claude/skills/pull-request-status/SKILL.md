---
name: branch-status
description: Check CI health of the current branch — GitHub Actions check runs (via gh CLI or REST API) plus SonarCloud quality gate and open issues (via SonarCloud web API). Use when the user asks about build status, failing checks, quality gate, or SonarCloud issues for a branch.
---

# Branch status: GitHub checks + SonarCloud

Project constants:

- GitHub repo: `alkampfergit/DotNetCoreCryptography` (public — unauthenticated REST works)
- SonarCloud project key: `alkampfergit_DotNetCoreCryptography`, organization: `alkampfergit-github`
- SonarCloud URL: https://sonarcloud.io/project/overview?id=alkampfergit_DotNetCoreCryptography

Get the branch once and reuse it: `git rev-parse --abbrev-ref HEAD`.

## 1. GitHub Actions check status

Preferred (gh CLI, requires `gh auth login`; on this machine gh lives at
`C:\Program Files\GitHub CLI\gh.exe` — add to PATH if not found):

```
gh run list --branch <branch> --limit 10
gh run view <run-id> --log-failed        # only when a run failed
```

Fallback when gh is missing or unauthenticated (repo is public):

```
curl -s "https://api.github.com/repos/alkampfergit/DotNetCoreCryptography/commits/<branch>/check-runs"
```

Each element of `check_runs[]` has `name`, `status` (`queued|in_progress|completed`) and
`conclusion` (`success|failure|neutral|cancelled|skipped|timed_out`). The branch is healthy
when every completed check has conclusion `success`.

Note: the "SonarCloud Code Analysis" check reports the quality gate — it can be `failure`
while the build itself is green. Diagnose that via SonarCloud (below), not via run logs.

## 2. SonarCloud quality gate + issues

No token needed (public project). All endpoints accept `branch=<branch>`.

Quality gate:

```
curl -s "https://sonarcloud.io/api/qualitygates/project_status?projectKey=alkampfergit_DotNetCoreCryptography&branch=<branch>"
```

`projectStatus.status` is `OK` or `ERROR`; `conditions[]` tells which metric failed
(e.g. `new_coverage`, `new_security_rating`).

Open issues on the branch:

```
curl -s "https://sonarcloud.io/api/issues/search?componentKeys=alkampfergit_DotNetCoreCryptography&branch=<branch>&resolved=false&ps=100"
```

Useful extra filters: `types=VULNERABILITY,BUG,CODE_SMELL`, `severities=BLOCKER,CRITICAL,MAJOR,MINOR,INFO`,
`sinceLeakPeriod=true` (only "new code" issues — these are what break the gate).

Security hotspots are a separate endpoint:

```
curl -s "https://sonarcloud.io/api/hotspots/search?projectKey=alkampfergit_DotNetCoreCryptography&branch=<branch>&status=TO_REVIEW"
```

For each issue report: `severity`, `type`, `rule`, `component` (strip the `<projectKey>:` prefix
to get the file path), `line`, `message`. Full rule description:
`https://sonarcloud.io/api/rules/show?key=<rule>` (e.g. `csharpsquid:S5344`).

Parse JSON with PowerShell (`ConvertFrom-Json`) — `jq` and `python` are not installed here.

## 3. Reporting

Summarize as: overall check status per workflow, quality gate status, then issues grouped by
severity with file:line. For each issue say whether it is (a) fixable in code, or (b) a candidate
to dismiss in SonarCloud — but never dismiss without the user's explicit approval. Known context:
this library intentionally keeps legacy v1 crypto paths (obsolete APIs, PBKDF2-SHA1@1000 in
`EncryptionUtils.DeriveKeyAndIv`) for backward-compatible *decryption only* — Sonar findings that
merely point at that retained legacy code are usually dismissable as "won't fix", findings on new
code are not.

Dismissing an issue requires a SonarCloud token with 'Administer Issues' permission:

```
curl -s -X POST -H "Authorization: Bearer $SONAR_TOKEN" \
  "https://sonarcloud.io/api/issues/do_transition" \
  -d "issue=<issueKey>&transition=wontfix"      # or: falsepositive
curl -s -X POST -H "Authorization: Bearer $SONAR_TOKEN" \
  "https://sonarcloud.io/api/issues/add_comment" \
  -d "issue=<issueKey>&text=<justification>"
```

Without a token, tell the user which issues to dismiss and why, and let them do it in the UI.
