# `workflow_security`

CI workflow security issue (GitHub Actions)

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | 0.9 (high band) |
| CWE | - |
| Tags | ci-security, supply-chain |
| Replaces legacy detector ids | script-injection, pr-target-checkout, unpinned-action, secret-in-run, broad-permissions, self-hosted-pr, workflow-run-artifact-poisoning, issue-comment-pr-checkout, github-script-injection, github-env-injection, default-token-permissions, oidc-on-untrusted-trigger, secrets-inherit, checkout-persist-credentials, cache-poisoning-pr-target, docker-action-unpinned, curl-pipe-shell |

## Why this rule fires

A workflow file contains a positively-present CI misconfiguration — an unpinned action, an untrusted checkout, an interpolated secret, write-all token permissions, OIDC on an untrusted trigger — that lets a pushed commit or PR run attacker-chosen code with the repository's token and secrets in scope. Per-kind CWE tags are attached to each finding from the taxonomy.

## Evidence expectations

GitHub Actions workflow findings (#142/#246), one per issue kind.

Equivalent port of the legacy branch: findings aggregate every issue of
a kind, severity is the max over that kind's issues, evidence lines keep
the ``file:line [context] — detail`` structure (the workflow's job/step
context survives verbatim) with the legacy ten-item cap, and tags carry
the kind's taxonomy CWE tags. Confidence is ``high`` for every kind,
exactly as the legacy branch emitted.
