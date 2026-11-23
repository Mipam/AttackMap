# `demo_weak_default_credentials`

Hard-coded default credential

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | 0.8 (high band) |
| CWE | CWE-798 |
| Tags | secret-exposure, auth-missing |
| Replaces legacy detector ids | - |

## Why this rule fires

A secret hint whose name names a default or admin credential appears as a literal in scanned sources; shipped defaults are a well-known account-takeover path (CWE-798).

## Evidence expectations

Seed rule: flags hard-coded default/admin credentials in scanned sources.

Reference implementation for the whole kernel: metadata-driven, one
`evaluate` method, findings attributed to `meta.id`.
