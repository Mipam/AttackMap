# `vulnerable_dependency`

Vulnerable dependency (known advisory on the dependency path)

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | 0.9 (high band) |
| CWE | CWE-1395 |
| OWASP / ASVS | A06:2021 · V14.2.1 |
| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/), [T1195.001](https://attack.mitre.org/techniques/T1195/001/) |
| Tags | cve, dependency |
| Replaces legacy detector ids | vulnerable-dependency |

## Why this rule fires

A package dependency resolves to a version with a published advisory; known-vulnerable code on the dependency path is the most direct supply-chain exposure (CWE-1395), so every advisory is aggregated into one finding per package for triage.

## Evidence expectations

CVE advisories on the dependency path (#60), one finding per package.

Equivalent port of the legacy branch: advisories are grouped by
(ecosystem, package name, resolved version) in scan order, the finding
severity tracks the most severe advisory, and the evidence list carries
the advisory-count headline, the transitive provenance line (when any
advisory is indirect) and up to ten advisory lines sorted by severity
then id. Locations are derived from the evidence prose exactly as the
legacy ``_fill_missing_locations`` pass derived them.
