# `hardcoded_secret_literals`

Hard-coded secret literals were found in source or config

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | 0.85 (high band) |
| CWE | CWE-798 |
| OWASP / ASVS | A07:2021 · V2.10.4 · V6.4.1 |
| ATT&CK | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) |
| Tags | secret-exposure, data-risk, hardcoded-literal |
| Replaces legacy detector ids | hardcoded-secret |

## Why this rule fires

Literal credential values in scanned sources or config files are readable by anyone with repository access and by every build or deployment system that checks the code out (CWE-798).

## Evidence expectations

Secret hints whose value is a literal pasted into source or config.

Port of the legacy ``hardcoded-secret`` branch (#39): exposure is broader
than env references — anyone with repo read access already has these
secrets — so severity is HIGH and the finding carries its own tags.
