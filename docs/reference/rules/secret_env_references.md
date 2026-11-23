# `secret_env_references`

Secret-bearing environment variables are referenced in executable paths

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | 0.8 (high band) |
| CWE | CWE-526 |
| OWASP / ASVS | A05:2021 · V6.4.1 |
| ATT&CK | [T1552](https://attack.mitre.org/techniques/T1552/) |
| Tags | secret-exposure |
| Replaces legacy detector ids | secret-env-reference |

## Why this rule fires

Executable paths that read secret-named environment variables put the runtime secret one hop from logs, errors and child processes; handling must be verified even though no value is hard-coded (CWE-526).

## Evidence expectations

Secret-bearing environment variables referenced in executable paths.

Port of the legacy ``secret-env-reference`` branch (#39): ``env_reference``
and ``env_template`` hints name a secret whose value resolves at runtime,
so the finding asks whether injection/logging/scoping are handled rather
than claiming a leaked value.
