# `debug_mode_exposure`

Debug mode or unrestricted management endpoints enabled

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | 0.8 (high band) |
| CWE | CWE-489 |
| OWASP / ASVS | A05:2021 · API8:2023 · V14.3.2 |
| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/) |
| Tags | web-hardening |
| Replaces legacy detector ids | debug-enabled |

## Why this rule fires

Debug mode and wildcard-exposed management endpoints positively present in source expose stack traces, internals and privileged diagnostics to anyone who can reach the app (CWE-489).

## Evidence expectations

Debug mode or unrestricted management endpoints enabled.

Port of the ``debug_enabled`` config-exposure family of the cascade's
web-hardening loop (#71): Flask/Django/Rails debug flags and Spring
actuator wildcard exposure leak internals and can enable RCE. Only this
kind belongs to the secrets/config port; the other web-hardening kinds
keep their cascade branch until their own port.
