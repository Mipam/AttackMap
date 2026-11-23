# `route_exposed_admin`

Administrative routes appear reachable from the main application surface

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | 0.9 (high band) |
| CWE | CWE-285 |
| OWASP / ASVS | A01:2021 · API5:2023 · V4.1.3 |
| ATT&CK | [T1078](https://attack.mitre.org/techniques/T1078/), [T1068](https://attack.mitre.org/techniques/T1068/), [T1098](https://attack.mitre.org/techniques/T1098/) |
| Tags | exposed-endpoint, auth-missing, privileged |
| Replaces legacy detector ids | exposed-admin-route |

## Why this rule fires

Administrative routes sit on the main application surface where every caller can reach them; without a narrower boundary each one is a privileged-action foothold (CWE-285).

## Evidence expectations

``AM-ROUTE-002`` (cascade ``exposed-admin-route``): administrative
routes reachable from the main application surface.

Ported from the ``admin_surfaces`` branch of
``threat_model.generate_findings`` (any runtime admin-category route).
