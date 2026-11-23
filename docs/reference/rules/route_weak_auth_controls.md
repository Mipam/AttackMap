# `route_weak_auth_controls`

Authentication routes were detected without strong nearby auth controls

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | 0.6 (medium band) |
| CWE | CWE-287 |
| OWASP / ASVS | A07:2021 · API2:2023 · V2.2.1 |
| ATT&CK | [T1110](https://attack.mitre.org/techniques/T1110/), [T1078](https://attack.mitre.org/techniques/T1078/) |
| Tags | exposed-endpoint, auth-missing |
| Replaces legacy detector ids | weak-auth-route |

## Why this rule fires

Authentication endpoints with no observed auth indicators nearby are common brute force and session-abuse targets; absence of indicators is weak evidence of absence of controls, hence medium severity and confidence (CWE-287).

## Evidence expectations

``AM-ROUTE-004`` (cascade ``weak-auth-route``): authentication routes
detected with no auth indicators near them.

Ported from the ``auth_surfaces`` branch of
``threat_model.generate_findings`` (fires only when NO auth-category
surface carries any auth signal).
