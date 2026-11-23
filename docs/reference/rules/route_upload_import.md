# `route_upload_import`

Upload or import routes expand attacker-controlled input handling

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | 0.6 (medium band) |
| CWE | CWE-434 |
| OWASP / ASVS | A04:2021 · V12.2.1 · V12.5.2 |
| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/), [T1505.003](https://attack.mitre.org/techniques/T1505/003/) |
| Tags | exposed-endpoint, input-handling |
| Replaces legacy detector ids | upload-route |

## Why this rule fires

Upload and import routes accept attacker-controlled files, so parser abuse and untrusted-content handling become reachable input paths (CWE-434); the risk depends on the parsers behind them, hence medium confidence.

## Evidence expectations

``AM-ROUTE-003`` (cascade ``upload-route``): upload/import routes widen
attacker-controlled input handling.

Ported from the ``upload_surfaces`` branch of
``threat_model.generate_findings`` (any runtime upload-category route).
