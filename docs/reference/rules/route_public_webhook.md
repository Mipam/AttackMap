# `route_public_webhook`

Public webhook endpoint may trust attacker-controlled events

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | 0.9 (high band) |
| CWE | CWE-345 |
| OWASP / ASVS | A08:2021 · V13.2.6 |
| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/), [T1199](https://attack.mitre.org/techniques/T1199/) |
| Tags | exposed-endpoint, auth-missing |
| Replaces legacy detector ids | public-webhook |

## Why this rule fires

A public mutating webhook route with a route-linked datastore or outbound relationship and no jwt/oauth/authorization/service auth signal likely trusts attacker-controlled events without verifying their origin (CWE-345).

## Evidence expectations

``AM-ROUTE-001`` (cascade ``public-webhook``): public webhook endpoints
that pass attacker-controlled events toward a datastore or outbound call
without strong auth signals.

Ported from the ``webhook_surfaces`` branch of
``threat_model.generate_findings``. The AM038 per-handler webhook
exposure variant in ``route_auth_fusion`` is a different producer and
is NOT ported here (see module docstring).
