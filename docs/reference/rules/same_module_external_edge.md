# `same_module_external_edge`

Outbound call in the same module as a route

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | 0.45 (low band) |
| CWE | - |
| Tags | integration-risk, weak-signal, ownership-unknown |
| Replaces legacy detector ids | - |

## Why this rule fires

An outbound external call shares the route's module key and no datastore hint answered first (the cascade's `elif external_by_module` order). Package-level proximity keeps route ownership unknown.

## Evidence expectations

An outbound call in the same module as a runtime route, consulted
only when the module has no datastore (the cascade's ``elif`` order).

Ports the ``_build_probable_chains`` ``external_by_module`` branch and
its verbatim evidence line.
