# `same_module_datastore_edge`

Datastore hint in the same module as a route

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | 0.45 (low band) |
| CWE | - |
| Tags | data-risk, weak-signal, ownership-unknown |
| Replaces legacy detector ids | - |

## Why this rule fires

A datastore hint shares the route's module key (the cascade's `db_by_module` branch). Package-level proximity is weaker than same-file co-location: many files can share a module, so route ownership stays unknown.

## Evidence expectations

A datastore hint in the same module as a runtime route (possibly a
different file — the cross-file co-location grade).

Ports the ``_build_probable_chains`` ``db_by_module`` branch and its
verbatim evidence line. The cascade consumes this decision only inside
the legacy ``framework-sink-chain`` finding, which stays unported (it
needs excluded framework hints).
