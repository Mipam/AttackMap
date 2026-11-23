# `same_file_datastore_edge`

Datastore co-located with a route in the same file

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | 0.6 (medium band) |
| CWE | - |
| Tags | data-risk, weak-signal, ownership-unknown |
| Replaces legacy detector ids | - |

## Why this rule fires

A datastore hint was observed in the same source file as a route (the cascade's `_same_file_datastore` decision). Co-location is context, not proof of reachability: route ownership of the datastore is unknown until a route-linked chain confirms it.

## Evidence expectations

A datastore hint observed in the same file as a runtime route.

Ports ``_same_file_datastore`` + the cascade's same-file datastore
evidence/context signals. Co-location is reported as context, never as
proof the route reaches the datastore.
