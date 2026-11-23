# `same_file_external_edge`

Outbound call co-located with a route in the same file

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | 0.6 (medium band) |
| CWE | - |
| Tags | integration-risk, weak-signal, ownership-unknown |
| Replaces legacy detector ids | - |

## Why this rule fires

An outbound external call was observed in the same source file as a route (the cascade's `_same_file_external` decision). Co-location is context, not proof the route steers the call.

## Evidence expectations

An outbound call observed in the same file as a runtime route.

Ports ``_same_file_external`` + the cascade's same-file outbound-call
evidence/context signals.
