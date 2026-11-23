# `taint_sink_open_redirect`

Request-reachable open redirect

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | 0.6 (medium band) |
| CWE | CWE-601 |
| OWASP / ASVS | A01:2021 · V5.1.5 |
| ATT&CK | [T1204.001](https://attack.mitre.org/techniques/T1204/001/), [T1566.002](https://attack.mitre.org/techniques/T1566/002/) |
| Tags | taint-chain, input-handling |
| Replaces legacy detector ids | open-redirect |

## Why this rule fires

A route reaches a redirect target sink (open-redirect) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

## Evidence expectations

Aggregated "request-reachable <sink>" finding for one dangerous-sink
kind (``TAINT_FINDING_SPEC``). Reach alone is the evidence here — these
sink kinds are dangerous regardless of the argument's shape, so a
non-speculative chain from a route is enough (matching the legacy gate).
