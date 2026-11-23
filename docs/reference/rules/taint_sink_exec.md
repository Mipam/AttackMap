# `taint_sink_exec`

Request-reachable code execution via exec

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | 0.6 (medium band) |
| CWE | CWE-94 |
| OWASP / ASVS | A03:2021 · V5.2.4 |
| ATT&CK | [T1059](https://attack.mitre.org/techniques/T1059/), [T1190](https://attack.mitre.org/techniques/T1190/) |
| Tags | taint-chain, input-handling |
| Replaces legacy detector ids | exec |

## Why this rule fires

A route reaches a code exec sink (exec) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

## Evidence expectations

Aggregated "request-reachable <sink>" finding for one dangerous-sink
kind (``TAINT_FINDING_SPEC``). Reach alone is the evidence here — these
sink kinds are dangerous regardless of the argument's shape, so a
non-speculative chain from a route is enough (matching the legacy gate).
