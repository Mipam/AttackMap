# `taint_sink_zip_slip`

Request-reachable archive extraction without path checks (zip-slip)

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | 0.6 (medium band) |
| CWE | CWE-22 |
| OWASP / ASVS | A01:2021 · V12.3.1 |
| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/) |
| Tags | taint-chain, input-handling |
| Replaces legacy detector ids | zip-slip |

## Why this rule fires

A route reaches a archive extraction sink (zip-slip) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

## Evidence expectations

Aggregated "request-reachable <sink>" finding for one dangerous-sink
kind (``TAINT_FINDING_SPEC``). Reach alone is the evidence here — these
sink kinds are dangerous regardless of the argument's shape, so a
non-speculative chain from a route is enough (matching the legacy gate).
