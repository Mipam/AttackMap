# `taint_sink_regex_injection`

Request input compiled as a regular expression (ReDoS)

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | 0.6 (medium band) |
| CWE | CWE-1333 |
| OWASP / ASVS | A03:2021 |
| ATT&CK | [T1499.004](https://attack.mitre.org/techniques/T1499/004/) |
| Tags | taint-chain, input-handling |
| Replaces legacy detector ids | regex-injection |

## Why this rule fires

A route reaches a regular expression (ReDoS) sink (regex-injection) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

## Evidence expectations

Aggregated "request-reachable <sink>" finding for one dangerous-sink
kind (``TAINT_FINDING_SPEC``). Reach alone is the evidence here — these
sink kinds are dangerous regardless of the argument's shape, so a
non-speculative chain from a route is enough (matching the legacy gate).
