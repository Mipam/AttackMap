# `taint_sink_ssrf`

Request-reachable server-side request forgery (SSRF)

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | 0.6 (medium band) |
| CWE | CWE-918 |
| OWASP / ASVS | A10:2021 · API7:2023 · V5.2.6 · V12.6.1 |
| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/), [T1552.005](https://attack.mitre.org/techniques/T1552/005/) |
| Tags | taint-chain, input-handling |
| Replaces legacy detector ids | ssrf |

## Why this rule fires

A route reaches a outbound request (SSRF) sink (ssrf) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

## Evidence expectations

Aggregated "request-reachable <sink>" finding for one dangerous-sink
kind (``TAINT_FINDING_SPEC``). Reach alone is the evidence here — these
sink kinds are dangerous regardless of the argument's shape, so a
non-speculative chain from a route is enough (matching the legacy gate).
