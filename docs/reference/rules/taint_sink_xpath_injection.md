# `taint_sink_xpath_injection`

Request input reaches an XPath expression (XPath injection)

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | 0.6 (medium band) |
| CWE | CWE-643 |
| OWASP / ASVS | A03:2021 · V5.3.10 |
| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/) |
| Tags | taint-chain, input-handling |
| Replaces legacy detector ids | xpath-injection |

## Why this rule fires

A route reaches a XPath expression sink (xpath-injection) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

## Evidence expectations

Aggregated "request-reachable <sink>" finding for one dangerous-sink
kind (``TAINT_FINDING_SPEC``). Reach alone is the evidence here — these
sink kinds are dangerous regardless of the argument's shape, so a
non-speculative chain from a route is enough (matching the legacy gate).
