# `taint_flow_path_traversal`

Request input flows into a filesystem path (path traversal)

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | 0.75 (medium band) |
| CWE | CWE-22 |
| OWASP / ASVS | A01:2021 · V12.3.1 |
| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/) |
| Tags | taint-chain, taint-flow |
| Replaces legacy detector ids | path-traversal |

## Why this rule fires

A request-derived value is traced into a filesystem path sink (path-traversal); a traced flow is injection-grade evidence, not just reachability. Ported 1:1 from the legacy flow-confirmed cascade block.

## Evidence expectations

Flow-confirmed SQL injection / path traversal for one canonical flow
kind (``FLOW_FINDING_SPEC``; ``dynamic_open`` is the schema alias of
``path_traversal``). Reach alone is not a finding for the trace-gated
kinds — only a chain with a traced request-derived source counts; the
#240 path sinks are request-gated at the scan layer already, so their
chains count (legacy ``confirmed`` check, kept verbatim).
