# `taint_flow_sql_execute`

Request input flows into a raw SQL query (SQL injection)

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | 0.75 (medium band) |
| CWE | CWE-89 |
| OWASP / ASVS | A03:2021 · V5.3.4 · V5.3.5 |
| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/) |
| Tags | taint-chain, taint-flow |
| Replaces legacy detector ids | sql-injection |

## Why this rule fires

A request-derived value is traced into a database (SQL execute) sink (sql-injection); a traced flow is injection-grade evidence, not just reachability. Ported 1:1 from the legacy flow-confirmed cascade block.

## Evidence expectations

Flow-confirmed SQL injection / path traversal for one canonical flow
kind (``FLOW_FINDING_SPEC``; ``dynamic_open`` is the schema alias of
``path_traversal``). Reach alone is not a finding for the trace-gated
kinds — only a chain with a traced request-derived source counts; the
#240 path sinks are request-gated at the scan layer already, so their
chains count (legacy ``confirmed`` check, kept verbatim).
