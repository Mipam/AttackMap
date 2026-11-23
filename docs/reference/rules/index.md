# Rule reference

Generated from the kernel rule registry (`attackmap.reasoning.rules.REGISTRY`) by `tools/gen_rule_docs.py` — 49 rules. Generated artifact: do not edit by hand, run

    python tools/gen_rule_docs.py

## ci-security

| Rule | Severity | Confidence | Title |
| --- | --- | --- | --- |
| [`workflow_security`](workflow_security.md) | high | high | CI workflow security issue (GitHub Actions) |

## cve

| Rule | Severity | Confidence | Title |
| --- | --- | --- | --- |
| [`vulnerable_dependency`](vulnerable_dependency.md) | high | high | Vulnerable dependency (known advisory on the dependency path) |

## data-risk

| Rule | Severity | Confidence | Title |
| --- | --- | --- | --- |
| [`same_file_datastore_edge`](same_file_datastore_edge.md) | low | medium | Datastore co-located with a route in the same file |
| [`same_module_datastore_edge`](same_module_datastore_edge.md) | low | low | Datastore hint in the same module as a route |

## exposed-endpoint

| Rule | Severity | Confidence | Title |
| --- | --- | --- | --- |
| [`route_exposed_admin`](route_exposed_admin.md) | high | high | Administrative routes appear reachable from the main application surface |
| [`route_public_webhook`](route_public_webhook.md) | high | high | Public webhook endpoint may trust attacker-controlled events |
| [`route_upload_import`](route_upload_import.md) | high | medium | Upload or import routes expand attacker-controlled input handling |
| [`route_weak_auth_controls`](route_weak_auth_controls.md) | medium | medium | Authentication routes were detected without strong nearby auth controls |

## integration-risk

| Rule | Severity | Confidence | Title |
| --- | --- | --- | --- |
| [`same_file_external_edge`](same_file_external_edge.md) | low | medium | Outbound call co-located with a route in the same file |
| [`same_module_external_edge`](same_module_external_edge.md) | low | low | Outbound call in the same module as a route |

## secret-exposure

| Rule | Severity | Confidence | Title |
| --- | --- | --- | --- |
| [`demo_weak_default_credentials`](demo_weak_default_credentials.md) | high | high | Hard-coded default credential |
| [`hardcoded_secret_literals`](hardcoded_secret_literals.md) | high | high | Hard-coded secret literals were found in source or config |
| [`secret_env_references`](secret_env_references.md) | medium | high | Secret-bearing environment variables are referenced in executable paths |

## supply-chain

| Rule | Severity | Confidence | Title |
| --- | --- | --- | --- |
| [`supply_chain_risk`](supply_chain_risk.md) | medium | high | Dependency supply-chain risk |

## taint-chain

| Rule | Severity | Confidence | Title |
| --- | --- | --- | --- |
| [`taint_flow_path_traversal`](taint_flow_path_traversal.md) | high | medium | Request input flows into a filesystem path (path traversal) |
| [`taint_flow_sql_execute`](taint_flow_sql_execute.md) | high | medium | Request input flows into a raw SQL query (SQL injection) |
| [`taint_sink_code_injection`](taint_sink_code_injection.md) | high | medium | Request input selects or builds code to run (code injection) |
| [`taint_sink_eval`](taint_sink_eval.md) | high | medium | Request-reachable code execution via eval |
| [`taint_sink_exec`](taint_sink_exec.md) | high | medium | Request-reachable code execution via exec |
| [`taint_sink_expression_injection`](taint_sink_expression_injection.md) | high | medium | Request input evaluated as an expression (SpEL/OGNL/MVEL/script injection) |
| [`taint_sink_header_injection`](taint_sink_header_injection.md) | low | medium | Request input sets an HTTP response header (header injection) |
| [`taint_sink_jndi_injection`](taint_sink_jndi_injection.md) | high | medium | Request input reaches a JNDI lookup (JNDI injection) |
| [`taint_sink_ldap_injection`](taint_sink_ldap_injection.md) | medium | medium | Request input reaches an LDAP search filter (LDAP injection) |
| [`taint_sink_nosql_injection`](taint_sink_nosql_injection.md) | medium | medium | Request-reachable NoSQL injection |
| [`taint_sink_open_redirect`](taint_sink_open_redirect.md) | medium | medium | Request-reachable open redirect |
| [`taint_sink_regex_injection`](taint_sink_regex_injection.md) | low | medium | Request input compiled as a regular expression (ReDoS) |
| [`taint_sink_ssrf`](taint_sink_ssrf.md) | medium | medium | Request-reachable server-side request forgery (SSRF) |
| [`taint_sink_ssti`](taint_sink_ssti.md) | high | medium | Request-reachable server-side template injection |
| [`taint_sink_subprocess_shell`](taint_sink_subprocess_shell.md) | high | medium | Request-reachable OS command execution |
| [`taint_sink_unsafe_deserialization`](taint_sink_unsafe_deserialization.md) | high | medium | Request-reachable unsafe deserialization |
| [`taint_sink_xpath_injection`](taint_sink_xpath_injection.md) | medium | medium | Request input reaches an XPath expression (XPath injection) |
| [`taint_sink_zip_slip`](taint_sink_zip_slip.md) | high | medium | Request-reachable archive extraction without path checks (zip-slip) |
| [`taint_speculative_code_injection`](taint_speculative_code_injection.md) | low | low | Speculative reach to a dynamic code / dispatch sink (recall mode) |
| [`taint_speculative_eval`](taint_speculative_eval.md) | low | low | Speculative reach to a code eval sink (recall mode) |
| [`taint_speculative_exec`](taint_speculative_exec.md) | low | low | Speculative reach to a code exec sink (recall mode) |
| [`taint_speculative_expression_injection`](taint_speculative_expression_injection.md) | low | low | Speculative reach to a expression language (SpEL/OGNL/MVEL/script) sink (recall mode) |
| [`taint_speculative_header_injection`](taint_speculative_header_injection.md) | low | low | Speculative reach to a HTTP response header sink (recall mode) |
| [`taint_speculative_jndi_injection`](taint_speculative_jndi_injection.md) | low | low | Speculative reach to a JNDI lookup sink (recall mode) |
| [`taint_speculative_ldap_injection`](taint_speculative_ldap_injection.md) | low | low | Speculative reach to a LDAP filter sink (recall mode) |
| [`taint_speculative_nosql_injection`](taint_speculative_nosql_injection.md) | low | low | Speculative reach to a NoSQL query sink (recall mode) |
| [`taint_speculative_open_redirect`](taint_speculative_open_redirect.md) | low | low | Speculative reach to a redirect target sink (recall mode) |
| [`taint_speculative_regex_injection`](taint_speculative_regex_injection.md) | low | low | Speculative reach to a regular expression (ReDoS) sink (recall mode) |
| [`taint_speculative_ssrf`](taint_speculative_ssrf.md) | low | low | Speculative reach to a outbound request (SSRF) sink (recall mode) |
| [`taint_speculative_ssti`](taint_speculative_ssti.md) | low | low | Speculative reach to a template injection sink (recall mode) |
| [`taint_speculative_subprocess_shell`](taint_speculative_subprocess_shell.md) | low | low | Speculative reach to a command execution sink (recall mode) |
| [`taint_speculative_unsafe_deserialization`](taint_speculative_unsafe_deserialization.md) | low | low | Speculative reach to a unsafe deserialization sink (recall mode) |
| [`taint_speculative_xpath_injection`](taint_speculative_xpath_injection.md) | low | low | Speculative reach to a XPath expression sink (recall mode) |
| [`taint_speculative_zip_slip`](taint_speculative_zip_slip.md) | low | low | Speculative reach to a archive extraction sink (recall mode) |

## web-hardening

| Rule | Severity | Confidence | Title |
| --- | --- | --- | --- |
| [`debug_mode_exposure`](debug_mode_exposure.md) | medium | high | Debug mode or unrestricted management endpoints enabled |
