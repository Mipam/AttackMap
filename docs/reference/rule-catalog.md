# Rule catalog

> Generated 2026-11-23 from `attackmap` **1.5.1** — source module
> `src/attackmap/reasoning/rules/registry.py` (`REGISTRY`, metadata per
> `src/attackmap/reasoning/rules/base.py::RuleMeta`). Static snapshot;
> regenerate when rules change (`attackmap rules list --json` shows the live set).

49 registered rules, sorted by severity then id.

| Rule id | Severity | Confidence | CWE | Title |
| --- | --- | --- | --- | --- |
| `demo_weak_default_credentials` | high | 0.80 | CWE-798 | Hard-coded default credential |
| `hardcoded_secret_literals` | high | 0.85 | CWE-798 | Hard-coded secret literals were found in source or config |
| `route_exposed_admin` | high | 0.90 | CWE-285 | Administrative routes appear reachable from the main application surface |
| `route_public_webhook` | high | 0.90 | CWE-345 | Public webhook endpoint may trust attacker-controlled events |
| `route_upload_import` | high | 0.60 | CWE-434 | Upload or import routes expand attacker-controlled input handling |
| `taint_flow_path_traversal` | high | 0.75 | CWE-22 | Request input flows into a filesystem path (path traversal) |
| `taint_flow_sql_execute` | high | 0.75 | CWE-89 | Request input flows into a raw SQL query (SQL injection) |
| `taint_sink_code_injection` | high | 0.60 | CWE-94 | Request input selects or builds code to run (code injection) |
| `taint_sink_eval` | high | 0.60 | CWE-95 | Request-reachable code execution via eval |
| `taint_sink_exec` | high | 0.60 | CWE-94 | Request-reachable code execution via exec |
| `taint_sink_expression_injection` | high | 0.60 | CWE-917 | Request input evaluated as an expression (SpEL/OGNL/MVEL/script injection) |
| `taint_sink_jndi_injection` | high | 0.60 | CWE-74 | Request input reaches a JNDI lookup (JNDI injection) |
| `taint_sink_ssti` | high | 0.60 | CWE-1336 | Request-reachable server-side template injection |
| `taint_sink_subprocess_shell` | high | 0.60 | CWE-78 | Request-reachable OS command execution |
| `taint_sink_unsafe_deserialization` | high | 0.60 | CWE-502 | Request-reachable unsafe deserialization |
| `taint_sink_zip_slip` | high | 0.60 | CWE-22 | Request-reachable archive extraction without path checks (zip-slip) |
| `vulnerable_dependency` | high | 0.90 | CWE-1395 | Vulnerable dependency (known advisory on the dependency path) |
| `workflow_security` | high | 0.90 | — | CI workflow security issue (GitHub Actions) |
| `debug_mode_exposure` | medium | 0.80 | CWE-489 | Debug mode or unrestricted management endpoints enabled |
| `route_weak_auth_controls` | medium | 0.60 | CWE-287 | Authentication routes were detected without strong nearby auth controls |
| `secret_env_references` | medium | 0.80 | CWE-526 | Secret-bearing environment variables are referenced in executable paths |
| `supply_chain_risk` | medium | 0.80 | — | Dependency supply-chain risk |
| `taint_sink_ldap_injection` | medium | 0.60 | CWE-90 | Request input reaches an LDAP search filter (LDAP injection) |
| `taint_sink_nosql_injection` | medium | 0.60 | CWE-943 | Request-reachable NoSQL injection |
| `taint_sink_open_redirect` | medium | 0.60 | CWE-601 | Request-reachable open redirect |
| `taint_sink_ssrf` | medium | 0.60 | CWE-918 | Request-reachable server-side request forgery (SSRF) |
| `taint_sink_xpath_injection` | medium | 0.60 | CWE-643 | Request input reaches an XPath expression (XPath injection) |
| `same_file_datastore_edge` | low | 0.60 | — | Datastore co-located with a route in the same file |
| `same_file_external_edge` | low | 0.60 | — | Outbound call co-located with a route in the same file |
| `same_module_datastore_edge` | low | 0.45 | — | Datastore hint in the same module as a route |
| `same_module_external_edge` | low | 0.45 | — | Outbound call in the same module as a route |
| `taint_sink_header_injection` | low | 0.60 | CWE-113 | Request input sets an HTTP response header (header injection) |
| `taint_sink_regex_injection` | low | 0.60 | CWE-1333 | Request input compiled as a regular expression (ReDoS) |
| `taint_speculative_code_injection` | low | 0.30 | CWE-94 | Speculative reach to a dynamic code / dispatch sink (recall mode) |
| `taint_speculative_eval` | low | 0.30 | CWE-95 | Speculative reach to a code eval sink (recall mode) |
| `taint_speculative_exec` | low | 0.30 | CWE-94 | Speculative reach to a code exec sink (recall mode) |
| `taint_speculative_expression_injection` | low | 0.30 | CWE-917 | Speculative reach to a expression language (SpEL/OGNL/MVEL/script) sink (recall mode) |
| `taint_speculative_header_injection` | low | 0.30 | CWE-113 | Speculative reach to a HTTP response header sink (recall mode) |
| `taint_speculative_jndi_injection` | low | 0.30 | CWE-74 | Speculative reach to a JNDI lookup sink (recall mode) |
| `taint_speculative_ldap_injection` | low | 0.30 | CWE-90 | Speculative reach to a LDAP filter sink (recall mode) |
| `taint_speculative_nosql_injection` | low | 0.30 | CWE-943 | Speculative reach to a NoSQL query sink (recall mode) |
| `taint_speculative_open_redirect` | low | 0.30 | CWE-601 | Speculative reach to a redirect target sink (recall mode) |
| `taint_speculative_regex_injection` | low | 0.30 | CWE-1333 | Speculative reach to a regular expression (ReDoS) sink (recall mode) |
| `taint_speculative_ssrf` | low | 0.30 | CWE-918 | Speculative reach to a outbound request (SSRF) sink (recall mode) |
| `taint_speculative_ssti` | low | 0.30 | CWE-1336 | Speculative reach to a template injection sink (recall mode) |
| `taint_speculative_subprocess_shell` | low | 0.30 | CWE-78 | Speculative reach to a command execution sink (recall mode) |
| `taint_speculative_unsafe_deserialization` | low | 0.30 | CWE-502 | Speculative reach to a unsafe deserialization sink (recall mode) |
| `taint_speculative_xpath_injection` | low | 0.30 | CWE-643 | Speculative reach to a XPath expression sink (recall mode) |
| `taint_speculative_zip_slip` | low | 0.30 | CWE-22 | Speculative reach to a archive extraction sink (recall mode) |

## Rationale per rule

### `demo_weak_default_credentials` — Hard-coded default credential

- Severity: **high** · confidence 0.80 · CWE-798 · tags: `secret-exposure`, `auth-missing`
- Rationale: A secret hint whose name names a default or admin credential appears as a literal in scanned sources; shipped defaults are a well-known account-takeover path (CWE-798).

### `hardcoded_secret_literals` — Hard-coded secret literals were found in source or config

- Severity: **high** · confidence 0.85 · CWE-798 · tags: `secret-exposure`, `data-risk`, `hardcoded-literal`
- Rationale: Literal credential values in scanned sources or config files are readable by anyone with repository access and by every build or deployment system that checks the code out (CWE-798).

### `route_exposed_admin` — Administrative routes appear reachable from the main application surface

- Severity: **high** · confidence 0.90 · CWE-285 · tags: `exposed-endpoint`, `auth-missing`, `privileged`
- Rationale: Administrative routes sit on the main application surface where every caller can reach them; without a narrower boundary each one is a privileged-action foothold (CWE-285).

### `route_public_webhook` — Public webhook endpoint may trust attacker-controlled events

- Severity: **high** · confidence 0.90 · CWE-345 · tags: `exposed-endpoint`, `auth-missing`
- Rationale: A public mutating webhook route with a route-linked datastore or outbound relationship and no jwt/oauth/authorization/service auth signal likely trusts attacker-controlled events without verifying their origin (CWE-345).

### `route_upload_import` — Upload or import routes expand attacker-controlled input handling

- Severity: **high** · confidence 0.60 · CWE-434 · tags: `exposed-endpoint`, `input-handling`
- Rationale: Upload and import routes accept attacker-controlled files, so parser abuse and untrusted-content handling become reachable input paths (CWE-434); the risk depends on the parsers behind them, hence medium confidence.

### `taint_flow_path_traversal` — Request input flows into a filesystem path (path traversal)

- Severity: **high** · confidence 0.75 · CWE-22 · tags: `taint-chain`, `taint-flow`
- Rationale: A request-derived value is traced into a filesystem path sink (path-traversal); a traced flow is injection-grade evidence, not just reachability. Ported 1:1 from the legacy flow-confirmed cascade block.

### `taint_flow_sql_execute` — Request input flows into a raw SQL query (SQL injection)

- Severity: **high** · confidence 0.75 · CWE-89 · tags: `taint-chain`, `taint-flow`
- Rationale: A request-derived value is traced into a database (SQL execute) sink (sql-injection); a traced flow is injection-grade evidence, not just reachability. Ported 1:1 from the legacy flow-confirmed cascade block.

### `taint_sink_code_injection` — Request input selects or builds code to run (code injection)

- Severity: **high** · confidence 0.60 · CWE-94 · tags: `taint-chain`, `input-handling`
- Rationale: A route reaches a dynamic code / dispatch sink (code-injection) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

### `taint_sink_eval` — Request-reachable code execution via eval

- Severity: **high** · confidence 0.60 · CWE-95 · tags: `taint-chain`, `input-handling`
- Rationale: A route reaches a code eval sink (eval) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

### `taint_sink_exec` — Request-reachable code execution via exec

- Severity: **high** · confidence 0.60 · CWE-94 · tags: `taint-chain`, `input-handling`
- Rationale: A route reaches a code exec sink (exec) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

### `taint_sink_expression_injection` — Request input evaluated as an expression (SpEL/OGNL/MVEL/script injection)

- Severity: **high** · confidence 0.60 · CWE-917 · tags: `taint-chain`, `input-handling`
- Rationale: A route reaches a expression language (SpEL/OGNL/MVEL/script) sink (expression-injection) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

### `taint_sink_jndi_injection` — Request input reaches a JNDI lookup (JNDI injection)

- Severity: **high** · confidence 0.60 · CWE-74 · tags: `taint-chain`, `input-handling`
- Rationale: A route reaches a JNDI lookup sink (jndi-injection) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

### `taint_sink_ssti` — Request-reachable server-side template injection

- Severity: **high** · confidence 0.60 · CWE-1336 · tags: `taint-chain`, `input-handling`
- Rationale: A route reaches a template injection sink (ssti) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

### `taint_sink_subprocess_shell` — Request-reachable OS command execution

- Severity: **high** · confidence 0.60 · CWE-78 · tags: `taint-chain`, `input-handling`
- Rationale: A route reaches a command execution sink (subprocess-shell) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

### `taint_sink_unsafe_deserialization` — Request-reachable unsafe deserialization

- Severity: **high** · confidence 0.60 · CWE-502 · tags: `taint-chain`, `input-handling`
- Rationale: A route reaches a unsafe deserialization sink (unsafe-deserialization) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

### `taint_sink_zip_slip` — Request-reachable archive extraction without path checks (zip-slip)

- Severity: **high** · confidence 0.60 · CWE-22 · tags: `taint-chain`, `input-handling`
- Rationale: A route reaches a archive extraction sink (zip-slip) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

### `vulnerable_dependency` — Vulnerable dependency (known advisory on the dependency path)

- Severity: **high** · confidence 0.90 · CWE-1395 · tags: `cve`, `dependency`
- Rationale: A package dependency resolves to a version with a published advisory; known-vulnerable code on the dependency path is the most direct supply-chain exposure (CWE-1395), so every advisory is aggregated into one finding per package for triage.

### `workflow_security` — CI workflow security issue (GitHub Actions)

- Severity: **high** · confidence 0.90 · tags: `ci-security`, `supply-chain`
- Rationale: A workflow file contains a positively-present CI misconfiguration — an unpinned action, an untrusted checkout, an interpolated secret, write-all token permissions, OIDC on an untrusted trigger — that lets a pushed commit or PR run attacker-chosen code with the repository's token and secrets in scope. Per-kind CWE tags are attached to each finding from the taxonomy.

### `debug_mode_exposure` — Debug mode or unrestricted management endpoints enabled

- Severity: **medium** · confidence 0.80 · CWE-489 · tags: `web-hardening`
- Rationale: Debug mode and wildcard-exposed management endpoints positively present in source expose stack traces, internals and privileged diagnostics to anyone who can reach the app (CWE-489).

### `route_weak_auth_controls` — Authentication routes were detected without strong nearby auth controls

- Severity: **medium** · confidence 0.60 · CWE-287 · tags: `exposed-endpoint`, `auth-missing`
- Rationale: Authentication endpoints with no observed auth indicators nearby are common brute force and session-abuse targets; absence of indicators is weak evidence of absence of controls, hence medium severity and confidence (CWE-287).

### `secret_env_references` — Secret-bearing environment variables are referenced in executable paths

- Severity: **medium** · confidence 0.80 · CWE-526 · tags: `secret-exposure`
- Rationale: Executable paths that read secret-named environment variables put the runtime secret one hop from logs, errors and child processes; handling must be verified even though no value is hard-coded (CWE-526).

### `supply_chain_risk` — Dependency supply-chain risk

- Severity: **medium** · confidence 0.80 · tags: `supply-chain`, `dependency-risk`
- Rationale: A manifest, lockfile or package-manager config contains a positively-present supply-chain risk — an internal-looking name resolvable from a public registry, a one-edit distance from a popular package, a mutable VCS pin, an install hook, a missing lockfile/integrity hash, or plain-HTTP registry traffic. Per-kind CWE tags are attached to each finding from the taxonomy.

### `taint_sink_ldap_injection` — Request input reaches an LDAP search filter (LDAP injection)

- Severity: **medium** · confidence 0.60 · CWE-90 · tags: `taint-chain`, `input-handling`
- Rationale: A route reaches a LDAP filter sink (ldap-injection) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

### `taint_sink_nosql_injection` — Request-reachable NoSQL injection

- Severity: **medium** · confidence 0.60 · CWE-943 · tags: `taint-chain`, `input-handling`
- Rationale: A route reaches a NoSQL query sink (nosql-injection) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

### `taint_sink_open_redirect` — Request-reachable open redirect

- Severity: **medium** · confidence 0.60 · CWE-601 · tags: `taint-chain`, `input-handling`
- Rationale: A route reaches a redirect target sink (open-redirect) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

### `taint_sink_ssrf` — Request-reachable server-side request forgery (SSRF)

- Severity: **medium** · confidence 0.60 · CWE-918 · tags: `taint-chain`, `input-handling`
- Rationale: A route reaches a outbound request (SSRF) sink (ssrf) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

### `taint_sink_xpath_injection` — Request input reaches an XPath expression (XPath injection)

- Severity: **medium** · confidence 0.60 · CWE-643 · tags: `taint-chain`, `input-handling`
- Rationale: A route reaches a XPath expression sink (xpath-injection) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

### `same_file_datastore_edge` — Datastore co-located with a route in the same file

- Severity: **low** · confidence 0.60 · tags: `data-risk`, `weak-signal`, `ownership-unknown`
- Rationale: A datastore hint was observed in the same source file as a route (the cascade's `_same_file_datastore` decision). Co-location is context, not proof of reachability: route ownership of the datastore is unknown until a route-linked chain confirms it.

### `same_file_external_edge` — Outbound call co-located with a route in the same file

- Severity: **low** · confidence 0.60 · tags: `integration-risk`, `weak-signal`, `ownership-unknown`
- Rationale: An outbound external call was observed in the same source file as a route (the cascade's `_same_file_external` decision). Co-location is context, not proof the route steers the call.

### `same_module_datastore_edge` — Datastore hint in the same module as a route

- Severity: **low** · confidence 0.45 · tags: `data-risk`, `weak-signal`, `ownership-unknown`
- Rationale: A datastore hint shares the route's module key (the cascade's `db_by_module` branch). Package-level proximity is weaker than same-file co-location: many files can share a module, so route ownership stays unknown.

### `same_module_external_edge` — Outbound call in the same module as a route

- Severity: **low** · confidence 0.45 · tags: `integration-risk`, `weak-signal`, `ownership-unknown`
- Rationale: An outbound external call shares the route's module key and no datastore hint answered first (the cascade's `elif external_by_module` order). Package-level proximity keeps route ownership unknown.

### `taint_sink_header_injection` — Request input sets an HTTP response header (header injection)

- Severity: **low** · confidence 0.60 · CWE-113 · tags: `taint-chain`, `input-handling`
- Rationale: A route reaches a HTTP response header sink (header-injection) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

### `taint_sink_regex_injection` — Request input compiled as a regular expression (ReDoS)

- Severity: **low** · confidence 0.60 · CWE-1333 · tags: `taint-chain`, `input-handling`
- Rationale: A route reaches a regular expression (ReDoS) sink (regex-injection) via the import graph without a neutralizing sanitizer; untrusted input reaching this sink class is a direct compromise path. Ported 1:1 from the legacy taint cascade so the finding fields (evidence, locations, tags, confidence band) stay byte-identical.

### `taint_speculative_code_injection` — Speculative reach to a dynamic code / dispatch sink (recall mode)

- Severity: **low** · confidence 0.30 · CWE-94 · tags: `taint-chain`, `speculative`, `recall`
- Rationale: Recall mode widens taint discovery (deeper hops, relaxed gates); every reach it adds is unconfirmed until a verifier adjudicates it, so it must be reported separately and can never clear the HIGH bar. Ported 1:1 from the legacy speculative block for dynamic code / dispatch.

### `taint_speculative_eval` — Speculative reach to a code eval sink (recall mode)

- Severity: **low** · confidence 0.30 · CWE-95 · tags: `taint-chain`, `speculative`, `recall`
- Rationale: Recall mode widens taint discovery (deeper hops, relaxed gates); every reach it adds is unconfirmed until a verifier adjudicates it, so it must be reported separately and can never clear the HIGH bar. Ported 1:1 from the legacy speculative block for code eval.

### `taint_speculative_exec` — Speculative reach to a code exec sink (recall mode)

- Severity: **low** · confidence 0.30 · CWE-94 · tags: `taint-chain`, `speculative`, `recall`
- Rationale: Recall mode widens taint discovery (deeper hops, relaxed gates); every reach it adds is unconfirmed until a verifier adjudicates it, so it must be reported separately and can never clear the HIGH bar. Ported 1:1 from the legacy speculative block for code exec.

### `taint_speculative_expression_injection` — Speculative reach to a expression language (SpEL/OGNL/MVEL/script) sink (recall mode)

- Severity: **low** · confidence 0.30 · CWE-917 · tags: `taint-chain`, `speculative`, `recall`
- Rationale: Recall mode widens taint discovery (deeper hops, relaxed gates); every reach it adds is unconfirmed until a verifier adjudicates it, so it must be reported separately and can never clear the HIGH bar. Ported 1:1 from the legacy speculative block for expression language (SpEL/OGNL/MVEL/script).

### `taint_speculative_header_injection` — Speculative reach to a HTTP response header sink (recall mode)

- Severity: **low** · confidence 0.30 · CWE-113 · tags: `taint-chain`, `speculative`, `recall`
- Rationale: Recall mode widens taint discovery (deeper hops, relaxed gates); every reach it adds is unconfirmed until a verifier adjudicates it, so it must be reported separately and can never clear the HIGH bar. Ported 1:1 from the legacy speculative block for HTTP response header.

### `taint_speculative_jndi_injection` — Speculative reach to a JNDI lookup sink (recall mode)

- Severity: **low** · confidence 0.30 · CWE-74 · tags: `taint-chain`, `speculative`, `recall`
- Rationale: Recall mode widens taint discovery (deeper hops, relaxed gates); every reach it adds is unconfirmed until a verifier adjudicates it, so it must be reported separately and can never clear the HIGH bar. Ported 1:1 from the legacy speculative block for JNDI lookup.

### `taint_speculative_ldap_injection` — Speculative reach to a LDAP filter sink (recall mode)

- Severity: **low** · confidence 0.30 · CWE-90 · tags: `taint-chain`, `speculative`, `recall`
- Rationale: Recall mode widens taint discovery (deeper hops, relaxed gates); every reach it adds is unconfirmed until a verifier adjudicates it, so it must be reported separately and can never clear the HIGH bar. Ported 1:1 from the legacy speculative block for LDAP filter.

### `taint_speculative_nosql_injection` — Speculative reach to a NoSQL query sink (recall mode)

- Severity: **low** · confidence 0.30 · CWE-943 · tags: `taint-chain`, `speculative`, `recall`
- Rationale: Recall mode widens taint discovery (deeper hops, relaxed gates); every reach it adds is unconfirmed until a verifier adjudicates it, so it must be reported separately and can never clear the HIGH bar. Ported 1:1 from the legacy speculative block for NoSQL query.

### `taint_speculative_open_redirect` — Speculative reach to a redirect target sink (recall mode)

- Severity: **low** · confidence 0.30 · CWE-601 · tags: `taint-chain`, `speculative`, `recall`
- Rationale: Recall mode widens taint discovery (deeper hops, relaxed gates); every reach it adds is unconfirmed until a verifier adjudicates it, so it must be reported separately and can never clear the HIGH bar. Ported 1:1 from the legacy speculative block for redirect target.

### `taint_speculative_regex_injection` — Speculative reach to a regular expression (ReDoS) sink (recall mode)

- Severity: **low** · confidence 0.30 · CWE-1333 · tags: `taint-chain`, `speculative`, `recall`
- Rationale: Recall mode widens taint discovery (deeper hops, relaxed gates); every reach it adds is unconfirmed until a verifier adjudicates it, so it must be reported separately and can never clear the HIGH bar. Ported 1:1 from the legacy speculative block for regular expression (ReDoS).

### `taint_speculative_ssrf` — Speculative reach to a outbound request (SSRF) sink (recall mode)

- Severity: **low** · confidence 0.30 · CWE-918 · tags: `taint-chain`, `speculative`, `recall`
- Rationale: Recall mode widens taint discovery (deeper hops, relaxed gates); every reach it adds is unconfirmed until a verifier adjudicates it, so it must be reported separately and can never clear the HIGH bar. Ported 1:1 from the legacy speculative block for outbound request (SSRF).

### `taint_speculative_ssti` — Speculative reach to a template injection sink (recall mode)

- Severity: **low** · confidence 0.30 · CWE-1336 · tags: `taint-chain`, `speculative`, `recall`
- Rationale: Recall mode widens taint discovery (deeper hops, relaxed gates); every reach it adds is unconfirmed until a verifier adjudicates it, so it must be reported separately and can never clear the HIGH bar. Ported 1:1 from the legacy speculative block for template injection.

### `taint_speculative_subprocess_shell` — Speculative reach to a command execution sink (recall mode)

- Severity: **low** · confidence 0.30 · CWE-78 · tags: `taint-chain`, `speculative`, `recall`
- Rationale: Recall mode widens taint discovery (deeper hops, relaxed gates); every reach it adds is unconfirmed until a verifier adjudicates it, so it must be reported separately and can never clear the HIGH bar. Ported 1:1 from the legacy speculative block for command execution.

### `taint_speculative_unsafe_deserialization` — Speculative reach to a unsafe deserialization sink (recall mode)

- Severity: **low** · confidence 0.30 · CWE-502 · tags: `taint-chain`, `speculative`, `recall`
- Rationale: Recall mode widens taint discovery (deeper hops, relaxed gates); every reach it adds is unconfirmed until a verifier adjudicates it, so it must be reported separately and can never clear the HIGH bar. Ported 1:1 from the legacy speculative block for unsafe deserialization.

### `taint_speculative_xpath_injection` — Speculative reach to a XPath expression sink (recall mode)

- Severity: **low** · confidence 0.30 · CWE-643 · tags: `taint-chain`, `speculative`, `recall`
- Rationale: Recall mode widens taint discovery (deeper hops, relaxed gates); every reach it adds is unconfirmed until a verifier adjudicates it, so it must be reported separately and can never clear the HIGH bar. Ported 1:1 from the legacy speculative block for XPath expression.

### `taint_speculative_zip_slip` — Speculative reach to a archive extraction sink (recall mode)

- Severity: **low** · confidence 0.30 · CWE-22 · tags: `taint-chain`, `speculative`, `recall`
- Rationale: Recall mode widens taint discovery (deeper hops, relaxed gates); every reach it adds is unconfirmed until a verifier adjudicates it, so it must be reported separately and can never clear the HIGH bar. Ported 1:1 from the legacy speculative block for archive extraction.

