# Analyzer reference

> Generated 2026-11-23 from `attackmap` **1.5.1** — source module
> `src/attackmap/orchestration/analyzers.py` (built-in analyzers registered via
> `get_registered_analyzers()`; metadata normalized to `sdk.AnalyzerMetadata`).
> Static snapshot; installed plugins add more at runtime (`attackmap modules`).

9 built-in analyzers, in run order (lower `priority` runs first;
merge is first-seen-wins, so priority also sets merge precedence).

| Name | Version | Priority | Default | Experimental | Targets | Languages |
| --- | --- | --- | --- | --- | --- | --- |
| `javascript-web` | 0.2.0 | 20 | yes | no | express, fastify, koa, node | javascript, typescript |
| `php-web` | 0.1.0 | 20 | yes | no | php | php |
| `python-web` | 0.1.0 | 20 | yes | no | fastapi, flask | python |
| `config` | 0.1.0 | 30 | yes | no | yaml, toml, json, ini, env | — |
| `python-service` | 0.1.0 | 50 | yes | yes | fastapi, flask, django, celery | python |
| `php-laminas` | 0.1.0 | 60 | yes | yes | laminas, zend-mvc | php |
| `default` | 0.1.0 | 100 | yes | no | — | — |
| `node-atproto` | 0.1.0 | 150 | yes | yes | atproto, xrpc, node-service | javascript, typescript |
| `omeka-s` | 0.1.0 | 160 | yes | yes | omeka-s | php |

## Details

### `javascript-web` — JavaScript / TypeScript Web Analyzer (0.2.0)

Broad built-in analyzer for JavaScript and TypeScript web applications.

- Scope: JavaScript/TypeScript source files (.js/.jsx/.mjs/.cjs/.ts/.tsx). Deep framework coverage lives in attackmap-analyzer-node-service; this is the fallback.
- Run order priority: 20
- Runs by default: yes
- Experimental: no

### `php-web` — PHP Web Analyzer (0.1.0)

Built-in analyzer for plain PHP web applications: generic routes plus request input, include chains, session/cookie handling, datastores, outbound HTTP.

- Scope: PHP source files (.php). Framework structure lives in php-laminas; Omeka S specifics in omeka-s.
- Run order priority: 20
- Runs by default: yes
- Experimental: no

### `python-web` — Python Web Analyzer (0.1.0)

Built-in analyzer for Python web frameworks and related security signals.

- Scope: Python source files handled by the current scanner-backed web heuristics.
- Run order priority: 20
- Runs by default: yes
- Experimental: no

### `config` — Config File Analyzer (0.1.0)

Broad built-in analyzer for YAML / TOML / JSON / INI / .env application config files.

- Scope: Application config files. Extracts DB connection strings, external service URLs, and secret-shaped literals; deep IaC parsing (docker-compose service graph, Dockerfile hardening) lives in attackmap-analyzer-iac.
- Run order priority: 30
- Runs by default: yes
- Experimental: no

### `python-service` — Python Services Ecosystem Analyzer (0.1.0)

Framework-enrichment overlay for Python web services (FastAPI/Flask/Django/Celery cross-file wiring).

- Scope: Python web-service repositories; adds cross-file router/blueprint/URLconf wiring, framework auth semantics, ORM scoping, and service-boundary signals on top of the per-file python-web pass.
- Run order priority: 50
- Runs by default: yes
- Experimental: yes

### `php-laminas` — PHP Laminas (Zend MVC) Analyzer (0.1.0)

Framework enrichment for Laminas / Zend MVC: module structure, router config, controllers/actions, service-manager wiring, middleware, validators/filters.

- Scope: Repos with laminas/ or zendframework/ composer dependencies, or Module.php files carrying Laminas/Zend markers.
- Run order priority: 60
- Runs by default: yes
- Experimental: yes

### `default` — Default Analyzer (0.1.0)

Fallback built-in analyzer for code file suffixes not claimed by a specialized built-in.

- Scope: Any CODE_EXTENSIONS suffix not covered by python-web or javascript-web.
- Run order priority: 100
- Runs by default: yes
- Experimental: no

### `node-atproto` — Node / ATProto Overlay Analyzer (0.1.0)

Thin ATProto / Node-service overlay: XRPC lexicon surface, identity and signing hotspots, service boundaries, and cross-file route wiring.

- Scope: Repositories that look like ATProto services (lexicons, @atproto dependencies, did:/NSID markers). Enriches javascript-web; extraction only, never scores.
- Run order priority: 150
- Runs by default: yes
- Experimental: yes

### `omeka-s` — Omeka S Analyzer (0.1.0)

Application overlay for Omeka S modules: module layout, API adapters vs representations vs routes, admin authentication, media ingestion, view output encoding.

- Scope: Repos with an Omeka S module marker (Omeka\Module\AbstractModule) or an omeka/* composer dependency.
- Run order priority: 160
- Runs by default: yes
- Experimental: yes

