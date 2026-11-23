# SDK surface (`attackmap.sdk`)

> Generated 2026-11-23 from `attackmap` **1.5.1** — source module
> `src/attackmap/sdk/__init__.py` (`__all__`, 51 exports). Everything importable
> from `attackmap.sdk` is the stable analyzer contract; anything else in the
> `attackmap` package is internal and may change without a major-version bump.
> Static snapshot.

Full contract narrative (merge semantics, taint-sink contribution,
responsibilities split) lives in the module docstring of
`src/attackmap/sdk/__init__.py`.

| Export | Kind | Summary |
| --- | --- | --- |
| `DEFAULT_SKIP_DIRS` | constant | — |
| `DEPENDENCY_ECOSYSTEMS` | constant | — |
| `EXTRACTION_CONTRACT_VERSION` | constant | — |
| `TAINT_SINK_KINDS` | constant | — |
| `TAINT_SINK_PLUGIN_GROUP` | constant | — |
| `AnalyzerMetadata` | class | Static, self-describing metadata every analyzer exposes. |
| `AnalyzerProtocol` | class | Base class for protocol classes. |
| `AnalyzerRepositoryModule` | class | !!! abstract "Usage Documentation" |
| `AnalyzerResult` | class | !!! abstract "Usage Documentation" |
| `AuthHint` | class | !!! abstract "Usage Documentation" |
| `DatabaseHint` | class | !!! abstract "Usage Documentation" |
| `DependencyEcosystem` | callable |  |
| `DependencyHint` | class | A single third-party dependency declared in a manifest or lockfile. |
| `DependencyObservation` | class | A v2 `dependency` observation wrapping a protocol-1.0 `DependencyHint`. |
| `EdgeHint` | class | !!! abstract "Usage Documentation" |
| `EdgeObservation` | class | A v2 `edge` observation wrapping a protocol-1.0 `EdgeHint`. |
| `EntrypointHint` | class | !!! abstract "Usage Documentation" |
| `EntrypointObservation` | class | A v2 `entrypoint` observation wrapping a protocol-1.0 `EntrypointHint`. |
| `ExternalCall` | class | !!! abstract "Usage Documentation" |
| `ExtractionResult` | class | Extraction contract v2: one discriminated list of observations. |
| `FrameworkHint` | class | !!! abstract "Usage Documentation" |
| `FrameworkObservation` | class | A v2 `framework` observation wrapping a protocol-1.0 `FrameworkHint`. |
| `Observation` | callable | Runtime representation of an annotated type. |
| `ProtocolHint` | class | !!! abstract "Usage Documentation" |
| `ProtocolObservation` | class | A v2 `protocol` observation wrapping a protocol-1.0 `ProtocolHint`. |
| `Route` | class | !!! abstract "Usage Documentation" |
| `RouteObservation` | class | A v2 `route` observation wrapping a protocol-1.0 `Route`. |
| `ScanResult` | class | !!! abstract "Usage Documentation" |
| `SecretHint` | class | !!! abstract "Usage Documentation" |
| `SecretObservation` | class | A v2 `secret` observation wrapping a protocol-1.0 `SecretHint`. |
| `ServiceHint` | class | !!! abstract "Usage Documentation" |
| `ServiceObservation` | class | A v2 `service` observation wrapping a protocol-1.0 `ServiceHint`. |
| `SupplyChainObservation` | class | A v2 `supply_chain` observation wrapping a protocol-1.0 `SupplyChainIssue`. |
| `VulnerabilityObservation` | class | A v2 `vulnerability` observation wrapping a protocol-1.0 `Vulnerability`. |
| `WeaknessObservation` | class | A v2 `weakness` observation wrapping a protocol-1.0 `CodeWeakness`. |
| `WorkflowObservation` | class | A v2 `workflow` observation wrapping a protocol-1.0 `WorkflowIssue`. |
| `contained_file` | callable | Resolve a repo-relative path from untrusted text (evidence, plugin |
| `fs` | constant | Shared repo walking and reading for analyzer plugins (#253). |
| `is_contained` | callable | True when ``path`` is inside ``root`` and is not reached via a symlink. |
| `iter_repo_files` | callable | Yield the repo's regular files, sorted and depth-first. |
| `line_of` | callable | 1-indexed line of a character offset (e.g. ``match.start()``). |
| `line_snippet` | callable | The stripped text of 1-indexed ``line``, truncated to ``max_len``. |
| `merge_extraction_results` | callable | Merge several v2 extraction results (e.g. per-analyzer payloads). |
| `normalize_analyzer_metadata` | callable |  |
| `read_repo_text` | callable | ``Path.read_text`` that refuses paths outside ``root`` or behind a symlink. |
| `read_source` | callable | Read a source file as text, or return None if it can't be read. |
| `rel` | callable | ``path`` relative to ``root``, POSIX-style (``src/app.py``). |
| `to_extraction_result` | callable | Adapt a protocol-1.0 ``ScanResult`` (v1) to an ``ExtractionResult`` (v2). |
| `to_scan_result` | callable | Adapt an ``ExtractionResult`` (v2) back to a protocol-1.0 ``ScanResult``. |
| `validate_taint_sink` | callable | Validate one registry entry and compile it. Raises SinkRegistryError. |
| `walk_repo` | callable | Yield regular files under ``root`` (depth-first, sorted per directory). |

## Notes

- `AnalyzerProtocol` — what an analyzer implements: `metadata`, `name`, `detect(root)`, `analyze(root)`.
- `AnalyzerMetadata` — static self-describing metadata every analyzer exposes.
- Observation/Hint model pairs (e.g. `Route`/`RouteObservation`) are the extraction contract v2 (`EXTRACTION_CONTRACT_VERSION`).
- `TAINT_SINK_PLUGIN_GROUP` / `TAINT_SINK_KINDS` / `DEPENDENCY_ECOSYSTEMS` — plugin extension points for taint sinks and dependency ecosystems.

