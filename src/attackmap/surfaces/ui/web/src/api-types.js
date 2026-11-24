/* eslint-disable */
/**
 * GENERATED FILE — do not edit by hand.
 *
 * Source of truth: src/attackmap/surfaces/ui/api/schemas.py (AR063 Pydantic
 * models, one typedef per ApiModel subclass). AR065 typed client: the web
 * modules annotate server payloads with
 * `@param {import("./api-types.js").StateResponse} state` etc.; this file has
 * no runtime exports.
 *
 * All models tolerate extra keys (extra="allow"), so every typedef is an
 * open shape: documented properties plus any additional wire fields.
 *
 * Regenerate: .venv/Scripts/python.exe tools/gen_api_types.py
 * Verify:     .venv/Scripts/python.exe tools/gen_api_types.py --check
 */


/**
 * POST /api/config and POST /api/run share the same scan options body.
 * @typedef {Object} ConfigRequest
 * @property {string} [repo]
 * @property {string[]} [repos]
 * @property {boolean} [cve]
 * @property {boolean} [recall]
 * @property {string} [llmMode]
 * @property {string} [llm]
 * @property {string} [provider]
 * @property {string} [model]
 * @property {string} [baseUrl]
 * @property {(string|string[]|null)} [modules]
 * @property {boolean} [noSuppress]
 * @property {boolean} [useBaseline]
 * @property {boolean} [failOnNewHigh]
 */

/**
 * POST /api/run — same shape as config; scan start reads current settings.
 * @typedef {Object} RunRequest
 * @property {string} [repo]
 * @property {string[]} [repos]
 * @property {boolean} [cve]
 * @property {boolean} [recall]
 * @property {string} [llmMode]
 * @property {string} [llm]
 * @property {string} [provider]
 * @property {string} [model]
 * @property {string} [baseUrl]
 * @property {(string|string[]|null)} [modules]
 * @property {boolean} [noSuppress]
 * @property {boolean} [useBaseline]
 * @property {boolean} [failOnNewHigh]
 */

/**
 * POST /api/pick — open the folder picker.
 * @typedef {Object} PickRequest
 * @property {boolean} [multi]
 */

/**
 * POST /api/cancel — no fields; cancellation targets the active run.
 * @typedef {Object} CancelRequest
 */

/**
 * POST /api/watch — toggle filesystem watching.
 * @typedef {Object} WatchRequest
 * @property {boolean} [enabled]
 */

/**
 * POST /api/settings — persist provider API keys in secure storage.
 * @typedef {Object} SettingsRequest
 * @property {string} [anthropicKey]
 * @property {string} [openaiKey]
 */

/**
 * POST /api/reveal — open the report folder; no fields.
 * @typedef {Object} RevealRequest
 */

/**
 * POST /api/suppress — suppression record; passed through to the writer.
 * @typedef {Object} SuppressRequest
 */

/**
 * POST /api/export — write a report view to a .md/.pdf path.
 * @typedef {Object} ExportRequest
 * @property {string} [view]
 * @property {string} [path]
 */

/**
 * POST /api/pick-save — ask for an export destination path.
 * @typedef {Object} PickSaveRequest
 * @property {string} [suggestedName]
 */

/**
 * GET /api/state and the state snapshot returned by most POST endpoints.
 * @typedef {Object} StateResponse
 * @property {string} [status]
 * @property {Object<string,*>} [progress]
 * @property {number} [exitCode]
 * @property {string} [error]
 * @property {string} [stderrTail]
 * @property {string} [repo]
 * @property {string[]} [repos]
 * @property {string} [repositoryKey]
 * @property {string} [runId]
 * @property {string} [reportGeneration]
 * @property {string} [reportRepositoryKey]
 * @property {string} [output]
 * @property {boolean} [cve]
 * @property {boolean} [recall]
 * @property {string} [llm]
 * @property {string} [llmMode]
 * @property {string} [provider]
 * @property {string} [model]
 * @property {string} [baseUrl]
 * @property {string[]} [modules]
 * @property {boolean} [watch]
 * @property {string} [watchNotice]
 * @property {boolean} [running]
 * @property {boolean} [hasReport]
 * @property {number} [findingCount]
 * @property {number} [newCount]
 * @property {number} [resolvedCount]
 * @property {string[]} [capabilities]
 * @property {Object<string,*>[]} [availableModules]
 * @property {Object<string,*>[]} [missingAnalyzers]
 * @property {Object<string,*>[]} [recents]
 * @property {boolean} [hasAnthropicKey]
 * @property {boolean} [hasOpenAIKey]
 * @property {string} [llmOffBoxWarning]
 * @property {Object<string,*>} [runContract]
 */

/**
 * POST /api/config — the applied configuration as a state snapshot.
 * @typedef {Object} ConfigResponse
 * @property {string} [status]
 * @property {Object<string,*>} [progress]
 * @property {number} [exitCode]
 * @property {string} [error]
 * @property {string} [stderrTail]
 * @property {string} [repo]
 * @property {string[]} [repos]
 * @property {string} [repositoryKey]
 * @property {string} [runId]
 * @property {string} [reportGeneration]
 * @property {string} [reportRepositoryKey]
 * @property {string} [output]
 * @property {boolean} [cve]
 * @property {boolean} [recall]
 * @property {string} [llm]
 * @property {string} [llmMode]
 * @property {string} [provider]
 * @property {string} [model]
 * @property {string} [baseUrl]
 * @property {string[]} [modules]
 * @property {boolean} [watch]
 * @property {string} [watchNotice]
 * @property {boolean} [running]
 * @property {boolean} [hasReport]
 * @property {number} [findingCount]
 * @property {number} [newCount]
 * @property {number} [resolvedCount]
 * @property {string[]} [capabilities]
 * @property {Object<string,*>[]} [availableModules]
 * @property {Object<string,*>[]} [missingAnalyzers]
 * @property {Object<string,*>[]} [recents]
 * @property {boolean} [hasAnthropicKey]
 * @property {boolean} [hasOpenAIKey]
 * @property {string} [llmOffBoxWarning]
 * @property {Object<string,*>} [runContract]
 */

/**
 * POST /api/run — state snapshot taken right after the run was requested.
 * @typedef {Object} RunResponse
 * @property {string} [status]
 * @property {Object<string,*>} [progress]
 * @property {number} [exitCode]
 * @property {string} [error]
 * @property {string} [stderrTail]
 * @property {string} [repo]
 * @property {string[]} [repos]
 * @property {string} [repositoryKey]
 * @property {string} [runId]
 * @property {string} [reportGeneration]
 * @property {string} [reportRepositoryKey]
 * @property {string} [output]
 * @property {boolean} [cve]
 * @property {boolean} [recall]
 * @property {string} [llm]
 * @property {string} [llmMode]
 * @property {string} [provider]
 * @property {string} [model]
 * @property {string} [baseUrl]
 * @property {string[]} [modules]
 * @property {boolean} [watch]
 * @property {string} [watchNotice]
 * @property {boolean} [running]
 * @property {boolean} [hasReport]
 * @property {number} [findingCount]
 * @property {number} [newCount]
 * @property {number} [resolvedCount]
 * @property {string[]} [capabilities]
 * @property {Object<string,*>[]} [availableModules]
 * @property {Object<string,*>[]} [missingAnalyzers]
 * @property {Object<string,*>[]} [recents]
 * @property {boolean} [hasAnthropicKey]
 * @property {boolean} [hasOpenAIKey]
 * @property {string} [llmOffBoxWarning]
 * @property {Object<string,*>} [runContract]
 */

/**
 * POST /api/cancel — state snapshot reflecting the cancellation request.
 * @typedef {Object} CancelResponse
 * @property {string} [status]
 * @property {Object<string,*>} [progress]
 * @property {number} [exitCode]
 * @property {string} [error]
 * @property {string} [stderrTail]
 * @property {string} [repo]
 * @property {string[]} [repos]
 * @property {string} [repositoryKey]
 * @property {string} [runId]
 * @property {string} [reportGeneration]
 * @property {string} [reportRepositoryKey]
 * @property {string} [output]
 * @property {boolean} [cve]
 * @property {boolean} [recall]
 * @property {string} [llm]
 * @property {string} [llmMode]
 * @property {string} [provider]
 * @property {string} [model]
 * @property {string} [baseUrl]
 * @property {string[]} [modules]
 * @property {boolean} [watch]
 * @property {string} [watchNotice]
 * @property {boolean} [running]
 * @property {boolean} [hasReport]
 * @property {number} [findingCount]
 * @property {number} [newCount]
 * @property {number} [resolvedCount]
 * @property {string[]} [capabilities]
 * @property {Object<string,*>[]} [availableModules]
 * @property {Object<string,*>[]} [missingAnalyzers]
 * @property {Object<string,*>[]} [recents]
 * @property {boolean} [hasAnthropicKey]
 * @property {boolean} [hasOpenAIKey]
 * @property {string} [llmOffBoxWarning]
 * @property {Object<string,*>} [runContract]
 */

/**
 * POST /api/watch — state snapshot reflecting the new watch flag.
 * @typedef {Object} WatchResponse
 * @property {string} [status]
 * @property {Object<string,*>} [progress]
 * @property {number} [exitCode]
 * @property {string} [error]
 * @property {string} [stderrTail]
 * @property {string} [repo]
 * @property {string[]} [repos]
 * @property {string} [repositoryKey]
 * @property {string} [runId]
 * @property {string} [reportGeneration]
 * @property {string} [reportRepositoryKey]
 * @property {string} [output]
 * @property {boolean} [cve]
 * @property {boolean} [recall]
 * @property {string} [llm]
 * @property {string} [llmMode]
 * @property {string} [provider]
 * @property {string} [model]
 * @property {string} [baseUrl]
 * @property {string[]} [modules]
 * @property {boolean} [watch]
 * @property {string} [watchNotice]
 * @property {boolean} [running]
 * @property {boolean} [hasReport]
 * @property {number} [findingCount]
 * @property {number} [newCount]
 * @property {number} [resolvedCount]
 * @property {string[]} [capabilities]
 * @property {Object<string,*>[]} [availableModules]
 * @property {Object<string,*>[]} [missingAnalyzers]
 * @property {Object<string,*>[]} [recents]
 * @property {boolean} [hasAnthropicKey]
 * @property {boolean} [hasOpenAIKey]
 * @property {string} [llmOffBoxWarning]
 * @property {Object<string,*>} [runContract]
 */

/**
 * POST /api/reveal — state snapshot (reveal itself has no payload).
 * @typedef {Object} RevealResponse
 * @property {string} [status]
 * @property {Object<string,*>} [progress]
 * @property {number} [exitCode]
 * @property {string} [error]
 * @property {string} [stderrTail]
 * @property {string} [repo]
 * @property {string[]} [repos]
 * @property {string} [repositoryKey]
 * @property {string} [runId]
 * @property {string} [reportGeneration]
 * @property {string} [reportRepositoryKey]
 * @property {string} [output]
 * @property {boolean} [cve]
 * @property {boolean} [recall]
 * @property {string} [llm]
 * @property {string} [llmMode]
 * @property {string} [provider]
 * @property {string} [model]
 * @property {string} [baseUrl]
 * @property {string[]} [modules]
 * @property {boolean} [watch]
 * @property {string} [watchNotice]
 * @property {boolean} [running]
 * @property {boolean} [hasReport]
 * @property {number} [findingCount]
 * @property {number} [newCount]
 * @property {number} [resolvedCount]
 * @property {string[]} [capabilities]
 * @property {Object<string,*>[]} [availableModules]
 * @property {Object<string,*>[]} [missingAnalyzers]
 * @property {Object<string,*>[]} [recents]
 * @property {boolean} [hasAnthropicKey]
 * @property {boolean} [hasOpenAIKey]
 * @property {string} [llmOffBoxWarning]
 * @property {Object<string,*>} [runContract]
 */

/**
 * POST /api/settings — state snapshot after key storage attempts.
 * @typedef {Object} SettingsResponse
 * @property {string} [status]
 * @property {Object<string,*>} [progress]
 * @property {number} [exitCode]
 * @property {string} [error]
 * @property {string} [stderrTail]
 * @property {string} [repo]
 * @property {string[]} [repos]
 * @property {string} [repositoryKey]
 * @property {string} [runId]
 * @property {string} [reportGeneration]
 * @property {string} [reportRepositoryKey]
 * @property {string} [output]
 * @property {boolean} [cve]
 * @property {boolean} [recall]
 * @property {string} [llm]
 * @property {string} [llmMode]
 * @property {string} [provider]
 * @property {string} [model]
 * @property {string} [baseUrl]
 * @property {string[]} [modules]
 * @property {boolean} [watch]
 * @property {string} [watchNotice]
 * @property {boolean} [running]
 * @property {boolean} [hasReport]
 * @property {number} [findingCount]
 * @property {number} [newCount]
 * @property {number} [resolvedCount]
 * @property {string[]} [capabilities]
 * @property {Object<string,*>[]} [availableModules]
 * @property {Object<string,*>[]} [missingAnalyzers]
 * @property {Object<string,*>[]} [recents]
 * @property {boolean} [hasAnthropicKey]
 * @property {boolean} [hasOpenAIKey]
 * @property {string} [llmOffBoxWarning]
 * @property {Object<string,*>} [runContract]
 */

/**
 * POST /api/pick — state snapshot plus the resolved repository paths.
 * @typedef {Object} PickResponse
 * @property {string} [status]
 * @property {Object<string,*>} [progress]
 * @property {number} [exitCode]
 * @property {string} [error]
 * @property {string} [stderrTail]
 * @property {string} [repo]
 * @property {string[]} [repos]
 * @property {string} [repositoryKey]
 * @property {string} [runId]
 * @property {string} [reportGeneration]
 * @property {string} [reportRepositoryKey]
 * @property {string} [output]
 * @property {boolean} [cve]
 * @property {boolean} [recall]
 * @property {string} [llm]
 * @property {string} [llmMode]
 * @property {string} [provider]
 * @property {string} [model]
 * @property {string} [baseUrl]
 * @property {string[]} [modules]
 * @property {boolean} [watch]
 * @property {string} [watchNotice]
 * @property {boolean} [running]
 * @property {boolean} [hasReport]
 * @property {number} [findingCount]
 * @property {number} [newCount]
 * @property {number} [resolvedCount]
 * @property {string[]} [capabilities]
 * @property {Object<string,*>[]} [availableModules]
 * @property {Object<string,*>[]} [missingAnalyzers]
 * @property {Object<string,*>[]} [recents]
 * @property {boolean} [hasAnthropicKey]
 * @property {boolean} [hasOpenAIKey]
 * @property {string} [llmOffBoxWarning]
 * @property {Object<string,*>} [runContract]
 * @property {string[]} [picked]
 */

/**
 * GET /api/report — the current report snapshot with identity fields.
 * @typedef {Object} ReportResponse
 * @property {string} [repositoryKey]
 * @property {string} [generationId]
 * @property {string} [error]
 */

/**
 * GET /api/export-source — raw Markdown for a report view.
 * @typedef {Object} ExportSourceResponse
 * @property {string} [markdown]
 */

/**
 * POST /api/suppress — the suppression file that was appended.
 * @typedef {Object} SuppressResponse
 * @property {boolean} [ok]
 * @property {string} [path]
 * @property {string} [error]
 */

/**
 * POST /api/export — the written artifact path, or an error body.
 * @typedef {Object} ExportResponse
 * @property {boolean} [ok]
 * @property {string} [path]
 * @property {string} [error]
 */

/**
 * POST /api/pick-save — the chosen path ("" when the dialog was cancelled).
 * @typedef {Object} PickSaveResponse
 * @property {string} [path]
 * @property {string} [error]
 */
