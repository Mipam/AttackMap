/* Settings nav view (AR065): provider keys and AI/CVE disclosure notes. */

/**
 * @param {import("../api-types.js").StateResponse} state
 * @returns {string}
 */
export function renderSettings(state) {
  return `<div class="settings">
    <p>AI and CVE checks are off on first launch. AI sends repository metadata, findings and evidence to the selected provider; verification and remediation may include source excerpts. Secret masking is best effort. Providers control retention.</p><p>CVE checks send dependency ecosystems, package names and versions to OSV (api.osv.dev), including private package names. Custom AI endpoints can be remote.</p><p>API keys are stored with Windows DPAPI and injected only into the selected scan child process.</p>
    <label>Anthropic API key ${state.hasAnthropicKey ? "(saved)" : ""}</label>
    <input type="password" id="anth-key" placeholder="sk-ant-…" />
    <label>OpenAI API key ${state.hasOpenAIKey ? "(saved)" : ""}</label>
    <input type="password" id="oai-key" placeholder="sk-…" />
    <p>LM Studio (OpenAI-compatible local endpoint): keep the provider set to
    <strong>LM Studio (local)</strong> in the toolbar and use Base URL
    <code>http://127.0.0.1:1234/v1</code>. LM Studio accepts any non-empty API key;
    stored production keys are not forwarded to loopback endpoints.</p>
    <p><button type="button" class="run" id="save-keys" style="margin-left:0">Save keys</button></p>
  </div>`;
}
