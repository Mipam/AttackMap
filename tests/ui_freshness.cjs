/* Exercises the shipped ES-module frontend (cache/view adapter) without a
 * browser dependency. AR065 port: the pre-module build vm.runInContext'ed
 * api.js+app.js as classic scripts and poked their globals; the module build
 * is loaded with vm.SourceTextModule and driven through the real module
 * namespaces (state.js `ui`/`refresh`/`pendingRefresh`, api.js
 * `getState`/`post`, paint.js `setRenderObserver`).
 *
 * markdown.js/mermaid-lite.js are replaced with passthrough stubs at link
 * time — the module-era equivalent of this harness's original renderMarkdown
 * stubs, so subtest assertions on innerHTML stay text-exact. Everything else
 * (api, state, paint, views, activity, main) is the real shipped code.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");

const srcDir = path.join(__dirname, "../src/attackmap/surfaces/ui/web/src");
const copy = (value) => JSON.parse(JSON.stringify(value));
const tick = () => new Promise((resolve) => setImmediate(resolve));
function deferred() {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
}

function snapshot(repo, generation, status = "done") {
  return {
    repositoryKey: repo, reportRepositoryKey: repo, reportGeneration: generation,
    runId: generation, status, hasReport: !!generation, repos: [repo],
    findingCount: 1, availableModules: [],
  };
}

function report(repo, generation) {
  return {
    repositoryKey: repo, generationId: generation, repoName: repo,
    reviewMd: `${repo}/${generation}`, findings: [], exploitability: [],
    severityCounts: {}, diagrams: {}, findingCount: 1,
  };
}

// Passthrough renderer stubs (link-time), mirroring the original harness.
const MARKDOWN_STUB = `export function renderMarkdown(src) { return src || ""; }`;
const MERMAID_STUB = `export function extractMermaidBlocks() { return []; }
export function renderMermaidBlock() { return ""; }
export function renderMermaidDocument(src) { return src || ""; }`;

async function harness() {
  const elements = new Map();
  const requests = [];
  const renders = [];
  const timers = [];
  const gates = new Map();
  let state = snapshot("a", null, "idle");
  let currentReport = null;
  let activeStates = 0;
  let maxStates = 0;
  function element(id) {
    if (!elements.has(id)) elements.set(id, {
      id, innerHTML: "", value: "", textContent: "", disabled: false, hidden: false,
      checked: false, style: {}, options: [], listeners: {},
      classList: { toggle() {} }, add() {}, remove() {},
      addEventListener(name, callback) { this.listeners[name] = callback; },
    });
    return elements.get(id);
  }
  const documentStub = {
    getElementById: element, activeElement: null,
    querySelectorAll: () => [],
  };
  const context = vm.createContext({
    URL, URLSearchParams, console, renders,
    location: { search: "", pathname: "/", origin: "http://127.0.0.1" },
    history: {}, sessionStorage: { getItem() { return "token"; } },
    document: documentStub,
    window: {}, Option: function () {},
    alert() {},
    setTimeout: (callback) => { timers.push(callback); return timers.length; },
    fetch: async (url, options) => {
      const u = url instanceof URL ? url : new URL(String(url), "http://127.0.0.1");
      requests.push(u.pathname);
      const isState = u.pathname === "/api/state";
      if (isState) maxStates = Math.max(maxStates, ++activeStates);
      const data = copy(isState ? state : u.pathname === "/api/report" ? currentReport : {});
      const gate = gates.get(u.pathname);
      gates.delete(u.pathname);
      if (gate) await gate.promise;
      if (isState) activeStates -= 1;
      return { ok: true, headers: { get: () => "application/json" }, json: async () => data };
    },
  });

  // Build the module graph; stub only the two renderer leaves.
  const files = [];
  (function walk(dir) {
    for (const name of fs.readdirSync(dir)) {
      const p = path.join(dir, name);
      if (fs.statSync(p).isDirectory()) walk(p);
      else if (name.endsWith(".js")) files.push(p);
    }
  })(srcDir);
  const keyOf = (p) => "./" + path.relative(srcDir, p).replace(/\\/g, "/");
  const modules = new Map();
  const sourceOf = (key) => {
    if (key === "./markdown.js") return MARKDOWN_STUB;
    if (key === "./mermaid-lite.js") return MERMAID_STUB;
    return fs.readFileSync(path.join(srcDir, key.slice(2)), "utf8");
  };
  for (const file of files) {
    const key = keyOf(file);
    modules.set(key, new vm.SourceTextModule(sourceOf(key), { identifier: key, context }));
  }
  const entry = modules.get("./main.js");
  await entry.link((specifier, referencing) => {
    assert.ok(specifier.startsWith("."), `bare specifier ${specifier} in ${referencing.identifier}`);
    const target = "./" + path.posix.normalize(
      path.posix.join(path.posix.dirname(referencing.identifier), specifier));
    const mod = modules.get(target);
    assert.ok(mod, `${referencing.identifier} imports missing ${specifier}`);
    return mod;
  });
  await entry.evaluate();

  const stateNs = modules.get("./state.js").namespace;
  const apiNs = modules.get("./api.js").namespace;
  const paintNs = modules.get("./paint.js").namespace;

  // Settle the initial poll (the old harness awaited `refreshPromise`), then
  // install the render observer and park the view on "review" — the module
  // equivalent of wrapping renderMain and setting currentView.
  await stateNs.pendingRefresh();
  paintNs.setRenderObserver(({ state, report, view }) => renders.push({ state, report, view }));
  stateNs.ui.currentView = "review";

  return {
    elements, requests, renders, timers,
    ui: stateNs.ui,
    refresh: () => stateNs.refresh(),
    getState: () => apiNs.getState(),
    post: (pathName, body) => apiNs.post(pathName, body),
    focus(id) { documentStub.activeElement = id ? { id } : null; },
    set(repo, generation, status = "done") {
      state = snapshot(repo, generation, status);
      currentReport = generation ? report(repo, generation) : null;
    },
    hold(url) { const gate = deferred(); gates.set(url, gate); return gate; },
    maxStates: () => maxStates,
  };
}

test("100 scan sequences retain only the selected repository and generation", async () => {
  const h = await harness();
  for (let i = 0; i < 100; i++) {
    const repo = `repo-${i % 3}`;
    h.set(repo, `first-${i}`);
    await h.refresh();
    assert.equal(h.elements.get("view").innerHTML, `${repo}/first-${i}`);
    if (i % 2) {
      h.set(repo, `first-${i}`, "running");
      for (const view of ["findings", "settings", "recents", "review"]) {
        h.ui.currentView = view;
        await h.refresh();
        assert.equal(h.ui.reportCache, null);
      }
    }
    // Even sequences finish entirely between polls.
    h.set(repo, `second-${i}`);
    await h.refresh();
    assert.equal(h.elements.get("view").innerHTML, `${repo}/second-${i}`);
    h.set(repo, `second-${i}`, "failed");
    await h.refresh();
    assert.equal(h.ui.reportCache, null);
    assert.ok(!h.elements.get("view").innerHTML.includes(`second-${i}`));
    assert.equal(h.elements.get("export-md").disabled, true);
    h.set(`other-${i}`, null, "idle");
    await h.refresh();
    assert.equal(h.ui.reportCache, null);
    h.set(`other-${i}`, `third-${i}`);
    await h.refresh();
    assert.equal(h.elements.get("view").innerHTML, `other-${i}/third-${i}`);
  }
  for (const { state, report } of h.renders) {
    if (report) {
      assert.equal(report.generationId, state.reportGeneration);
      assert.equal(report.repositoryKey, state.repositoryKey);
      assert.ok(["idle", "done"].includes(state.status));
    }
  }
  assert.equal(h.maxStates(), 1);
});

test("delayed report cannot overwrite a newer workspace or navigation request", async () => {
  const h = await harness();
  h.set("old", "g1");
  const gate = h.hold("/api/report");
  const old = h.refresh();
  await tick();
  h.set("new", "g2");
  h.ui.currentView = "findings";
  const latest = h.refresh();
  gate.resolve();
  await Promise.all([old, latest]);
  assert.ok(!h.renders.some((r) => r.report && r.report.generationId === "g1"));
  assert.equal(h.renders.at(-1).view, "findings");
  assert.equal(h.ui.reportCache.generationId, "g2");
  assert.equal(h.ui.reportCache.repositoryKey, "new");
});

for (const transition of [
  { repo: "a", generation: "g2", status: "done" },
  { repo: "a", generation: "g1", status: "running" },
  { repo: "a", generation: "g1", status: "failed" },
  { repo: "b", generation: "g2", status: "done" },
  { repo: "b", generation: null, status: "idle" },
]) {
  test(`server transition during report load is revalidated: ${JSON.stringify(transition)}`, async () => {
    const h = await harness();
    h.set("a", "g1");
    const gate = h.hold("/api/report");
    const pending = h.refresh();
    await tick();
    // Watch/native changes do not issue another frontend refresh or POST.
    h.set(transition.repo, transition.generation, transition.status);
    gate.resolve();
    await pending;
    assert.ok(!h.renders.some((r) => r.report && r.report.generationId === "g1"));
    if (transition.status === "done") {
      assert.equal(h.ui.reportCache.generationId, transition.generation);
      assert.equal(h.ui.reportCache.repositoryKey, transition.repo);
    } else {
      assert.equal(h.ui.reportCache, null);
      assert.equal(h.elements.get("export-md").disabled, true);
    }
    assert.equal(h.maxStates(), 1);
  });
}

test("report validation does not reuse a state read that predates the report response", async () => {
  const h = await harness();
  h.set("a", "g1");
  const reportGate = h.hold("/api/report");
  const pending = h.refresh();
  await tick();
  const stateGate = h.hold("/api/state");
  const commandState = h.getState();
  await tick();
  h.set("a", "g2");
  reportGate.resolve();
  await tick();
  assert.ok(!h.renders.some((r) => r.report));
  stateGate.resolve();
  await Promise.all([pending, commandState]);
  assert.equal(h.ui.reportCache.generationId, "g2");
  assert.ok(!h.renders.some((r) => r.report && r.report.generationId === "g1"));
  assert.equal(h.maxStates(), 1);
});

test("state polling is serialized across refresh and command handlers", async () => {
  const h = await harness();
  const gate = h.hold("/api/state");
  const requests = [h.refresh(), h.getState(), h.getState(), h.refresh()];
  await tick();
  assert.equal(h.maxStates(), 1);
  gate.resolve();
  await Promise.all(requests);
  assert.equal(h.maxStates(), 1);
  // A new timer is armed only after the prior poll resolves.
  assert.equal(h.timers.length, 1);
  const nextGate = h.hold("/api/state");
  const poll = h.timers[0]();
  await tick();
  assert.equal(h.timers.length, 1);
  nextGate.resolve();
  await poll;
  assert.equal(h.timers.length, 2);
});

test("responses started before a mutation are discarded even without another refresh", async () => {
  const h = await harness();
  h.set("before", "g1");
  const gate = h.hold("/api/state");
  const pending = h.refresh();
  await tick();
  h.set("after", "g2");
  await h.post("/api/config", { repo: "after" });
  gate.resolve();
  await pending;
  assert.equal(h.ui.reportCache.generationId, "g2");
  assert.ok(!h.renders.some((r) => r.state.repositoryKey === "before"));
  assert.equal(h.maxStates(), 1);
});

test("mismatched report identity never enters the cache", async () => {
  const h = await harness();
  h.set("a", "g1");
  const gate = h.hold("/api/state");
  const pending = h.refresh();
  await tick();
  h.set("b", "g2");
  gate.resolve();
  await pending;
  // The post-load validation observes the changed workspace and retries
  // immediately; only the matching current generation may be painted.
  assert.ok(!h.renders.some((r) => r.report && r.report.generationId === "g1"));
  assert.ok(h.renders.every((r) => !r.report || r.report.repositoryKey === r.state.repositoryKey));
  assert.equal(h.ui.reportCache.generationId, "g2");
});

test("typing cannot preserve an old view while the next generation loads", async () => {
  const h = await harness();
  h.set("a", "g1");
  await h.refresh();
  assert.equal(h.elements.get("view").innerHTML, "a/g1");
  h.focus("suppress-reason");
  h.set("a", "g2");
  const gate = h.hold("/api/report");
  const pending = h.refresh();
  await tick();
  assert.ok(!h.elements.get("view").innerHTML.includes("a/g1"));
  assert.equal(h.elements.get("export-md").disabled, true);
  gate.resolve();
  await pending;
  assert.equal(h.elements.get("view").innerHTML, "a/g2");
  h.set("a", "g2", "running");
  h.focus("repo-label");
  await h.refresh();
  assert.ok(h.elements.get("view").innerHTML.includes("Scanning"));
  assert.equal(h.ui.reportCache, null);
});
