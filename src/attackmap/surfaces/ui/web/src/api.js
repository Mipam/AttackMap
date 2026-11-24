/* Loopback API client for the GUI (AR065: ES module; same contract as the
 * pre-module api.js — the X-AttackMap-Token header or ?token= query param is
 * the only auth, and post() stays the single funnel for mutations so the
 * state stream stays serialized via stateEpoch).
 *
 * Token resolution order: ?token= query param (then stripped from the URL and
 * mirrored into sessionStorage) → sessionStorage → "".
 */

const params = new URLSearchParams(location.search);
let TOKEN = params.get("token") || "";
if (TOKEN) {
  try { sessionStorage.setItem("attackmap-token", TOKEN); } catch { /* private mode */ }
  if (history.replaceState) history.replaceState({}, "", location.pathname);
} else {
  try { TOKEN = sessionStorage.getItem("attackmap-token") || ""; } catch { TOKEN = ""; }
}

/** Current auth token (live read; never reassign from importers). */
export function getToken() {
  return TOKEN;
}

/**
 * Fetch a /api/* path with the auth token; JSON-decodes JSON bodies.
 * @param {string} path
 * @param {RequestInit} [opts]
 * @returns {Promise<any>}
 */
export async function api(path, opts) {
  const url = new URL(path, location.origin);
  const res = await fetch(url, Object.assign({ headers: { "X-AttackMap-Token": TOKEN } }, opts || {}));
  if (!res.ok) throw new Error(String(res.status));
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) return res.json();
  return res.text();
}

let stateRequest = null;
/** Bumped by every mutation; readers use it to detect stale responses. */
export let stateEpoch = 0;

/**
 * Serialized state read: concurrent callers share one in-flight request and
 * responses from a superseded epoch are re-read.
 * @returns {Promise<import("./api-types.js").StateResponse>}
 */
export function getState() {
  if (!stateRequest) {
    const epoch = stateEpoch;
    stateRequest = api("/api/state")
      .then((state) => ({ state, epoch }))
      .finally(() => { stateRequest = null; });
  }
  return stateRequest.then(({ state, epoch }) => epoch === stateEpoch ? state : getState());
}

export async function getFreshState() {
  // A command handler may already be reading a snapshot captured before the
  // report response arrived. Drain that read before starting the validation
  // read, while keeping the state stream serialized.
  if (stateRequest) {
    try { await stateRequest; } catch { /* retry with a fresh request below */ }
  }
  return getState();
}

/**
 * @param {import("./api-types.js").StateResponse} state
 * @returns {Promise<import("./api-types.js").ReportResponse>}
 */
export function getReport(state) {
  const query = new URLSearchParams({
    repositoryKey: state.repositoryKey,
    generationId: state.reportGeneration,
  });
  return api(`/api/report?${query}`);
}

/**
 * POST a mutation. Every post invalidates in-flight state reads (stateEpoch),
 * which is what keeps command handlers and the poller from painting stale
 * snapshots.
 * @param {string} path
 * @param {object} [body]
 * @returns {Promise<any>}
 */
export async function post(path, body) {
  stateEpoch += 1;
  try {
    return await api(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-AttackMap-Token": TOKEN },
      body: JSON.stringify(body || {}),
    });
  } finally {
    stateEpoch += 1;
  }
}
