// Contract model for the X3's real Cards V1 and Inbox V2 HTTP clients.
//
// The production clients cannot be imported into a browser: they are tightly
// coupled to ArduinoJson, SecureHttpClient, WiFi, HalStorage and mbedTLS. This
// module mirrors only their externally observable protocol and transaction
// seams while the C++ host tests continue to execute the shared pure firmware
// policies themselves. All requests are same-origin localhost fixture calls.

export const SIM_READ_TOKEN = "synthetic-read-token";
export const DIRECT_PAGE_CHANGES = 8;
export const MAX_PAGES_PER_WAKE = 10;
export const MAX_INBOX_ITEMS = 64;
export const MAX_SYNC_BODY_BYTES = 28 * 1024;
export const MAX_MANIFEST_BYTES = 8 * 1024;
export const MAX_CARD_BYTES = 16 * 1024;
export const MAX_REPORT_BYTES = 24 * 1024;
export const MAX_ARTIFACT_BYTES = 20 * 1024 * 1024;
export const MAX_OUTBOX_EVENTS = 48;
export const MAX_OUTBOX_BYTES = 32 * 1024;
export const MAX_OUTBOX_EVENT_LINE_BYTES = 1536;
export const MAX_ACK_EVENTS = 24;
export const MAX_DEVICE_ACK_JSON_BYTES = 4 * 1024;
export const MAX_SYNTHETIC_LATENCY_MS = 1500;
export const MAX_SYNTHETIC_INTERRUPT_BYTES = 64 * 1024;
export const SYNTHETIC_INTERRUPT_TARGETS = Object.freeze([
  "none", "manifest", "card", "report", "sync", "artifact", "ack"
]);
export const V1_TASK_IDS = Object.freeze([
  "market-briefing",
  "weekday-freelancer-scan",
  "3d-job-search",
  "outlook-attention-watch"
]);

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const ACTION_EVENTS = Object.freeze({
  opened: "opened",
  keep: "kept",
  archive: "archived",
  done: "done",
  defer: "deferred",
  "open-phone": "open-phone",
  delete: "deleted",
  like: "like",
  dislike: "dislike"
});
const KIND_MIMES = Object.freeze({
  card: new Set(["text/plain", "text/plain; charset=utf-8"]),
  text: new Set(["text/plain", "text/plain; charset=utf-8"]),
  action: new Set(["text/plain", "text/plain; charset=utf-8"]),
  "image-1bit": new Set(["image/bmp"]),
  "sleep-screen": new Set(["image/bmp"]),
  epub: new Set(["application/epub+zip"])
});

export class NetworkContractError extends Error {
  constructor(result, message) {
    super(message);
    this.name = "NetworkContractError";
    this.result = result;
  }
}

export function normalizeSyntheticNetworkOverrides(value = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Synthetic overrides must be an object");
  }
  const allowed = ["latency_ms", "interrupt_target", "interrupt_after_bytes"];
  if (Object.keys(value).some(key => !allowed.includes(key))) {
    throw new Error("Synthetic overrides contain unsupported fields");
  }
  const latency = value.latency_ms ?? 0;
  const target = value.interrupt_target ?? "none";
  const afterBytes = value.interrupt_after_bytes ?? 1024;
  if (!Number.isInteger(latency) || latency < 0 || latency > MAX_SYNTHETIC_LATENCY_MS) {
    throw new Error(`Synthetic latency must be 0-${MAX_SYNTHETIC_LATENCY_MS} ms`);
  }
  if (!SYNTHETIC_INTERRUPT_TARGETS.includes(target)) {
    throw new Error("Synthetic interruption target is not allowed");
  }
  if (!Number.isInteger(afterBytes) || afterBytes < 1 || afterBytes > MAX_SYNTHETIC_INTERRUPT_BYTES) {
    throw new Error(`Synthetic interruption must occur after 1-${MAX_SYNTHETIC_INTERRUPT_BYTES} bytes`);
  }
  return { latency_ms: latency, interrupt_target: target, interrupt_after_bytes: afterBytes };
}

function syntheticRequestTarget(pathname, method) {
  if (method === "POST" && pathname === "/mock/v2/acks") return "ack";
  if (method !== "GET") return "none";
  if (pathname === "/mock/v1/manifest.json") return "manifest";
  if (/^\/mock\/v1\/cards\/[^/]+\.json$/.test(pathname)) return "card";
  if (/^\/mock\/v1\/reports\/[^/]+\/[^/]+\.txt$/.test(pathname)) return "report";
  if (pathname === "/mock/v2/sync") return "sync";
  if (/^\/mock\/v2\/artifacts\/[0-9a-f]{64}$/.test(pathname)) return "artifact";
  return "none";
}

function safeSyntheticPath(input) {
  if (typeof input !== "string" || !input.startsWith("/mock/")) {
    throw new NetworkContractError("NETWORK_ERROR", "Synthetic transport blocked a non-loopback fixture URL");
  }
  const parsed = new URL(input, "http://x3-simulator.invalid");
  if (parsed.origin !== "http://x3-simulator.invalid" || !parsed.pathname.startsWith("/mock/")) {
    throw new NetworkContractError("NETWORK_ERROR", "Synthetic transport blocked a non-loopback fixture URL");
  }
  return parsed;
}

// Browser-only fault injection around the existing same-origin /mock contract.
// It deliberately has no URL override: every request is rejected unless it is
// one of the simulator's relative, loopback fixture paths.
export class SyntheticNetworkController {
  constructor(fetchImpl = globalThis.fetch.bind(globalThis)) {
    if (typeof fetchImpl !== "function") throw new Error("Synthetic transport requires fetch");
    this.fetchImpl = fetchImpl;
    this.overrides = normalizeSyntheticNetworkOverrides();
    this.interrupted = false;
  }

  configure(value) {
    this.overrides = normalizeSyntheticNetworkOverrides(value);
    this.interrupted = false;
    return this.status();
  }

  resetAttempt() {
    this.interrupted = false;
  }

  status() {
    return { ...this.overrides, interruption_consumed: this.interrupted };
  }

  async fetch(input, init = {}) {
    const parsed = safeSyntheticPath(input);
    const method = String(init.method || "GET").toUpperCase();
    if (this.overrides.latency_ms) {
      await new Promise(resolve => setTimeout(resolve, this.overrides.latency_ms));
    }
    const response = await this.fetchImpl(input, { ...init, redirect: "error" });
    const target = syntheticRequestTarget(parsed.pathname, method);
    if (
      this.interrupted || this.overrides.interrupt_target === "none" ||
      target !== this.overrides.interrupt_target || !response.ok
    ) return response;

    const body = new Uint8Array(await response.arrayBuffer());
    if (body.byteLength < 2) {
      return new Response(body, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers
      });
    }
    const end = Math.min(this.overrides.interrupt_after_bytes, body.byteLength - 1);
    const responseHeaders = new Headers(response.headers);
    if (!responseHeaders.has("content-length")) responseHeaders.set("content-length", String(body.byteLength));
    this.interrupted = true;
    return new Response(body.slice(0, end), {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });
  }
}

function byteLength(value) {
  return textEncoder.encode(String(value)).length;
}

function assertContract(condition, message) {
  if (!condition) throw new NetworkContractError("INVALID_DATA", message);
}

function isSafeId(value) {
  return typeof value === "string" && /^[a-z0-9][a-z0-9-]{0,31}$/.test(value);
}

function isSha256(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function isRevision32(value) {
  return typeof value === "string" && /^[0-9a-f]{32}$/.test(value);
}

function isBoundedText(value, maximumBytes, allowEmpty = false) {
  return typeof value === "string" && (allowEmpty || value.length > 0) && byteLength(value) <= maximumBytes;
}

function isBoundedAscii(value, maximumBytes, allowEmpty = false) {
  return isBoundedText(value, maximumBytes, allowEmpty) && /^[\x20-\x7e]*$/.test(value);
}

export async function sha256Hex(bytes) {
  const view = bytes instanceof Uint8Array
    ? bytes
    : new Uint8Array(bytes.buffer || bytes, bytes.byteOffset || 0, bytes.byteLength);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", view);
  return [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, "0")).join("");
}

function headers(accept, extras = {}) {
  return {
    Accept: accept,
    Authorization: `Bearer ${SIM_READ_TOKEN}`,
    ...extras
  };
}

async function boundedBytes(response, maximum, label) {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && (!/^\d+$/.test(contentLength) || Number(contentLength) > maximum)) {
    throw new NetworkContractError("INVALID_DATA", `${label} Content-Length exceeded ${maximum} bytes`);
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > maximum) {
    throw new NetworkContractError("INVALID_DATA", `${label} exceeded ${maximum} bytes`);
  }
  return bytes;
}

function parseJsonBytes(bytes, label) {
  try {
    return JSON.parse(textDecoder.decode(bytes));
  } catch {
    throw new NetworkContractError("INVALID_DATA", `${label} was not valid UTF-8 JSON`);
  }
}

async function request(fetchImpl, url, options, label) {
  try {
    return await fetchImpl(url, options);
  } catch (error) {
    throw new NetworkContractError("NETWORK_ERROR", `${label} transport failed: ${error.message}`);
  }
}

function classifyHttp(response, label, expected = 200) {
  if (response.status === 401 || response.status === 403) {
    throw new NetworkContractError("UNAUTHORIZED", `${label} was unauthorized`);
  }
  if (response.status !== expected) {
    throw new NetworkContractError("NETWORK_ERROR", `${label} returned HTTP ${response.status}`);
  }
}

function validateDigest(value) {
  if (value == null) return null;
  assertContract(value && typeof value === "object" && !Array.isArray(value), "Inbox digest must be an object");
  assertContract(
    Object.keys(value).sort().join("|") === "points|schema|summary",
    "Inbox digest must have the exact v1 shape"
  );
  assertContract(value.schema === "xtinct.inbox-digest/v1", "Inbox digest schema is invalid");
  assertContract(isBoundedText(value.summary, 144), "Inbox digest summary exceeds 144 bytes");
  assertContract(Array.isArray(value.points) && value.points.length <= 2, "Inbox digest points exceed two");
  for (const point of value.points) assertContract(isBoundedText(point, 64), "Inbox digest point exceeds 64 bytes");
  return structuredClone(value);
}

function validateManifest(value, responseEtag) {
  assertContract(value && typeof value === "object" && !Array.isArray(value), "V1 manifest must be an object");
  assertContract(value.schema === 1 && isBoundedAscii(value.etag, 95), "V1 manifest schema or ETag is invalid");
  assertContract(!responseEtag || responseEtag === value.etag, "V1 response/body ETags differ");
  assertContract(
    Array.isArray(value.cards) && value.cards.length === V1_TASK_IDS.length,
    "V1 manifest must contain all four fixed card slots"
  );
  const seen = new Set();
  const cards = value.cards.map(reference => {
    assertContract(reference && typeof reference === "object", "V1 card reference must be an object");
    assertContract(V1_TASK_IDS.includes(reference.id) && !seen.has(reference.id), "V1 task ID is unknown or duplicated");
    assertContract(isRevision32(reference.revision), "V1 revision must be 32 lowercase hex characters");
    assertContract(reference.url === `/v1/cards/${reference.id}.json`, "V1 card URL is not canonical");
    seen.add(reference.id);
    return { id: reference.id, revision: reference.revision, url: reference.url };
  });
  return { schema: 1, etag: value.etag, cards };
}

function validateCard(value, expectedId, expectedRevision) {
  assertContract(value && typeof value === "object" && !Array.isArray(value), "V1 card must be an object");
  assertContract(value.schema === 1 && value.task_id === expectedId, "V1 card task identity differs from manifest");
  assertContract(value.revision === expectedRevision && isRevision32(value.revision), "V1 card revision differs from manifest");
  assertContract(isBoundedText(value.generated_at, 39), "V1 generated_at is invalid");
  assertContract(isBoundedText(value.title, 80) && isBoundedText(value.summary, 320), "V1 title or summary exceeds firmware storage");
  const metrics = value.metrics ?? [];
  assertContract(Array.isArray(metrics) && metrics.length <= 4, "V1 metrics exceed four");
  for (const metric of metrics) {
    assertContract(
      isBoundedText(metric?.label, 40, true) && isBoundedText(metric?.value, 80, true) &&
        isBoundedText(metric?.tone ?? "neutral", 7),
      "V1 metric exceeds firmware storage"
    );
  }
  const sections = value.sections ?? [];
  assertContract(Array.isArray(sections) && sections.length <= 3, "V1 sections exceed three");
  for (const section of sections) {
    assertContract(isBoundedText(section?.heading, 48, true), "V1 section heading exceeds firmware storage");
    assertContract(Array.isArray(section?.lines) && section.lines.length <= 4, "V1 section exceeds four lines");
    for (const line of section.lines) assertContract(isBoundedText(line, 240, true), "V1 line exceeds 240 bytes");
  }
  if (value.report != null) {
    assertContract(value.report && typeof value.report === "object" && !Array.isArray(value.report), "V1 report must be an object");
    assertContract(Object.keys(value.report).sort().join("|") === "bytes|sha256|url", "V1 report shape is invalid");
    assertContract(
      Number.isInteger(value.report.bytes) && value.report.bytes > 0 && value.report.bytes <= MAX_REPORT_BYTES &&
        isSha256(value.report.sha256) &&
        value.report.url === `/v1/reports/${expectedId}/${expectedRevision}.txt`,
      "V1 report identity is invalid"
    );
  }
  return structuredClone(value);
}

function validateDelivery(value) {
  assertContract(value && typeof value === "object" && !Array.isArray(value), "V2 delivery must be an object");
  assertContract(isSafeId(value.delivery_id) && isSafeId(value.item_id) && isSafeId(value.module_id), "V2 delivery IDs are invalid");
  assertContract(KIND_MIMES[value.kind]?.has(value.mime), "V2 kind/MIME pair is invalid");
  assertContract(isBoundedText(value.title, 120), "V2 title exceeds 120 bytes");
  assertContract(isSha256(value.revision) && isSha256(value.sha256), "V2 revision or artifact SHA is invalid");
  assertContract(Number.isInteger(value.bytes) && value.bytes > 0 && value.bytes <= MAX_ARTIFACT_BYTES, "V2 artifact size is invalid");
  assertContract(isBoundedAscii(value.created_at, 39), "V2 created_at is invalid");
  assertContract(value.expires_at == null || isBoundedAscii(value.expires_at, 39, true), "V2 expires_at is invalid");
  assertContract(Array.isArray(value.actions) && value.actions.length <= 5, "V2 actions exceed five");
  const seen = new Set();
  for (const action of value.actions) {
    assertContract(["keep", "archive", "done", "defer", "open-phone", "like", "dislike"].includes(action), "V2 action is invalid");
    assertContract(!seen.has(action), "V2 action is duplicated");
    seen.add(action);
  }
  const metadata = value.metadata ?? null;
  assertContract(metadata == null || (typeof metadata === "object" && !Array.isArray(metadata)), "V2 metadata must be an object");
  assertContract(byteLength(JSON.stringify(metadata ?? {})) <= 2048, "V2 metadata exceeds 2 KiB");
  const digest = validateDigest(metadata?.digest ?? null);
  assertContract(value.kind === "sleep-screen" || metadata?.activate !== true, "Only a sleep screen may request activation");
  return { ...structuredClone(value), digest, state: "new" };
}

function validateTombstone(value) {
  assertContract(value && typeof value === "object" && !Array.isArray(value), "V2 tombstone must be an object");
  assertContract(isSafeId(value.delivery_id) && isSafeId(value.item_id), "V2 tombstone IDs are invalid");
  assertContract(isSha256(value.revision) && isBoundedAscii(value.deleted_at, 39), "V2 tombstone revision/date is invalid");
  return structuredClone(value);
}

function validateSyncPage(value) {
  assertContract(value && typeof value === "object" && !Array.isArray(value), "V2 page must be an object");
  assertContract(value.schema === 2 && isSafeId(value.device_id), "V2 page schema/device is invalid");
  assertContract(typeof value.cursor === "string" && /^\d{1,23}$/.test(value.cursor), "V2 cursor must be decimal");
  assertContract(Array.isArray(value.deliveries) && Array.isArray(value.tombstones), "V2 page arrays are missing");
  assertContract(
    value.deliveries.length <= DIRECT_PAGE_CHANGES && value.tombstones.length <= DIRECT_PAGE_CHANGES &&
      value.deliveries.length + value.tombstones.length <= DIRECT_PAGE_CHANGES,
    "V2 page exceeds the direct X3 eight-change cap"
  );
  const deliveries = value.deliveries.map(validateDelivery);
  assertContract(new Set(deliveries.map(item => item.item_id)).size === deliveries.length, "V2 page repeats an item ID");
  return {
    schema: 2,
    deviceId: value.device_id,
    cursor: value.cursor,
    hasMore: Boolean(value.has_more),
    deliveries,
    tombstones: value.tombstones.map(validateTombstone)
  };
}

function digestEqual(first, second) {
  return JSON.stringify(first ?? null) === JSON.stringify(second ?? null);
}

function sortedInbox(metadata) {
  return [...metadata.values()].sort((first, second) => {
    const dateOrder = String(second.created_at).localeCompare(String(first.created_at));
    return dateOrder || String(second.item_id).localeCompare(String(first.item_id));
  });
}

function little16(bytes, offset) {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function little32(bytes, offset) {
  return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) |
    (bytes[offset + 3] << 24)) >>> 0;
}

export function textFromStoredEpub(bytes) {
  let offset = 0;
  while (offset + 30 <= bytes.length && little32(bytes, offset) === 0x04034b50) {
    const flags = little16(bytes, offset + 6);
    const method = little16(bytes, offset + 8);
    const compressedBytes = little32(bytes, offset + 18);
    const nameBytes = little16(bytes, offset + 26);
    const extraBytes = little16(bytes, offset + 28);
    const nameStart = offset + 30;
    const dataStart = nameStart + nameBytes + extraBytes;
    const dataEnd = dataStart + compressedBytes;
    assertContract((flags & 0x08) === 0 && dataEnd <= bytes.length, "EPUB fixture uses an unsupported ZIP descriptor");
    const name = textDecoder.decode(bytes.subarray(nameStart, nameStart + nameBytes));
    if (/\.xhtml?$/i.test(name)) {
      assertContract(method === 0, "EPUB fixture XHTML must be stored for bounded browser inspection");
      const markup = textDecoder.decode(bytes.subarray(dataStart, dataEnd));
      return markup
        .replace(/<script[\s\S]*?<\/script>/gi, " ")
        .replace(/<style[\s\S]*?<\/style>/gi, " ")
        .replace(/<[^>]+>/g, " ")
        .replace(/&nbsp;/gi, " ")
        .replace(/&amp;/gi, "&")
        .replace(/&lt;/gi, "<")
        .replace(/&gt;/gi, ">")
        .replace(/\s+/g, " ")
        .trim();
    }
    offset = dataEnd;
  }
  throw new NetworkContractError("INVALID_DATA", "EPUB fixture has no readable XHTML spine document");
}

export class X3NetworkModel {
  constructor(fetchImpl = globalThis.fetch.bind(globalThis), baseUrl = "/mock") {
    this.fetch = fetchImpl;
    this.baseUrl = baseUrl;
    this.reset();
  }

  reset() {
    this.environmentScenario = "happy-path";
    this.cardManifest = null;
    this.cardEtag = "";
    this.cardCache = new Map();
    this.reportCache = new Map();
    this.inboxMetadata = new Map();
    this.artifacts = new Map();
    this.cursor = "0";
    this.deviceId = "sim-x3-main";
    this.eventSequence = 0;
    this.outbox = [];
    this.attemptDay = 0;
    this.freshDay = 0;
    this.inboxCompleteToday = false;
    this.last = { cards: "NOT_RUN", inbox: "NOT_RUN", receipts: "CURRENT", pages: 0 };
  }

  setEnvironmentScenario(scenario) {
    this.environmentScenario = scenario || "happy-path";
  }

  _cachedCardsValid(manifest = this.cardManifest) {
    if (!manifest || manifest.etag !== this.cardEtag) return false;
    return manifest.cards.every(reference => {
      const card = this.cardCache.get(reference.id);
      if (!card || card.revision !== reference.revision) return false;
      if (!card.report) return true;
      const report = this.reportCache.get(`${reference.id}:${reference.revision}`);
      return report && report.byteLength === card.report.bytes && report.sha256 === card.report.sha256;
    });
  }

  async syncCards() {
    let requestEtag = this.cardEtag;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const requestHeaders = headers("application/json");
      if (attempt === 0 && requestEtag) requestHeaders["If-None-Match"] = requestEtag;
      const response = await request(
        this.fetch,
        `${this.baseUrl}/v1/manifest.json`,
        { headers: requestHeaders },
        "V1 manifest"
      );
      if (response.status === 304) {
        if (attempt === 0 && requestEtag && this._cachedCardsValid()) {
          this.last.cards = "NOT_MODIFIED";
          return { result: "NOT_MODIFIED", cards: this.cards(), requests: attempt + 1 };
        }
        if (attempt !== 0 || !requestEtag) {
          throw new NetworkContractError("INVALID_DATA", "304 did not reference a usable V1 cache");
        }
        this.cardEtag = "";
        requestEtag = "";
        continue;
      }
      classifyHttp(response, "V1 manifest");
      const manifestBytes = await boundedBytes(response, MAX_MANIFEST_BYTES, "V1 manifest");
      const manifest = validateManifest(parseJsonBytes(manifestBytes, "V1 manifest"), response.headers.get("etag") ?? "");
      const stagedCards = new Map();
      const stagedReports = new Map();
      for (const reference of manifest.cards) {
        let card = this.cardCache.get(reference.id);
        let report = this.reportCache.get(`${reference.id}:${reference.revision}`);
        const unchanged = card?.revision === reference.revision &&
          (!card.report || (report?.byteLength === card.report.bytes && report?.sha256 === card.report.sha256));
        if (!unchanged) {
          const cardResponse = await request(
            this.fetch,
            `${this.baseUrl}${reference.url}?revision=${encodeURIComponent(reference.revision)}`,
            { headers: headers("application/json") },
            `V1 card ${reference.id}`
          );
          classifyHttp(cardResponse, `V1 card ${reference.id}`);
          const cardBytes = await boundedBytes(cardResponse, MAX_CARD_BYTES, `V1 card ${reference.id}`);
          card = validateCard(parseJsonBytes(cardBytes, `V1 card ${reference.id}`), reference.id, reference.revision);
          report = undefined;
          if (card.report) {
            const reportResponse = await request(
              this.fetch,
              `${this.baseUrl}${card.report.url}`,
              { headers: headers("text/plain; charset=utf-8") },
              `V1 report ${reference.id}`
            );
            classifyHttp(reportResponse, `V1 report ${reference.id}`);
            const reportBytes = await boundedBytes(reportResponse, MAX_REPORT_BYTES, `V1 report ${reference.id}`);
            assertContract(reportBytes.byteLength === card.report.bytes, "V1 report byte count differs from card");
            const reportSha = await sha256Hex(reportBytes);
            assertContract(reportSha === card.report.sha256, "V1 report SHA-256 differs from card");
            report = { bytes: reportBytes, byteLength: reportBytes.byteLength, sha256: reportSha };
          }
        }
        stagedCards.set(reference.id, card);
        if (report) stagedReports.set(`${reference.id}:${reference.revision}`, report);
      }
      // Commit only after the complete manifest/card/report transaction passes.
      this.cardManifest = manifest;
      this.cardEtag = manifest.etag;
      this.cardCache = stagedCards;
      this.reportCache = stagedReports;
      this.last.cards = "UPDATED";
      return { result: "UPDATED", cards: this.cards(), requests: attempt + 1 };
    }
    throw new NetworkContractError("INVALID_DATA", "V1 recovery request limit was exceeded");
  }

  cards() {
    return V1_TASK_IDS.filter(id => this.cardCache.has(id)).map(id => {
      const card = this.cardCache.get(id);
      return {
        taskId: card.task_id,
        revision: card.revision,
        generatedAt: card.generated_at,
        title: card.title,
        summary: card.summary,
        priority: Math.min(Number(card.priority || 0), 3),
        status: card.state || "ok",
        metrics: structuredClone(card.metrics || []),
        sections: structuredClone(card.sections || []),
        hasReport: Boolean(card.report)
      };
    });
  }

  _queueEvent(item, action, data = {}) {
    const type = ACTION_EVENTS[action] || action;
    assertContract(
      ["downloaded", "opened", "failed", "kept", "archived", "done", "deferred", "progress", "open-phone", "deleted", "like", "dislike", "device-status"].includes(type),
      "Receipt type is not accepted by firmware"
    );
    const sequence = this.eventSequence + 1;
    const event = {
      event_id: `${this.deviceId}-1786492800-${sequence}`,
      item_id: item.item_id,
      revision: item.revision,
      type,
      occurred_at: "2026-08-12T08:00:00Z",
      data: structuredClone(data)
    };
    const lineBytes = byteLength(JSON.stringify(event));
    const existingBytes = this.outbox.reduce((total, candidate) => total + byteLength(JSON.stringify(candidate)) + 1, 0);
    if (
      this.outbox.length >= MAX_OUTBOX_EVENTS || lineBytes > MAX_OUTBOX_EVENT_LINE_BYTES ||
      existingBytes + lineBytes + 1 > MAX_OUTBOX_BYTES
    ) return false;
    this.eventSequence = sequence;
    this.outbox.push(event);
    return true;
  }

  async flushOutbox() {
    if (!this.outbox.length) {
      this.last.receipts = "CURRENT";
      return { result: "CURRENT", sent: 0, remaining: 0 };
    }
    let count = 0;
    let payload = null;
    for (let candidate = 1; candidate <= Math.min(MAX_ACK_EVENTS, this.outbox.length); candidate += 1) {
      const next = { schema: 2, events: this.outbox.slice(0, candidate) };
      if (byteLength(JSON.stringify(next)) > MAX_DEVICE_ACK_JSON_BYTES) break;
      count = candidate;
      payload = next;
    }
    if (!payload || count === 0) {
      this.last.receipts = "OUTBOX_INVALID";
      return { result: "OUTBOX_INVALID", sent: 0, remaining: this.outbox.length };
    }
    let response;
    try {
      response = await request(
        this.fetch,
        `${this.baseUrl}/v2/acks`,
        {
          method: "POST",
          headers: headers("application/json", { "Content-Type": "application/json" }),
          body: JSON.stringify(payload)
        },
        "V2 receipts"
      );
      classifyHttp(response, "V2 receipts");
      const responseBytes = await boundedBytes(response, 1024, "V2 receipt response");
      const result = parseJsonBytes(responseBytes, "V2 receipt response");
      const represented = Number(result.accepted || 0) + Number(result.duplicates || 0) + Number(result.rejected || 0);
      assertContract(result.schema === 2 && represented === count, "V2 receipt response did not represent the sent prefix");
    } catch (error) {
      // ACKs are best effort. Keep the exact durable prefix for an idempotent retry.
      this.last.receipts = error.result || "NETWORK_ERROR";
      return { result: this.last.receipts, sent: 0, remaining: this.outbox.length };
    }
    this.outbox.splice(0, count);
    this.last.receipts = "UPDATED";
    return { result: "UPDATED", sent: count, remaining: this.outbox.length };
  }

  async _downloadArtifact(item) {
    const response = await request(
      this.fetch,
      `${this.baseUrl}/v2/artifacts/${item.sha256}`,
      { headers: headers(item.mime) },
      `V2 artifact ${item.item_id}`
    );
    classifyHttp(response, `V2 artifact ${item.item_id}`);
    const contentLength = response.headers.get("content-length");
    assertContract(contentLength !== null && Number(contentLength) === item.bytes, "V2 artifact Content-Length differs from delivery");
    assertContract(response.headers.get("content-type") === item.mime, "V2 artifact Content-Type differs from delivery");
    assertContract(response.headers.get("etag") === `"${item.sha256}"`, "V2 artifact ETag differs from delivery SHA");
    assertContract(response.headers.get("x-content-type-options") === "nosniff", "V2 artifact lacks nosniff");
    const bytes = await boundedBytes(response, MAX_ARTIFACT_BYTES, `V2 artifact ${item.item_id}`);
    assertContract(bytes.byteLength === item.bytes, "V2 artifact byte count differs from delivery");
    assertContract(await sha256Hex(bytes) === item.sha256, "V2 artifact SHA-256 differs from delivery");
    if (item.kind === "epub") {
      assertContract(bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 3 && bytes[3] === 4, "EPUB artifact lacks ZIP header");
    } else if (["text", "card", "action"].includes(item.kind)) {
      try { textDecoder.decode(bytes); } catch { throw new NetworkContractError("INVALID_DATA", "Text artifact is not valid UTF-8"); }
    }
    return { bytes, byteLength: bytes.byteLength, sha256: item.sha256, mime: item.mime };
  }

  async syncInbox() {
    await this.flushOutbox(); // Best effort and deliberately non-blocking.
    let changed = false;
    let fullyCaughtUp = false;
    let downloadReceiptsAvailable = true;
    let pages = 0;
    for (let pageIndex = 0; pageIndex < MAX_PAGES_PER_WAKE; pageIndex += 1) {
      const response = await request(
        this.fetch,
        `${this.baseUrl}/v2/sync?cursor=${encodeURIComponent(this.cursor)}&limit=${DIRECT_PAGE_CHANGES}`,
        { headers: headers("application/json") },
        "V2 sync"
      );
      classifyHttp(response, "V2 sync");
      const pageBytes = await boundedBytes(response, MAX_SYNC_BODY_BYTES, "V2 sync page");
      const page = validateSyncPage(parseJsonBytes(pageBytes, "V2 sync page"));
      pages += 1;
      this.deviceId = page.deviceId;
      for (const item of page.deliveries) {
        const cached = this.inboxMetadata.get(item.item_id);
        const artifact = this.artifacts.get(item.sha256);
        const sameMetadata = cached && cached.revision === item.revision && cached.sha256 === item.sha256 &&
          digestEqual(cached.digest, item.digest);
        const validArtifact = artifact && artifact.byteLength === item.bytes && artifact.sha256 === item.sha256;
        if (!sameMetadata || !validArtifact) {
          let downloaded;
          try {
            downloaded = await this._downloadArtifact(item);
          } catch (error) {
            this._queueEvent(item, "failed", { reason: "artifact-download" });
            this.last.inbox = error.result || "NETWORK_ERROR";
            this.last.pages = pages;
            throw error;
          }
          // Artifact and metadata become visible together before cursor advance.
          this.artifacts.set(item.sha256, downloaded);
          this.inboxMetadata.set(item.item_id, item);
          if (downloadReceiptsAvailable && !this._queueEvent(item, "downloaded")) downloadReceiptsAvailable = false;
          changed = true;
        }
      }
      for (const tombstone of page.tombstones) {
        const cached = this.inboxMetadata.get(tombstone.item_id);
        if (cached?.revision === tombstone.revision) {
          this.inboxMetadata.delete(tombstone.item_id);
          changed = true;
        }
      }
      // Mirrors firmware durability: every complete page advances its own cursor.
      this.cursor = page.cursor;
      if (!page.hasMore) {
        fullyCaughtUp = true;
        break;
      }
    }
    this.inboxCompleteToday = fullyCaughtUp;
    this.last.inbox = fullyCaughtUp ? (changed ? "UPDATED" : "CURRENT") : "CATCH_UP_PENDING";
    this.last.pages = pages;
    this._queueEvent(
      { item_id: "device-status", revision: "0".repeat(64) },
      "device-status",
      { battery_percent: 83, free_sd_bytes: 1024 * 1024 * 1024, result: this.last.inbox }
    );
    await this.flushOutbox();
    return {
      result: this.last.inbox,
      cursor: this.cursor,
      pages,
      complete: fullyCaughtUp,
      inbox: this.inbox()
    };
  }

  inbox() {
    // Match the firmware's bounded over-capacity fallback: retain visibility
    // of the newest 64 instead of presenting an empty Inbox.
    return sortedInbox(this.inboxMetadata).slice(0, MAX_INBOX_ITEMS).map(item => ({
      deliveryId: item.delivery_id,
      itemId: item.item_id,
      moduleId: item.module_id,
      kind: item.kind,
      title: item.title,
      revision: item.revision,
      sha256: item.sha256,
      bytes: item.bytes,
      mime: item.mime,
      createdAt: item.created_at,
      state: item.state || "new",
      actions: structuredClone(item.actions || []),
      digest: structuredClone(item.digest)
    }));
  }

  applyInboxAction(itemId, action) {
    const item = this.inboxMetadata.get(itemId);
    if (!item || !ACTION_EVENTS[action]) return { queued: false, local: false };
    const data = action === "defer" ? { until: "2026-08-13T08:00:00Z" } : {};
    const queued = this._queueEvent(item, action, data);
    if (action !== "delete" && !queued) return { queued: false, local: false };
    if (["delete", "archive", "done", "like", "dislike"].includes(action)) {
      // Delete is always local. The other terminal actions remove only after
      // their receipt has been durably queued, exactly like InboxActivity.
      this.inboxMetadata.delete(itemId);
      return { queued, local: true };
    }
    if (action === "keep") item.state = "kept";
    if (action === "defer") item.state = "deferred";
    return { queued, local: true };
  }

  recordOpenedBestEffort(itemId) {
    const item = this.inboxMetadata.get(itemId);
    return item ? this._queueEvent(item, "opened") : false;
  }

  artifact(itemId) {
    const item = this.inboxMetadata.get(itemId);
    return item ? this.artifacts.get(item.sha256) ?? null : null;
  }

  documentText(itemId) {
    const item = this.inboxMetadata.get(itemId);
    const artifact = item ? this.artifacts.get(item.sha256) : null;
    if (!item || !artifact) return "Downloaded content is unavailable.";
    if (item.kind === "epub") return textFromStoredEpub(artifact.bytes);
    if (["text", "card", "action"].includes(item.kind)) return textDecoder.decode(artifact.bytes);
    return `Verified ${item.kind} artifact · ${artifact.byteLength} bytes · SHA-256 ${artifact.sha256}`;
  }

  reportText(taskId) {
    const card = this.cardCache.get(taskId);
    if (!card?.report) return "No full report is attached to this card.";
    const report = this.reportCache.get(`${taskId}:${card.revision}`);
    return report ? textDecoder.decode(report.bytes) : "The full report is unavailable.";
  }

  async runDailyRefresh(currentDay, { manual = false } = {}) {
    assertContract(Number.isInteger(currentDay) && currentDay > 0, "Current synthetic day must be known");
    if (!manual && (this.attemptDay === currentDay || this.freshDay === currentDay)) {
      return { result: "CACHE_FIRST", requested: false, cards: this.last.cards, inbox: this.last.inbox };
    }
    this.attemptDay = currentDay;
    this.freshDay = 0;
    if (this.environmentScenario === "no-config") {
      this.last.cards = "NO_CONFIG";
      this.last.inbox = "NOT_RUN";
      return { result: "NO_CONFIG", requested: true, cards: "NO_CONFIG", inbox: "NOT_RUN" };
    }
    if (this.environmentScenario === "no-wifi") {
      this.last.cards = "NO_WIFI";
      this.last.inbox = "NOT_RUN";
      return { result: "NO_WIFI", requested: true, cards: "NO_WIFI", inbox: "NOT_RUN" };
    }
    if (this.environmentScenario === "clock-error") {
      this.last.cards = "CLOCK_ERROR";
      this.last.inbox = "NOT_RUN";
      return { result: "CLOCK_ERROR", requested: true, cards: "CLOCK_ERROR", inbox: "NOT_RUN" };
    }
    if (this.environmentScenario === "storage-error") {
      this.last.cards = "STORAGE_ERROR";
      this.last.inbox = "NOT_RUN";
      throw new NetworkContractError("STORAGE_ERROR", "Local recovery/storage preflight failed");
    }
    const cards = await this.syncCards();
    const inbox = await this.syncInbox();
    if (["UPDATED", "NOT_MODIFIED"].includes(cards.result) && inbox.complete) this.freshDay = currentDay;
    return { result: this.freshDay === currentDay ? "FRESH" : "PARTIAL", requested: true, cards, inbox };
  }

  status() {
    return {
      ...this.last,
      cursor: this.cursor,
      cardsCached: this.cardCache.size,
      inboxCached: this.inboxMetadata.size,
      artifactsCached: this.artifacts.size,
      outboxEvents: this.outbox.length,
      attemptDay: this.attemptDay,
      freshDay: this.freshDay,
      inboxCompleteToday: this.inboxCompleteToday
    };
  }
}
