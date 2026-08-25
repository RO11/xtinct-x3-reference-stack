import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import worker from "../src/index.js";
import { sha256Hex } from "../src/contract.js";

const readValue = "read-reference-value-0000000000000001";
const writeValue = "write-reference-value-000000000000001";

class D1Statement {
  constructor(owner, sql, values = []) {
    this.owner = owner;
    this.sql = sql;
    this.values = values;
  }

  bind(...values) {
    return new D1Statement(this.owner, this.sql, values);
  }

  async first() {
    return this.owner.database.prepare(this.sql).get(...this.values) ?? null;
  }

  async all() {
    return { results: this.owner.database.prepare(this.sql).all(...this.values) };
  }

  async run() {
    return this.owner.execute(this);
  }
}

class MemoryD1 {
  constructor(migration) {
    this.database = new DatabaseSync(":memory:");
    this.database.exec(migration);
  }

  prepare(sql) {
    return new D1Statement(this, sql);
  }

  execute(statement) {
    const result = this.database.prepare(statement.sql).run(...statement.values);
    return { success: true, meta: { changes: Number(result.changes) } };
  }

  async batch(statements) {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const results = statements.map((statement) => this.execute(statement));
      this.database.exec("COMMIT");
      return results;
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }
}

class MemoryR2 {
  constructor() {
    this.objects = new Map();
  }

  async put(key, value, options = {}) {
    let bytes;
    if (value instanceof Uint8Array) bytes = new Uint8Array(value);
    else if (value instanceof ArrayBuffer) bytes = new Uint8Array(value.slice(0));
    else if (typeof value === "string") bytes = new TextEncoder().encode(value);
    else throw new TypeError("unsupported MemoryR2 value");
    this.objects.set(key, { bytes, options });
    return { key, size: bytes.byteLength };
  }

  async get(key) {
    const stored = this.objects.get(key);
    if (!stored) return null;
    const bytes = new Uint8Array(stored.bytes);
    return {
      key,
      size: bytes.byteLength,
      body: new Blob([bytes]).stream(),
    };
  }
}

async function environment() {
  const migration = await readFile(new URL("../migrations/0001_initial.sql", import.meta.url), "utf8");
  return {
    DB: new MemoryD1(migration),
    ARTIFACTS: new MemoryR2(),
    READ_TOKEN: readValue,
    WRITE_TOKEN: writeValue,
    DEVICE_ID: "x3-reference",
  };
}

function request(path, token, init = {}) {
  const headers = new Headers(init.headers ?? {});
  if (token) headers.set("Authorization", `Bearer ${token}`);
  return new Request(`https://xtinct-feed-reference.example.invalid${path}`, { ...init, headers });
}

async function fetchWorker(env, path, token, init = {}) {
  return worker.fetch(request(path, token, init), env, {});
}

test("health is public while feed and admin routes use separate bearer tokens", async () => {
  const env = await environment();
  assert.equal((await fetchWorker(env, "/healthz", null)).status, 200);
  assert.equal((await fetchWorker(env, "/v1/manifest.json", null)).status, 401);
  assert.equal((await fetchWorker(env, "/admin/v2/acks", readValue)).status, 401);
  assert.equal((await fetchWorker(env, "/admin/v2/acks", writeValue)).status, 200);
});

test("V1 publication yields an exact immutable revision and conditional manifest", async () => {
  const env = await environment();
  const card = JSON.parse(await readFile(new URL("../examples/v1-card.json", import.meta.url), "utf8"));
  const published = await fetchWorker(env, "/admin/v1/cards/market-briefing", writeValue, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(card),
  });
  assert.equal(published.status, 201);
  const identity = await published.json();
  assert.match(identity.revision, /^[0-9a-f]{32}$/);

  const manifestResponse = await fetchWorker(env, "/v1/manifest.json", readValue);
  assert.equal(manifestResponse.status, 200);
  const etag = manifestResponse.headers.get("etag");
  const manifest = await manifestResponse.json();
  assert.equal(manifest.schema, 1);
  assert.equal(manifest.etag, etag);
  assert.deepEqual(manifest.cards, [{
    id: "market-briefing",
    revision: identity.revision,
    url: "/v1/cards/market-briefing.json",
  }]);

  const current = await fetchWorker(env, `/v1/cards/market-briefing.json?revision=${identity.revision}`, readValue);
  assert.equal(current.status, 200);
  const currentBody = await current.json();
  assert.equal(currentBody.revision, identity.revision);

  const report = await fetchWorker(env, currentBody.report.url, readValue);
  assert.equal(report.status, 200);
  assert.equal(report.headers.get("content-length"), String(currentBody.report.bytes));
  assert.equal(report.headers.get("etag"), `"${currentBody.report.sha256}"`);
  assert.equal(await report.text(), card.report_text);

  const notModified = await fetchWorker(env, "/v1/manifest.json", readValue, { headers: { "If-None-Match": etag } });
  assert.equal(notModified.status, 304);
});

test("V2 upload, delivery, paging, artifact headers, feedback dedupe and tombstone interoperate", async () => {
  const env = await environment();
  const artifactBytes = new TextEncoder().encode("REFERENCE ARTICLE\n\nA small fictional artifact.");
  const digest = await sha256Hex(artifactBytes);
  const uploaded = await fetchWorker(env, `/admin/v2/artifacts/${digest}?kind=text`, writeValue, {
    method: "PUT",
    headers: { "Content-Type": "text/plain; charset=utf-8" },
    body: artifactBytes,
  });
  assert.equal(uploaded.status, 201);

  const deliveryInput = {
    delivery_id: "reference-delivery-001",
    item_id: "reference-article-001",
    module_id: "daily-fiction",
    kind: "text",
    title: "Reference serial: The Quiet Relay",
    sha256: digest,
    mime: "text/plain; charset=utf-8",
    actions: ["like", "dislike", "archive"],
    metadata: {
      digest: {
        schema: "xtinct.inbox-digest/v1",
        summary: "A fictional e-ink serial used only for contract testing.",
        points: ["Short daily reading.", "Feedback is returned as receipts."],
      },
    },
  };
  const published = await fetchWorker(env, "/admin/v2/deliveries", writeValue, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(deliveryInput),
  });
  assert.equal(published.status, 201);
  const identity = await published.json();
  assert.match(identity.revision, /^[0-9a-f]{64}$/);

  const pageResponse = await fetchWorker(env, "/v2/sync?cursor=0&limit=8", readValue);
  assert.equal(pageResponse.status, 200);
  const page = await pageResponse.json();
  assert.equal(page.schema, 2);
  assert.equal(page.device_id, "x3-reference");
  assert.equal(page.deliveries.length, 1);
  assert.equal(page.tombstones.length, 0);
  assert.equal(page.deliveries[0].revision, identity.revision);
  assert.equal(page.has_more, false);

  const artifact = await fetchWorker(env, `/v2/artifacts/${digest}`, readValue);
  assert.equal(artifact.status, 200);
  assert.equal(artifact.headers.get("content-type"), "text/plain; charset=utf-8");
  assert.equal(artifact.headers.get("content-length"), String(artifactBytes.byteLength));
  assert.equal(artifact.headers.get("etag"), `"${digest}"`);
  assert.equal(artifact.headers.get("x-content-type-options"), "nosniff");
  assert.deepEqual(new Uint8Array(await artifact.arrayBuffer()), artifactBytes);

  const event = {
    event_id: "x3-reference-1760000000-1",
    item_id: deliveryInput.item_id,
    revision: identity.revision,
    type: "like",
    occurred_at: "2026-01-15T00:00:00Z",
    data: {},
  };
  const sendAcks = () => fetchWorker(env, "/v2/acks", readValue, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ schema: 2, events: [event] }),
  });
  assert.deepEqual(await (await sendAcks()).json(), { schema: 2, accepted: 1, duplicates: 0, rejected: 0 });
  assert.deepEqual(await (await sendAcks()).json(), { schema: 2, accepted: 0, duplicates: 1, rejected: 0 });

  const feedback = await fetchWorker(env, "/admin/v2/acks?limit=10", writeValue);
  const feedbackBody = await feedback.json();
  assert.equal(feedbackBody.events.length, 1);
  assert.equal(feedbackBody.events[0].type, "like");

  const removed = await fetchWorker(env, `/admin/v2/deliveries/${deliveryInput.item_id}`, writeValue, { method: "DELETE" });
  assert.equal(removed.status, 200);
  const next = await fetchWorker(env, `/v2/sync?cursor=${page.cursor}&limit=8`, readValue);
  const nextPage = await next.json();
  assert.equal(nextPage.deliveries.length, 0);
  assert.equal(nextPage.tombstones.length, 1);
  assert.equal(nextPage.tombstones[0].revision, identity.revision);
});

test("V2 compacts rapid republishes so one sync page never repeats an item_id", async () => {
  const env = await environment();
  const artifactBytes = new TextEncoder().encode("A reusable public test artifact.");
  const digest = await sha256Hex(artifactBytes);
  assert.equal((await fetchWorker(env, `/admin/v2/artifacts/${digest}?kind=text`, writeValue, {
    method: "PUT",
    headers: { "Content-Type": "text/plain" },
    body: artifactBytes,
  })).status, 201);

  const base = {
    delivery_id: "rapid-delivery-001",
    item_id: "rapid-article-001",
    module_id: "reference-module",
    kind: "text",
    sha256: digest,
    mime: "text/plain",
    actions: ["archive"],
    metadata: {},
  };
  for (const title of ["First pending title", "Second pending title"]) {
    const response = await fetchWorker(env, "/admin/v2/deliveries", writeValue, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...base, title }),
    });
    assert.equal(response.status, 201);
  }
  const page = await (await fetchWorker(env, "/v2/sync?cursor=0&limit=8", readValue)).json();
  assert.equal(page.deliveries.length, 1);
  assert.equal(page.deliveries[0].title, "Second pending title");
  assert.equal(page.tombstones.length, 0);
});
