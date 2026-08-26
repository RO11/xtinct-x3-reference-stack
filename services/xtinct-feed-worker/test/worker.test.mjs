import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import worker from "../src/index.js";
import { V1_TASK_IDS, sha256Hex } from "../src/contract.js";

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
    this.beforeNextBatch = null;
    this.failNextBatchAt = null;
  }

  prepare(sql) {
    return new D1Statement(this, sql);
  }

  execute(statement) {
    const prepared = this.database.prepare(statement.sql);
    if (/^\s*(?:SELECT|WITH|PRAGMA)\b/i.test(statement.sql)) {
      return { success: true, results: prepared.all(...statement.values), meta: { changes: 0 } };
    }
    const result = prepared.run(...statement.values);
    return { success: true, meta: { changes: Number(result.changes) } };
  }

  async batch(statements) {
    const beforeBatch = this.beforeNextBatch;
    this.beforeNextBatch = null;
    if (beforeBatch) await beforeBatch(this);
    const failAt = this.failNextBatchAt;
    this.failNextBatchAt = null;
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const results = [];
      for (let index = 0; index < statements.length; index += 1) {
        if (index === failAt) throw new Error("injected D1 batch failure");
        results.push(this.execute(statements[index]));
      }
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

async function uploadTextArtifact(env, text = "A reusable synthetic reference artifact.") {
  const bytes = new TextEncoder().encode(text);
  const digest = await sha256Hex(bytes);
  const response = await fetchWorker(env, `/admin/v2/artifacts/${digest}?kind=text`, writeValue, {
    method: "PUT",
    headers: { "Content-Type": "text/plain" },
    body: bytes,
  });
  assert.equal(response.status, 201);
  return { bytes, digest };
}

async function publishTextDelivery(env, digest, suffix, overrides = {}) {
  const response = await fetchWorker(env, "/admin/v2/deliveries", writeValue, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      delivery_id: `test-delivery-${suffix}`,
      item_id: `test-item-${suffix}`,
      module_id: "reference-module",
      kind: "text",
      title: `Synthetic item ${suffix}`,
      sha256: digest,
      mime: "text/plain",
      actions: ["archive"],
      metadata: {},
      ...overrides,
    }),
  });
  assert.equal(response.status, 201);
  return response.json();
}

async function publishNumberedDeliveries(env, digest, count, prefix) {
  for (let index = 1; index <= count; index += 1) {
    const suffix = String(index).padStart(3, "0");
    await publishTextDelivery(env, digest, `${prefix}-${suffix}`, {
      delivery_id: `${prefix}-delivery-${suffix}`,
      item_id: `${prefix}-item-${suffix}`,
      title: `${prefix} item ${suffix}`,
    });
  }
}

function liveDeliveryCount(env) {
  const row = env.DB.database.prepare("SELECT COUNT(*) AS count FROM v2_deliveries").get();
  return Number(row.count);
}

test("health is public while feed and admin routes use separate bearer tokens", async () => {
  const env = await environment();
  assert.equal((await fetchWorker(env, "/healthz", null)).status, 200);
  assert.equal((await fetchWorker(env, "/v1/manifest.json", null)).status, 401);
  assert.equal((await fetchWorker(env, "/admin/v2/acks", readValue)).status, 401);
  assert.equal((await fetchWorker(env, "/admin/v2/acks", writeValue)).status, 200);
});

test("V1 empty storage yields four deterministic placeholders with stable cache semantics", async () => {
  const env = await environment();
  const firstResponse = await fetchWorker(env, "/v1/manifest.json", readValue);
  assert.equal(firstResponse.status, 200);
  assert.equal(firstResponse.headers.get("cache-control"), "private, no-cache");
  const etag = firstResponse.headers.get("etag");
  const manifest = await firstResponse.json();
  assert.equal(manifest.schema, 1);
  assert.equal(manifest.etag, etag);
  assert.deepEqual(manifest.cards.map((card) => card.id), V1_TASK_IDS);
  assert.equal(manifest.cards.length, 4);

  const repeated = await fetchWorker(env, "/v1/manifest.json", readValue);
  assert.equal(repeated.headers.get("etag"), etag);
  assert.deepEqual(await repeated.json(), manifest);
  const notModified = await fetchWorker(env, "/v1/manifest.json", readValue, {
    headers: { "If-None-Match": etag },
  });
  assert.equal(notModified.status, 304);
  assert.equal(notModified.headers.get("etag"), etag);

  for (const descriptor of manifest.cards) {
    const current = await fetchWorker(env, descriptor.url, readValue);
    assert.equal(current.status, 200);
    assert.equal(current.headers.get("cache-control"), "private, no-cache");
    const placeholder = await current.json();
    assert.equal(placeholder.schema, 1);
    assert.equal(placeholder.task_id, descriptor.id);
    assert.equal(placeholder.revision, descriptor.revision);
    assert.equal(placeholder.generated_at, "1970-01-01T00:00:00.000Z");
    assert.equal(placeholder.summary, "No published card is available for this task yet.");
    assert.equal(placeholder.priority, 0);
    assert.equal(placeholder.state, "empty");
    assert.deepEqual(placeholder.metrics, []);
    assert.deepEqual(placeholder.sections, [{
      heading: "Status",
      lines: ["Waiting for the next successful producer run."],
    }]);
    assert.equal("report" in placeholder, false);

    const pinned = await fetchWorker(env, `${descriptor.url}?revision=${descriptor.revision}`, readValue);
    assert.equal(pinned.status, 200);
    assert.equal(pinned.headers.get("cache-control"), "private, immutable");
    assert.deepEqual(await pinned.json(), placeholder);

    const unrelatedRevision = descriptor.revision === "0".repeat(32) ? "1".repeat(32) : "0".repeat(32);
    assert.equal((await fetchWorker(
      env,
      `${descriptor.url}?revision=${unrelatedRevision}`,
      readValue,
    )).status, 404);
    assert.equal((await fetchWorker(
      env,
      `/v1/reports/${descriptor.id}/${descriptor.revision}.txt`,
      readValue,
    )).status, 404);
  }
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
  assert.equal(manifest.cards.length, 4);
  assert.deepEqual(manifest.cards.map((candidate) => candidate.id), V1_TASK_IDS);
  assert.deepEqual(manifest.cards[0], {
    id: "market-briefing",
    revision: identity.revision,
    url: "/v1/cards/market-briefing.json",
  });
  for (const placeholder of manifest.cards.slice(1)) {
    const response = await fetchWorker(env, `${placeholder.url}?revision=${placeholder.revision}`, readValue);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.task_id, placeholder.id);
    assert.equal(body.revision, placeholder.revision);
    assert.equal(body.summary, "No published card is available for this task yet.");
  }

  const current = await fetchWorker(env, "/v1/cards/market-briefing.json", readValue);
  assert.equal(current.status, 200);
  assert.equal(current.headers.get("cache-control"), "private, no-cache");
  const currentBody = await current.json();
  assert.equal(currentBody.revision, identity.revision);

  const pinned = await fetchWorker(env, `/v1/cards/market-briefing.json?revision=${identity.revision}`, readValue);
  assert.equal(pinned.status, 200);
  assert.equal(pinned.headers.get("cache-control"), "private, immutable");
  assert.deepEqual(await pinned.json(), currentBody);

  const report = await fetchWorker(env, currentBody.report.url, readValue);
  assert.equal(report.status, 200);
  assert.equal(report.headers.get("content-length"), String(currentBody.report.bytes));
  assert.equal(report.headers.get("etag"), `"${currentBody.report.sha256}"`);
  assert.equal(await report.text(), card.report_text);

  const notModified = await fetchWorker(env, "/v1/manifest.json", readValue, { headers: { "If-None-Match": etag } });
  assert.equal(notModified.status, 304);
});

test("V1 refuses corrupt retained card identity instead of substituting a placeholder", async () => {
  const env = await environment();
  const input = JSON.parse(await readFile(new URL("../examples/v1-card.json", import.meta.url), "utf8"));
  const published = await fetchWorker(env, "/admin/v1/cards/market-briefing", writeValue, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
  assert.equal(published.status, 201);
  const { revision } = await published.json();
  const corrupt = JSON.stringify({ schema: 1, task_id: "3d-job-search", revision });
  env.DB.database.prepare(
    "UPDATE v1_cards_current SET card_json = ?1 WHERE task_id = 'market-briefing'",
  ).run(corrupt);
  env.DB.database.prepare(
    "UPDATE v1_card_versions SET card_json = ?1 WHERE task_id = 'market-briefing' AND revision = ?2",
  ).run(corrupt, revision);

  assert.equal((await fetchWorker(env, "/v1/manifest.json", readValue)).status, 500);
  assert.equal((await fetchWorker(env, "/v1/cards/market-briefing.json", readValue)).status, 500);
  assert.equal((await fetchWorker(
    env,
    `/v1/cards/market-briefing.json?revision=${revision}`,
    readValue,
  )).status, 500);
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

test("V2 repairs expired deliveries before overflow while future and non-expiring items survive", async () => {
  const env = await environment();
  const { digest } = await uploadTextArtifact(env, "An expiring synthetic reference artifact.");
  const expiredIdentity = await publishTextDelivery(env, digest, "expired", {
      delivery_id: "expired-delivery-001",
      item_id: "expired-item-001",
      title: "Expired synthetic item",
      expires_at: "2000-01-01T00:00:00.000Z",
  });
  await publishTextDelivery(env, digest, "future", {
    delivery_id: "future-delivery-001",
    item_id: "future-item-001",
    title: "Future synthetic item",
    expires_at: "2099-01-01T00:00:00.000Z",
  });
  await publishTextDelivery(env, digest, "no-expiry", {
    delivery_id: "no-expiry-delivery-001",
    item_id: "no-expiry-item-001",
    title: "Non-expiring synthetic item",
  });
  assert.equal(liveDeliveryCount(env), 3);

  const response = await fetchWorker(env, "/v2/sync?cursor=0&limit=8", readValue);
  assert.equal(response.status, 200);
  const page = await response.json();
  assert.equal(liveDeliveryCount(env), 2);
  assert.deepEqual(new Set(page.deliveries.map((delivery) => delivery.item_id)), new Set([
    "future-item-001",
    "no-expiry-item-001",
  ]));
  assert.deepEqual(page.tombstones, [{
    delivery_id: "expired-delivery-001",
    item_id: "expired-item-001",
    revision: expiredIdentity.revision,
    deleted_at: "2000-01-01T00:00:00.000Z",
  }]);
});

test("V2 enforces 64 live items and exposes all replacement tombstones through cursor paging", async () => {
  const env = await environment();
  const { digest } = await uploadTextArtifact(env, "A reusable capacity-test artifact.");
  await publishNumberedDeliveries(env, digest, 81, "cap");
  assert.equal(liveDeliveryCount(env), 81);

  let cursor = "0";
  let pages = 0;
  const deliveries = [];
  const tombstones = [];
  while (pages < 12) {
    const response = await fetchWorker(env, `/v2/sync?cursor=${cursor}&limit=8`, readValue);
    assert.equal(response.status, 200);
    const page = await response.json();
    pages += 1;
    cursor = page.cursor;
    deliveries.push(...page.deliveries);
    tombstones.push(...page.tombstones);
    if (!page.has_more) break;
  }
  assert.equal(pages, 11);
  assert.equal(deliveries.length, 64);
  assert.equal(tombstones.length, 17);
  assert.equal(new Set(deliveries.map((delivery) => delivery.item_id)).size, 64);
  assert.equal(new Set(tombstones.map((tombstone) => tombstone.item_id)).size, 17);
  assert.equal(liveDeliveryCount(env), 64);
  const cursorOrder = env.DB.database.prepare(
    "SELECT change_type, MIN(cursor) AS minimum, MAX(cursor) AS maximum FROM v2_changes GROUP BY change_type",
  ).all();
  const deliveryCursor = cursorOrder.find((row) => row.change_type === "delivery");
  const tombstoneCursor = cursorOrder.find((row) => row.change_type === "tombstone");
  assert.ok(Number(tombstoneCursor.minimum) > Number(deliveryCursor.maximum));
});

test("V2 returns retryable 503 without a cursor until a greater-than-scan backlog converges", async () => {
  const env = await environment();
  const { digest } = await uploadTextArtifact(env, "A bounded reconciliation scan artifact.");
  await publishNumberedDeliveries(env, digest, 100, "scan");
  assert.equal(liveDeliveryCount(env), 100);

  const first = await fetchWorker(env, "/v2/sync?cursor=0&limit=8", readValue);
  assert.equal(first.status, 503);
  assert.equal(first.headers.get("retry-after"), "1");
  const pending = await first.json();
  assert.equal(pending.error, "repair_pending");
  assert.equal("cursor" in pending, false);
  assert.equal(liveDeliveryCount(env), 76);

  const second = await fetchWorker(env, "/v2/sync?cursor=0&limit=8", readValue);
  assert.equal(second.status, 200);
  const page = await second.json();
  assert.equal(page.schema, 2);
  assert.equal(page.deliveries.length + page.tombstones.length, 8);
  assert.equal(liveDeliveryCount(env), 64);
});

test("V2 reconciliation preserves a replacement published after victim selection", async () => {
  const env = await environment();
  const { digest } = await uploadTextArtifact(env, "A stale-selection race artifact.");
  await publishNumberedDeliveries(env, digest, 65, "race");
  const victim = env.DB.database.prepare(
    "SELECT item_id, delivery_id, revision, delivery_json FROM v2_deliveries " +
    "ORDER BY updated_at DESC, item_id DESC LIMIT 1 OFFSET 64",
  ).get();
  assert.ok(victim);

  const replacementRevision = "f".repeat(64);
  const replacementDeliveryId = "race-replacement-001";
  env.DB.beforeNextBatch = async (database) => {
    const replacement = {
      ...JSON.parse(victim.delivery_json),
      delivery_id: replacementDeliveryId,
      revision: replacementRevision,
      title: "Replacement published during reconciliation",
      expires_at: null,
    };
    const replacementJson = JSON.stringify(replacement);
    const updated = database.database.prepare(
      "UPDATE v2_deliveries SET delivery_id = ?1, revision = ?2, delivery_json = ?3, updated_at = ?4 " +
      "WHERE item_id = ?5 AND delivery_id = ?6 AND revision = ?7",
    ).run(
      replacementDeliveryId,
      replacementRevision,
      replacementJson,
      "2099-01-01T00:00:00.000Z",
      victim.item_id,
      victim.delivery_id,
      victim.revision,
    );
    assert.equal(Number(updated.changes), 1);
    database.database.prepare("DELETE FROM v2_changes WHERE item_id = ?1").run(victim.item_id);
    database.database.prepare(
      "INSERT INTO v2_changes (item_id, change_type, payload_json) VALUES (?1, 'delivery', ?2)",
    ).run(victim.item_id, replacementJson);
  };

  const raced = await fetchWorker(env, "/v2/sync?cursor=0&limit=8", readValue);
  assert.equal(raced.status, 503);
  assert.equal((await raced.json()).error, "repair_pending");
  assert.equal(liveDeliveryCount(env), 65);
  const replacementChange = env.DB.database.prepare(
    "SELECT cursor, change_type, payload_json FROM v2_changes WHERE item_id = ?1",
  ).get(victim.item_id);
  assert.equal(replacementChange.change_type, "delivery");
  assert.equal(JSON.parse(replacementChange.payload_json).revision, replacementRevision);

  const resumeCursor = String(Number(replacementChange.cursor) - 1);
  const resumed = await fetchWorker(env, `/v2/sync?cursor=${resumeCursor}&limit=8`, readValue);
  assert.equal(resumed.status, 200);
  const page = await resumed.json();
  const replacement = page.deliveries.find((delivery) => delivery.item_id === victim.item_id);
  assert.ok(replacement);
  assert.equal(replacement.delivery_id, replacementDeliveryId);
  assert.equal(replacement.revision, replacementRevision);
  assert.equal(liveDeliveryCount(env), 64);
});

test("V2 reconciliation batch failure rolls back both the tombstone and delivery deletion", async () => {
  const env = await environment();
  const { digest } = await uploadTextArtifact(env, "A transactional rollback artifact.");
  await publishNumberedDeliveries(env, digest, 65, "rollback");
  const victim = env.DB.database.prepare(
    "SELECT item_id, delivery_id, revision FROM v2_deliveries " +
    "ORDER BY updated_at DESC, item_id DESC LIMIT 1 OFFSET 64",
  ).get();
  const beforeChange = env.DB.database.prepare(
    "SELECT cursor, change_type, payload_json FROM v2_changes WHERE item_id = ?1",
  ).get(victim.item_id);
  env.DB.failNextBatchAt = 1;

  const failed = await fetchWorker(env, "/v2/sync?cursor=0&limit=8", readValue);
  assert.equal(failed.status, 500);
  assert.equal(liveDeliveryCount(env), 65);
  const retained = env.DB.database.prepare(
    "SELECT delivery_id, revision FROM v2_deliveries WHERE item_id = ?1",
  ).get(victim.item_id);
  assert.equal(retained.delivery_id, victim.delivery_id);
  assert.equal(retained.revision, victim.revision);
  const afterChange = env.DB.database.prepare(
    "SELECT cursor, change_type, payload_json FROM v2_changes WHERE item_id = ?1",
  ).get(victim.item_id);
  assert.deepEqual(afterChange, beforeChange);

  const retried = await fetchWorker(env, "/v2/sync?cursor=0&limit=8", readValue);
  assert.equal(retried.status, 200);
  assert.equal(liveDeliveryCount(env), 64);
  assert.equal(env.DB.database.prepare(
    "SELECT change_type FROM v2_changes WHERE item_id = ?1",
  ).get(victim.item_id).change_type, "tombstone");
});
