import {
  MAX,
  V1_TASK_IDS,
  V2_KINDS,
  buildDelivery,
  buildV1Card,
  canonicalJson,
  isBoundedAscii,
  isPlainObject,
  isSafeId,
  isSha256,
  isV1Revision,
  mimeAllowed,
  parseDecimalCursor,
  sha256Hex,
  utf8Length,
  validateAckEvent,
  validateArtifact,
  validateDeliveryInput,
  validateV1CardInput,
} from "./contract.js";

const JSON_HEADERS = Object.freeze({
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
});

function jsonResponse(value, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { ...JSON_HEADERS, ...extraHeaders },
  });
}

function errorResponse(status, code, detail, extraHeaders = {}) {
  return jsonResponse({ error: code, detail }, status, extraHeaders);
}

async function readBoundedBytes(request, maximum) {
  const declared = request.headers.get("content-length");
  if (declared !== null && (!/^[0-9]+$/.test(declared) || Number(declared) > maximum)) {
    throw new RangeError("request body exceeds the route limit");
  }
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximum) {
        await reader.cancel("bounded body exceeded");
        throw new RangeError("request body exceeds the route limit");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

async function readBoundedJson(request, maximum) {
  const bytes = await readBoundedBytes(request, maximum);
  if (bytes.byteLength === 0) throw new SyntaxError("empty JSON body");
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

function parseBearer(request) {
  const header = request.headers.get("authorization") ?? "";
  const match = /^Bearer ([\x21-\x7e]{32,256})$/.exec(header);
  return match ? match[1] : null;
}

async function hashSecret(value) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}

async function secretsEqual(provided, expected) {
  if (typeof provided !== "string" || typeof expected !== "string" || expected.length < 32 || expected.length > 256) {
    return false;
  }
  const [left, right] = await Promise.all([hashSecret(provided), hashSecret(expected)]);
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

async function authorize(request, expectedToken) {
  if (typeof expectedToken !== "string" || expectedToken.length < 32 || expectedToken.length > 256) {
    return errorResponse(503, "not_configured", "required secret binding is missing");
  }
  if (!await secretsEqual(parseBearer(request), expectedToken)) {
    return errorResponse(401, "unauthorized", "valid bearer token required", { "WWW-Authenticate": "Bearer" });
  }
  return null;
}

function nowIso() {
  return new Date().toISOString();
}

function d1Changes(result) {
  return Number(result?.meta?.changes ?? 0);
}

function safeJsonParse(value) {
  if (typeof value !== "string") throw new TypeError("stored JSON is not text");
  return JSON.parse(value);
}

async function handleV1Manifest(request, env) {
  const rows = (await env.DB.prepare(
    "SELECT task_id, revision FROM v1_cards_current ORDER BY task_id",
  ).all()).results ?? [];
  const byTask = new Map(rows.map((row) => [row.task_id, row.revision]));
  const cards = V1_TASK_IDS.filter((taskId) => isV1Revision(byTask.get(taskId))).map((taskId) => ({
    id: taskId,
    revision: byTask.get(taskId),
    url: `/v1/cards/${taskId}.json`,
  }));
  const etag = `"v1-${await sha256Hex(canonicalJson(cards))}"`;
  if (request.headers.get("if-none-match") === etag) {
    return new Response(null, { status: 304, headers: { ETag: etag, "Cache-Control": "private, no-cache" } });
  }
  const body = JSON.stringify({ schema: 1, etag, cards });
  if (utf8Length(body) > MAX.v1ManifestBytes) throw new RangeError("generated V1 manifest exceeds firmware bound");
  return new Response(body, {
    headers: {
      ...JSON_HEADERS,
      ETag: etag,
      "Cache-Control": "private, no-cache",
    },
  });
}

async function handleV1Card(url, env, taskId) {
  if (!V1_TASK_IDS.includes(taskId)) return errorResponse(404, "not_found", "unknown card task");
  const requestedRevision = url.searchParams.get("revision");
  if (requestedRevision !== null && !isV1Revision(requestedRevision)) {
    return errorResponse(400, "invalid_revision", "revision must be 32 lowercase hex characters");
  }
  const statement = requestedRevision === null
    ? env.DB.prepare("SELECT card_json FROM v1_cards_current WHERE task_id = ?1").bind(taskId)
    : env.DB.prepare("SELECT card_json FROM v1_card_versions WHERE task_id = ?1 AND revision = ?2")
      .bind(taskId, requestedRevision);
  const row = await statement.first();
  if (!row) return errorResponse(404, "not_found", "card revision is not retained");
  if (typeof row.card_json !== "string" || utf8Length(row.card_json) > MAX.v1CardBytes) {
    throw new RangeError("stored V1 card exceeds firmware bound");
  }
  return new Response(row.card_json, { headers: { ...JSON_HEADERS, "Cache-Control": "private, no-cache" } });
}

async function handleV1Report(env, taskId, revision) {
  if (!V1_TASK_IDS.includes(taskId) || !isV1Revision(revision)) return errorResponse(404, "not_found", "unknown report");
  const row = await env.DB.prepare(
    "SELECT report_object_key, report_sha256, report_bytes FROM v1_card_versions WHERE task_id = ?1 AND revision = ?2",
  ).bind(taskId, revision).first();
  if (!row || typeof row.report_object_key !== "string" || !isSha256(row.report_sha256) ||
      !Number.isInteger(row.report_bytes) || row.report_bytes <= 0 || row.report_bytes > MAX.v1ReportBytes) {
    return errorResponse(404, "not_found", "report revision is not retained");
  }
  const object = await env.ARTIFACTS.get(row.report_object_key);
  if (!object || object.size !== row.report_bytes) throw new Error("retained report object is missing or has changed size");
  return new Response(object.body, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Content-Length": String(row.report_bytes),
      ETag: `"${row.report_sha256}"`,
      "Cache-Control": "private, immutable",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

async function handleV2Sync(url, env) {
  const cursor = parseDecimalCursor(url.searchParams.get("cursor") ?? "");
  const requestedLimit = Number(url.searchParams.get("limit") ?? "0");
  if (cursor === null || !Number.isInteger(requestedLimit) || requestedLimit < 1 || requestedLimit > MAX.v2SyncChanges) {
    return errorResponse(400, "invalid_page", "cursor must be decimal and limit must be 1-8");
  }
  const rows = (await env.DB.prepare(
    "SELECT cursor, change_type, payload_json FROM v2_changes WHERE cursor > ?1 ORDER BY cursor LIMIT ?2",
  ).bind(cursor, requestedLimit).all()).results ?? [];
  const deliveries = [];
  const tombstones = [];
  let nextCursor = cursor;
  for (const row of rows) {
    const payload = safeJsonParse(row.payload_json);
    if (row.change_type === "delivery") deliveries.push(payload);
    else if (row.change_type === "tombstone") tombstones.push(payload);
    else throw new Error("unknown stored V2 change type");
    nextCursor = String(row.cursor);
  }
  const later = await env.DB.prepare("SELECT cursor FROM v2_changes WHERE cursor > ?1 ORDER BY cursor LIMIT 1")
    .bind(nextCursor).first();
  const deviceId = isSafeId(env.DEVICE_ID) ? env.DEVICE_ID : "x3-reference";
  const body = JSON.stringify({
    schema: 2,
    device_id: deviceId,
    cursor: nextCursor,
    has_more: later !== null,
    deliveries,
    tombstones,
  });
  if (utf8Length(body) > MAX.v2SyncBytes) throw new RangeError("generated V2 sync page exceeds firmware bound");
  return new Response(body, { headers: JSON_HEADERS });
}

async function handleV2Artifact(env, digest) {
  if (!isSha256(digest)) return errorResponse(404, "not_found", "unknown artifact");
  const row = await env.DB.prepare(
    "SELECT object_key, bytes, mime FROM v2_artifacts WHERE sha256 = ?1",
  ).bind(digest).first();
  if (!row || typeof row.object_key !== "string" || !Number.isInteger(row.bytes) || row.bytes <= 0 ||
      row.bytes > MAX.v2ArtifactBytes || typeof row.mime !== "string") {
    return errorResponse(404, "not_found", "unknown artifact");
  }
  const object = await env.ARTIFACTS.get(row.object_key);
  if (!object || object.size !== row.bytes) throw new Error("retained V2 object is missing or has changed size");
  return new Response(object.body, {
    headers: {
      "Content-Type": row.mime,
      "Content-Length": String(row.bytes),
      ETag: `"${digest}"`,
      "Cache-Control": "private, immutable",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

async function handleV2Acks(request, env) {
  let body;
  try {
    body = await readBoundedJson(request, MAX.v2AckBytes);
  } catch (error) {
    return errorResponse(error instanceof RangeError ? 413 : 400, "invalid_ack_batch", error.message);
  }
  if (!isPlainObject(body) || body.schema !== 2 || !Array.isArray(body.events) ||
      body.events.length === 0 || body.events.length > MAX.v2AckEvents) {
    return errorResponse(400, "invalid_ack_batch", "expected schema 2 and 1-24 events");
  }
  const valid = body.events.filter(validateAckEvent);
  const rejected = body.events.length - valid.length;
  const receivedAt = nowIso();
  const statements = valid.map((event) => env.DB.prepare(
    "INSERT OR IGNORE INTO v2_acks (event_id, event_json, received_at) VALUES (?1, ?2, ?3)",
  ).bind(event.event_id, JSON.stringify(event), receivedAt));
  const results = statements.length > 0 ? await env.DB.batch(statements) : [];
  const accepted = results.reduce((total, result) => total + d1Changes(result), 0);
  const duplicates = valid.length - accepted;
  return jsonResponse({ schema: 2, accepted, duplicates, rejected });
}

async function handleAdminV1Card(request, env, taskId) {
  let input;
  try {
    input = await readBoundedJson(request, MAX.adminJsonBytes);
  } catch (error) {
    return errorResponse(error instanceof RangeError ? 413 : 400, "invalid_card", error.message);
  }
  const errors = validateV1CardInput(taskId, input);
  if (errors.length > 0) return errorResponse(400, "invalid_card", errors.join("; "));
  const built = await buildV1Card(taskId, input);
  const cardJson = JSON.stringify(built.card);
  if (utf8Length(cardJson) > MAX.v1CardBytes) return errorResponse(400, "invalid_card", "serialized card exceeds 16 KiB");
  let reportObjectKey = null;
  if (built.reportBytes) {
    reportObjectKey = `v1/reports/${taskId}/${built.revision}.txt`;
    await env.ARTIFACTS.put(reportObjectKey, built.reportBytes, {
      httpMetadata: { contentType: "text/plain; charset=utf-8" },
      customMetadata: { sha256: built.reportSha256, contract: "xtinct-v1-report" },
    });
  }
  const publishedAt = nowIso();
  await env.DB.batch([
    env.DB.prepare(
      "INSERT OR IGNORE INTO v1_card_versions (task_id, revision, card_json, report_object_key, report_sha256, report_bytes, published_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    ).bind(taskId, built.revision, cardJson, reportObjectKey, built.reportSha256, built.reportBytes?.byteLength ?? null, publishedAt),
    env.DB.prepare(
      "INSERT INTO v1_cards_current (task_id, revision, card_json, report_object_key, report_sha256, report_bytes, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT(task_id) DO UPDATE SET revision=excluded.revision, card_json=excluded.card_json, report_object_key=excluded.report_object_key, report_sha256=excluded.report_sha256, report_bytes=excluded.report_bytes, updated_at=excluded.updated_at",
    ).bind(taskId, built.revision, cardJson, reportObjectKey, built.reportSha256, built.reportBytes?.byteLength ?? null, publishedAt),
  ]);
  return jsonResponse({ schema: 1, task_id: taskId, revision: built.revision }, 201);
}

async function handleAdminV2Artifact(request, url, env, digest) {
  if (!isSha256(digest)) return errorResponse(400, "invalid_artifact", "path digest must be 64 lowercase hex characters");
  const kind = url.searchParams.get("kind") ?? "";
  const mime = request.headers.get("content-type") ?? "";
  if (!V2_KINDS.includes(kind) || !mimeAllowed(kind, mime)) {
    return errorResponse(400, "invalid_artifact", "kind and Content-Type must match the firmware contract");
  }
  let bytes;
  try {
    bytes = await readBoundedBytes(request, MAX.v2ArtifactBytes);
  } catch (error) {
    return errorResponse(413, "invalid_artifact", error.message);
  }
  const errors = validateArtifact(kind, mime, bytes);
  const actual = await sha256Hex(bytes);
  if (actual !== digest) errors.push("path digest does not match the uploaded bytes");
  if (errors.length > 0) return errorResponse(400, "invalid_artifact", errors.join("; "));
  const existing = await env.DB.prepare("SELECT bytes, mime, kind FROM v2_artifacts WHERE sha256 = ?1").bind(digest).first();
  if (existing && (existing.bytes !== bytes.byteLength || existing.mime !== mime || existing.kind !== kind)) {
    return errorResponse(409, "artifact_conflict", "digest is already registered with different contract metadata");
  }
  const objectKey = `v2/artifacts/${digest}`;
  await env.ARTIFACTS.put(objectKey, bytes, {
    httpMetadata: { contentType: mime },
    customMetadata: { sha256: digest, kind, contract: "xtinct-v2-artifact" },
  });
  await env.DB.prepare(
    "INSERT OR IGNORE INTO v2_artifacts (sha256, object_key, bytes, mime, kind, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
  ).bind(digest, objectKey, bytes.byteLength, mime, kind, nowIso()).run();
  return jsonResponse({ schema: 2, sha256: digest, bytes: bytes.byteLength, mime, kind }, 201);
}

async function handleAdminV2Delivery(request, env) {
  let input;
  try {
    input = await readBoundedJson(request, MAX.adminJsonBytes);
  } catch (error) {
    return errorResponse(error instanceof RangeError ? 413 : 400, "invalid_delivery", error.message);
  }
  const artifact = isPlainObject(input) && isSha256(input.sha256)
    ? await env.DB.prepare("SELECT sha256, bytes, mime, kind FROM v2_artifacts WHERE sha256 = ?1").bind(input.sha256).first()
    : null;
  const errors = validateDeliveryInput(input, artifact);
  if (errors.length > 0) return errorResponse(400, "invalid_delivery", errors.join("; "));
  const publishedAt = nowIso();
  const delivery = await buildDelivery(input, artifact, publishedAt);
  const deliveryJson = JSON.stringify(delivery);
  if (utf8Length(deliveryJson) > MAX.v2SyncBytes) return errorResponse(400, "invalid_delivery", "delivery envelope is too large");
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO v2_deliveries (item_id, delivery_id, revision, delivery_json, updated_at) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(item_id) DO UPDATE SET delivery_id=excluded.delivery_id, revision=excluded.revision, delivery_json=excluded.delivery_json, updated_at=excluded.updated_at",
    ).bind(delivery.item_id, delivery.delivery_id, delivery.revision, deliveryJson, publishedAt),
    env.DB.prepare("DELETE FROM v2_changes WHERE item_id = ?1").bind(delivery.item_id),
    env.DB.prepare("INSERT INTO v2_changes (item_id, change_type, payload_json) VALUES (?1, 'delivery', ?2)")
      .bind(delivery.item_id, deliveryJson),
  ]);
  return jsonResponse({ schema: 2, item_id: delivery.item_id, revision: delivery.revision }, 201);
}

async function handleAdminV2Delete(env, itemId) {
  if (!isSafeId(itemId)) return errorResponse(400, "invalid_item", "item_id is not safe");
  const row = await env.DB.prepare(
    "SELECT delivery_id, revision, delivery_json FROM v2_deliveries WHERE item_id = ?1",
  ).bind(itemId).first();
  if (!row || !isSafeId(row.delivery_id) || !isSha256(row.revision)) {
    return errorResponse(404, "not_found", "active delivery was not found");
  }
  const tombstone = {
    delivery_id: row.delivery_id,
    item_id: itemId,
    revision: row.revision,
    deleted_at: nowIso(),
  };
  const tombstoneJson = JSON.stringify(tombstone);
  const results = await env.DB.batch([
    env.DB.prepare("DELETE FROM v2_changes WHERE item_id = ?1").bind(itemId),
    env.DB.prepare(
      "INSERT INTO v2_changes (item_id, change_type, payload_json) SELECT ?2, 'tombstone', ?1 WHERE EXISTS (SELECT 1 FROM v2_deliveries WHERE item_id = ?2 AND revision = ?3)",
    ).bind(tombstoneJson, itemId, row.revision),
    env.DB.prepare("DELETE FROM v2_deliveries WHERE item_id = ?1 AND revision = ?2").bind(itemId, row.revision),
  ]);
  if (d1Changes(results[1]) !== 1 || d1Changes(results[2]) !== 1) throw new Error("delivery changed during tombstone transaction");
  return jsonResponse({ schema: 2, tombstone }, 200);
}

async function handleAdminV2Acks(url, env) {
  const requested = Number(url.searchParams.get("limit") ?? "100");
  if (!Number.isInteger(requested) || requested < 1 || requested > 250) {
    return errorResponse(400, "invalid_limit", "limit must be an integer from 1 to 250");
  }
  const rows = (await env.DB.prepare(
    "SELECT event_json, received_at FROM v2_acks ORDER BY received_at DESC, event_id DESC LIMIT ?1",
  ).bind(requested).all()).results ?? [];
  return jsonResponse({ schema: 2, events: rows.map((row) => ({ ...safeJsonParse(row.event_json), received_at: row.received_at })) });
}

export async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  if (request.method === "GET" && path === "/healthz") {
    return jsonResponse({ ok: true, service: "xtinct-feed-reference", schemas: [1, 2] });
  }

  const isAdmin = path.startsWith("/admin/");
  const authFailure = await authorize(request, isAdmin ? env.WRITE_TOKEN : env.READ_TOKEN);
  if (authFailure) return authFailure;

  if (request.method === "GET" && path === "/v1/manifest.json") return handleV1Manifest(request, env);
  const v1Card = /^\/v1\/cards\/([a-z0-9-]+)\.json$/.exec(path);
  if (request.method === "GET" && v1Card) return handleV1Card(url, env, v1Card[1]);
  const v1Report = /^\/v1\/reports\/([a-z0-9-]+)\/([0-9a-f]{32})\.txt$/.exec(path);
  if (request.method === "GET" && v1Report) return handleV1Report(env, v1Report[1], v1Report[2]);
  if (request.method === "GET" && path === "/v2/sync") return handleV2Sync(url, env);
  const v2Artifact = /^\/v2\/artifacts\/([0-9a-f]{64})$/.exec(path);
  if (request.method === "GET" && v2Artifact) return handleV2Artifact(env, v2Artifact[1]);
  if (request.method === "POST" && path === "/v2/acks") return handleV2Acks(request, env);

  const adminV1Card = /^\/admin\/v1\/cards\/([a-z0-9-]+)$/.exec(path);
  if (request.method === "PUT" && adminV1Card) return handleAdminV1Card(request, env, adminV1Card[1]);
  const adminV2Artifact = /^\/admin\/v2\/artifacts\/([0-9a-f]{64})$/.exec(path);
  if (request.method === "PUT" && adminV2Artifact) return handleAdminV2Artifact(request, url, env, adminV2Artifact[1]);
  if (request.method === "POST" && path === "/admin/v2/deliveries") return handleAdminV2Delivery(request, env);
  const adminV2Delete = /^\/admin\/v2\/deliveries\/([a-z0-9-]+)$/.exec(path);
  if (request.method === "DELETE" && adminV2Delete) return handleAdminV2Delete(env, adminV2Delete[1]);
  if (request.method === "GET" && path === "/admin/v2/acks") return handleAdminV2Acks(url, env);
  return errorResponse(404, "not_found", "route does not exist");
}

export default {
  async fetch(request, env) {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      console.error(JSON.stringify({
        message: "XTINCT feed request failed",
        method: request.method,
        path: new URL(request.url).pathname,
        error: error instanceof Error ? error.message : "unknown error",
      }));
      return errorResponse(500, "internal_error", "request stopped safely");
    }
  },
};
