export const V1_TASK_IDS = Object.freeze([
  "market-briefing",
  "weekday-freelancer-scan",
  "3d-job-search",
  "outlook-attention-watch",
]);

export const V2_KINDS = Object.freeze([
  "card",
  "text",
  "image-1bit",
  "epub",
  "action",
  "sleep-screen",
]);

export const V2_ACTIONS = Object.freeze([
  "keep",
  "archive",
  "done",
  "defer",
  "open-phone",
  "like",
  "dislike",
]);

export const ACK_EVENT_TYPES = Object.freeze([
  "downloaded",
  "opened",
  "failed",
  "kept",
  "archived",
  "done",
  "deferred",
  "progress",
  "open-phone",
  "deleted",
  "like",
  "dislike",
  "device-status",
]);

export const MAX = Object.freeze({
  v1ManifestBytes: 8 * 1024,
  v1CardBytes: 16 * 1024,
  v1ReportBytes: 24 * 1024,
  v2ArtifactBytes: 20 * 1024 * 1024,
  v2MetadataBytes: 2 * 1024,
  v2SyncChanges: 8,
  v2SyncBytes: 28 * 1024,
  v2AckEvents: 24,
  v2AckBytes: 16 * 1024,
  v2AckEventDataBytes: 1024,
  adminJsonBytes: 64 * 1024,
});

const encoder = new TextEncoder();
const fatalDecoder = new TextDecoder("utf-8", { fatal: true });

export function utf8Length(value) {
  return typeof value === "string" ? encoder.encode(value).byteLength : -1;
}

export function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

export function isSafeId(value) {
  return typeof value === "string" && /^[a-z0-9][a-z0-9-]{0,31}$/.test(value);
}

export function isSha256(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

export function isV1Revision(value) {
  return typeof value === "string" && /^[0-9a-f]{32}$/.test(value);
}

export function isBoundedAscii(value, maximum, allowEmpty = false) {
  if (typeof value !== "string" || value.length > maximum || (!allowEmpty && value.length === 0)) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code > 0x7e) return false;
  }
  return true;
}

export function isIsoTimestamp(value, allowEmpty = false) {
  if (allowEmpty && value === "") return true;
  return isBoundedAscii(value, 39) && !Number.isNaN(Date.parse(value));
}

export function isUtf8Text(bytes, { allowEmpty = false } = {}) {
  if (!(bytes instanceof Uint8Array) || (!allowEmpty && bytes.byteLength === 0)) return false;
  try {
    return !fatalDecoder.decode(bytes).includes("\u0000");
  } catch {
    return false;
  }
}

function textWithin(value, maximumBytes, allowEmpty = false) {
  const length = utf8Length(value);
  return length >= (allowEmpty ? 0 : 1) && length <= maximumBytes && !value.includes("\u0000");
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (!isPlainObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

export async function sha256Hex(value) {
  const bytes = typeof value === "string" ? encoder.encode(value) : value;
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function mimeAllowed(kind, mime) {
  if (["card", "text", "action"].includes(kind)) {
    return mime === "text/plain" || mime === "text/plain; charset=utf-8";
  }
  if (kind === "image-1bit" || kind === "sleep-screen") return mime === "image/bmp";
  if (kind === "epub") return mime === "application/epub+zip";
  return false;
}

function little16(bytes, offset) {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function little32(bytes, offset) {
  return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) |
    (bytes[offset + 3] << 24)) >>> 0;
}

function signed32(bytes, offset) {
  return little32(bytes, offset) | 0;
}

export function isX3OneBitBmp(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 48_062 || bytes.byteLength < 62) return false;
  return bytes[0] === 0x42 && bytes[1] === 0x4d && little32(bytes, 2) === bytes.byteLength &&
    little32(bytes, 10) === 62 && little32(bytes, 14) >= 40 && signed32(bytes, 18) === 480 &&
    (signed32(bytes, 22) === 800 || signed32(bytes, 22) === -800) && little16(bytes, 26) === 1 &&
    little16(bytes, 28) === 1 && little32(bytes, 30) === 0;
}

export function isX3NativeSleepBmp(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 209_158 || bytes.byteLength < 70) return false;
  const palette = [0, 0, 0, 0, 85, 85, 85, 0, 170, 170, 170, 0, 255, 255, 255, 0];
  return bytes[0] === 0x42 && bytes[1] === 0x4d && little32(bytes, 2) === bytes.byteLength &&
    little16(bytes, 6) === 0 && little16(bytes, 8) === 0 && little32(bytes, 10) === 70 &&
    little32(bytes, 14) === 40 && signed32(bytes, 18) === 528 &&
    (signed32(bytes, 22) === 792 || signed32(bytes, 22) === -792) && little16(bytes, 26) === 1 &&
    little16(bytes, 28) === 4 && little32(bytes, 30) === 0 && little32(bytes, 34) === 264 * 792 &&
    little32(bytes, 46) === 4 && (little32(bytes, 50) === 0 || little32(bytes, 50) === 4) &&
    palette.every((value, index) => bytes[54 + index] === value);
}

export function validateArtifact(kind, mime, bytes) {
  const errors = [];
  if (!V2_KINDS.includes(kind)) errors.push("kind is not supported");
  if (!mimeAllowed(kind, mime)) errors.push("mime does not match kind");
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0 || bytes.byteLength > MAX.v2ArtifactBytes) {
    errors.push("artifact byte count is outside the X3 contract");
    return errors;
  }
  if (["card", "text", "action"].includes(kind) && !isUtf8Text(bytes)) {
    errors.push("text artifacts must be complete UTF-8 without NUL");
  }
  if (kind === "image-1bit" && !isX3OneBitBmp(bytes)) errors.push("image-1bit must be the exact 480x800 1-bpp BMP contract");
  if (kind === "sleep-screen" && !isX3NativeSleepBmp(bytes)) errors.push("sleep-screen must be the exact 528x792 native 4-bpp BMP contract");
  if (kind === "epub" && !(bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04)) {
    errors.push("epub must start with the ZIP local-file signature");
  }
  return errors;
}

function validateV1Metrics(value, errors) {
  if (!Array.isArray(value) || value.length > 4) {
    errors.push("metrics must be an array with at most 4 entries");
    return;
  }
  for (const metric of value) {
    if (!isPlainObject(metric) || !textWithin(metric.label, 40) || !textWithin(metric.value, 80) ||
        !textWithin(metric.tone ?? "neutral", 7)) {
      errors.push("each metric needs bounded label, value and tone strings");
    }
  }
}

function validateV1Sections(value, errors) {
  if (!Array.isArray(value) || value.length > 3) {
    errors.push("sections must be an array with at most 3 entries");
    return;
  }
  for (const section of value) {
    if (!isPlainObject(section) || !textWithin(section.heading, 48) || !Array.isArray(section.lines) ||
        section.lines.length === 0 || section.lines.length > 4 ||
        section.lines.some((line) => !textWithin(line, 240))) {
      errors.push("each section needs a bounded heading and 1-4 bounded lines");
    }
  }
}

export function validateV1CardInput(taskId, input) {
  const errors = [];
  if (!V1_TASK_IDS.includes(taskId)) errors.push("task_id is not in the firmware allowlist");
  if (!isPlainObject(input)) return [...errors, "body must be a JSON object"];
  if (!isIsoTimestamp(input.generated_at)) errors.push("generated_at must be an ISO timestamp");
  if (!textWithin(input.title, 80)) errors.push("title must be 1-80 UTF-8 bytes");
  if (!textWithin(input.summary, 320)) errors.push("summary must be 1-320 UTF-8 bytes");
  if (!Number.isInteger(input.priority ?? 0) || (input.priority ?? 0) < 0 || (input.priority ?? 0) > 3) {
    errors.push("priority must be an integer from 0 to 3");
  }
  if (!["ok", "empty", "attention", "error"].includes(input.state ?? "ok")) errors.push("state is not supported");
  validateV1Metrics(input.metrics ?? [], errors);
  validateV1Sections(input.sections ?? [], errors);
  if (input.report_text !== undefined && !textWithin(input.report_text, MAX.v1ReportBytes)) {
    errors.push("report_text must be non-empty UTF-8 within 24 KiB");
  }
  return errors;
}

export async function buildV1Card(taskId, input) {
  const reportBytes = input.report_text === undefined ? null : encoder.encode(input.report_text);
  const reportSha256 = reportBytes ? await sha256Hex(reportBytes) : null;
  const revisionSeed = canonicalJson({
    task_id: taskId,
    generated_at: input.generated_at,
    title: input.title,
    summary: input.summary,
    priority: input.priority ?? 0,
    state: input.state ?? "ok",
    metrics: input.metrics ?? [],
    sections: input.sections ?? [],
    report_sha256: reportSha256,
  });
  const revision = (await sha256Hex(revisionSeed)).slice(0, 32);
  const card = {
    schema: 1,
    task_id: taskId,
    revision,
    generated_at: input.generated_at,
    title: input.title,
    summary: input.summary,
    priority: input.priority ?? 0,
    state: input.state ?? "ok",
    metrics: input.metrics ?? [],
    sections: input.sections ?? [],
  };
  if (reportBytes) {
    card.report = {
      url: `/v1/reports/${taskId}/${revision}.txt`,
      bytes: reportBytes.byteLength,
      sha256: reportSha256,
    };
  }
  return { card, revision, reportBytes, reportSha256 };
}

export function validateDeliveryInput(input, artifact) {
  const errors = [];
  if (!isPlainObject(input)) return ["body must be a JSON object"];
  if (!isSafeId(input.delivery_id)) errors.push("delivery_id must be a safe lowercase ID of at most 32 bytes");
  if (!isSafeId(input.item_id)) errors.push("item_id must be a safe lowercase ID of at most 32 bytes");
  if (!isSafeId(input.module_id)) errors.push("module_id must be a safe lowercase ID of at most 32 bytes");
  if (!V2_KINDS.includes(input.kind)) errors.push("kind is not supported");
  if (!textWithin(input.title, 120)) errors.push("title must be 1-120 UTF-8 bytes");
  if (!isSha256(input.sha256)) errors.push("sha256 must be 64 lowercase hex characters");
  if (!mimeAllowed(input.kind, input.mime)) errors.push("mime does not match kind");
  if (input.created_at !== undefined && !isIsoTimestamp(input.created_at)) errors.push("created_at must be an ISO timestamp");
  if (input.expires_at !== undefined && input.expires_at !== null && !isIsoTimestamp(input.expires_at, true)) {
    errors.push("expires_at must be null or an ISO timestamp");
  }
  if (!Array.isArray(input.actions) || input.actions.length > 5 || new Set(input.actions).size !== input.actions.length ||
      input.actions.some((action) => !V2_ACTIONS.includes(action))) {
    errors.push("actions must contain at most 5 unique supported actions");
  }
  if (input.metadata !== undefined && !isPlainObject(input.metadata)) errors.push("metadata must be a JSON object");
  const metadata = input.metadata ?? {};
  if (utf8Length(JSON.stringify(metadata)) > MAX.v2MetadataBytes) errors.push("metadata exceeds 2 KiB");
  if (metadata.activate !== undefined && typeof metadata.activate !== "boolean") errors.push("metadata.activate must be boolean");
  if (input.kind !== "sleep-screen" && metadata.activate === true) errors.push("only sleep-screen may request activation");
  if (metadata.digest !== undefined) {
    const digest = metadata.digest;
    if (!isPlainObject(digest) || Object.keys(digest).sort().join(",") !== "points,schema,summary" ||
        digest.schema !== "xtinct.inbox-digest/v1" || !textWithin(digest.summary, 144) ||
        !Array.isArray(digest.points) || digest.points.length > 2 ||
        digest.points.some((point) => !textWithin(point, 64))) {
      errors.push("metadata.digest does not match xtinct.inbox-digest/v1");
    }
  }
  if (!artifact || artifact.sha256 !== input.sha256 || artifact.kind !== input.kind ||
      artifact.mime !== input.mime || !Number.isInteger(artifact.bytes) || artifact.bytes <= 0) {
    errors.push("referenced artifact was not uploaded with the same digest, kind and mime");
  }
  return errors;
}

export async function buildDelivery(input, artifact, nowIso) {
  const createdAt = input.created_at ?? nowIso;
  const envelope = {
    delivery_id: input.delivery_id,
    item_id: input.item_id,
    module_id: input.module_id,
    kind: input.kind,
    title: input.title,
    sha256: input.sha256,
    bytes: artifact.bytes,
    mime: input.mime,
    created_at: createdAt,
    expires_at: input.expires_at ?? null,
    actions: input.actions,
    metadata: input.metadata ?? {},
  };
  const revision = await sha256Hex(canonicalJson(envelope));
  return { ...envelope, revision };
}

export function validateAckEvent(event) {
  if (!isPlainObject(event)) return false;
  if (!isBoundedAscii(event.event_id, 95) || !isSafeId(event.item_id) || !isSha256(event.revision) ||
      !ACK_EVENT_TYPES.includes(event.type) || !isIsoTimestamp(event.occurred_at) || !isPlainObject(event.data)) {
    return false;
  }
  return utf8Length(JSON.stringify(event.data)) <= MAX.v2AckEventDataBytes;
}

export function parseDecimalCursor(value) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,22})$/.test(value)) return null;
  const parsed = BigInt(value);
  return parsed <= 9_223_372_036_854_775_807n ? value : null;
}

