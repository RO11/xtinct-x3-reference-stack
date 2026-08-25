import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  buildDelivery,
  buildV1Card,
  isSafeId,
  isX3NativeSleepBmp,
  parseDecimalCursor,
  sha256Hex,
  validateAckEvent,
  validateArtifact,
  validateDeliveryInput,
  validateV1CardInput,
} from "../src/contract.js";

const exampleUrl = new URL("../examples/v1-card.json", import.meta.url);

function write16(bytes, offset, value) {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
}

function write32(bytes, offset, value) {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
  bytes[offset + 2] = (value >>> 16) & 0xff;
  bytes[offset + 3] = (value >>> 24) & 0xff;
}

function nativeSleepBmp() {
  const bytes = new Uint8Array(209_158);
  bytes[0] = 0x42;
  bytes[1] = 0x4d;
  write32(bytes, 2, bytes.byteLength);
  write32(bytes, 10, 70);
  write32(bytes, 14, 40);
  write32(bytes, 18, 528);
  write32(bytes, 22, 792);
  write16(bytes, 26, 1);
  write16(bytes, 28, 4);
  write32(bytes, 34, 264 * 792);
  write32(bytes, 46, 4);
  const palette = [0, 0, 0, 0, 85, 85, 85, 0, 170, 170, 170, 0, 255, 255, 255, 0];
  bytes.set(palette, 54);
  return bytes;
}

test("safe IDs match the firmware's lowercase path contract", () => {
  assert.equal(isSafeId("reference-article-001"), true);
  assert.equal(isSafeId("Reference"), false);
  assert.equal(isSafeId("../escape"), false);
  assert.equal(isSafeId("a".repeat(33)), false);
});

test("the sanitized V1 example validates and builds a deterministic revision", async () => {
  const input = JSON.parse(await readFile(exampleUrl, "utf8"));
  assert.deepEqual(validateV1CardInput("market-briefing", input), []);
  const first = await buildV1Card("market-briefing", input);
  const second = await buildV1Card("market-briefing", input);
  assert.match(first.revision, /^[0-9a-f]{32}$/);
  assert.equal(first.revision, second.revision);
  assert.equal(first.card.report.bytes, new TextEncoder().encode(input.report_text).byteLength);
  assert.equal(first.card.report.sha256, await sha256Hex(first.reportBytes));
  assert.equal(first.card.report.url, `/v1/reports/market-briefing/${first.revision}.txt`);
});

test("V1 rejects non-allowlisted tasks and oversized renderer text", () => {
  const errors = validateV1CardInput("private-task", {
    generated_at: "2026-01-15T07:00:00+10:00",
    title: "x".repeat(81),
    summary: "summary",
    metrics: [],
    sections: [],
  });
  assert.ok(errors.some((error) => error.includes("allowlist")));
  assert.ok(errors.some((error) => error.includes("title")));
});

test("V2 text and native sleep artifacts enforce the physical byte contracts", () => {
  const text = new TextEncoder().encode("REFERENCE ARTICLE\n\nNo private content.");
  assert.deepEqual(validateArtifact("text", "text/plain; charset=utf-8", text), []);
  assert.ok(validateArtifact("text", "text/plain; charset=utf-8", new Uint8Array([0])).length > 0);

  const sleep = nativeSleepBmp();
  assert.equal(isX3NativeSleepBmp(sleep), true);
  assert.deepEqual(validateArtifact("sleep-screen", "image/bmp", sleep), []);
  sleep[54] = 1;
  assert.equal(isX3NativeSleepBmp(sleep), false);
});

test("V2 delivery metadata, digest and action vocabulary match the firmware", async () => {
  const bytes = new TextEncoder().encode("A small fictional article.");
  const digest = await sha256Hex(bytes);
  const artifact = { sha256: digest, bytes: bytes.byteLength, mime: "text/plain", kind: "text" };
  const input = {
    delivery_id: "delivery-001",
    item_id: "article-001",
    module_id: "daily-fiction",
    kind: "text",
    title: "The Quiet Relay",
    sha256: digest,
    mime: "text/plain",
    actions: ["like", "dislike", "archive"],
    metadata: {
      digest: {
        schema: "xtinct.inbox-digest/v1",
        summary: "A fictional article for a public contract test.",
        points: ["Short daily reading.", "Feedback is returned as a receipt."],
      },
    },
  };
  assert.deepEqual(validateDeliveryInput(input, artifact), []);
  const delivery = await buildDelivery(input, artifact, "2026-01-15T00:00:00.000Z");
  assert.match(delivery.revision, /^[0-9a-f]{64}$/);
  assert.equal(delivery.bytes, bytes.byteLength);
  assert.equal(delivery.created_at, "2026-01-15T00:00:00.000Z");
});

test("acknowledgements and decimal cursors are bounded", () => {
  assert.equal(validateAckEvent({
    event_id: "x3-reference-1760000000-1",
    item_id: "article-001",
    revision: "a".repeat(64),
    type: "like",
    occurred_at: "2026-01-15T00:00:00Z",
    data: {},
  }), true);
  assert.equal(parseDecimalCursor("0"), "0");
  assert.equal(parseDecimalCursor("42"), "42");
  assert.equal(parseDecimalCursor("042"), null);
  assert.equal(parseDecimalCursor("9223372036854775808"), null);
});

