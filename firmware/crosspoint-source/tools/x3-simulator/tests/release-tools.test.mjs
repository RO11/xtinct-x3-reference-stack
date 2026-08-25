import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  MAX_RECORDED_INPUTS,
  appendInputAction,
  createInputRecording,
  createSanitizedBugBundle,
  deriveFirmwareContext,
  validateInputRecording
} from "../web/simulator-core.js";
import {
  SyntheticNetworkController,
  normalizeSyntheticNetworkOverrides
} from "../web/network-model.js";

const simulatorRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("input recordings contain only bounded, replayable device actions", () => {
  let recording = createInputRecording();
  recording = appendInputAction(recording, "confirm", "home", 0);
  recording = appendInputAction(recording, "down", "inbox", 24);
  assert.deepEqual(validateInputRecording(recording), recording);
  assert.throws(
    () => validateInputRecording({ ...recording, content: "private article body" }),
    /only schema, type and actions/
  );
  assert.throws(
    () => validateInputRecording({ ...recording, actions: [{ at_ms: 0, button: "touch", route: "home" }] }),
    /unsupported button/
  );
  assert.throws(
    () => validateInputRecording({ ...recording, actions: [{ at_ms: 0, button: "confirm", route: "C:\\Users\\person" }] }),
    /invalid route/
  );
  assert.throws(
    () => validateInputRecording({ ...recording, actions: Array.from({ length: MAX_RECORDED_INPUTS + 1 }) }),
    /limited/
  );
  assert.throws(() => appendInputAction(recording, "confirm", "home", 300001), /five-minute/);
});

test("bug bundle is constructed from a privacy-safe allowlist", () => {
  const secret = "SECRET-CONTENT-BODY";
  const bundle = createSanitizedBugBundle({
    appVersion: "0.1.0-alpha",
    generatedAt: "2026-08-24T00:00:00Z",
    contractLoaded: true,
    firmwareLoaded: true,
    networkAvailable: true,
    firmware: {
      exists: true,
      byteCount: 1234,
      sha256: "a".repeat(64),
      headerValid: true,
      budgetStatus: "pass",
      path: `C:\\Users\\person\\${secret}`,
      buildId: secret
    },
    qemu: { available: true, fullFlashReady: false, ready: false, path: secret },
    network: {
      scenario: "happy-path", cards: "UPDATED", inbox: "CURRENT", receipts: "CURRENT",
      cursor: secret, pages: 1, cardsCached: 4, inboxCached: 3, artifactsCached: 3, outboxEvents: 0,
      requests: [{ url: `https://example.invalid/?token=${secret}` }]
    },
    overrides: { latency_ms: 25, interrupt_target: "artifact", interrupt_after_bytes: 512, url: secret },
    session: {
      route: "inbox", sdEntryCount: 12, recordedActions: 2,
      inputHistogram: { confirm: 1, down: 1 }, title: secret, content: secret
    }
  });
  const exported = JSON.stringify(bundle);
  assert.doesNotMatch(exported, /SECRET-CONTENT-BODY|C:\\\\Users|example\.invalid|token=/);
  assert.equal(bundle.privacy.includes("no paths"), true);
  assert.equal(bundle.app.version, "0.1.0-alpha");
  assert.equal(bundle.evidence.qemu, false);
  assert.equal(bundle.evidence.physical_device_required, true);
  assert.equal(bundle.firmware_context.optional_local_image, "READ-ONLY IMAGE SELECTED");
  assert.equal(bundle.firmware_context.physical_x3, "NOT READ BY THIS APP · INSTALLED VERSION UNKNOWN");
  assert.deepEqual(bundle.session.input_histogram, { confirm: 1, down: 1 });
});

test("firmware context separates package, preview, optional image, QEMU and physical device", () => {
  const empty = deriveFirmwareContext({
    firmware: { exists: false },
    qemu: { qemu: { available: false }, full_flash_inputs: { ready: false }, ready_to_execute: false }
  });
  assert.equal(empty.package.status, "BUNDLED CROSSPOINT BASELINE UNAVAILABLE");
  assert.equal(empty.preview.status, "SYNTHETIC PREVIEW · NOT FIRMWARE EXECUTION");
  assert.equal(empty.localImage.status, "NONE SELECTED");
  assert.equal(empty.qemu.status, "NOT BUNDLED · NOT STARTED");
  assert.equal(empty.physicalX3.status, "NOT READ BY THIS APP · INSTALLED VERSION UNKNOWN");

  const inspected = deriveFirmwareContext({
    firmware: { exists: true, execution: "disabled" },
    qemu: { qemu: { available: true }, full_flash_inputs: { ready: false }, ready_to_execute: false }
  });
  assert.equal(inspected.localImage.status, "READ-ONLY IMAGE SELECTED");
  assert.match(inspected.localImage.detail, /does not draw the preview/i);
  assert.equal(inspected.preview.status, empty.preview.status, "selecting an image never changes preview provenance");
  assert.equal(inspected.qemu.status, "NOT BUNDLED · DETECTED, NOT STARTED");

  const bundled = deriveFirmwareContext({
    firmware: {
      exists: true,
      package_firmware_bundled: true,
      bundled_baseline_available: true,
      source_kind: "bundled-baseline",
      baseline_version: "v1.5.0"
    },
    qemu: { qemu: { available: false }, full_flash_inputs: { ready: false }, ready_to_execute: false }
  });
  assert.equal(bundled.package.status, "CROSSPOINT v1.5.0 STABLE INCLUDED · READ-ONLY");
  assert.equal(bundled.localImage.status, "BUNDLED BASELINE SELECTED");
  assert.match(bundled.package.detail, /hash-checked/i);

  const readyButNotStarted = deriveFirmwareContext({
    firmware: { exists: true },
    qemu: {
      qemu: { available: true },
      full_flash_inputs: { ready: true },
      ready_to_execute: true,
      execution: "running"
    }
  });
  assert.equal(readyButNotStarted.qemu.status, "NOT BUNDLED · READY, NOT STARTED");
  assert.doesNotMatch(JSON.stringify(readyButNotStarted), /\brunning\b/i, "UI must never infer an active QEMU run");
});

test("synthetic overrides reject URL fields and enforce bounded fault controls", () => {
  assert.deepEqual(normalizeSyntheticNetworkOverrides({}), {
    latency_ms: 0,
    interrupt_target: "none",
    interrupt_after_bytes: 1024
  });
  assert.throws(() => normalizeSyntheticNetworkOverrides({ url: "https://example.com" }), /unsupported fields/);
  assert.throws(() => normalizeSyntheticNetworkOverrides({ latency_ms: 1501 }), /0-1500/);
  assert.throws(() => normalizeSyntheticNetworkOverrides({ interrupt_target: "redirect" }), /not allowed/);
  assert.throws(() => normalizeSyntheticNetworkOverrides({ interrupt_after_bytes: 0 }), /1-65536/);
});

test("synthetic interruption is one-shot and cannot leave the same-origin mock namespace", async () => {
  const body = new TextEncoder().encode("0123456789");
  let calls = 0;
  let observedInit;
  const transport = new SyntheticNetworkController(async (_input, init) => {
    calls += 1;
    observedInit = init;
    return new Response(body, {
      status: 200,
      headers: { "content-type": "application/json", "content-length": String(body.byteLength) }
    });
  });
  transport.configure({ latency_ms: 0, interrupt_target: "sync", interrupt_after_bytes: 4 });
  const interrupted = await transport.fetch("/mock/v2/sync?cursor=0&limit=8");
  assert.equal((await interrupted.arrayBuffer()).byteLength, 4);
  assert.equal(observedInit.redirect, "error", "fixture fetch refuses redirects instead of following an outbound target");
  assert.equal(interrupted.headers.get("content-length"), "10", "original declared length exposes interruption");
  assert.equal(transport.status().interruption_consumed, true);
  const retried = await transport.fetch("/mock/v2/sync?cursor=0&limit=8");
  assert.equal((await retried.arrayBuffer()).byteLength, 10);
  assert.equal(calls, 2);
  await assert.rejects(
    transport.fetch("https://example.com/mock/v2/sync"),
    error => error.result === "NETWORK_ERROR"
  );
  assert.equal(calls, 2, "blocked URL never reaches the wrapped fetch implementation");
});

test("release UI makes every evidence boundary and complementary simulator relationship explicit", () => {
  const html = fs.readFileSync(path.join(simulatorRoot, "web", "index.html"), "utf8");
  const app = fs.readFileSync(path.join(simulatorRoot, "web", "app.js"), "utf8");
  const core = fs.readFileSync(path.join(simulatorRoot, "web", "simulator-core.js"), "utf8");
  for (const label of ["MODELED", "REAL CONTRACT TEST", "QEMU", "PHYSICAL DEVICE REQUIRED"]) {
    assert.match(html, new RegExp(label));
  }
  assert.match(html, /synthetic demo content is already loaded/i);
  assert.match(html, /What firmware does this lab come with\?/i);
  assert.match(html, /CROSSPOINT v1\.5\.0 STABLE INCLUDED · READ-ONLY/);
  assert.match(html, /SYNTHETIC PREVIEW · NOT FIRMWARE EXECUTION/);
  assert.match(html, /NOT READ BY THIS APP · INSTALLED VERSION UNKNOWN/);
  assert.match(html, /sanitized bug bundle/i);
  assert.match(app, /firmware\?\.exists === true/);
  assert.match(app, /NOT PROVIDED/);
  assert.match(app, /Selected firmware metadata/);
  assert.match(app, /does not draw the preview/);
  assert.match(app, /json\("\/api\/release"\)/);
  assert.match(app, /appVersion: release\?\.version \|\| "development"/);
  assert.match(app, /firmwareLoaded: firmware\?\.exists === true/);
  assert.match(app, /Run state<\/dt><dd>NOT STARTED/);
  assert.match(app, /complementary source-level rendering tool/);
  assert.match(app, /does not integrate with, proxy or replace it/);
  assert.doesNotMatch(html, /type="url"/i, "synthetic editor exposes no arbitrary URL field");
  assert.doesNotMatch(
    `${html}\n${app}\n${core}`,
    /Private Project|Private City|Sensitive Generator|Private Mail Watch/i,
    "visible demo defaults contain no personal project, location or provider history"
  );
});

test("inspector tabs and canvas tools expose bounded keyboard and accessibility semantics", () => {
  const html = fs.readFileSync(path.join(simulatorRoot, "web", "index.html"), "utf8");
  const app = fs.readFileSync(path.join(simulatorRoot, "web", "app.js"), "utf8");
  assert.match(html, /role="tablist"[^>]*aria-label="Inspector panels"/);
  assert.equal((html.match(/role="tab"/g) || []).length, 6);
  assert.equal((html.match(/role="tabpanel"/g) || []).length, 6);
  assert.equal((html.match(/role="tabpanel"[^>]*hidden/g) || []).length, 5, "only the active panel is exposed initially");
  for (const name of ["firmware", "contract", "session", "network", "visual", "qemu"]) {
    assert.match(html, new RegExp(`id="tab-${name}"[^>]+aria-controls="panel-${name}"[^>]+aria-selected=`));
    assert.match(html, new RegExp(`id="panel-${name}"[^>]+aria-labelledby="tab-${name}"`));
  }
  assert.match(app, /tab\.setAttribute\("aria-selected", String\(active\)\)/);
  assert.match(app, /panel\.hidden = !active/);
  assert.match(app, /\["ArrowRight", "ArrowDown"\]/);
  assert.match(app, /event\.key === "Home"/);
  assert.match(app, /event\.key === "End"/);
  assert.match(html, /id="x3-screen"[^>]+tabindex="0"[^>]+aria-describedby="x3-keyboard-help"/);
  assert.match(html, /id="visual-diff"[^>]+role="img"[^>]+hidden/);
  assert.match(html, /id="visual-baseline"[^>]+aria-describedby="visual-privacy-note visual-baseline-state"/);
  assert.match(html, /id="visual-candidate"[^>]+aria-describedby="visual-privacy-note visual-candidate-state"/);
});
