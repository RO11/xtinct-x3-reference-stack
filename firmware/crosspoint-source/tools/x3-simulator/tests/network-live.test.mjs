import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { MAX_INBOX_ITEMS, X3NetworkModel } from "../web/network-model.js";

const simulatorRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
let serverProcess;
let origin;
let cookie = "";

function waitForServer(process) {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => reject(new Error(`simulator did not start: ${stderr}`)), 10000);
    process.stdout.on("data", chunk => {
      stdout += chunk.toString();
      const match = stdout.match(/XTINCT X3 simulator: (http:\/\/127\.0\.0\.1:\d+\/)/);
      if (match) {
        clearTimeout(timeout);
        resolve(match[1].replace(/\/$/, ""));
      }
    });
    process.stderr.on("data", chunk => { stderr += chunk.toString(); });
    process.once("exit", code => {
      clearTimeout(timeout);
      reject(new Error(`simulator exited before startup with ${code}: ${stderr}`));
    });
  });
}

async function cookieFetch(input, init = {}) {
  const requestHeaders = new Headers(init.headers || {});
  if (cookie) requestHeaders.set("Cookie", cookie);
  const response = await fetch(input, { ...init, headers: requestHeaders });
  const setCookie = response.headers.get("set-cookie");
  if (setCookie) cookie = setCookie.split(";", 1)[0];
  return response;
}

async function selectScenario(scenario) {
  const response = await cookieFetch(`${origin}/api/network/scenario`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scenario })
  });
  assert.equal(response.status, 200);
  const status = await response.json();
  assert.equal(status.scenario, scenario);
}

async function serverStatus() {
  const response = await cookieFetch(`${origin}/api/network/status`);
  assert.equal(response.status, 200);
  return response.json();
}

function model() {
  return new X3NetworkModel(cookieFetch, `${origin}/mock`);
}

before(async () => {
  const python = process.env.PYTHON || "python";
  const smokeRunner = `
import sys
import threading
import server

store = server.SessionStore()
httpd = server.X3SimulatorHTTPServer((server.LOOPBACK_HOST, 0), store)
thread = threading.Thread(target=httpd.serve_forever, daemon=True)
thread.start()
print(f"XTINCT X3 simulator: http://{server.LOOPBACK_HOST}:{httpd.server_address[1]}/", flush=True)
try:
    sys.stdin.readline()
finally:
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=2)
    store.close()
`;
  serverProcess = spawn(python, ["-u", "-B", "-c", smokeRunner], {
    cwd: simulatorRoot,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true
  });
  origin = await waitForServer(serverProcess);
});

after(async () => {
  if (!serverProcess || serverProcess.exitCode !== null) return;
  serverProcess.stdin.write("stop\n");
  serverProcess.stdin.end();
  const exited = await new Promise(resolve => {
    const timeout = setTimeout(() => resolve(false), 5000);
    serverProcess.once("exit", () => { clearTimeout(timeout); resolve(true); });
  });
  if (!exited && serverProcess.exitCode === null) {
    serverProcess.kill();
    await new Promise(resolve => serverProcess.once("exit", resolve));
    assert.fail("simulator did not stop cleanly through its test control channel");
  }
});

test("full Daily Cards run downloads exact V1 reports and V2 artifacts over loopback HTTP", async () => {
  await selectScenario("happy-path");
  const client = model();
  const result = await client.runDailyRefresh(20677, { manual: true });
  assert.equal(result.result, "FRESH");
  assert.equal(client.cards().length, 4);
  assert.equal(client.inbox().length, 4);
  assert.equal(client.status().cursor, "4");
  assert.equal(client.status().outboxEvents, 0);
  const today = client.inbox().find(item => item.kind === "epub");
  assert.match(client.documentText(today.itemId), /Inbox downloads and opens a complete local EPUB artifact/);
  assert.match(client.reportText("market-briefing"), /deterministic full report/i);
  const status = await serverStatus();
  assert.equal(status.outbound_network, "disabled");
  assert.equal(status.request_counts["GET /v1/manifest.json"], 1);
  assert.equal(status.request_counts["GET /v2/sync"], 1);
  assert.equal(status.request_counts["POST /v2/acks"], 1);
  assert.equal(status.accepted_event_count, 5); // four downloads plus device status
  assert.equal(status.requests.every(request => request.path.startsWith("/v1/") || request.path.startsWith("/v2/")), true);
});

test("valid ETag cache returns 304 and same-day automatic opening performs no HTTP", async () => {
  await selectScenario("cache-current");
  const client = model();
  await client.runDailyRefresh(20677, { manual: true });
  const firstStatus = await serverStatus();
  const firstRequests = firstStatus.requests.length;
  const cards = await client.syncCards();
  assert.equal(cards.result, "NOT_MODIFIED");
  const after304 = await serverStatus();
  assert.equal(after304.request_counts["GET /v1/manifest.json"], 2);
  assert.equal(after304.request_counts["GET /v1/cards/market-briefing.json"], 1);
  const cached = await client.runDailyRefresh(20677);
  assert.equal(cached.result, "CACHE_FIRST");
  assert.equal(cached.requested, false);
  const finalStatus = await serverStatus();
  assert.equal(finalStatus.requests.length, firstRequests + 1); // the explicit 304 only
});

test("cursor paging commits 8/8/2 pages and applies the final tombstone", async () => {
  await selectScenario("pagination");
  const client = model();
  const result = await client.syncInbox();
  assert.equal(result.pages, 3);
  assert.equal(result.cursor, "18");
  assert.equal(result.complete, true);
  assert.equal(client.inbox().length, 16);
  assert.equal(client.inbox().some(item => item.itemId === "sim-inbox-02"), false);
  const status = await serverStatus();
  assert.equal(status.request_counts["GET /v2/sync"], 3);
  assert.deepEqual(
    status.requests.filter(request => request.path === "/v2/sync").map(request => request.detail),
    ["cursor=0&limit=8", "cursor=8&limit=8", "cursor=16&limit=8"]
  );
});

test("the ten-page safety cap reports catch-up pending instead of current", async () => {
  const requests = [];
  const fakeFetch = async input => {
    const url = new URL(input);
    requests.push(`${url.pathname}?${url.searchParams.toString()}`);
    if (url.pathname === "/v2/acks") {
      return new Response(JSON.stringify({ schema: 2, accepted: 1, duplicates: 0, rejected: 0 }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }
    assert.equal(url.pathname, "/v2/sync");
    const cursor = Number(url.searchParams.get("cursor"));
    const tombstones = Array.from({ length: 8 }, (_, index) => {
      const sequence = cursor + index + 1;
      return {
        delivery_id: `delivery-${sequence}`,
        item_id: `item-${sequence}`,
        revision: sequence.toString(16).padStart(64, "0"),
        deleted_at: "2026-08-12T08:00:00Z"
      };
    });
    return new Response(JSON.stringify({
      schema: 2,
      device_id: "sim-x3-main",
      cursor: String(cursor + tombstones.length),
      has_more: true,
      deliveries: [],
      tombstones
    }), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  const client = new X3NetworkModel(fakeFetch, "https://firmware.test");
  const result = await client.syncInbox();
  assert.equal(result.pages, 10);
  assert.equal(result.cursor, "80");
  assert.equal(result.complete, false);
  assert.equal(result.result, "CATCH_UP_PENDING");
  assert.equal(requests.filter(request => request.startsWith("/v2/sync?")).length, 10);
});

test("a partial V1 manifest is rejected before it can replace the fixed cache", async () => {
  const partial = {
    schema: 1,
    etag: '"partial"',
    cards: ["market-briefing", "weekday-freelancer-scan", "3d-job-search"].map((id, index) => ({
      id,
      revision: String(index + 1).repeat(32),
      url: `/v1/cards/${id}.json`
    }))
  };
  const client = new X3NetworkModel(
    async () => new Response(JSON.stringify(partial), {
      status: 200,
      headers: { "Content-Type": "application/json", ETag: partial.etag }
    }),
    "https://firmware.test"
  );
  await assert.rejects(client.syncCards(), error => error.result === "INVALID_DATA");
  assert.equal(client.cards().length, 0);
});

test("an over-capacity modeled cache still exposes its newest bounded page set", () => {
  const client = model();
  for (let index = 0; index < 65; index += 1) {
    client.inboxMetadata.set(`item-${index}`, {
      delivery_id: `delivery-${index}`,
      item_id: `item-${index}`,
      module_id: "inbox",
      kind: "text",
      title: `Item ${index}`,
      revision: String(index + 1).padStart(64, "0"),
      sha256: String(index + 1).padStart(64, "0"),
      bytes: 1,
      mime: "text/plain; charset=utf-8",
      created_at: `2026-08-12T08:${String(index).padStart(2, "0")}:00Z`,
      state: "new",
      actions: []
    });
  }
  assert.equal(client.inbox().length, 64);
  assert.equal(client.inbox().some(item => item.itemId === "item-0"), false);
});

test("81 live Inbox changes pause after ten pages, keep newest 64 visible, then converge", async () => {
  await selectScenario("catch-up-81");
  const client = model();

  const first = await client.syncInbox();
  assert.equal(first.result, "CATCH_UP_PENDING");
  assert.equal(first.pages, 10);
  assert.equal(first.cursor, "80");
  assert.equal(first.complete, false);
  assert.equal(client.status().inboxCached, 80);
  assert.equal(client.inbox().length, MAX_INBOX_ITEMS);
  assert.equal(client.inbox()[0].itemId, "sim-inbox-80");
  assert.equal(client.inbox().at(-1).itemId, "sim-inbox-17");
  assert.match(client.documentText("sim-inbox-65"), /complete synthetic long-form content/);

  const second = await client.syncInbox();
  assert.equal(second.result, "UPDATED");
  assert.equal(second.pages, 1);
  assert.equal(second.cursor, "81");
  assert.equal(second.complete, true);
  assert.equal(client.status().inboxCached, 81);
  assert.equal(client.inbox().length, MAX_INBOX_ITEMS);
  assert.equal(client.inbox()[0].itemId, "sim-inbox-81");
  assert.equal(client.inbox().at(-1).itemId, "sim-inbox-18");

  const status = await serverStatus();
  assert.equal(status.request_counts["GET /v2/sync"], 11);
  assert.deepEqual(
    status.requests.filter(request => request.path === "/v2/sync").map(request => request.detail),
    [
      "cursor=0&limit=8", "cursor=8&limit=8", "cursor=16&limit=8", "cursor=24&limit=8",
      "cursor=32&limit=8", "cursor=40&limit=8", "cursor=48&limit=8", "cursor=56&limit=8",
      "cursor=64&limit=8", "cursor=72&limit=8", "cursor=80&limit=8"
    ]
  );
});

test("artifact failure preserves cursor and queued failure receipt, then retry resumes safely", async () => {
  await selectScenario("artifact-failure-once");
  const client = model();
  await assert.rejects(client.syncInbox(), error => error.result === "NETWORK_ERROR");
  assert.equal(client.status().cursor, "0");
  assert.equal(client.status().inboxCached, 1);
  assert.equal(client.status().artifactsCached, 1);
  assert.equal(client.status().outboxEvents, 2); // item one downloaded, item two failed
  const retry = await client.syncInbox();
  assert.equal(retry.cursor, "4");
  assert.equal(retry.complete, true);
  assert.equal(client.status().outboxEvents, 0);
  const status = await serverStatus();
  assert.equal(status.request_counts["GET /v2/sync"], 2);
  const artifactRequests = status.requests.filter(request => request.path.startsWith("/v2/artifacts/"));
  assert.equal(artifactRequests.length, 5); // first item once, failed second twice, remaining two once
  const frequencies = new Map();
  for (const request of artifactRequests) frequencies.set(request.path, (frequencies.get(request.path) || 0) + 1);
  assert.deepEqual([...frequencies.values()].sort(), [1, 1, 1, 2]);
  assert.equal(status.accepted_event_count, 6); // failed + four downloads + status
});

test("short V2 artifact preserves the committed prefix and retry converges", async () => {
  await selectScenario("artifact-short-once");
  const client = model();
  await assert.rejects(client.syncInbox(), error => error.result === "INVALID_DATA");
  assert.equal(client.status().cursor, "0");
  assert.equal(client.status().inboxCached, 1);
  assert.equal(client.status().artifactsCached, 1);
  const retry = await client.syncInbox();
  assert.equal(retry.cursor, "4");
  assert.equal(retry.complete, true);
  assert.equal(client.inbox().length, 4);
});

test("short V1 report never commits a partial card transaction and retry succeeds", async () => {
  await selectScenario("report-short-once");
  const client = model();
  await assert.rejects(client.syncCards(), error => error.result === "INVALID_DATA");
  assert.equal(client.cards().length, 0);
  assert.equal(client.status().cardsCached, 0);
  const retry = await client.syncCards();
  assert.equal(retry.result, "UPDATED");
  assert.equal(client.cards().length, 4);
});

test("ACK failure leaves exact outbox prefix intact and later retry clears it", async () => {
  await selectScenario("ack-failure-once");
  const client = model();
  await client.syncInbox();
  assert.equal(client.status().outboxEvents, 5);
  assert.equal(client.status().receipts, "NETWORK_ERROR");
  const retry = await client.flushOutbox();
  assert.equal(retry.result, "UPDATED");
  assert.equal(retry.sent, 5);
  assert.equal(retry.remaining, 0);
  const status = await serverStatus();
  assert.equal(status.request_counts["POST /v2/acks"], 2);
  assert.equal(status.accepted_event_count, 5);
});

test("opening is best effort and delete remains local even before its receipt is sent", async () => {
  await selectScenario("happy-path");
  const client = model();
  await client.syncInbox();
  const selected = client.inbox()[0];
  assert.equal(client.recordOpenedBestEffort(selected.itemId), true);
  const deletion = client.applyInboxAction(selected.itemId, "delete");
  assert.deepEqual(deletion, { queued: true, local: true });
  assert.equal(client.inbox().some(item => item.itemId === selected.itemId), false);
  assert.equal(client.status().outboxEvents, 2);
  await client.flushOutbox();
  assert.equal(client.status().outboxEvents, 0);
});

test("full outbox blocks non-delete actions but never traps a local delete", async () => {
  await selectScenario("happy-path");
  const client = model();
  await client.syncInbox();
  const archiveItem = client.inbox()[0];
  client.outbox = Array.from({ length: 48 }, (_, index) => ({
    event_id: `sim-x3-main-1786492800-${index + 100}`,
    item_id: "device-status",
    revision: "0".repeat(64),
    type: "device-status",
    occurred_at: "2026-08-12T08:00:00Z",
    data: {}
  }));
  assert.deepEqual(client.applyInboxAction(archiveItem.itemId, "archive"), { queued: false, local: false });
  assert.equal(client.inbox().some(item => item.itemId === archiveItem.itemId), true);
  assert.deepEqual(client.applyInboxAction(archiveItem.itemId, "delete"), { queued: false, local: true });
  assert.equal(client.inbox().some(item => item.itemId === archiveItem.itemId), false);
});

test("terminal feedback actions remove only after the receipt is queued", async () => {
  await selectScenario("happy-path");
  const client = model();
  await client.syncInbox();
  const liked = client.inbox()[0];
  assert.deepEqual(client.applyInboxAction(liked.itemId, "like"), { queued: true, local: true });
  assert.equal(client.inbox().some(item => item.itemId === liked.itemId), false);
});

for (const [scenario, expected] of [
  ["no-config", "NO_CONFIG"],
  ["no-wifi", "NO_WIFI"],
  ["clock-error", "CLOCK_ERROR"],
  ["storage-error", "STORAGE_ERROR"]
]) {
  test(`${scenario} fails before any feed HTTP request`, async () => {
    await selectScenario(scenario);
    const client = model();
    client.setEnvironmentScenario(scenario);
    if (scenario === "storage-error") {
      await assert.rejects(client.runDailyRefresh(20677, { manual: true }), error => error.result === expected);
    } else {
      const result = await client.runDailyRefresh(20677, { manual: true });
      assert.equal(result.result, expected);
    }
    const status = await serverStatus();
    assert.equal(status.requests.length, 0);
  });
}

test("malformed response is rejected before cache/cursor mutation", async () => {
  await selectScenario("malformed-payload");
  const client = model();
  await assert.rejects(client.syncCards(), error => error.result === "INVALID_DATA");
  await assert.rejects(client.syncInbox(), error => error.result === "INVALID_DATA");
  assert.equal(client.cards().length, 0);
  assert.equal(client.inbox().length, 0);
  assert.equal(client.status().cursor, "0");
});
