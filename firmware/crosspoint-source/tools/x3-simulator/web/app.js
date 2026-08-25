import {
  MAX_RECORDED_INPUTS,
  appendInputAction,
  createInputRecording,
  createSanitizedBugBundle,
  createState,
  decodeX3Bmp,
  deriveFirmwareContext,
  inboxActions,
  reduceInput,
  validateInputRecording
} from "./simulator-core.js";
import {
  NetworkContractError,
  SyntheticNetworkController,
  X3NetworkModel,
  normalizeSyntheticNetworkOverrides
} from "./network-model.js";
import { X3Renderer } from "./x3-renderer.js";

const canvas = document.querySelector("#x3-screen");
const renderer = new X3Renderer(canvas);
let fixtures;
let state;
let contract = null;
let firmware = null;
let qemu = null;
let release = null;
let sdEntries = [];
let networkScenarios = null;
let networkServerStatus = null;
let networkBusy = false;
let inputRecording = createInputRecording();
let recordingEnabled = true;
let recordingStartedAt = performance.now();
let replayBusy = false;
let recordingMessage = "Ready to capture a reproducible input sequence.";
let visualBaseline = null;
let visualCandidate = null;
let visualSummary = null;
const syntheticNetwork = new SyntheticNetworkController(globalThis.fetch.bind(globalThis));
const networkModel = new X3NetworkModel(syntheticNetwork.fetch.bind(syntheticNetwork));

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function downloadJson(filename, value) {
  const blob = new Blob([`${JSON.stringify(value, null, 2)}\n`], { type: "application/json" });
  const link = document.createElement("a");
  const objectUrl = URL.createObjectURL(blob);
  link.download = filename;
  link.href = objectUrl;
  link.click();
  setTimeout(() => URL.revokeObjectURL(objectUrl), 0);
}

async function json(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

function publicDemoFixtures(raw) {
  const cardTemplates = [
    {
      title: "Sample Project Pulse",
      summary: "A synthetic status snapshot for checking card layout, metrics and report navigation.",
      metrics: [{ value: "4", label: "items" }, { value: "2", label: "watch" }, { value: "Low", label: "urgency" }],
      sections: [{ heading: "TODAY", lines: ["Review the sample milestone", "Choose one bounded next action"] }]
    },
    {
      title: "Sample Queue Review",
      summary: "A synthetic queue summary with no account, provider or personal message history.",
      metrics: [{ value: "0", label: "urgent" }, { value: "3", label: "reviewed" }],
      sections: [{ heading: "QUEUE", lines: ["No response required", "Demo follow-up remains on schedule"] }]
    }
  ];
  const inboxTemplates = [
    {
      title: "Sample Daily Digest",
      summary: "A synthetic daily edition for checking EPUB download and reader behavior.",
      points: ["No real calendar is connected", "All content is generated demo data"]
    },
    {
      title: "Sample Technical Note",
      summary: "A synthetic reading note for checking text artifact and feedback actions.",
      points: ["Fixture bytes stay on loopback", "No external provider is contacted"]
    },
    {
      title: "Sample Local Guide",
      summary: "A synthetic local guide for checking longer titles and digest points.",
      points: ["Choose one demo activity", "Verify details in a real workflow later"]
    }
  ];
  return {
    schema: "x3-preview-lab-demo/1",
    clock: "2026-01-15T08:00:00Z",
    timezone: "UTC",
    batteryPercent: Number.isFinite(raw?.batteryPercent) ? raw.batteryPercent : 83,
    recentBooks: [{
      title: "Sample Daily Digest",
      author: "Demo source",
      kind: "epub",
      spines: [[
        "Welcome to the offline X3 Preview Lab. This edition contains synthetic content only.",
        "Use the modeled page controls to check navigation, progress and end-of-book behavior."
      ]]
    }],
    cards: (raw?.cards || []).map((card, index) => ({
      taskId: card.taskId,
      status: "Demo",
      generatedAt: "2026-01-15T08:00:00Z",
      hasReport: Boolean(card.hasReport),
      ...(cardTemplates[index] || {
        title: `Sample Card ${index + 1}`,
        summary: "Synthetic card content for layout and navigation testing.",
        metrics: [{ value: String(index + 1), label: "sample" }],
        sections: [{ heading: "DEMO", lines: ["No production source is connected"] }]
      })
    })),
    inbox: (raw?.inbox || []).map((item, index) => {
      const template = inboxTemplates[index] || {
        title: `Sample Inbox Item ${index + 1}`,
        summary: "Synthetic inbox content for layout and action testing.",
        points: ["No private source data"]
      };
      return {
        itemId: `demo-inbox-${String(index + 1).padStart(2, "0")}`,
        moduleId: "demo-source",
        kind: item.kind || "text",
        title: template.title,
        createdAt: "2026-01-15T08:00:00Z",
        state: "pending",
        digest: { schema: "xtinct.inbox-digest/v1", summary: template.summary, points: template.points }
      };
    })
  };
}

async function loadSleep() {
  const response = await fetch("/api/sd/file?path=%2Fsleep.bmp");
  if (!response.ok) throw new Error("sleep.bmp not available in cloned SD");
  const decoded = decodeX3Bmp(await response.arrayBuffer());
  renderer.setSleepImage(new ImageData(decoded.pixels, decoded.width, decoded.height));
}

function renderFirmwareContext() {
  const context = deriveFirmwareContext({ firmware, qemu });
  const rows = [
    ["#firmware-context-package", "Package", context.package],
    ["#firmware-context-preview", "Preview", context.preview],
    ["#firmware-context-local", "Selected inspection image", context.localImage],
    ["#firmware-context-qemu", "QEMU", context.qemu],
    ["#firmware-context-physical", "Physical X3", context.physicalX3]
  ];
  for (const [selector, label, item] of rows) {
    const target = document.querySelector(selector);
    target.textContent = item.status;
    target.setAttribute("aria-label", `${label}: ${item.status}. ${item.detail}`);
  }
  document.querySelector("#firmware-context").setAttribute("aria-busy", "false");
}

function renderInspector() {
  const firmwarePanel = document.querySelector("#panel-firmware");
  const firmwareProvided = firmware?.exists === true;
  const headroom = firmware?.ota_headroom_bytes ?? null;
  const headroomStatus = firmware?.budget_status || "unknown";
  const headroomLabel = headroom == null
    ? "—"
    : `${headroom.toLocaleString()} B${headroomStatus === "pass" ? "" : ` · ${headroomStatus.toUpperCase()}`}`;
  firmwarePanel.innerHTML = `
    <h2><span class="mini-evidence modeled">MODELED</span> Selected firmware metadata</h2>
    <p class="boundary-callout"><strong>This selected image does not draw the preview.</strong><br>It is inspected read-only; header and resource metadata do not mean firmware execution.</p>
    <dl>
      <dt>Build</dt><dd>${escapeHtml(firmwareProvided ? (firmware?.embedded_build_id || "Unknown") : "Not configured")}</dd>
      <dt>Image label</dt><dd>${escapeHtml(firmwareProvided ? (firmware?.path || "Selected image") : "Not configured")}</dd>
      <dt>Bytes</dt><dd>${firmware?.byte_count?.toLocaleString() || "—"}</dd>
      <dt>SHA-256</dt><dd>${escapeHtml(firmware?.sha256 || "—")}</dd>
      <dt>ESP32-C3 image</dt><dd class="${firmwareProvided ? (firmware?.esp32c3_image_valid ? "pass" : "warn") : ""}">${firmwareProvided ? (firmware?.esp32c3_image_valid ? "HEADER PASS" : "NOT VALID") : "NOT PROVIDED"}</dd>
      <dt>OTA headroom</dt><dd class="${firmwareProvided ? (headroomStatus === "pass" ? "pass" : "warn") : ""}">${headroomLabel}</dd>
      <dt>Execution</dt><dd>${escapeHtml(firmware?.execution || "disabled")}</dd>
    </dl>`;
  const device = contract?.device || {};
  const sleep = contract?.data_limits?.sleep_screen || {};
  document.querySelector("#panel-contract").innerHTML = `
    <h2><span class="mini-evidence contract">REAL CONTRACT TEST</span> X3 contract</h2>
    <dl>
      <dt>Model</dt><dd>${escapeHtml(device.model || "Xteink X3")}</dd>
      <dt>MCU</dt><dd>${escapeHtml(device.mcu || "ESP32-C3")}</dd>
      <dt>Logical frame</dt><dd>${sleep.portrait_width_pixels || 528} × ${sleep.portrait_height_pixels || 792}</dd>
      <dt>Gray levels</dt><dd>${device.display_levels || 4}</dd>
      <dt>PSRAM</dt><dd>${device.psram_bytes || 0} B</dd>
      <dt>OTA slot</dt><dd>${device.ota_slot_bytes?.toLocaleString() || "—"} B</dd>
      <dt>Sleep BMP</dt><dd>${sleep.bits_per_pixel || 4} bpp / ${sleep.bmp_file_bytes?.toLocaleString() || "—"} B</dd>
      <dt>Network</dt><dd>DISABLED</dd>
    </dl>`;
  document.querySelector("#session-status").innerHTML = `
    <dt>Route</dt><dd>${escapeHtml(state?.route || "—")}</dd>
    <dt>Cards</dt><dd>${state?.fixtures.cards.length ?? 0}</dd>
    <dt>Inbox items</dt><dd>${state?.fixtures.inbox.length ?? 0}</dd>
    <dt>SD entries</dt><dd>${sdEntries.length}</dd>
    <dt>Recorded inputs</dt><dd>${inputRecording.actions.length} / ${MAX_RECORDED_INPUTS}</dd>
    <dt>Cloned SD</dt><dd>READ-ONLY</dd>
    <dt>Touch / radio</dt><dd>NOT EMULATED</dd>`;
  const recordingState = document.querySelector("#recording-state");
  recordingState.textContent = replayBusy ? "REPLAYING" : recordingEnabled ? "RECORDING" : "PAUSED";
  recordingState.classList.toggle("paused", !recordingEnabled || replayBusy);
  const toggleRecording = document.querySelector("#toggle-recording");
  toggleRecording.textContent = recordingEnabled ? "Pause" : "Resume";
  toggleRecording.setAttribute("aria-pressed", String(recordingEnabled));
  toggleRecording.disabled = replayBusy;
  document.querySelector("#clear-recording").disabled = replayBusy || inputRecording.actions.length === 0;
  document.querySelector("#export-recording").disabled = replayBusy || inputRecording.actions.length === 0;
  document.querySelector("#replay-recording").disabled = replayBusy;
  document.querySelector("#recording-message").textContent = recordingMessage;
  renderQemuInspector();
  renderEvidenceState();
  renderFirmwareContext();
  renderNetworkInspector();
}

function renderEvidenceState() {
  const contractCard = document.querySelector(".evidence-contract");
  const qemuCard = document.querySelector(".evidence-qemu");
  contractCard.classList.toggle("evidence-unavailable", !networkScenarios);
  qemuCard.classList.toggle("evidence-unavailable", !qemu?.ready_to_execute);
  contractCard.querySelector("span").textContent = networkScenarios
    ? "Available · isolated HTTP bytes and transaction seams"
    : "Unavailable · fixture server did not load";
  const qemuDetected = Boolean(qemu?.qemu?.available);
  qemuCard.querySelector("span").textContent = qemu?.ready_to_execute
    ? "Ready, not started · separate local runtime, never bundled"
    : qemuDetected
      ? "Detected, not started · full-flash execution is blocked"
      : "Optional, not bundled · execution is not started";
}

function renderQemuInspector() {
  const panel = document.querySelector("#panel-qemu");
  const qemuAvailable = Boolean(qemu?.qemu?.available);
  const flashReady = Boolean(qemu?.full_flash_inputs?.ready);
  const ready = Boolean(qemu?.ready_to_execute);
  panel.innerHTML = `
    <h2><span class="mini-evidence qemu">QEMU</span> Advanced execution</h2>
    <p class="network-note">QEMU is optional, offline and never bundled with this Preview Lab. Detection refers only to a separate runtime on this computer. An OTA <code>update.bin</code> alone is not a bootable full-flash image.</p>
    <dl>
      <dt>ESP32-C3 QEMU</dt><dd class="${qemuAvailable ? "pass" : "warn"}">${qemuAvailable ? "DETECTED ON THIS COMPUTER" : "NOT DETECTED"}</dd>
      <dt>Matching flash set</dt><dd class="${flashReady ? "pass" : "warn"}">${flashReady ? "READY" : "NOT RETAINED"}</dd>
      <dt>Execution readiness</dt><dd class="${ready ? "pass" : "warn"}">${ready ? "READY" : "BLOCKED"}</dd>
      <dt>Run state</dt><dd>NOT STARTED</dd>
      <dt>Network</dt><dd>DISABLED</dd>
    </dl>
    <div class="qemu-requirements">
      <h3>One authoritative build must retain</h3>
      <ul>
        <li><code>bootloader.bin</code></li>
        <li><code>partitions.bin</code></li>
        <li><code>firmware.bin</code></li>
        <li><code>boot_app0.bin</code></li>
      </ul>
    </div>
    <p class="boundary-callout"><strong>PHYSICAL DEVICE REQUIRED</strong><br>Even a successful QEMU boot cannot prove E-Ink waveform, ADC buttons, microSD power-loss recovery, Wi-Fi/Bluetooth, RTC wake or battery use.</p>
    <p class="network-note">The <a href="https://github.com/crosspoint-reader/crosspoint-simulator" target="_blank" rel="noopener noreferrer">official CrossPoint Simulator</a> is a complementary source-level rendering tool. This Preview Lab does not integrate with, proxy or replace it.</p>`;
}

function renderNetworkInspector() {
  const panel = document.querySelector("#panel-network");
  if (!panel) return;
  if (!panel.querySelector("#network-scenario")) {
    const options = (networkScenarios?.scenarios || [])
      .map(scenario => `<option value="${escapeHtml(scenario.id)}">${escapeHtml(scenario.id)}</option>`)
      .join("");
    panel.innerHTML = `
      <h2><span class="mini-evidence contract">REAL CONTRACT TEST</span> Local HTTP</h2>
      <p class="network-note">Real same-origin HTTP bytes over synthetic fixtures. Production, device access and arbitrary outbound URLs are disabled.</p>
      <label for="network-scenario">Deterministic scenario</label>
      <select id="network-scenario" ${networkBusy ? "disabled" : ""}>${options}</select>
      <div class="network-actions">
        <button id="network-run-all" ${networkBusy ? "disabled" : ""}>Run Cards + Inbox</button>
        <button id="network-flush" ${networkBusy ? "disabled" : ""}>Retry receipts</button>
      </div>
      <dl id="network-status"></dl>
      <fieldset class="synthetic-editor">
        <legend>Safe synthetic overrides</legend>
        <p>Layer bounded delay or one interrupted response onto the selected fixture. No host or URL field exists.</p>
        <label for="network-latency">Delay each fixture request (0–1500 ms)</label>
        <input id="network-latency" type="number" min="0" max="1500" step="25" value="0" inputmode="numeric">
        <label for="network-interrupt">Interrupt once</label>
        <select id="network-interrupt">
          <option value="none">None</option>
          <option value="artifact">Artifact download</option>
          <option value="report">Card report</option>
          <option value="sync">Inbox sync page</option>
          <option value="manifest">Cards manifest</option>
          <option value="card">Card JSON</option>
          <option value="ack">Receipt response</option>
        </select>
        <label for="network-interrupt-bytes">Cut after bytes (1–65536)</label>
        <input id="network-interrupt-bytes" type="number" min="1" max="65536" step="1" value="1024" inputmode="numeric">
        <div class="network-actions">
          <button id="network-apply-overrides" type="button">Apply overrides</button>
          <button id="network-clear-overrides" type="button">Clear overrides</button>
        </div>
        <p id="network-override-message" class="tool-message" aria-live="polite">Default transport; no injected delay or interruption.</p>
      </fieldset>`;
    const select = panel.querySelector("#network-scenario");
    if (networkServerStatus?.scenario) select.value = networkServerStatus.scenario;
    select.addEventListener("change", () => selectNetworkScenario(select.value));
    panel.querySelector("#network-run-all").addEventListener("click", () => runFullNetworkSync());
    panel.querySelector("#network-flush").addEventListener("click", () => retryReceipts());
    panel.querySelector("#network-apply-overrides").addEventListener("click", applyNetworkOverrides);
    panel.querySelector("#network-clear-overrides").addEventListener("click", clearNetworkOverrides);
  }
  const select = panel.querySelector("#network-scenario");
  const runButton = panel.querySelector("#network-run-all");
  const flushButton = panel.querySelector("#network-flush");
  if (select) select.disabled = networkBusy;
  if (runButton) runButton.disabled = networkBusy;
  if (flushButton) flushButton.disabled = networkBusy;
  panel.querySelectorAll(".synthetic-editor input, .synthetic-editor select, .synthetic-editor button")
    .forEach(control => { control.disabled = networkBusy; });
  const client = networkModel.status();
  const injected = syntheticNetwork.status();
  const requestCount = Object.values(networkServerStatus?.request_counts || {})
    .reduce((total, value) => total + Number(value), 0);
  const status = panel.querySelector("#network-status");
  if (status) status.innerHTML = `
    <dt>Isolation</dt><dd class="pass">LOOPBACK ONLY</dd>
    <dt>Scenario</dt><dd>${escapeHtml(networkServerStatus?.scenario || "loading")}</dd>
    <dt>Cards V1</dt><dd>${escapeHtml(client.cards)}</dd>
    <dt>Inbox V2</dt><dd>${escapeHtml(client.inbox)}</dd>
    <dt>Cursor / pages</dt><dd>${escapeHtml(client.cursor)} / ${client.pages}</dd>
    <dt>Cached</dt><dd>${client.cardsCached} cards · ${client.inboxCached} inbox · ${client.artifactsCached} artifacts</dd>
    <dt>Outbox</dt><dd>${client.outboxEvents} queued · ${escapeHtml(client.receipts)}</dd>
    <dt>Injected fault</dt><dd>${injected.interrupt_target === "none" ? "NONE" : `${escapeHtml(injected.interrupt_target).toUpperCase()}${injected.interruption_consumed ? " · USED" : " · ARMED"}`}</dd>
    <dt>Daily proof</dt><dd>${client.inboxCompleteToday && client.freshDay ? "COMPLETE" : "NOT COMPLETE"}</dd>
    <dt>HTTP requests</dt><dd>${requestCount}</dd>`;
}

function applyNetworkOverrides() {
  const panel = document.querySelector("#panel-network");
  const message = panel.querySelector("#network-override-message");
  try {
    const overrides = normalizeSyntheticNetworkOverrides({
      latency_ms: Number(panel.querySelector("#network-latency").value),
      interrupt_target: panel.querySelector("#network-interrupt").value,
      interrupt_after_bytes: Number(panel.querySelector("#network-interrupt-bytes").value)
    });
    syntheticNetwork.configure(overrides);
    message.textContent = overrides.interrupt_target === "none"
      ? `Applied ${overrides.latency_ms} ms bounded fixture delay.`
      : `Armed one ${overrides.interrupt_target} interruption after ${overrides.interrupt_after_bytes} bytes, with ${overrides.latency_ms} ms delay.`;
    state.refreshState = "Synthetic overrides applied";
    paint();
  } catch (error) {
    message.textContent = error.message;
  }
}

function clearNetworkOverrides() {
  const panel = document.querySelector("#panel-network");
  panel.querySelector("#network-latency").value = "0";
  panel.querySelector("#network-interrupt").value = "none";
  panel.querySelector("#network-interrupt-bytes").value = "1024";
  syntheticNetwork.configure({});
  panel.querySelector("#network-override-message").textContent = "Default transport; no injected delay or interruption.";
  state.refreshState = "Synthetic overrides cleared";
  paint();
}

function paint() {
  renderer.render(state);
  renderInspector();
  const flash = document.querySelector("#refresh-flash");
  flash.classList.remove("flash");
  requestAnimationFrame(() => flash.classList.add("flash"));
}

function demoDay() {
  const epoch = Date.parse(fixtures.clock);
  return Math.floor(epoch / (24 * 60 * 60 * 1000));
}

function useNetworkFixtures() {
  const cards = networkModel.cards();
  const inbox = networkModel.inbox();
  const publicView = publicDemoFixtures({ cards, inbox, batteryPercent: fixtures.batteryPercent });
  const safeCards = cards.map((card, index) => ({
    ...card,
    title: publicView.cards[index].title,
    summary: publicView.cards[index].summary,
    metrics: publicView.cards[index].metrics,
    sections: publicView.cards[index].sections
  }));
  const safeInbox = inbox.map((item, index) => ({
    ...item,
    moduleId: "demo-source",
    title: publicView.inbox[index].title,
    digest: publicView.inbox[index].digest
  }));
  state.fixtures = {
    ...state.fixtures,
    cards: safeCards.length ? safeCards : state.fixtures.cards,
    inbox: safeInbox.length || networkModel.status().cursor !== "0" ? safeInbox : state.fixtures.inbox
  };
  state.cardIndex = Math.min(state.cardIndex, Math.max(0, state.fixtures.cards.length - 1));
  state.inboxIndex = Math.min(state.inboxIndex, Math.max(0, state.fixtures.inbox.length - 1));
}

async function refreshNetworkServerStatus() {
  try { networkServerStatus = await json("/api/network/status"); } catch { /* Inspector remains honest with client state. */ }
}

function networkFailure(error) {
  const result = error instanceof NetworkContractError ? error.result : "NETWORK_ERROR";
  state.refreshState = `${result}: ${error.message}`;
  return result;
}

async function withNetworkWork(work) {
  if (networkBusy) return;
  networkBusy = true;
  state.refreshState = "Syncing local HTTP...";
  paint();
  try {
    await work();
  } catch (error) {
    networkFailure(error);
    console.error(error);
  } finally {
    useNetworkFixtures();
    await refreshNetworkServerStatus();
    networkBusy = false;
    paint();
  }
}

async function runFullNetworkSync() {
  await withNetworkWork(async () => {
    const result = await networkModel.runDailyRefresh(demoDay(), { manual: true });
    state.refreshState = result.result === "FRESH" ? "Updated · Cards + Inbox complete" : result.result;
  });
}

async function retryReceipts() {
  await withNetworkWork(async () => {
    const result = await networkModel.flushOutbox();
    state.refreshState = `${result.result} · ${result.remaining} receipts queued`;
  });
}

async function selectNetworkScenario(scenario) {
  if (networkBusy) return;
  networkBusy = true;
  paint();
  try {
    networkServerStatus = await json("/api/network/scenario", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario })
    });
    networkModel.reset();
    syntheticNetwork.resetAttempt();
    networkModel.setEnvironmentScenario(scenario);
    state = createState(fixtures);
    state.sdEntries = [...sdEntries];
    state.refreshState = `Scenario: ${scenario}`;
  } catch (error) {
    networkFailure(error);
  } finally {
    networkBusy = false;
    paint();
  }
}

function captureInput(button) {
  if (!recordingEnabled || replayBusy) return;
  try {
    inputRecording = appendInputAction(inputRecording, button, state?.route || "home", performance.now() - recordingStartedAt);
    recordingMessage = `Captured ${inputRecording.actions.length} action${inputRecording.actions.length === 1 ? "" : "s"}.`;
  } catch (error) {
    recordingEnabled = false;
    recordingMessage = error.message;
  }
}

async function dispatch(button, { record = true } = {}) {
  if (networkBusy) return;
  if (record) captureInput(button);
  if (state.route === "cards" && button === "confirm") {
    await runFullNetworkSync();
    return;
  }
  if (state.route === "actions" && button === "confirm") {
    const action = inboxActions(state)[state.actionIndex]?.code;
    if (action === "sync") {
      await withNetworkWork(async () => {
        const result = await networkModel.syncInbox();
        state.route = "inbox";
        state.refreshState = `${result.result} · cursor ${result.cursor}`;
      });
      return;
    }
    if (action && !["browse-list"].includes(action)) {
      const selected = state.fixtures.inbox[state.inboxIndex];
      const outcome = selected ? networkModel.applyInboxAction(selected.itemId, action) : null;
      state = reduceInput(state, button);
      if (outcome?.local) useNetworkFixtures();
      state.refreshState = outcome?.queued ? "Receipt queued" : "Local action · receipt unavailable";
      paint();
      return;
    }
  }
  if (state.route === "inbox" && state.inboxView === "preview" && ["left", "up"].includes(button)) {
    const selected = state.fixtures.inbox[state.inboxIndex];
    if (selected) {
      networkModel.recordOpenedBestEffort(selected.itemId);
      if (networkModel.artifact(selected.itemId)) state.documentBody = networkModel.documentText(selected.itemId);
    }
  }
  if (state.route === "cards" && ["left", "up"].includes(button)) {
    const selected = state.fixtures.cards[state.cardIndex];
    if (selected?.taskId) state.documentBody = networkModel.reportText(selected.taskId);
  }
  state = reduceInput(state, button);
  paint();
}

function keyToButton(event) {
  const map = {
    Escape: "back", Backspace: "back", Enter: "confirm",
    ArrowLeft: "left", ArrowRight: "right", ArrowUp: "up", ArrowDown: "down",
    PageUp: "up", PageDown: "down", p: "power", P: "power"
  };
  return map[event.key];
}

function inputHistogram() {
  return inputRecording.actions.reduce((counts, action) => {
    counts[action.button] = (counts[action.button] || 0) + 1;
    return counts;
  }, {});
}

function sanitizedBugBundle() {
  const client = networkModel.status();
  return createSanitizedBugBundle({
    appVersion: release?.version || "development",
    generatedAt: new Date().toISOString(),
    contractLoaded: Boolean(contract),
    firmwareLoaded: firmware?.exists === true,
    networkAvailable: Boolean(networkScenarios),
    firmware: {
      exists: firmware?.exists === true,
      byteCount: firmware?.byte_count,
      sha256: firmware?.sha256,
      headerValid: firmware?.esp32c3_image_valid,
      budgetStatus: firmware?.budget_status
    },
    qemu: {
      available: qemu?.qemu?.available,
      fullFlashReady: qemu?.full_flash_inputs?.ready,
      ready: qemu?.ready_to_execute
    },
    network: {
      scenario: networkServerStatus?.scenario,
      cards: client.cards,
      inbox: client.inbox,
      receipts: client.receipts,
      cursor: client.cursor,
      pages: client.pages,
      cardsCached: client.cardsCached,
      inboxCached: client.inboxCached,
      artifactsCached: client.artifactsCached,
      outboxEvents: client.outboxEvents
    },
    overrides: syntheticNetwork.status(),
    session: {
      route: state?.route,
      sdEntryCount: sdEntries.length,
      recordedActions: inputRecording.actions.length,
      inputHistogram: inputHistogram()
    }
  });
}

async function loadLocalImage(file, label) {
  if (!file || !["image/png", "image/jpeg", "image/webp", "image/bmp"].includes(file.type)) {
    throw new Error(`${label} must be a PNG, JPEG, WebP or BMP image`);
  }
  if (file.size < 1 || file.size > 10 * 1024 * 1024) {
    throw new Error(`${label} must be no larger than 10 MiB`);
  }
  const bitmap = await createImageBitmap(file);
  if (
    bitmap.width < 1 || bitmap.height < 1 || bitmap.width > 4096 || bitmap.height > 4096 ||
    bitmap.width * bitmap.height > 16 * 1024 * 1024
  ) {
    bitmap.close();
    throw new Error(`${label} dimensions exceed the 16-megapixel local comparison limit`);
  }
  return bitmap;
}

function updateVisualControls() {
  document.querySelector("#visual-baseline-state").textContent = visualBaseline
    ? `Ready · ${visualBaseline.width} × ${visualBaseline.height}`
    : "No image selected";
  document.querySelector("#visual-candidate-state").textContent = visualCandidate
    ? `Ready · ${visualCandidate.width} × ${visualCandidate.height}`
    : "No image selected";
  document.querySelector("#compare-images").disabled = !visualBaseline || !visualCandidate;
}

async function selectVisualImage(kind, file) {
  const result = document.querySelector("#visual-result");
  document.querySelector("#visual-diff").hidden = true;
  try {
    const bitmap = await loadLocalImage(file, kind === "baseline" ? "Baseline" : "Candidate");
    if (kind === "baseline") {
      visualBaseline?.close();
      visualBaseline = bitmap;
    } else {
      visualCandidate?.close();
      visualCandidate = bitmap;
    }
    visualSummary = null;
    result.textContent = "Image decoded locally. Select the other image or compare now.";
  } catch (error) {
    if (kind === "baseline") {
      visualBaseline?.close();
      visualBaseline = null;
    } else {
      visualCandidate?.close();
      visualCandidate = null;
    }
    result.textContent = error.message;
  }
  updateVisualControls();
}

function compareVisualImages() {
  const result = document.querySelector("#visual-result");
  const output = document.querySelector("#visual-diff");
  output.hidden = true;
  if (!visualBaseline || !visualCandidate) return;
  if (visualBaseline.width !== visualCandidate.width || visualBaseline.height !== visualCandidate.height) {
    result.textContent = `Dimensions differ: ${visualBaseline.width} × ${visualBaseline.height} versus ${visualCandidate.width} × ${visualCandidate.height}.`;
    return;
  }
  const width = visualBaseline.width;
  const height = visualBaseline.height;
  const source = document.createElement("canvas");
  source.width = width;
  source.height = height;
  const sourceContext = source.getContext("2d", { willReadFrequently: true });
  sourceContext.drawImage(visualBaseline, 0, 0);
  const baselinePixels = sourceContext.getImageData(0, 0, width, height).data;
  sourceContext.clearRect(0, 0, width, height);
  sourceContext.drawImage(visualCandidate, 0, 0);
  const candidatePixels = sourceContext.getImageData(0, 0, width, height).data;
  output.width = width;
  output.height = height;
  const outputContext = output.getContext("2d");
  const difference = outputContext.createImageData(width, height);
  let totalDifference = 0;
  let changedPixels = 0;
  for (let index = 0; index < baselinePixels.length; index += 4) {
    const delta = Math.round((
      Math.abs(baselinePixels[index] - candidatePixels[index]) +
      Math.abs(baselinePixels[index + 1] - candidatePixels[index + 1]) +
      Math.abs(baselinePixels[index + 2] - candidatePixels[index + 2])
    ) / 3);
    totalDifference += delta;
    if (delta > 12) changedPixels += 1;
    difference.data[index] = delta > 12 ? 212 : delta;
    difference.data[index + 1] = delta > 12 ? 255 : delta;
    difference.data[index + 2] = delta > 12 ? 63 : delta;
    difference.data[index + 3] = 255;
  }
  outputContext.putImageData(difference, 0, 0);
  const pixels = width * height;
  visualSummary = {
    width,
    height,
    meanAbsoluteDifference: totalDifference / pixels,
    changedPercent: (changedPixels / pixels) * 100
  };
  result.textContent = `Changed pixels: ${visualSummary.changedPercent.toFixed(2)}% · mean RGB difference: ${visualSummary.meanAbsoluteDifference.toFixed(2)} / 255.`;
  output.setAttribute("aria-label", `Pixel difference preview. ${visualSummary.changedPercent.toFixed(2)} percent of pixels changed.`);
  output.hidden = false;
}

async function replayRecordingFile(file) {
  if (!file || file.size < 1 || file.size > 128 * 1024) {
    throw new Error("Replay JSON must be between 1 byte and 128 KiB");
  }
  const recording = validateInputRecording(JSON.parse(await file.text()));
  replayBusy = true;
  recordingMessage = `Replaying ${recording.actions.length} validated actions from a fresh modeled state…`;
  state = createState(fixtures);
  state.sdEntries = [...sdEntries];
  networkModel.reset();
  paint();
  try {
    for (const action of recording.actions) {
      await dispatch(action.button, { record: false });
      await new Promise(resolve => requestAnimationFrame(resolve));
    }
    recordingMessage = `Replay complete · ${recording.actions.length} actions applied in order.`;
  } finally {
    replayBusy = false;
    paint();
  }
}

async function boot() {
  fixtures = publicDemoFixtures(await json("/api/fixtures"));
  state = createState(fixtures);
  const [releaseResult, contractResult, firmwareResult, qemuResult, treeResult, scenarioResult, networkResult] = await Promise.allSettled([
    json("/api/release"), json("/api/device-contract"), json("/api/firmware"), json("/api/qemu"), json("/api/sd/tree"),
    json("/api/network/scenarios"), json("/api/network/status")
  ]);
  if (releaseResult.status === "fulfilled") release = releaseResult.value;
  if (contractResult.status === "fulfilled") contract = contractResult.value;
  if (firmwareResult.status === "fulfilled") firmware = firmwareResult.value;
  if (qemuResult.status === "fulfilled") qemu = qemuResult.value;
  if (treeResult.status === "fulfilled") sdEntries = treeResult.value.entries || treeResult.value;
  if (scenarioResult.status === "fulfilled") networkScenarios = scenarioResult.value;
  if (networkResult.status === "fulfilled") networkServerStatus = networkResult.value;
  renderer.setSdEntries(sdEntries);
  state.sdEntries = [...sdEntries];
  try { await loadSleep(); } catch (error) { console.warn(error); }
  document.querySelector("#connection-status").textContent = "LOCAL / ISOLATED";
  paint();
}

document.addEventListener("keydown", event => {
  if (event.target.closest("input, select, textarea, button, summary, a")) return;
  const button = keyToButton(event);
  if (!button || event.repeat) return;
  event.preventDefault();
  dispatch(button);
});

document.querySelectorAll("[data-button]").forEach(button =>
  button.addEventListener("click", () => dispatch(button.dataset.button)));

function activateInspectorTab(button, { focus = false } = {}) {
  document.querySelectorAll("[data-tab]").forEach(tab => {
    const active = tab === button;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
    tab.tabIndex = active ? 0 : -1;
  });
  document.querySelectorAll(".inspector-panel").forEach(panel => {
    const active = panel.id === `panel-${button.dataset.tab}`;
    panel.classList.toggle("active", active);
    panel.hidden = !active;
  });
  if (focus) button.focus();
}

document.querySelectorAll("[data-tab]").forEach(button => {
  button.addEventListener("click", () => activateInspectorTab(button));
  button.addEventListener("keydown", event => {
    const tabs = [...document.querySelectorAll("[data-tab]")];
    const current = tabs.indexOf(button);
    let next = null;
    if (["ArrowRight", "ArrowDown"].includes(event.key)) next = tabs[(current + 1) % tabs.length];
    if (["ArrowLeft", "ArrowUp"].includes(event.key)) next = tabs[(current - 1 + tabs.length) % tabs.length];
    if (event.key === "Home") next = tabs[0];
    if (event.key === "End") next = tabs.at(-1);
    if (!next) return;
    event.preventDefault();
    activateInspectorTab(next, { focus: true });
  });
});

document.querySelector("#reset-session").addEventListener("click", async () => {
  await json("/api/session/reset", { method: "POST" });
  networkModel.reset();
  await refreshNetworkServerStatus();
  state = createState(fixtures);
  const tree = await json("/api/sd/tree");
  sdEntries = tree.entries || tree;
  renderer.setSdEntries(sdEntries);
  state.sdEntries = [...sdEntries];
  await loadSleep();
  paint();
});

document.querySelector("#export-frame").addEventListener("click", () => {
  const link = document.createElement("a");
  link.download = `x3-${state.route}-528x792.png`;
  link.href = canvas.toDataURL("image/png");
  link.click();
});

document.querySelector("#toggle-recording").addEventListener("click", () => {
  recordingEnabled = !recordingEnabled;
  if (recordingEnabled && inputRecording.actions.length === 0) recordingStartedAt = performance.now();
  recordingMessage = recordingEnabled ? "Recording resumed." : "Recording paused.";
  paint();
});

document.querySelector("#clear-recording").addEventListener("click", () => {
  inputRecording = createInputRecording();
  recordingStartedAt = performance.now();
  recordingMessage = "Recording cleared. The next input starts a fresh sequence.";
  paint();
});

document.querySelector("#export-recording").addEventListener("click", () => {
  const validated = validateInputRecording(inputRecording);
  downloadJson("x3-input-recording.json", validated);
  recordingMessage = `Exported ${validated.actions.length} content-free actions.`;
  paint();
});

document.querySelector("#replay-recording").addEventListener("change", async event => {
  try {
    await replayRecordingFile(event.target.files?.[0]);
  } catch (error) {
    recordingMessage = `Replay rejected safely: ${error.message}`;
    paint();
  } finally {
    event.target.value = "";
  }
});

document.querySelector("#visual-baseline").addEventListener("change", event =>
  selectVisualImage("baseline", event.target.files?.[0]));
document.querySelector("#visual-candidate").addEventListener("change", event =>
  selectVisualImage("candidate", event.target.files?.[0]));
document.querySelector("#compare-images").addEventListener("click", compareVisualImages);

document.querySelector("#export-bug-bundle").addEventListener("click", () => {
  downloadJson("x3-preview-lab-bug-bundle.json", sanitizedBugBundle());
  recordingMessage = "Sanitized bug bundle exported without host paths, filenames, URLs, tokens, titles or content bodies.";
  paint();
});

boot().catch(error => {
  document.querySelector("#connection-status").textContent = "BOOT ERROR";
  document.querySelector("#recording-message").textContent = `Boot failed: ${error.message}`;
  console.error(error);
});
