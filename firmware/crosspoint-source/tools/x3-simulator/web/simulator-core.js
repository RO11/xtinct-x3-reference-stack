export const SCREEN_WIDTH = 528;
export const SCREEN_HEIGHT = 792;
export const GRAY_LEVELS = Object.freeze([0, 85, 170, 255]);
export const X3_SLEEP_BMP_BYTES = 209158;
export const INPUT_RECORDING_SCHEMA = 1;
export const MAX_RECORDED_INPUTS = 256;
export const MAX_REPLAY_DURATION_MS = 5 * 60 * 1000;
export const RECORDED_INPUTS = Object.freeze([
  "back", "back-hold", "confirm", "confirm-hold", "left", "right", "up", "down", "power"
]);
export const HOME_ITEMS = Object.freeze([
  "Files",
  "Recents",
  "File Transfer",
  "XTINCT Inbox",
  "Daily Cards",
  "Phone Sync",
  "Phone Wi-Fi",
  "Settings"
]);

export const SUPPORTED_BOOK_EXTENSIONS = Object.freeze([".epub", ".xtc", ".txt", ".md", ".markdown", ".bmp"]);
export const SETTINGS_CATEGORIES = Object.freeze([
  {
    label: "Display",
    items: [
      { id: "status-bar", label: "Status bar", value: "On", type: "toggle" },
      { id: "sleep-screen", label: "Sleep screen", value: "Custom", type: "choice" }
    ]
  },
  {
    label: "Reader",
    items: [
      { id: "text-settings", label: "Text settings", value: "Ubuntu", type: "choice" },
      { id: "remove-read", label: "Remove read from Recents", value: "Off", type: "toggle" }
    ]
  },
  {
    label: "Controls",
    items: [
      { id: "button-map", label: "Remap front buttons", value: "Default", type: "choice" },
      { id: "sleep-timeout", label: "Time to sleep", value: "5 min", type: "choice" }
    ]
  },
  {
    label: "System",
    items: [
      { id: "network", label: "Network", type: "action" },
      { id: "daily-wake", label: "Daily Wake Status", type: "action" },
      { id: "firmware", label: "SD Card Firmware Update", type: "action" },
      { id: "resources", label: "Resource status", type: "action" },
      { id: "crash-report", label: "Crash report", type: "action" }
    ]
  }
]);

export function clamp(value, minimum, maximum) {
  return Math.min(maximum, Math.max(minimum, value));
}

export function wrapIndex(index, count) {
  if (count <= 0) return 0;
  return ((index % count) + count) % count;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function hasOnlyKeys(value, allowed) {
  return Object.keys(value).every(key => allowed.includes(key));
}

export function deriveFirmwareContext({ firmware = {}, qemu = {} } = {}) {
  const localImageSelected = firmware?.exists === true;
  const bundledBaselineSelected = firmware?.source_kind === "bundled-baseline";
  const bundledBaselineAvailable = firmware?.package_firmware_bundled === true &&
    firmware?.bundled_baseline_available === true;
  const qemuDetected = qemu?.qemu?.available === true || qemu?.available === true;
  const fullFlashReady = qemu?.full_flash_inputs?.ready === true || qemu?.fullFlashReady === true;
  const qemuReady = qemuDetected && fullFlashReady &&
    (qemu?.ready_to_execute === true || qemu?.ready === true);
  const qemuStatus = qemuReady
    ? "NOT BUNDLED · READY, NOT STARTED"
    : qemuDetected
      ? "NOT BUNDLED · DETECTED, NOT STARTED"
      : "NOT BUNDLED · NOT STARTED";
  return {
    package: {
      status: bundledBaselineAvailable
        ? `CROSSPOINT ${firmware?.baseline_version || "v1.5.0"} STABLE INCLUDED · READ-ONLY`
        : "BUNDLED CROSSPOINT BASELINE UNAVAILABLE",
      detail: bundledBaselineAvailable
        ? "The exact official stable firmware asset is included and hash-checked; it is never auto-flashed."
        : "The package contract expects an official stable CrossPoint baseline, but it could not be verified."
    },
    preview: {
      status: "SYNTHETIC PREVIEW · NOT FIRMWARE EXECUTION",
      detail: "The device canvas is drawn from generic modeled fixtures."
    },
    localImage: bundledBaselineSelected && localImageSelected
      ? {
          status: "BUNDLED BASELINE SELECTED",
          detail: "Metadata inspection only; this firmware does not draw the modeled preview."
        }
      : localImageSelected
      ? {
          status: "READ-ONLY IMAGE SELECTED",
          detail: "Metadata inspection only; this image does not draw the preview."
        }
      : {
          status: "NONE SELECTED",
          detail: "No optional local firmware image is configured."
        },
    qemu: {
      status: qemuStatus,
      detail: "QEMU is optional and separate; the bundled OTA image alone is not a complete boot set."
    },
    physicalX3: {
      status: "NOT READ BY THIS APP · INSTALLED VERSION UNKNOWN",
      detail: "A physical X3 remains a separate device-verification boundary."
    }
  };
}

function safeDiagnosticCode(value, fallback = "unknown") {
  return typeof value === "string" && /^[a-z0-9][a-z0-9-]{0,39}$/i.test(value) ? value : fallback;
}

function safeVersion(value) {
  return typeof value === "string" && /^[a-z0-9][a-z0-9.+-]{0,39}$/i.test(value) ? value : "development";
}

function boundedInteger(value, minimum, maximum, fallback = 0) {
  return Number.isInteger(value) && value >= minimum && value <= maximum ? value : fallback;
}

export function createInputRecording() {
  return { schema: INPUT_RECORDING_SCHEMA, type: "x3-input-recording", actions: [] };
}

export function validateInputRecording(document) {
  if (!isPlainObject(document) || !hasOnlyKeys(document, ["schema", "type", "actions"])) {
    throw new Error("Recording must contain only schema, type and actions");
  }
  if (document.schema !== INPUT_RECORDING_SCHEMA || document.type !== "x3-input-recording") {
    throw new Error("Unsupported X3 input recording");
  }
  if (!Array.isArray(document.actions) || document.actions.length > MAX_RECORDED_INPUTS) {
    throw new Error(`Recording is limited to ${MAX_RECORDED_INPUTS} actions`);
  }
  let previous = 0;
  const actions = document.actions.map((action, index) => {
    if (!isPlainObject(action) || !hasOnlyKeys(action, ["at_ms", "button", "route"])) {
      throw new Error(`Recording action ${index + 1} has unsupported fields`);
    }
    if (!RECORDED_INPUTS.includes(action.button)) {
      throw new Error(`Recording action ${index + 1} has an unsupported button`);
    }
    if (!Number.isInteger(action.at_ms) || action.at_ms < previous || action.at_ms > MAX_REPLAY_DURATION_MS) {
      throw new Error(`Recording action ${index + 1} has an invalid timestamp`);
    }
    if (typeof action.route !== "string" || !/^[a-z0-9][a-z0-9-]{0,31}$/.test(action.route)) {
      throw new Error(`Recording action ${index + 1} has an invalid route`);
    }
    previous = action.at_ms;
    return { at_ms: action.at_ms, button: action.button, route: action.route };
  });
  return { schema: INPUT_RECORDING_SCHEMA, type: "x3-input-recording", actions };
}

export function appendInputAction(recording, button, route, atMs) {
  const current = validateInputRecording(recording);
  if (current.actions.length >= MAX_RECORDED_INPUTS) {
    throw new Error(`Recording reached its ${MAX_RECORDED_INPUTS}-action limit`);
  }
  const previous = current.actions.at(-1)?.at_ms || 0;
  const roundedAtMs = Math.round(atMs);
  if (!Number.isInteger(roundedAtMs) || roundedAtMs < previous || roundedAtMs > MAX_REPLAY_DURATION_MS) {
    throw new Error("Recording reached its five-minute duration limit");
  }
  const next = {
    at_ms: roundedAtMs,
    button,
    route
  };
  return validateInputRecording({ ...current, actions: [...current.actions, next] });
}

// Construct diagnostics from an allowlist instead of trying to scrub an
// arbitrary state object. This prevents titles, content, URLs, host paths and
// credentials from entering an exported support bundle in the first place.
export function createSanitizedBugBundle(snapshot = {}) {
  const firmware = isPlainObject(snapshot.firmware) ? snapshot.firmware : {};
  const qemu = isPlainObject(snapshot.qemu) ? snapshot.qemu : {};
  const network = isPlainObject(snapshot.network) ? snapshot.network : {};
  const session = isPlainObject(snapshot.session) ? snapshot.session : {};
  const overrides = isPlainObject(snapshot.overrides) ? snapshot.overrides : {};
  const firmwareContext = deriveFirmwareContext({ firmware, qemu });
  const sha256 = typeof firmware.sha256 === "string" && /^[0-9a-f]{64}$/.test(firmware.sha256)
    ? firmware.sha256
    : null;
  const generatedAt = typeof snapshot.generatedAt === "string" && !Number.isNaN(Date.parse(snapshot.generatedAt))
    ? new Date(snapshot.generatedAt).toISOString()
    : new Date().toISOString();
  const histogram = {};
  if (isPlainObject(session.inputHistogram)) {
    for (const button of RECORDED_INPUTS) {
      const count = boundedInteger(session.inputHistogram[button], 0, MAX_RECORDED_INPUTS, 0);
      if (count) histogram[button] = count;
    }
  }
  return {
    schema: 1,
    type: "x3-preview-lab-bug-bundle",
    generated_at: generatedAt,
    privacy: "Allowlisted diagnostics only; no paths, URLs, tokens, filenames, titles or content bodies.",
    app: { version: safeVersion(snapshot.appVersion) },
    firmware_context: {
      package: firmwareContext.package.status,
      preview: firmwareContext.preview.status,
      optional_local_image: firmwareContext.localImage.status,
      qemu: firmwareContext.qemu.status,
      physical_x3: firmwareContext.physicalX3.status
    },
    evidence: {
      modeled: true,
      real_contract_test: Boolean(snapshot.contractLoaded && snapshot.networkAvailable),
      qemu: Boolean(qemu.ready),
      physical_device_required: true
    },
    runtime_checks: {
      contract_loaded: Boolean(snapshot.contractLoaded),
      firmware_metadata_loaded: Boolean(snapshot.firmwareLoaded),
      synthetic_network_available: Boolean(snapshot.networkAvailable),
      qemu_binary_available: Boolean(qemu.available),
      full_flash_set_ready: Boolean(qemu.fullFlashReady)
    },
    firmware: {
      byte_count: boundedInteger(firmware.byteCount, 0, 16 * 1024 * 1024, 0),
      sha256,
      esp32c3_header_valid: Boolean(firmware.headerValid),
      budget_status: safeDiagnosticCode(firmware.budgetStatus)
    },
    network: {
      isolation: "same-origin-loopback-only",
      base_scenario: safeDiagnosticCode(network.scenario),
      cards: safeDiagnosticCode(network.cards, "not-run"),
      inbox: safeDiagnosticCode(network.inbox, "not-run"),
      receipts: safeDiagnosticCode(network.receipts, "current"),
      cursor_length: Math.min(String(network.cursor ?? "").length, 64),
      pages: boundedInteger(network.pages, 0, 10, 0),
      cards_cached: boundedInteger(network.cardsCached, 0, 128, 0),
      inbox_cached: boundedInteger(network.inboxCached, 0, 1024, 0),
      artifacts_cached: boundedInteger(network.artifactsCached, 0, 1024, 0),
      outbox_events: boundedInteger(network.outboxEvents, 0, 48, 0),
      overrides: {
        latency_ms: boundedInteger(overrides.latency_ms, 0, 1500, 0),
        interrupt_target: safeDiagnosticCode(overrides.interrupt_target, "none"),
        interrupt_after_bytes: boundedInteger(overrides.interrupt_after_bytes, 1, 65536, 1024)
      }
    },
    session: {
      route: safeDiagnosticCode(session.route),
      sd_entry_count: boundedInteger(session.sdEntryCount, 0, 10000, 0),
      recorded_actions: boundedInteger(session.recordedActions, 0, MAX_RECORDED_INPUTS, 0),
      input_histogram: histogram
    }
  };
}

export function quantizeGray(value) {
  const bounded = clamp(Math.round(value), 0, 255);
  return GRAY_LEVELS.reduce((best, level) =>
    Math.abs(level - bounded) < Math.abs(best - bounded) ? level : best, GRAY_LEVELS[0]);
}

export function quantizeRgbaInPlace(pixels) {
  if (!pixels || pixels.length % 4 !== 0) throw new Error("RGBA pixel buffer must be a multiple of four bytes");
  for (let index = 0; index < pixels.length; index += 4) {
    const luminance = Math.round(
      (77 * pixels[index] + 150 * pixels[index + 1] + 29 * pixels[index + 2]) / 256
    );
    const native = quantizeGray(luminance);
    pixels[index] = native;
    pixels[index + 1] = native;
    pixels[index + 2] = native;
    pixels[index + 3] = 255;
  }
  return pixels;
}

export function formatX3Date(value) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf())) return String(value || "date unavailable").slice(0, 24);
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    timeZone: "UTC"
  }).format(parsed);
}

export function createState(fixtures) {
  const clonedFixtures = {
    ...fixtures,
    recentBooks: [...(fixtures.recentBooks || [])],
    cards: [...(fixtures.cards || [])],
    inbox: [...(fixtures.inbox || [])]
  };
  return {
    route: "home",
    homeIndex: 3,
    homeRecentSelected: false,
    recentIndex: 0,
    fileIndex: 0,
    filePath: "/",
    sdEntries: [...(fixtures.sdEntries || [])],
    deleteTarget: null,
    cardIndex: 0,
    inboxIndex: 0,
    inboxView: "preview",
    actionIndex: 0,
    documentTitle: "",
    documentBody: "",
    readerPage: 0,
    readerPages: [],
    readerSpine: 0,
    readerSpines: [],
    readerProgress: 0,
    readerManaged: false,
    readerKind: "text",
    lastRoute: "home",
    refreshState: "Current",
    transferStatus: "READY - isolated cloned SD",
    settingCategory: 0,
    settingIndex: 0,
    settings: SETTINGS_CATEGORIES.map(category => ({
      ...category,
      items: category.items.map(item => ({ ...item }))
    })),
    firmwareIndex: 0,
    firmwareSelection: "",
    firmwareStatus: "Select a verified .bin file",
    dailyWake: {
      requested: true,
      credentialsReady: true,
      lastResult: "Cards + Inbox complete",
      nextWake: "Tomorrow 06:00 local"
    },
    pocketPhase: "Complete",
    pocketCheckpoint: { stream: 2, offset: 196608, sealed: true },
    pocketConfigured: true,
    phoneWifiState: "Saved network available",
    panicCleared: false,
    crashReason: "Task watchdog reset (sanitized retained fields only)",
    fixtures: clonedFixtures
  };
}

function extensionOf(path) {
  const leaf = String(path || "").split("/").pop() || "";
  const dot = leaf.lastIndexOf(".");
  return dot < 0 ? "" : leaf.slice(dot).toLowerCase();
}

function basename(path) {
  return String(path || "").replace(/\/+$/, "").split("/").pop() || "/";
}

function parentPath(path) {
  const value = String(path || "/").replace(/\/+$/, "") || "/";
  const cut = value.lastIndexOf("/");
  return cut <= 0 ? "/" : value.slice(0, cut);
}

function normalPath(path) {
  const parts = [];
  for (const part of String(path || "/").replace(/\\/g, "/").split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") return null;
    parts.push(part);
  }
  return `/${parts.join("/")}`;
}

export function visibleFileEntries(state) {
  const current = normalPath(state.filePath) || "/";
  const prefix = current === "/" ? "/" : `${current}/`;
  return (state.sdEntries || [])
    .filter(entry => {
      const path = normalPath(entry.path);
      if (!path || path === current || !path.startsWith(prefix)) return false;
      const relative = path.slice(prefix.length);
      if (!relative || relative.includes("/")) return false;
      if (relative === "System Volume Information" || relative.startsWith(".")) return false;
      return entry.type === "directory" || SUPPORTED_BOOK_EXTENSIONS.includes(extensionOf(path)) || extensionOf(path) === ".bin";
    })
    .sort((a, b) => Number(b.type === "directory") - Number(a.type === "directory") || a.path.localeCompare(b.path));
}

export function firmwareEntries(state) {
  return (state.sdEntries || [])
    .filter(entry => entry.type !== "directory" && extensionOf(entry.path) === ".bin")
    .sort((a, b) => a.path.localeCompare(b.path));
}

export function settingsFor(state) {
  return state.settings[state.settingCategory]?.items || [];
}

function splitTextPages(text) {
  const value = String(text || "").trim();
  if (!value) return ["No readable local text was supplied by this synthetic fixture."];
  if (value.includes("\f")) return value.split("\f").map(page => page.trim()).filter(Boolean);
  const pages = [];
  let remaining = value;
  while (remaining.length) {
    let cut = Math.min(remaining.length, 700);
    if (cut < remaining.length) {
      const boundary = remaining.lastIndexOf(" ", cut);
      if (boundary > 350) cut = boundary;
    }
    pages.push(remaining.slice(0, cut).trim());
    remaining = remaining.slice(cut).trim();
  }
  return pages;
}

function defaultBody(source) {
  const summary = source.digest?.summary || source.summary || source.body || source.title || "Local document";
  const points = source.digest?.points || [];
  return [summary, ...points.map(point => `- ${point}`)].join("\n\n");
}

function syntheticTodaySpine(source) {
  if (source.body) return [splitTextPages(source.body)];
  const lead = defaultBody(source);
  return [[
    `${lead}\n\nSample project\nReview the highest-priority demo item and choose one small next action.`,
    "Recent proof\nKeep the evidence that matters, discard noise, and make the next decision from verified local information.",
    "Recovery\nLeave enough margin for recovery, then close the edition with one clear action for tomorrow."
  ]];
}

function readerKindFor(source) {
  const extension = extensionOf(source.path || source.title);
  if (source.kind === "epub" || extension === ".epub" || extension === ".xtc" || /^Today\b/i.test(source.title || "")) return "epub";
  if (source.kind === "image" || source.kind === "sleep-screen" || extension === ".bmp") return "image";
  return "text";
}

export function readerProgress(state) {
  if (state.route === "txt-reader") {
    const total = Math.max(1, state.readerPages.length);
    return Math.round(((state.readerPage + 1) * 10000) / total);
  }
  const spines = state.readerSpines || [];
  const total = Math.max(1, spines.reduce((sum, pages) => sum + pages.length, 0));
  let consumed = state.readerPage + 1;
  for (let index = 0; index < state.readerSpine; index += 1) consumed += spines[index]?.length || 0;
  return Math.round((consumed * 10000) / total);
}

function openReader(state, source, returnRoute) {
  const next = { ...state };
  const kind = readerKindFor(source || {});
  next.documentTitle = source?.title || state.documentTitle || "Reader";
  next.lastRoute = returnRoute;
  next.readerManaged = Boolean(source?.itemId || source?.managed);
  next.readerKind = kind;
  if (kind === "image") {
    next.route = "image-viewer";
    next.readerProgress = 10000;
    return next;
  }
  if (kind === "text") {
    next.route = "txt-reader";
    next.readerPages = Array.isArray(source?.pages) && source.pages.length
      ? source.pages.map(String)
      : splitTextPages(source?.body || state.documentBody || defaultBody(source || {}));
    next.readerPage = clamp(Number(source?.savedPage) || 0, 0, Math.max(0, next.readerPages.length - 1));
    next.readerProgress = readerProgress(next);
    return next;
  }
  next.route = "epub-reader";
  next.readerSpines = Array.isArray(source?.spines) && source.spines.length
    ? source.spines.map(spine => Array.isArray(spine) ? spine.map(String) : splitTextPages(spine))
    : syntheticTodaySpine({ ...(source || {}), body: source?.body || state.documentBody });
  const requestedSpine = Number(source?.savedSpine) || 0;
  const validSavedSpine = requestedSpine >= 0 && requestedSpine < next.readerSpines.length;
  next.readerSpine = validSavedSpine ? requestedSpine : 0;
  next.readerPage = validSavedSpine
    ? clamp(Number(source?.savedPage) || 0, 0, Math.max(0, next.readerSpines[next.readerSpine].length - 1))
    : 0;
  next.readerProgress = readerProgress(next);
  return next;
}

function reduceReader(state, button) {
  const next = { ...state };
  if (button === "back") { next.route = state.lastRoute || "home"; return next; }
  if (state.route === "txt-reader") {
    if (button === "up" || button === "left") next.readerPage = clamp(state.readerPage - 1, 0, state.readerPages.length - 1);
    if (button === "down" || button === "right") next.readerPage = clamp(state.readerPage + 1, 0, state.readerPages.length - 1);
    next.readerProgress = readerProgress(next);
    return next;
  }
  if (button === "up" || button === "left") {
    if (state.readerPage > 0) next.readerPage -= 1;
    else if (state.readerSpine > 0) {
      next.readerSpine -= 1;
      next.readerPage = Math.max(0, next.readerSpines[next.readerSpine].length - 1);
    }
  }
  if (button === "down" || button === "right") {
    const pages = state.readerSpines[state.readerSpine] || [];
    if (state.readerPage + 1 < pages.length) next.readerPage += 1;
    else if (state.readerSpine + 1 < state.readerSpines.length) {
      next.readerSpine += 1;
      next.readerPage = 0;
    } else {
      next.route = "end-of-book";
      return next;
    }
  }
  next.readerProgress = readerProgress(next);
  return next;
}

const ACTION_LABELS = Object.freeze({
  keep: "Keep",
  archive: "Archive",
  done: "Done",
  defer: "Defer",
  like: "Like",
  dislike: "Dislike",
  "open-phone": "Open on Phone"
});

export function inboxActions(state) {
  const actions = [{ code: "sync", label: "Sync now" }];
  const inbox = state.fixtures.inbox;
  if (state.inboxView === "preview" && inbox.length) {
    actions.push({ code: "browse-list", label: "Browse list" });
  }
  const selected = inbox[state.inboxIndex];
  if (selected) {
    for (const code of selected.actions || []) {
      if (ACTION_LABELS[code]) actions.push({ code, label: ACTION_LABELS[code] });
    }
    actions.push({ code: "delete", label: "Delete" });
  }
  return actions;
}

export function labelsFor(state) {
  switch (state.route) {
    case "home": return [state.fixtures.recentBooks?.length ? "Resume" : "", "Select", "Up", "Down"];
    case "cards": return ["Back", "Refresh", "Open", state.fixtures.cards.length > 1 ? "Next" : ""];
    case "inbox":
      if (state.inboxView === "list") return ["Home", "Open", "Actions", "Next"];
      return ["Back", "Actions", "Open", state.fixtures.inbox.length > 1 ? "Next" : ""];
    case "actions": return ["Back", "Select", "Up", "Down"];
    case "document":
    case "txt-reader":
    case "epub-reader": return ["Back", "", "Prev", "Next"];
    case "image-viewer": return ["Back", "", "", ""];
    case "end-of-book": return ["Back", "Home", "", ""];
    case "sleep": return ["Wake", "", "", ""];
    case "files": return ["Back", "Open", "Up", "Down"];
    case "delete-confirm": return ["Cancel", "Delete", "", ""];
    case "recents": return ["Home", "Open", "Up", "Down"];
    case "remove-recent-confirm": return ["Cancel", "Remove", "", ""];
    case "file-transfer": return ["Back", "", "", ""];
    case "phone-sync": return ["Back", "Reset hold", "", ""];
    case "phone-wifi": return ["Back", "Select", "Up", "Down"];
    case "settings": return ["Back", state.settingIndex === 0 ? "Next tab" : "Select", "Up", "Down"];
    case "daily-wake-status":
    case "resource-status":
    case "crash-report": return ["Back", "", "", ""];
    case "firmware-picker": return ["Cancel", "Select", "Up", "Down"];
    case "firmware-confirm": return ["Cancel", "Validate", "", ""];
    default: return ["Back", "", "", ""];
  }
}

export function reduceInput(state, button) {
  const next = { ...state };
  const cards = state.fixtures.cards;
  const inbox = state.fixtures.inbox;
  if (state.route === "sleep") {
    if (button === "back" || button === "confirm" || button === "power") next.route = state.lastRoute || "home";
    return next;
  }
  if (button === "power") {
    next.lastRoute = state.route;
    next.route = "sleep";
    return next;
  }
  if (state.route === "document" || state.route === "txt-reader" || state.route === "epub-reader") {
    if (state.route !== "document") return reduceReader(state, button);
    if (button === "back") next.route = state.lastRoute || "home";
    return next;
  }
  if (state.route === "image-viewer") {
    if (button === "back") next.route = state.lastRoute || "home";
    return next;
  }
  if (state.route === "end-of-book") {
    if (button === "back") next.route = "epub-reader";
    if (button === "confirm") next.route = "home";
    return next;
  }
  if (state.route === "files") {
    const entries = visibleFileEntries(state);
    if (button === "up" || button === "left") next.fileIndex = wrapIndex(state.fileIndex - 1, entries.length);
    if (button === "down" || button === "right") next.fileIndex = wrapIndex(state.fileIndex + 1, entries.length);
    if (button === "back-hold") { next.filePath = "/"; next.fileIndex = 0; }
    if (button === "back") {
      if (state.filePath === "/") next.route = "home";
      else { next.filePath = parentPath(state.filePath); next.fileIndex = 0; }
    }
    if (button === "confirm-hold" && entries.length) {
      next.deleteTarget = entries[state.fileIndex];
      next.route = "delete-confirm";
    }
    if (button === "confirm" && entries.length) {
      const selected = entries[state.fileIndex];
      if (selected.type === "directory") {
        next.filePath = normalPath(selected.path) || "/";
        next.fileIndex = 0;
      } else if (extensionOf(selected.path) !== ".bin") {
        return openReader(next, { ...selected, title: basename(selected.path) }, "files");
      }
    }
    return next;
  }
  if (state.route === "delete-confirm") {
    if (button === "back") { next.route = "files"; next.deleteTarget = null; }
    if (button === "confirm" && state.deleteTarget) {
      const target = normalPath(state.deleteTarget.path);
      next.sdEntries = state.sdEntries.filter(entry => {
        const path = normalPath(entry.path);
        return path !== target && !path?.startsWith(`${target}/`);
      });
      next.fileIndex = 0;
      next.deleteTarget = null;
      next.route = "files";
    }
    return next;
  }
  if (state.route === "recents") {
    const recents = state.fixtures.recentBooks || [];
    if (button === "back") next.route = "home";
    if (button === "up" || button === "left") next.recentIndex = wrapIndex(state.recentIndex - 1, recents.length);
    if (button === "down" || button === "right") next.recentIndex = wrapIndex(state.recentIndex + 1, recents.length);
    if (button === "confirm-hold" && recents.length) {
      next.route = "remove-recent-confirm";
      next.deleteTarget = recents[state.recentIndex];
    }
    if (button === "confirm" && recents.length) return openReader(next, recents[state.recentIndex], "recents");
    return next;
  }
  if (state.route === "remove-recent-confirm") {
    if (button === "back") { next.route = "recents"; next.deleteTarget = null; }
    if (button === "confirm" && state.deleteTarget) {
      const recents = state.fixtures.recentBooks.filter(book =>
        book !== state.deleteTarget && !(state.deleteTarget.path && book.path === state.deleteTarget.path));
      next.fixtures = { ...state.fixtures, recentBooks: recents };
      next.recentIndex = clamp(state.recentIndex, 0, Math.max(0, recents.length - 1));
      next.deleteTarget = null;
      next.route = "recents";
    }
    return next;
  }
  if (state.route === "file-transfer") {
    if (button === "back") next.route = "home";
    return next;
  }
  if (state.route === "phone-sync") {
    if (button === "back") next.route = "home";
    if (button === "confirm-hold") {
      next.pocketConfigured = false;
      next.pocketPhase = "Advertising";
      next.pocketCheckpoint = { stream: 0, offset: 0, sealed: false };
    }
    return next;
  }
  if (state.route === "phone-wifi") {
    if (button === "back") next.route = "home";
    if (button === "confirm") next.phoneWifiState = state.phoneWifiState === "Saved network available"
      ? "Provisioning preview - radio disabled"
      : "Saved network available";
    return next;
  }
  if (state.route === "settings") {
    const settings = settingsFor(state);
    if (button === "back") next.route = "home";
    if (button === "up" || button === "left") next.settingIndex = wrapIndex(state.settingIndex - 1, settings.length + 1);
    if (button === "down" || button === "right") next.settingIndex = wrapIndex(state.settingIndex + 1, settings.length + 1);
    if (button === "confirm" && state.settingIndex === 0) {
      next.settingCategory = wrapIndex(state.settingCategory + 1, state.settings.length);
      next.settingIndex = 0;
    } else if (button === "confirm") {
      const setting = settings[state.settingIndex - 1];
      if (setting?.id === "network") next.route = "phone-wifi";
      else if (setting?.id === "daily-wake") next.route = "daily-wake-status";
      else if (setting?.id === "firmware") { next.route = "firmware-picker"; next.firmwareIndex = 0; }
      else if (setting?.id === "resources") next.route = "resource-status";
      else if (setting?.id === "crash-report") { next.route = "crash-report"; next.panicCleared = true; }
      else if (setting?.type === "toggle") {
        const categories = state.settings.map((category, categoryIndex) => categoryIndex !== state.settingCategory ? category : {
          ...category,
          items: category.items.map((item, itemIndex) => itemIndex !== state.settingIndex - 1 ? item : {
            ...item,
            value: item.value === "On" ? "Off" : "On"
          })
        });
        next.settings = categories;
      }
    }
    return next;
  }
  if (state.route === "daily-wake-status" || state.route === "resource-status" || state.route === "crash-report") {
    if (button === "back") next.route = "settings";
    return next;
  }
  if (state.route === "firmware-picker") {
    const entries = firmwareEntries(state);
    if (button === "back") next.route = "settings";
    if (button === "up" || button === "left") next.firmwareIndex = wrapIndex(state.firmwareIndex - 1, entries.length);
    if (button === "down" || button === "right") next.firmwareIndex = wrapIndex(state.firmwareIndex + 1, entries.length);
    if (button === "confirm" && entries.length) {
      next.firmwareSelection = entries[state.firmwareIndex].path;
      next.route = "firmware-confirm";
    }
    return next;
  }
  if (state.route === "firmware-confirm") {
    if (button === "back") { next.route = "firmware-picker"; next.firmwareSelection = ""; }
    if (button === "confirm") {
      next.firmwareStatus = "Validated only - simulator cannot flash hardware";
      next.route = "settings";
    }
    return next;
  }
  if (state.route === "actions") {
    const actions = inboxActions(state);
    if (button === "back") { next.route = "inbox"; return next; }
    if (button === "up" || button === "left") next.actionIndex = wrapIndex(state.actionIndex - 1, actions.length);
    if (button === "down" || button === "right") next.actionIndex = wrapIndex(state.actionIndex + 1, actions.length);
    if (button === "confirm") {
      const action = actions[wrapIndex(state.actionIndex, actions.length)]?.code;
      if (action === "sync") { next.route = "inbox"; next.refreshState = "Updated (simulated)"; }
      else if (action === "browse-list") { next.route = "inbox"; next.inboxView = "list"; }
      else if (action === "delete" && inbox.length) {
        const replacement = inbox.filter((_, index) => index !== state.inboxIndex);
        next.fixtures = { ...state.fixtures, inbox: replacement };
        next.inboxIndex = wrapIndex(state.inboxIndex, replacement.length);
        next.route = "inbox";
        next.inboxView = replacement.length ? "preview" : "list";
      } else next.route = "inbox";
    }
    return next;
  }
  if (state.route === "home") {
    const hasRecent = Boolean(state.fixtures.recentBooks?.length);
    if (button === "back" && state.fixtures.recentBooks?.length) {
      return openReader(next, state.fixtures.recentBooks[0], "home");
    }
    if (button === "up" || button === "left") {
      if (hasRecent && state.homeRecentSelected) {
        next.homeRecentSelected = false;
        next.homeIndex = HOME_ITEMS.length - 1;
      } else if (hasRecent && state.homeIndex === 0) {
        next.homeRecentSelected = true;
      } else {
        next.homeIndex = wrapIndex(state.homeIndex - 1, HOME_ITEMS.length);
      }
    }
    if (button === "down" || button === "right") {
      if (hasRecent && state.homeRecentSelected) {
        next.homeRecentSelected = false;
        next.homeIndex = 0;
      } else if (hasRecent && state.homeIndex === HOME_ITEMS.length - 1) {
        next.homeRecentSelected = true;
      } else {
        next.homeIndex = wrapIndex(state.homeIndex + 1, HOME_ITEMS.length);
      }
    }
    if (button === "power") { next.lastRoute = "home"; next.route = "sleep"; }
    if (button === "confirm") {
      if (hasRecent && state.homeRecentSelected) {
        return openReader(next, state.fixtures.recentBooks[0], "home");
      }
      const target = HOME_ITEMS[state.homeIndex];
      if (target === "XTINCT Inbox") next.route = "inbox";
      else if (target === "Daily Cards") next.route = "cards";
      else if (target === "Files") next.route = "files";
      else if (target === "Recents") next.route = "recents";
      else if (target === "File Transfer") next.route = "file-transfer";
      else if (target === "Phone Sync") next.route = "phone-sync";
      else if (target === "Phone Wi-Fi") next.route = "phone-wifi";
      else if (target === "Settings") next.route = "settings";
    }
    return next;
  }
  if (state.route === "cards") {
    if (button === "back") next.route = "home";
    else if (button === "confirm") next.refreshState = "Updated (simulated)";
    else if (button === "right" || button === "down") next.cardIndex = wrapIndex(state.cardIndex + 1, cards.length);
    else if ((button === "left" || button === "up") && cards.length) {
      return openReader(next, { ...cards[state.cardIndex], kind: "text" }, "cards");
    }
    return next;
  }
  if (state.route === "inbox") {
    if (!inbox.length) {
      if (button === "back") next.route = "home";
      else if (button === "confirm") next.route = "actions";
      return next;
    }
    if (state.inboxView === "preview") {
      if (button === "back") next.route = "home";
      else if (button === "confirm") next.route = "actions";
      else if (button === "right" || button === "down") next.inboxIndex = wrapIndex(state.inboxIndex + 1, inbox.length);
      else if (button === "left" || button === "up") {
        return openReader(next, inbox[state.inboxIndex], "inbox");
      }
    } else {
      if (button === "back") next.inboxView = "preview";
      else if (button === "confirm") next.inboxView = "preview";
      else if (button === "left" || button === "up") { next.route = "actions"; next.actionIndex = 0; }
      else if (button === "right" || button === "down") next.inboxIndex = wrapIndex(state.inboxIndex + 1, inbox.length);
    }
  }
  return next;
}

export function parseBmpHeader(buffer) {
  const view = new DataView(buffer);
  if (view.byteLength < 70 || view.getUint8(0) !== 0x42 || view.getUint8(1) !== 0x4d) {
    throw new Error("Not a BMP file");
  }
  const fileBytes = view.getUint32(2, true);
  const reserved1 = view.getUint16(6, true);
  const reserved2 = view.getUint16(8, true);
  const dibHeaderBytes = view.getUint32(14, true);
  const width = view.getInt32(18, true);
  const rawHeight = view.getInt32(22, true);
  const planes = view.getUint16(26, true);
  const bpp = view.getUint16(28, true);
  const compression = view.getUint32(30, true);
  const imageBytes = view.getUint32(34, true);
  const pixelOffset = view.getUint32(10, true);
  const colorsUsed = view.getUint32(46, true);
  const importantColors = view.getUint32(50, true);
  return {
    fileBytes, reserved1, reserved2, dibHeaderBytes, width,
    height: Math.abs(rawHeight), topDown: rawHeight < 0,
    planes, bpp, compression, imageBytes, pixelOffset, colorsUsed, importantColors
  };
}

export function decodeX3Bmp(buffer) {
  const header = parseBmpHeader(buffer);
  const view = new DataView(buffer);
  const rowBytes = Math.ceil((SCREEN_WIDTH * 4) / 32) * 4;
  const expectedImageBytes = rowBytes * SCREEN_HEIGHT;
  if (
    header.fileBytes !== X3_SLEEP_BMP_BYTES || view.byteLength !== X3_SLEEP_BMP_BYTES ||
    header.reserved1 !== 0 || header.reserved2 !== 0 ||
    header.dibHeaderBytes !== 40 || header.pixelOffset !== 70 || header.planes !== 1 ||
    header.width !== SCREEN_WIDTH || header.height !== SCREEN_HEIGHT ||
    header.bpp !== 4 || header.compression !== 0 ||
    header.imageBytes !== expectedImageBytes || header.colorsUsed !== 4 ||
    ![0, 4].includes(header.importantColors)
  ) {
    throw new Error("BMP does not match the native X3 sleep-screen contract");
  }
  const palette = [];
  for (let index = 0; index < 4; index += 1) {
    const offset = 54 + index * 4;
    const blue = view.getUint8(offset);
    const green = view.getUint8(offset + 1);
    const red = view.getUint8(offset + 2);
    const reserved = view.getUint8(offset + 3);
    if (red !== green || green !== blue || reserved !== 0) {
      throw new Error("BMP palette is not the native four-gray X3 palette");
    }
    palette.push(red);
  }
  if (palette.some((value, index) => value !== GRAY_LEVELS[index])) {
    throw new Error("BMP palette is not the native four-gray X3 palette");
  }
  const pixels = new Uint8ClampedArray(header.width * header.height * 4);
  const usedIndices = new Set();
  for (let y = 0; y < header.height; y += 1) {
    const sourceY = header.topDown ? y : header.height - 1 - y;
    const row = header.pixelOffset + sourceY * rowBytes;
    for (let x = 0; x < header.width; x += 1) {
      const packed = view.getUint8(row + Math.floor(x / 2));
      const index = x % 2 === 0 ? packed >> 4 : packed & 0x0f;
      if (index > 3) throw new Error("BMP uses a non-native palette index");
      usedIndices.add(index);
      const value = palette[index];
      const target = (y * header.width + x) * 4;
      pixels[target] = value;
      pixels[target + 1] = value;
      pixels[target + 2] = value;
      pixels[target + 3] = 255;
    }
  }
  if (usedIndices.size < 3) throw new Error("BMP does not preserve enough native grayscale levels");
  return { ...header, palette, pixels };
}
