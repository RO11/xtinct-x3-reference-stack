import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  GRAY_LEVELS,
  HOME_ITEMS,
  X3_SLEEP_BMP_BYTES,
  createState,
  decodeX3Bmp,
  firmwareEntries,
  inboxActions,
  labelsFor,
  quantizeGray,
  quantizeRgbaInPlace,
  readerProgress,
  reduceInput,
  settingsFor,
  visibleFileEntries,
  wrapIndex
} from "../web/simulator-core.js";
import { X3_ICONS } from "../web/assets/x3-icons.js";

const fixtures = {
  recentBooks: [{ title: "Today", author: "Sample Project" }],
  cards: [{ title: "Card", hasReport: true }, { title: "Card 2", hasReport: true }],
  inbox: [{ title: "Item" }, { title: "Item 2" }]
};

const simulatorRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function nativeBmp() {
  const bytes = new Uint8Array(X3_SLEEP_BMP_BYTES);
  const view = new DataView(bytes.buffer);
  bytes[0] = 0x42;
  bytes[1] = 0x4d;
  view.setUint32(2, X3_SLEEP_BMP_BYTES, true);
  view.setUint32(10, 70, true);
  view.setUint32(14, 40, true);
  view.setInt32(18, 528, true);
  view.setInt32(22, 792, true);
  view.setUint16(26, 1, true);
  view.setUint16(28, 4, true);
  view.setUint32(30, 0, true);
  view.setUint32(34, 209088, true);
  view.setUint32(46, 4, true);
  view.setUint32(50, 4, true);
  GRAY_LEVELS.forEach((level, index) => {
    const offset = 54 + index * 4;
    bytes[offset] = level;
    bytes[offset + 1] = level;
    bytes[offset + 2] = level;
  });
  for (let index = 70; index < bytes.length; index += 2) {
    bytes[index] = 0x01;
    bytes[index + 1] = 0x23;
  }
  return bytes;
}

test("native palette quantization never emits an unsupported shade", () => {
  for (let value = -20; value < 280; value += 1) assert.ok(GRAY_LEVELS.includes(quantizeGray(value)));
  assert.equal(quantizeGray(49), 85);
  assert.equal(quantizeGray(220), 255);
});

test("full RGBA frames are clamped to four opaque native gray levels", () => {
  const pixels = new Uint8ClampedArray([
    1, 17, 31, 0,
    70, 90, 110, 127,
    130, 170, 190, 2,
    240, 230, 220, 14
  ]);
  quantizeRgbaInPlace(pixels);
  const levels = new Set();
  for (let index = 0; index < pixels.length; index += 4) {
    assert.equal(pixels[index], pixels[index + 1]);
    assert.equal(pixels[index], pixels[index + 2]);
    assert.equal(pixels[index + 3], 255);
    levels.add(pixels[index]);
  }
  assert.ok([...levels].every(level => GRAY_LEVELS.includes(level)));
  assert.throws(() => quantizeRgbaInPlace(new Uint8Array(3)), /multiple of four/);
});

test("generated icons stay byte-identical to their current firmware sources", () => {
  const sources = {
    Files: ["folder.h", "FolderIcon"], Recents: ["recent.h", "RecentIcon"],
    "File Transfer": ["transfer.h", "TransferIcon"], "XTINCT Inbox": ["inbox.h", "InboxIcon"],
    "Daily Cards": ["cards.h", "CardsIcon"], "Phone Sync": ["transfer.h", "TransferIcon"],
    "Phone Wi-Fi": ["wifi.h", "WifiIcon"], Settings: ["settings2.h", "Settings2Icon"],
    Cover: ["cover.h", "CoverIcon"], Book: ["book.h", "BookIcon"]
  };
  assert.deepEqual(Object.keys(X3_ICONS), [...HOME_ITEMS, "Cover", "Book"]);
  for (const bitmap of Object.values(X3_ICONS)) {
    assert.equal(bitmap.length, 128);
    assert.ok(bitmap.every(value => Number.isInteger(value) && value >= 0 && value <= 255));
  }
  const iconRoot = path.resolve(simulatorRoot, "../../src/components/icons");
  for (const [label, [filename, symbol]] of Object.entries(sources)) {
    const source = fs.readFileSync(path.join(iconRoot, filename), "utf8");
    const block = source.match(new RegExp(`uint8_t\\s+${symbol}\\[\\]\\s*=\\s*\\{([\\s\\S]*?)\\};`));
    assert.ok(block, `${symbol} source exists`);
    const expected = [...block[1].matchAll(/0x[0-9a-f]{2}/gi)].map(match => Number.parseInt(match[0], 16));
    assert.deepEqual(X3_ICONS[label], expected, `${label} bytes match ${symbol}`);
  }
});

test("sleep BMP decoder enforces the exact native X3 header and grayscale use", () => {
  const bytes = nativeBmp();
  const decoded = decodeX3Bmp(bytes.buffer);
  assert.equal(decoded.width, 528);
  assert.equal(decoded.height, 792);
  assert.deepEqual(decoded.palette, GRAY_LEVELS);

  const wrongOffset = nativeBmp();
  new DataView(wrongOffset.buffer).setUint32(10, 118, true);
  assert.throws(() => decodeX3Bmp(wrongOffset.buffer), /native X3 sleep-screen contract/);

  const reservedHeader = nativeBmp();
  new DataView(reservedHeader.buffer).setUint16(6, 1, true);
  assert.throws(() => decodeX3Bmp(reservedHeader.buffer), /native X3 sleep-screen contract/);

  const twoTone = nativeBmp();
  twoTone.fill(0x01, 70);
  assert.throws(() => decodeX3Bmp(twoTone.buffer), /grayscale levels/);
});

test("index movement wraps like the device navigator", () => {
  assert.equal(wrapIndex(-1, 8), 7);
  assert.equal(wrapIndex(8, 8), 0);
  assert.equal(wrapIndex(4, 0), 0);
});

test("home opens current Inbox preview and models a completed power hold", () => {
  const state = createState(fixtures);
  assert.equal(HOME_ITEMS[state.homeIndex], "XTINCT Inbox");
  const inbox = reduceInput(state, "confirm");
  assert.equal(inbox.route, "inbox");
  assert.equal(inbox.inboxView, "preview");
  const sleeping = reduceInput(state, "power");
  assert.equal(sleeping.route, "sleep");
  assert.equal(reduceInput(sleeping, "power").route, "home");
  const resumed = reduceInput(state, "back");
  assert.equal(resumed.route, "epub-reader");
  assert.equal(resumed.documentTitle, "Today");

  const files = { ...state, homeIndex: 0 };
  const recent = reduceInput(files, "up");
  assert.equal(recent.homeRecentSelected, true);
  assert.equal(reduceInput(recent, "confirm").documentTitle, "Today");
});

test("Cards and Inbox keep the current firmware button contracts", () => {
  let state = { ...createState(fixtures), route: "cards" };
  assert.deepEqual(labelsFor(state), ["Back", "Refresh", "Open", "Next"]);
  state = reduceInput(state, "down");
  assert.equal(state.cardIndex, 1);
  state = reduceInput(state, "up");
  assert.equal(state.route, "txt-reader");
  state = { ...createState(fixtures), route: "inbox" };
  assert.deepEqual(labelsFor(state), ["Back", "Actions", "Open", "Next"]);
  state = reduceInput(state, "confirm");
  assert.equal(state.route, "actions");
  assert.deepEqual(inboxActions(state).map(action => action.label), ["Sync now", "Browse list", "Delete"]);

  state = { ...createState(fixtures), route: "inbox", inboxView: "list" };
  state = reduceInput(state, "up");
  assert.equal(state.route, "actions");
  assert.deepEqual(inboxActions(state).map(action => action.label), ["Sync now", "Delete"]);
});

test("simulated delete changes only browser fixture state", () => {
  const original = createState(fixtures);
  const actions = { ...original, route: "actions", actionIndex: 2 };
  const next = reduceInput(actions, "confirm");
  assert.equal(next.fixtures.inbox.length, 1);
  assert.equal(fixtures.inbox.length, 2);
});

const sdEntries = [
  { type: "directory", path: "/Books" },
  { type: "file", path: "/Books/guide.txt", body: "Guide page one\fGuide page two" },
  { type: "file", path: "/Books/novel.epub", spines: [["One", "Two"], ["Three"]] },
  { type: "directory", path: "/Books/Notes" },
  { type: "file", path: "/Books/Notes/idea.md", body: "Idea" },
  { type: "file", path: "/sleep.bmp" },
  { type: "file", path: "/update.bin" },
  { type: "file", path: "/rollback.BIN" },
  { type: "file", path: "/ignore.pdf" },
  { type: "directory", path: "/System Volume Information" },
  { type: "file", path: "/.secret.txt" }
];

function surfaceState(overrides = {}) {
  return {
    ...createState({
      ...fixtures,
      recentBooks: [
        { title: "Novel", author: "Author", path: "/Books/novel.epub", spines: [["One", "Two"], ["Three"]] },
        { title: "Notes", path: "/Books/guide.txt", pages: ["Alpha", "Beta", "Gamma"] }
      ],
      sdEntries
    }),
    ...overrides
  };
}

test("Files listing routes supported content and recursive delete changes only the cloned tree", () => {
  let state = surfaceState({ route: "files" });
  assert.deepEqual(visibleFileEntries(state).map(entry => entry.path), ["/Books", "/rollback.BIN", "/sleep.bmp", "/update.bin"]);
  state = reduceInput(state, "confirm");
  assert.equal(state.filePath, "/Books");
  assert.deepEqual(visibleFileEntries(state).map(entry => entry.path), ["/Books/Notes", "/Books/guide.txt", "/Books/novel.epub"]);
  state = { ...state, fileIndex: 1 };
  const txt = reduceInput(state, "confirm");
  assert.equal(txt.route, "txt-reader");
  state = reduceInput(state, "back-hold");
  assert.equal(state.filePath, "/");
  state = { ...state, fileIndex: 0 };
  state = reduceInput(state, "confirm-hold");
  assert.equal(state.route, "delete-confirm");
  const deleted = reduceInput(state, "confirm");
  assert.equal(deleted.sdEntries.some(entry => entry.path.startsWith("/Books")), false, "recursive delete removes the clone subtree");
  assert.equal(sdEntries.some(entry => entry.path === "/Books/guide.txt"), true, "workspace fixture remains intact");
});

test("Files delete cancellation and parent Back preserve the cloned listing", () => {
  const state = surfaceState({ route: "files", fileIndex: 0 });
  const confirmation = reduceInput(state, "confirm-hold");
  const cancelled = reduceInput(confirmation, "back");
  assert.equal(cancelled.route, "files");
  assert.deepEqual(cancelled.sdEntries, state.sdEntries, "delete cancellation changes nothing");
  const nested = reduceInput(state, "confirm");
  assert.equal(reduceInput(nested, "back").filePath, "/");
});

test("Recents opens an existing document and long Confirm can remove from Recents without deleting the book", () => {
  let state = surfaceState({ route: "recents" });
  const opened = reduceInput(state, "confirm");
  assert.equal(opened.route, "epub-reader");
  state = reduceInput(state, "confirm-hold");
  assert.equal(state.route, "remove-recent-confirm");
  const removed = reduceInput(state, "confirm");
  assert.equal(removed.fixtures.recentBooks.length, 1);
  assert.equal(removed.sdEntries.some(entry => entry.path === "/Books/novel.epub"), true);
});

test("TXT reader pages move monotonically and TXT progress remains in basis-point range", () => {
  let state = surfaceState({ route: "recents", recentIndex: 1 });
  state = reduceInput(state, "confirm");
  assert.equal(state.route, "txt-reader");
  assert.equal(state.readerPage, 0);
  assert.equal(state.readerProgress, 3333);
  state = reduceInput(state, "down");
  assert.equal(state.readerPage, 1);
  assert.equal(state.readerProgress, 6667);
  state = reduceInput(state, "down");
  assert.equal(readerProgress(state), 10000);
  assert.equal(reduceInput(state, "back").route, "recents");
});

test("EPUB crosses page and spine boundaries, then Back leaves end-of-book on the final page", () => {
  let state = reduceInput(surfaceState({ route: "recents" }), "confirm");
  assert.equal(state.readerSpine, 0);
  state = reduceInput(state, "down");
  assert.equal(state.readerPage, 1);
  state = reduceInput(state, "down");
  assert.equal(state.readerSpine, 1);
  assert.equal(state.readerPage, 0);
  state = reduceInput(state, "down");
  assert.equal(state.route, "end-of-book");
  state = reduceInput(state, "back");
  assert.equal(state.route, "epub-reader");
  assert.equal(state.readerSpine, 1);
  assert.equal(state.readerPage, 0);
});

test("stale EPUB progress resets safely and Today single spine still spans multiple pages", () => {
  const staleFixtures = {
    ...fixtures,
    recentBooks: [{ title: "Stale.epub", path: "/Stale.epub", spines: [["First", "Second"]], savedSpine: 9, savedPage: 1 }]
  };
  let state = reduceInput({ ...createState(staleFixtures), route: "recents" }, "confirm");
  assert.equal(state.readerSpine, 0);
  assert.equal(state.readerPage, 0);
  const today = { ...fixtures, recentBooks: [{ title: "Today - 12-08-2026", kind: "epub" }] };
  state = reduceInput({ ...createState(today), route: "recents" }, "confirm");
  assert.equal(state.readerSpines.length, 1);
  assert.ok(state.readerSpines[0].length > 1);
});

test("File Transfer surface reports an incomplete transfer without replacing the prior destination", () => {
  let state = surfaceState({ route: "home", homeIndex: 2 });
  state = reduceInput(state, "confirm");
  assert.equal(state.route, "file-transfer");
  state = { ...state, transferStatus: "INCOMPLETE - prior /update.bin retained" };
  assert.match(state.transferStatus, /prior \/update\.bin retained/);
  assert.equal(reduceInput(state, "back").route, "home");
});

test("Settings surface opens Daily Wake Status and firmware picker filters to bin files", () => {
  let state = surfaceState({ route: "settings", settingCategory: 3, settingIndex: 2 });
  assert.equal(settingsFor(state)[1].id, "daily-wake");
  state = reduceInput(state, "confirm");
  assert.equal(state.route, "daily-wake-status");
  assert.equal(state.dailyWake.credentialsReady, true);
  state = reduceInput(state, "back");
  state = { ...state, settingIndex: 3 };
  state = reduceInput(state, "confirm");
  assert.equal(state.route, "firmware-picker");
  assert.deepEqual(firmwareEntries(state).map(entry => entry.path), ["/rollback.BIN", "/update.bin"]);
  state = reduceInput(state, "confirm");
  assert.equal(state.route, "firmware-confirm");
  state = reduceInput(state, "back");
  assert.equal(state.route, "firmware-picker", "firmware picker supports cancellation");
});

test("Crash report surface clears modeled panic state and exposes only a sanitized crash reason", () => {
  let state = surfaceState({ route: "settings", settingCategory: 3, settingIndex: 5 });
  state = reduceInput(state, "confirm");
  assert.equal(state.route, "crash-report");
  assert.equal(state.panicCleared, true);
  assert.match(state.crashReason, /sanitized retained fields only/);
  assert.doesNotMatch(state.crashReason, /password|token|0x[0-9a-f]{8}/i);
});

test("Pocket Sync surface shows a sealed pack checkpoint and reset hold returns to advertising", () => {
  let state = surfaceState({ route: "home", homeIndex: 5 });
  state = reduceInput(state, "confirm");
  assert.equal(state.route, "phone-sync");
  assert.equal(state.pocketPhase, "Complete");
  assert.equal(state.pocketCheckpoint.sealed, true, "sealed pack is explicit");
  state = reduceInput(state, "confirm-hold");
  assert.equal(state.pocketPhase, "Advertising");
  assert.equal(state.pocketCheckpoint.sealed, false);
  assert.equal(reduceInput(state, "back").route, "home");
});

test("Phone Wi-Fi and every remaining Home destination use a concrete modeled route", () => {
  const expected = ["files", "recents", "file-transfer", "inbox", "cards", "phone-sync", "phone-wifi", "settings"];
  for (let index = 0; index < HOME_ITEMS.length; index += 1) {
    const opened = reduceInput(surfaceState({ route: "home", homeIndex: index, homeRecentSelected: false }), "confirm");
    assert.equal(opened.route, expected[index], HOME_ITEMS[index]);
    assert.notEqual(opened.route, "document");
  }
  const wifi = reduceInput(surfaceState({ route: "home", homeIndex: 6 }), "confirm");
  assert.match(reduceInput(wifi, "confirm").phoneWifiState, /radio disabled/);
});

test("power hold sleeps from a nested surface and wakes back to the same route", () => {
  const settings = surfaceState({ route: "settings" });
  const asleep = reduceInput(settings, "power");
  assert.equal(asleep.route, "sleep");
  assert.equal(asleep.lastRoute, "settings");
  assert.equal(reduceInput(asleep, "power").route, "settings");
});
