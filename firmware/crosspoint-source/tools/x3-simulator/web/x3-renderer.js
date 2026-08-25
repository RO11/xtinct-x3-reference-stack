import {
  HOME_ITEMS,
  SCREEN_HEIGHT,
  SCREEN_WIDTH,
  firmwareEntries,
  formatX3Date,
  inboxActions,
  labelsFor,
  quantizeRgbaInPlace,
  settingsFor,
  visibleFileEntries
} from "./simulator-core.js";
import { X3_ICONS } from "./assets/x3-icons.js";

const PALETTE = Object.freeze({ ink: "#000000", dark: "#555555", light: "#aaaaaa", paper: "#ffffff" });
const METRICS = Object.freeze({
  topPadding: 5,
  headerHeight: 84,
  verticalSpacing: 16,
  contentSidePadding: 20,
  tabBarHeight: 40,
  homeTopPadding: 56,
  homeCoverTileHeight: 242,
  homeMenuTopOffset: 16,
  menuRowHeight: 64,
  menuSpacing: 8,
  buttonHintsHeight: 40
});

function setFont(ctx, size, bold = false, small = false) {
  ctx.font = `${bold ? 700 : 400} ${size}px "${small ? "X3 Noto" : "X3 Ubuntu"}"`;
  ctx.textBaseline = "top";
  ctx.fillStyle = PALETTE.ink;
}

function clipText(ctx, text, width) {
  let value = String(text ?? "");
  if (ctx.measureText(value).width <= width) return value;
  while (value.length > 1 && ctx.measureText(`${value}…`).width > width) value = value.slice(0, -1);
  return `${value}…`;
}

function wrappedLines(ctx, text, width, maximum) {
  const words = String(text ?? "").split(/\s+/).filter(Boolean);
  const lines = [];
  let line = "";
  for (const word of words) {
    const candidate = line ? `${line} ${word}` : word;
    if (ctx.measureText(candidate).width <= width) line = candidate;
    else {
      if (line) lines.push(line);
      line = word;
      if (lines.length === maximum) break;
    }
  }
  if (line && lines.length < maximum) lines.push(line);
  if (lines.length === maximum && words.join(" ") !== lines.join(" ")) {
    lines[maximum - 1] = clipText(ctx, `${lines[maximum - 1]}…`, width);
  }
  return lines;
}

function drawCenteredWrapped(ctx, text, x, y, width, lineHeight, maximum, size, bold = false) {
  setFont(ctx, size, bold);
  const lines = wrappedLines(ctx, text, width, maximum);
  lines.forEach((line, index) => {
    const clipped = clipText(ctx, line, width);
    ctx.fillText(clipped, x + (width - ctx.measureText(clipped).width) / 2, y + index * lineHeight);
  });
}

function drawBattery(ctx, percent) {
  ctx.strokeStyle = PALETTE.ink;
  ctx.lineWidth = 2;
  ctx.strokeRect(482, 11, 20, 12);
  ctx.fillRect(503, 14, 3, 6);
  ctx.fillRect(485, 14, Math.round(14 * Math.max(0, Math.min(100, percent)) / 100), 6);
  setFont(ctx, 10, false, true);
  ctx.fillText(`${percent}%`, 447, 9);
}

function drawHeader(ctx, title, battery, height = METRICS.headerHeight) {
  drawBattery(ctx, battery);
  if (title) {
    setFont(ctx, 24, true);
    ctx.fillText(clipText(ctx, title, SCREEN_WIDTH - 40), 20, 48);
    ctx.fillRect(0, METRICS.topPadding + height - 3, SCREEN_WIDTH, 3);
  }
}

function drawSubHeader(ctx, label) {
  setFont(ctx, 18);
  ctx.fillText(clipText(ctx, label, SCREEN_WIDTH - 40), 20, 95);
  ctx.fillRect(0, 128, SCREEN_WIDTH, 1);
}

function roundedRect(ctx, x, y, width, height, radius, fill, stroke = PALETTE.ink) {
  ctx.beginPath();
  ctx.roundRect(x, y, width, height, radius);
  if (fill) { ctx.fillStyle = fill; ctx.fill(); }
  if (stroke) { ctx.strokeStyle = stroke; ctx.lineWidth = 1; ctx.stroke(); }
}

function checkerFill(ctx, x, y, width, height, period, ink = PALETTE.ink) {
  ctx.save();
  ctx.fillStyle = PALETTE.paper;
  ctx.fillRect(x, y, width, height);
  ctx.fillStyle = ink;
  // GfxRenderer::LightGray is anchored to absolute even x/even y pixels.
  const firstX = x + ((period - ((x % period) + period) % period) % period);
  const firstY = y + ((period - ((y % period) + period) % period) % period);
  for (let py = firstY; py < y + height; py += period) {
    for (let px = firstX; px < x + width; px += period) ctx.fillRect(px, py, 1, 1);
  }
  ctx.restore();
}

function checkerRoundedFill(ctx, x, y, width, height, radius) {
  ctx.save();
  ctx.beginPath();
  ctx.roundRect(x, y, width, height, radius);
  ctx.clip();
  checkerFill(ctx, x, y, width, height, 2);
  ctx.restore();
}

function drawButtonHints(ctx, labels) {
  const positions = [65, 157, 291, 383];
  labels.forEach((label, index) => {
    const x = positions[index];
    if (label) {
      roundedRect(ctx, x, 752, 80, 40, 6, PALETTE.paper);
      setFont(ctx, 12, false, true);
      const clipped = clipText(ctx, label, 70);
      ctx.fillText(clipped, x + (80 - ctx.measureText(clipped).width) / 2, 762);
    } else roundedRect(ctx, x, 777, 80, 15, 6, PALETTE.paper);
  });
}

function drawX3Icon(ctx, label, x, y) {
  const bitmap = X3_ICONS[label];
  if (!bitmap) return;
  ctx.save();
  ctx.fillStyle = PALETTE.ink;
  // Mirrors GfxRenderer::drawIcon: 32x32, MSB first, cleared bit = ink,
  // with the source rows rotated into the portrait framebuffer.
  for (let row = 0; row < 32; row += 1) {
    for (let col = 0; col < 32; col += 1) {
      const byte = bitmap[row * 4 + (col >> 3)];
      const ink = ((byte >> (7 - (col & 7))) & 1) === 0;
      if (ink) ctx.fillRect(x + 31 - row, y + col, 1, 1);
    }
  }
  ctx.restore();
}

function drawHome(ctx, state) {
  drawHeader(ctx, "XTINCT", state.fixtures.batteryPercent, METRICS.homeTopPadding);
  const recent = state.fixtures.recentBooks?.[0];
  if (recent) {
    const coverX = 28;
    const coverY = 64;
    const coverWidth = 135;
    const coverHeight = 226;
    if (state.homeRecentSelected) {
      checkerRoundedFill(ctx, 20, 56, 488, 8, 6);
      checkerFill(ctx, 20, 64, 8, 226, 2);
      checkerFill(ctx, 163, 64, 345, 226, 2);
      checkerRoundedFill(ctx, 20, 290, 488, 8, 6);
    }
    ctx.strokeStyle = PALETTE.ink;
    ctx.strokeRect(coverX, coverY, coverWidth, coverHeight);
    ctx.fillStyle = PALETTE.ink;
    ctx.fillRect(coverX, coverY + Math.floor(coverHeight / 3), coverWidth, Math.floor(coverHeight * 2 / 3));
    drawX3Icon(ctx, "Cover", coverX + 24, coverY + 24);

    const textX = 179;
    const textWidth = 309;
    setFont(ctx, 24, true);
    const titleLines = wrappedLines(ctx, recent.title, textWidth, 3);
    const titleHeight = titleLines.length * 29;
    const authorHeight = recent.author ? 36 : 0;
    let titleY = 56 + Math.floor((242 - titleHeight - authorHeight) / 2);
    titleLines.forEach(line => {
      ctx.fillText(clipText(ctx, line, textWidth), textX, titleY);
      titleY += 29;
    });
    if (recent.author) {
      titleY += 12;
      setFont(ctx, 20);
      ctx.fillText(clipText(ctx, recent.author, textWidth), textX, titleY);
    }
  } else {
    setFont(ctx, 24, true);
    ctx.fillText("No open book", 48, 146);
    setFont(ctx, 20);
    ctx.fillText("Start reading to see it here", 48, 179);
  }

  const top = 314;
  const rowsVisible = 5;
  const first = Math.min(Math.max(0, state.homeIndex - rowsVisible + 1), Math.max(0, HOME_ITEMS.length - rowsVisible));
  HOME_ITEMS.slice(first, first + rowsVisible).forEach((label, visibleIndex) => {
    const index = first + visibleIndex;
    const x = 20;
    const y = top + visibleIndex * 72;
    if (!state.homeRecentSelected && index === state.homeIndex) {
      checkerRoundedFill(ctx, x, y, 488, 64, 6);
    }
    drawX3Icon(ctx, label, x + 16, y + 16);
    setFont(ctx, 17, false);
    ctx.fillText(clipText(ctx, label, 414), x + 58, y + 19);
  });
  drawButtonHints(ctx, labelsFor(state));
}

function drawMetrics(ctx, metrics, y) {
  if (!metrics?.length) return y;
  const margin = 20;
  const gap = 16;
  const width = SCREEN_WIDTH - margin * 2;
  const cellWidth = (width - gap * (metrics.length - 1)) / metrics.length;
  metrics.forEach((metric, index) => {
    const x = margin + index * (cellWidth + gap);
    ctx.strokeStyle = PALETTE.ink;
    ctx.strokeRect(x, y, cellWidth, 61);
    setFont(ctx, 17, true);
    const value = clipText(ctx, metric.value, cellWidth - 8);
    ctx.fillText(value, x + (cellWidth - ctx.measureText(value).width) / 2, y + 6);
    setFont(ctx, 10, false, true);
    const label = clipText(ctx, metric.label, cellWidth - 8);
    ctx.fillText(label, x + (cellWidth - ctx.measureText(label).width) / 2, y + 32);
  });
  return y + 77;
}

function drawCardLike(ctx, state, model, position, kind) {
  drawHeader(ctx, model.title, state.fixtures.batteryPercent);
  drawSubHeader(ctx, position);
  setFont(ctx, 12, false, true);
  ctx.fillText(`Updated ${formatX3Date(model.generatedAt || model.createdAt)}`, 20, 145);
  drawCenteredWrapped(ctx, model.summary || model.digest?.summary, 20, 184, 488, 24, 3, 18, true);
  let y = kind === "cards" ? 272 : 288;
  if (kind === "cards") y = drawMetrics(ctx, model.metrics || [], y);
  const sections = kind === "cards"
    ? model.sections || []
    : [{ heading: "KEY POINTS", lines: model.digest?.points || [] }];
  for (const section of sections) {
    if (y >= 708) break;
    setFont(ctx, 17, true);
    ctx.fillText(clipText(ctx, section.heading, 488), 20, y);
    y += 25;
    for (const line of section.lines || []) {
      if (y >= 708) break;
      setFont(ctx, 12, false, true);
      ctx.fillText(clipText(ctx, `- ${line}`, 488), 20, y);
      y += 25;
    }
    y += 16;
  }
  drawButtonHints(ctx, labelsFor(state));
}

function drawCards(ctx, state) {
  const card = state.fixtures.cards[state.cardIndex];
  if (!card) return drawEmpty(ctx, state, "DAILY CARDS", "No cached cards.");
  drawCardLike(ctx, state, card, `${state.cardIndex + 1}/${state.fixtures.cards.length}  ${state.refreshState}`, "cards");
}

function drawInboxPreview(ctx, state) {
  const item = state.fixtures.inbox[state.inboxIndex];
  if (!item) return drawEmpty(ctx, state, "XTINCT INBOX", "Inbox empty. Open Actions and choose Sync now.");
  drawCardLike(ctx, state, item, `${state.inboxIndex + 1}/${state.fixtures.inbox.length}  ${item.moduleId}  ${item.kind}`, "inbox");
}

function drawInboxList(ctx, state) {
  drawHeader(ctx, "XTINCT Inbox · 1", state.fixtures.batteryPercent);
  let y = 105;
  state.fixtures.inbox.slice(0, 10).forEach((item, index) => {
    const selected = index === state.inboxIndex;
    if (selected) checkerRoundedFill(ctx, 20, y, 487, 60, 6);
    setFont(ctx, 17, true);
    ctx.fillStyle = PALETTE.ink;
    ctx.fillText(clipText(ctx, item.title, 419), 68, y + 7);
    setFont(ctx, 10, false, true);
    ctx.fillStyle = PALETTE.ink;
    ctx.fillText(clipText(ctx, `${item.moduleId} · ${item.kind} · ${item.state}`, 419), 68, y + 30);
    if (item.kind === "epub") drawX3Icon(ctx, "Book", 28, y + 16);
    y += 60;
  });
  drawButtonHints(ctx, labelsFor(state));
}

function drawActions(ctx, state) {
  drawInboxPreview(ctx, { ...state, route: "inbox" });
  ctx.fillStyle = PALETTE.paper;
  ctx.fillRect(36, 210, 456, 370);
  ctx.strokeStyle = PALETTE.ink;
  ctx.lineWidth = 2;
  ctx.strokeRect(36, 210, 456, 370);
  setFont(ctx, 20, true);
  ctx.fillText("INBOX ACTIONS", 58, 235);
  ctx.fillRect(37, 275, 454, 2);
  inboxActions(state).forEach((action, index) => {
    const y = 298 + index * 62;
    if (index === state.actionIndex) roundedRect(ctx, 54, y, 420, 50, 5, PALETTE.ink, PALETTE.ink);
    setFont(ctx, 16);
    ctx.fillStyle = index === state.actionIndex ? PALETTE.paper : PALETTE.ink;
    ctx.fillText(action.label, 72, y + 15);
  });
}

function drawReaderBody(ctx, state, body, footer) {
  drawHeader(ctx, state.documentTitle || "Reader", state.fixtures.batteryPercent);
  setFont(ctx, 12, false, true);
  ctx.fillText("VERIFIED LOCAL CONTENT", 20, 112);
  setFont(ctx, 15, false);
  const lines = wrappedLines(ctx, body || "The selected local document is empty.", 488, 21);
  lines.forEach((line, index) => ctx.fillText(clipText(ctx, line, 488), 20, 150 + index * 25));
  ctx.fillStyle = PALETTE.light;
  ctx.fillRect(20, 716, 488, 2);
  setFont(ctx, 10, false, true);
  ctx.fillStyle = PALETTE.ink;
  ctx.fillText(clipText(ctx, footer, 470), 28, 727);
  drawButtonHints(ctx, labelsFor(state));
}

function drawDocument(ctx, state) {
  drawReaderBody(ctx, state, state.documentBody || "Local content is loaded from the isolated simulator session.",
    "Cloned fixture bytes - no device or production write");
}

function drawTxtReader(ctx, state) {
  const page = state.readerPages[state.readerPage] || "";
  drawReaderBody(ctx, state, page,
    `TXT page ${state.readerPage + 1}/${Math.max(1, state.readerPages.length)} - ${Math.round(state.readerProgress / 100)}%`);
}

function drawEpubReader(ctx, state) {
  const pages = state.readerSpines[state.readerSpine] || [];
  const page = pages[state.readerPage] || "";
  drawReaderBody(ctx, state, page,
    `EPUB spine ${state.readerSpine + 1}/${Math.max(1, state.readerSpines.length)} - page ${state.readerPage + 1}/${Math.max(1, pages.length)} - ${Math.round(state.readerProgress / 100)}%`);
}

function drawEndOfBook(ctx, state) {
  drawHeader(ctx, "End of book", state.fixtures.batteryPercent);
  drawCenteredWrapped(ctx, state.documentTitle, 40, 245, 448, 30, 3, 22, true);
  drawCenteredWrapped(ctx, "Back returns to the final page. Managed Inbox artifacts do not expose hash-named sibling files.", 50, 365, 428, 25, 4, 16);
  drawButtonHints(ctx, labelsFor(state));
}

function drawImageViewer(ctx, state) {
  drawHeader(ctx, state.documentTitle || "Image", state.fixtures.batteryPercent);
  checkerRoundedFill(ctx, 54, 138, 420, 510, 8);
  drawCenteredWrapped(ctx, "BMP image surface - cloned session only", 80, 666, 368, 24, 2, 16, true);
  drawButtonHints(ctx, labelsFor(state));
}

function drawListRows(ctx, rows, selected, y = 144) {
  if (!rows.length) {
    setFont(ctx, 15);
    ctx.fillText("No entries", 20, y + 16);
    return;
  }
  rows.slice(0, 9).forEach((row, index) => {
    if (index === selected) checkerRoundedFill(ctx, 20, y, 488, 58, 6);
    setFont(ctx, 16, true);
    ctx.fillText(clipText(ctx, row.title, 448), 38, y + 7);
    if (row.detail) {
      setFont(ctx, 10, false, true);
      ctx.fillText(clipText(ctx, row.detail, 448), 38, y + 32);
    }
    y += 62;
  });
}

function drawFiles(ctx, state, sdEntries) {
  const modeled = { ...state, sdEntries: state.sdEntries?.length ? state.sdEntries : sdEntries };
  const entries = visibleFileEntries(modeled);
  drawHeader(ctx, "FILES", state.fixtures.batteryPercent);
  drawSubHeader(ctx, `${state.filePath} - CLONED SESSION`);
  drawListRows(ctx, entries.map(entry => ({
    title: `${entry.type === "directory" ? "[DIR]" : "[FILE]"} ${entry.path.split("/").pop()}`,
    detail: entry.type === "directory" ? "Directory" : "Supported local file"
  })), state.fileIndex);
  drawButtonHints(ctx, labelsFor(state));
}

function drawRecents(ctx, state) {
  drawHeader(ctx, "RECENTS", state.fixtures.batteryPercent);
  drawListRows(ctx, (state.fixtures.recentBooks || []).map(book => ({ title: book.title, detail: book.author || book.path || "Local document" })), state.recentIndex, 110);
  drawButtonHints(ctx, labelsFor(state));
}

function drawConfirmation(ctx, state, heading, detail) {
  drawHeader(ctx, heading, state.fixtures.batteryPercent);
  drawCenteredWrapped(ctx, detail, 50, 272, 428, 30, 5, 20, true);
  drawButtonHints(ctx, labelsFor(state));
}

function drawFileTransfer(ctx, state) {
  drawHeader(ctx, "FILE TRANSFER", state.fixtures.batteryPercent);
  drawCenteredWrapped(ctx, state.transferStatus, 40, 220, 448, 30, 4, 22, true);
  drawCenteredWrapped(ctx, "Session root is isolated. Atomic PUT keeps the prior destination when an upload is incomplete.", 55, 380, 418, 25, 5, 16);
  drawCenteredWrapped(ctx, "Physical Wi-Fi, SD writes and browser interoperability are not exercised here.", 55, 540, 418, 25, 4, 14);
  drawButtonHints(ctx, labelsFor(state));
}

function drawSettings(ctx, state) {
  const category = state.settings[state.settingCategory];
  const rows = [{ title: `[${category.label}]`, detail: "Select to change category" }, ...settingsFor(state).map(setting => ({
    title: setting.label,
    detail: setting.value || (setting.type === "action" ? "Open" : "")
  }))];
  drawHeader(ctx, "SETTINGS", state.fixtures.batteryPercent);
  drawSubHeader(ctx, state.firmwareStatus);
  drawListRows(ctx, rows, state.settingIndex);
  drawButtonHints(ctx, labelsFor(state));
}

function drawDailyWakeStatus(ctx, state) {
  drawHeader(ctx, "DAILY WAKE STATUS", state.fixtures.batteryPercent);
  const rows = [["Requested", state.dailyWake.requested ? "Yes" : "No"], ["Credentials", state.dailyWake.credentialsReady ? "Ready" : "Missing"], ["Last result", state.dailyWake.lastResult], ["Next wake", state.dailyWake.nextWake]];
  let y = 150;
  rows.forEach(([label, value]) => {
    setFont(ctx, 16, true); ctx.fillText(label, 28, y);
    setFont(ctx, 15); ctx.fillText(clipText(ctx, value, 285), 215, y);
    y += 72;
  });
  drawButtonHints(ctx, labelsFor(state));
}

function drawFirmwarePicker(ctx, state) {
  const entries = firmwareEntries(state);
  drawHeader(ctx, "FIRMWARE PICKER", state.fixtures.batteryPercent);
  drawSubHeader(ctx, ".bin files only - validation does not flash");
  drawListRows(ctx, entries.map(entry => ({ title: entry.path.split("/").pop(), detail: entry.path })), state.firmwareIndex);
  drawButtonHints(ctx, labelsFor(state));
}

function drawResourceStatus(ctx, state) {
  drawHeader(ctx, "RESOURCE STATUS", state.fixtures.batteryPercent);
  drawCenteredWrapped(ctx, "Firmware SHA, OTA bytes, linked DRAM, task stacks and configured buffers are supplied by the release inspector beside this frame.", 45, 235, 438, 28, 7, 17, true);
  drawButtonHints(ctx, labelsFor(state));
}

function drawCrashReport(ctx, state) {
  drawHeader(ctx, "CRASH REPORT", state.fixtures.batteryPercent);
  drawCenteredWrapped(ctx, "The retained panic flag was cleared when this surface opened.", 45, 180, 438, 28, 4, 18, true);
  setFont(ctx, 14);
  wrappedLines(ctx, state.crashReason, 448, 6).forEach((line, index) => ctx.fillText(line, 40, 340 + index * 26));
  setFont(ctx, 11, false, true);
  ctx.fillText(state.panicCleared ? "PANIC STATE: CLEARED" : "PANIC STATE: PENDING", 40, 565);
  ctx.fillText("No raw stack, logs, credentials or abort strings retained", 40, 604);
  drawButtonHints(ctx, labelsFor(state));
}

function drawPhoneSync(ctx, state) {
  drawHeader(ctx, "PHONE SYNC", state.fixtures.batteryPercent);
  drawCenteredWrapped(ctx, state.pocketPhase, 45, 175, 438, 34, 3, 24, true);
  const checkpoint = state.pocketCheckpoint || { stream: 0, offset: 0, sealed: false };
  drawCenteredWrapped(ctx, `Checkpoint stream ${checkpoint.stream} at ${checkpoint.offset} bytes`, 55, 310, 418, 28, 3, 17);
  drawCenteredWrapped(ctx, checkpoint.sealed ? "Pack sealed and atomically committed" : "Staging is incomplete - no V1 or V2 publication", 55, 430, 418, 28, 4, 17, true);
  drawCenteredWrapped(ctx, "Protocol state only. BLE radio, bonding, MTU and phone interoperability require physical hardware.", 55, 570, 418, 23, 5, 13);
  drawButtonHints(ctx, labelsFor(state));
}

function drawPhoneWifi(ctx, state) {
  drawHeader(ctx, "PHONE WI-FI", state.fixtures.batteryPercent);
  drawCenteredWrapped(ctx, state.phoneWifiState, 45, 230, 438, 32, 4, 22, true);
  drawCenteredWrapped(ctx, "Provisioning flow is modeled without enabling a browser, radio or production network.", 55, 420, 418, 26, 4, 16);
  drawButtonHints(ctx, labelsFor(state));
}

function drawSleep(ctx, state, sleepImage) {
  if (sleepImage) ctx.putImageData(sleepImage, 0, 0);
  else drawEmpty(ctx, state, "SLEEP", "Native sleep.bmp is unavailable.");
}

function drawEmpty(ctx, state, title, message) {
  drawHeader(ctx, title, state.fixtures.batteryPercent);
  drawCenteredWrapped(ctx, message, 40, 250, 448, 28, 4, 20, true);
  drawButtonHints(ctx, labelsFor(state));
}

export class X3Renderer {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d", { alpha: false, willReadFrequently: true });
    this.ctx.imageSmoothingEnabled = false;
    this.sleepImage = null;
    this.sdEntries = [];
  }

  setSleepImage(imageData) { this.sleepImage = imageData; }
  setSdEntries(entries) { this.sdEntries = entries || []; }

  quantizeFrame() {
    const image = this.ctx.getImageData(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT);
    quantizeRgbaInPlace(image.data);
    this.ctx.putImageData(image, 0, 0);
  }

  render(state) {
    const { ctx } = this;
    ctx.save();
    ctx.fillStyle = PALETTE.paper;
    ctx.fillRect(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT);
    ctx.lineJoin = "round";
    ctx.lineCap = "square";
    switch (state.route) {
      case "home": drawHome(ctx, state); break;
      case "cards": drawCards(ctx, state); break;
      case "inbox": state.inboxView === "list" ? drawInboxList(ctx, state) : drawInboxPreview(ctx, state); break;
      case "actions": drawActions(ctx, state); break;
      case "document": drawDocument(ctx, state); break;
      case "txt-reader": drawTxtReader(ctx, state); break;
      case "epub-reader": drawEpubReader(ctx, state); break;
      case "end-of-book": drawEndOfBook(ctx, state); break;
      case "image-viewer": drawImageViewer(ctx, state); break;
      case "files": drawFiles(ctx, state, this.sdEntries); break;
      case "recents": drawRecents(ctx, state); break;
      case "delete-confirm": drawConfirmation(ctx, state, "DELETE FROM CLONE?", state.deleteTarget?.path || "No target"); break;
      case "remove-recent-confirm": drawConfirmation(ctx, state, "REMOVE FROM RECENTS?", state.deleteTarget?.title || "No target"); break;
      case "file-transfer": drawFileTransfer(ctx, state); break;
      case "settings": drawSettings(ctx, state); break;
      case "daily-wake-status": drawDailyWakeStatus(ctx, state); break;
      case "firmware-picker": drawFirmwarePicker(ctx, state); break;
      case "firmware-confirm": drawConfirmation(ctx, state, "VALIDATE FIRMWARE?", state.firmwareSelection); break;
      case "resource-status": drawResourceStatus(ctx, state); break;
      case "crash-report": drawCrashReport(ctx, state); break;
      case "phone-sync": drawPhoneSync(ctx, state); break;
      case "phone-wifi": drawPhoneWifi(ctx, state); break;
      case "sleep": drawSleep(ctx, state, this.sleepImage); break;
      default: drawEmpty(ctx, state, "XTINCT", "Route not implemented.");
    }
    ctx.restore();
    this.quantizeFrame();
  }
}
