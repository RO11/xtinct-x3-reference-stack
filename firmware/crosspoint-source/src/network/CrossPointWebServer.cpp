#include "CrossPointWebServer.h"

#include <ArduinoJson.h>
#include <FsHelpers.h>
#include <HalGPIO.h>
#include <HalStorage.h>
#include <Logging.h>
#include <WiFi.h>
#include <esp_efuse.h>
#include <esp_efuse_table.h>
#include <esp_system.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

#include "CrossPointSettings.h"
#include "FontInstaller.h"
#include "FileTransferPathPolicy.h"
#include "SdCardFontSystem.h"
#include "SettingsList.h"
#include "WebDAVHandler.h"
#include "XtinctBuildInfo.h"
#include "XtinctFeedConfigStore.h"
#include "XtinctWakePlan.h"
#include "XtinctWakeStatusStore.h"
#include "html/FilesPageHtml.generated.h"
#include "html/FontsPageHtml.generated.h"
#include "html/HomePageHtml.generated.h"
#include "html/SettingsPageHtml.generated.h"
#include "html/js/jszip_minJs.generated.h"
#include "util/BookCacheUtils.h"
#include "util/TaskWatchdog.h"
#include "util/XtinctWakeSchedule.h"

namespace {
// Folders/files to hide from the web interface file browser
// Note: Items starting with "." are automatically hidden
constexpr const char* HIDDEN_ITEMS[] = {"System Volume Information", "XTCache"};
constexpr uint16_t UDP_PORTS[] = {54982, 48123, 39001, 44044, 59678};
constexpr uint16_t LOCAL_UDP_PORT = 8134;
constexpr size_t MAX_DELETE_REQUEST_BYTES = 4096;
constexpr size_t MAX_DELETE_ITEMS = 32;
constexpr size_t MAX_DELETE_FAILURE_BYTES = 1024;

struct WebReplaceOps {
  bool exists(const char* path) const { return Storage.exists(path); }
  bool rename(const char* source, const char* destination) const { return Storage.rename(source, destination); }
  bool remove(const char* path) const { return Storage.remove(path); }
};

bool makeUniqueWebSibling(const String& destination, const char* purpose, String& path) {
  const int slash = destination.lastIndexOf('/');
  String parent = slash <= 0 ? "/" : destination.substring(0, slash);
  if (!parent.endsWith("/")) parent += "/";
  for (uint8_t attempt = 0; attempt < 16; ++attempt) {
    char leaf[52];
    const int leafBytes = snprintf(leaf, sizeof(leaf), ".xtinct-web-%s-%08lx.tmp", purpose,
                                   static_cast<unsigned long>(esp_random()));
    if (leafBytes <= 0 || static_cast<size_t>(leafBytes) >= sizeof(leaf) ||
        parent.length() > xtinct::file_transfer::MAX_PATH_BYTES - static_cast<size_t>(leafBytes)) {
      path = "";
      return false;
    }
    path = parent + leaf;
    if (!Storage.exists(path.c_str())) return true;
  }
  path = "";
  return false;
}

// File Transfer is an unauthenticated convenience service. Daily Cards' local
// wake time and NTP-validity latch are security-sensitive because they control
// unattended network activity, so they can be changed only through the
// short-lived, physically initiated Phone Wi-Fi Setup portal.
bool isProtectedFileTransferSetting(const char* key) {
  return key != nullptr &&
         (std::strcmp(key, "clockUtcOffsetQ") == 0 || std::strcmp(key, "clockHasBeenSynced") == 0);
}

// Static pointer for WebSocket callback (WebSocketsServer requires C-style callback)
CrossPointWebServer* wsInstance = nullptr;

// WebSocket upload state
HalFile wsUploadFile;
String wsUploadFileName;
String wsUploadPath;
String wsUploadFilePath;
size_t wsUploadSize = 0;
size_t wsUploadReceived = 0;
unsigned long wsUploadStartTime = 0;
bool wsUploadInProgress = false;
bool wsUploadOwnsPartial = false;
uint8_t wsUploadClientNum = 255;  // 255 = no active upload client
size_t wsLastProgressSent = 0;
String wsLastCompleteName;
size_t wsLastCompleteSize = 0;
unsigned long wsLastCompleteAt = 0;

String normalizeWebPath(const String& inputPath) {
  String normalized;
  return xtinct::file_transfer::normalizeTransferPath(inputPath, normalized) ? normalized : String();
}

bool isProtectedItemName(const String& name) {
  return xtinct::file_transfer::isProtectedTransferComponent(name);
}

bool isProtectedWebPath(const String& path,
                        const xtinct::file_transfer::PathIntent intent = xtinct::file_transfer::PathIntent::Existing) {
  return xtinct::file_transfer::checkTransferPath(path, intent) != xtinct::file_transfer::PathDecision::Allowed;
}

void appendDeleteFailure(char* output, const size_t capacity, size_t& used, const String& path, const char* reason) {
  if (!output || capacity == 0 || used >= capacity - 1) return;
  const String& label = path.isEmpty() ? String("<invalid>") : path;
  for (size_t index = 0; index < label.length() && used < capacity - 1; ++index) output[used++] = label[index];
  for (size_t index = 0; reason[index] != '\0' && used < capacity - 1; ++index) output[used++] = reason[index];
  output[used] = '\0';
}
}  // namespace

// File listing page template - now using generated headers:
// - HomePageHtml (from html/HomePage.html)
// - FilesPageHeaderHtml (from html/FilesPageHeader.html)
// - FilesPageFooterHtml (from html/FilesPageFooter.html)
CrossPointWebServer::CrossPointWebServer() {}

CrossPointWebServer::~CrossPointWebServer() { stop(); }

void CrossPointWebServer::begin() {
  if (running) {
    LOG_DBG("WEB", "Web server already running");
    return;
  }

  // Check if we have a valid network connection (either STA connected or AP mode)
  const wifi_mode_t wifiMode = WiFi.getMode();
  const bool isStaConnected = (wifiMode & WIFI_MODE_STA) && (WiFi.status() == WL_CONNECTED);
  const bool isInApMode = (wifiMode & WIFI_MODE_AP) && (WiFi.softAPgetStationNum() >= 0);  // AP is running

  if (!isStaConnected && !isInApMode) {
    LOG_DBG("WEB", "Cannot start webserver - no valid network (mode=%d, status=%d)", wifiMode, WiFi.status());
    return;
  }

  // Store AP mode flag for later use (e.g., in handleStatus)
  apMode = isInApMode;

  LOG_DBG("WEB", "[MEM] Free heap before begin: %d bytes", ESP.getFreeHeap());
  LOG_DBG("WEB", "Network mode: %s", apMode ? "AP" : "STA");

  LOG_DBG("WEB", "Creating web server on port %d...", port);
  server.reset(new WebServer(port));

  // Disable WiFi sleep to improve responsiveness and prevent 'unreachable' errors.
  // This is critical for reliable web server operation on ESP32.
  WiFi.setSleep(false);
  // Default varies by ESP32 core version. The activity's loss-recovery loop
  // relies on driver retries during transient disconnects.
  WiFi.setAutoReconnect(true);

  // Note: WebServer class doesn't have setNoDelay() in the standard ESP32 library.
  // We rely on disabling WiFi sleep for responsiveness.

  LOG_DBG("WEB", "[MEM] Free heap after WebServer allocation: %d bytes", ESP.getFreeHeap());

  if (!server) {
    LOG_ERR("WEB", "Failed to create WebServer!");
    return;
  }

  // Add Access-Control-Allow-* headers to every response so web-based clients
  // and PWAs on other origins can use the HTTP API. Preflight OPTIONS requests
  // are answered in handleNotFound().
  server->enableCORS(true);

  // Setup routes
  LOG_DBG("WEB", "Setting up routes...");
  server->on("/", HTTP_GET, [this] { handleRoot(); });
  server->on("/files", HTTP_GET, [this] { handleFileList(); });
  server->on("/js/jszip.min.js", HTTP_GET, [this] { handleJszip(); });

  server->on("/api/status", HTTP_GET, [this] { handleStatus(); });
  server->on("/api/files", HTTP_GET, [this] { handleFileListData(); });
  server->on("/download", HTTP_GET, [this] { handleDownload(); });

  // Upload endpoint with special handling for multipart form data
  server->on("/upload", HTTP_POST, [this] { handleUploadPost(upload); }, [this] { handleUpload(upload); });

  // Create folder endpoint
  server->on("/mkdir", HTTP_POST, [this] { handleCreateFolder(); });

  // Rename file endpoint
  server->on("/rename", HTTP_POST, [this] { handleRename(); });

  // Move file endpoint
  server->on("/move", HTTP_POST, [this] { handleMove(); });

  // Delete file/folder endpoint
  server->on("/delete", HTTP_POST, [this] { handleDelete(); });

  // Settings endpoints
  server->on("/settings", HTTP_GET, [this] { handleSettingsPage(); });
  server->on("/api/settings", HTTP_GET, [this] { handleGetSettings(); });
  server->on("/api/settings", HTTP_POST, [this] { handlePostSettings(); });

  // Font management endpoints
  server->on("/fonts", HTTP_GET, [this] { handleFontsPage(); });
  server->on("/api/fonts", HTTP_GET, [this] { handleFontList(); });
  server->on("/api/fonts/upload", HTTP_POST, [this] { handleFontUpload(); }, [this] { handleFontUploadData(); });
  server->on("/api/fonts/delete", HTTP_POST, [this] { handleFontDelete(); });

  server->onNotFound([this] { handleNotFound(); });
  LOG_DBG("WEB", "[MEM] Free heap after route setup: %d bytes", ESP.getFreeHeap());

  // Collect WebDAV headers and register handler
  const char* davHeaders[] = {"Depth", "Destination", "Overwrite", "If", "Lock-Token", "Timeout"};
  server->collectHeaders(davHeaders, 6);
  server->addHandler(new WebDAVHandler());  // Note: WebDAVHandler will be deleted by WebServer when server is stopped
  LOG_DBG("WEB", "WebDAV handler initialized");

  server->begin();

  // Start WebSocket server for fast binary uploads
  LOG_DBG("WEB", "Starting WebSocket server on port %d...", wsPort);
  wsServer.reset(new WebSocketsServer(wsPort));
  wsInstance = const_cast<CrossPointWebServer*>(this);
  wsServer->begin();
  wsServer->onEvent(wsEventCallback);
  LOG_DBG("WEB", "WebSocket server started");

  udpActive = udp.begin(LOCAL_UDP_PORT);
  LOG_DBG("WEB", "Discovery UDP %s on port %d", udpActive ? "enabled" : "failed", LOCAL_UDP_PORT);

  // All request handlers run on the task that calls handleClient(). Register
  // that task before any handler can call esp_task_wdt_reset().
  const esp_err_t watchdogResult = esp_task_wdt_add(nullptr);
  watchdogTaskRegistered = watchdogResult == ESP_OK;
  if (!watchdogTaskRegistered) {
    LOG_ERR("WEB", "Failed to register web server task with watchdog: %s", esp_err_to_name(watchdogResult));
  }

  running = true;

  LOG_DBG("WEB", "Web server started on port %d", port);
  // Show the correct IP based on network mode
  const String ipAddr = apMode ? WiFi.softAPIP().toString() : WiFi.localIP().toString();
  LOG_DBG("WEB", "Access at http://%s/", ipAddr.c_str());
  LOG_DBG("WEB", "WebSocket at ws://%s:%d/", ipAddr.c_str(), wsPort);
  LOG_DBG("WEB", "[MEM] Free heap after server.begin(): %d bytes", ESP.getFreeHeap());
}

void CrossPointWebServer::abortWsUpload(const char* tag) {
  // Explicit close() required: file-scope global persists beyond function scope
  if (wsUploadFile) wsUploadFile.close();
  if (wsUploadOwnsPartial) {
    if (Storage.remove(wsUploadFilePath.c_str()) || !Storage.exists(wsUploadFilePath.c_str())) {
      LOG_DBG(tag, "Deleted incomplete upload: %s", wsUploadFilePath.c_str());
      wsUploadOwnsPartial = false;
      wsUploadFilePath = "";
    } else {
      LOG_ERR(tag, "Failed to delete owned incomplete upload: %s", wsUploadFilePath.c_str());
    }
  }
  wsUploadInProgress = false;
  wsUploadClientNum = 255;
  wsLastProgressSent = 0;
}

void CrossPointWebServer::stop() {
  if (!running || !server) {
    LOG_DBG("WEB", "stop() called but already stopped (running=%d, server=%p)", running, server.get());
    if (watchdogTaskRegistered) {
      esp_task_wdt_delete(nullptr);
      watchdogTaskRegistered = false;
    }
    return;
  }

  LOG_DBG("WEB", "STOP INITIATED - setting running=false first");
  running = false;  // Set this FIRST to prevent handleClient from using server

  LOG_DBG("WEB", "[MEM] Free heap before stop: %d bytes", ESP.getFreeHeap());

  // Close any in-progress WebSocket upload and remove partial file
  if (wsUploadInProgress || wsUploadOwnsPartial) {
    abortWsUpload("WEB");
  }

  // Stop WebSocket server
  if (wsServer) {
    LOG_DBG("WEB", "Stopping WebSocket server...");
    wsServer->close();
    wsServer.reset();
    wsInstance = nullptr;
    LOG_DBG("WEB", "WebSocket server stopped");
  }

  if (udpActive) {
    udp.stop();
    udpActive = false;
  }

  // Brief delay to allow any in-flight handleClient() calls to complete
  delay(20);

  server->stop();
  LOG_DBG("WEB", "[MEM] Free heap after server->stop(): %d bytes", ESP.getFreeHeap());

  // Brief delay before deletion
  delay(10);

  server.reset();
  LOG_DBG("WEB", "Web server stopped and deleted");
  LOG_DBG("WEB", "[MEM] Free heap after delete server: %d bytes", ESP.getFreeHeap());

  if (watchdogTaskRegistered) {
    esp_task_wdt_delete(nullptr);
    watchdogTaskRegistered = false;
  }

  // Note: Static upload variables (uploadFileName, uploadPath, uploadError) are declared
  // later in the file and will be cleared when they go out of scope or on next upload
  LOG_DBG("WEB", "[MEM] Free heap final: %d bytes", ESP.getFreeHeap());
}

void CrossPointWebServer::handleClient() {
  static unsigned long lastDebugPrint = 0;

  // Check running flag FIRST before accessing server
  if (!running) {
    return;
  }

  // Double-check server pointer is valid
  if (!server) {
    LOG_DBG("WEB", "WARNING: handleClient called with null server!");
    return;
  }

  // Print debug every 10 seconds to confirm handleClient is being called
  if (millis() - lastDebugPrint > 10000) {
    LOG_DBG("WEB", "handleClient active, server running on port %d", port);
    lastDebugPrint = millis();
  }

  server->handleClient();

  // Handle WebSocket events
  if (wsServer) {
    wsServer->loop();
  }

  // Respond to discovery broadcasts
  if (udpActive) {
    int packetSize = udp.parsePacket();
    if (packetSize > 0) {
      char buffer[16];
      int len = udp.read(buffer, sizeof(buffer) - 1);
      if (len > 0) {
        buffer[len] = '\0';
        if (strcmp(buffer, "hello") == 0) {
          String hostname = WiFi.getHostname();
          if (hostname.isEmpty()) {
            hostname = "crosspoint";
          }
          String message = "crosspoint (on " + hostname + ");" + String(wsPort);
          udp.beginPacket(udp.remoteIP(), udp.remotePort());
          udp.write(reinterpret_cast<const uint8_t*>(message.c_str()), message.length());
          udp.endPacket();
        }
      }
    }
  }
}

CrossPointWebServer::WsUploadStatus CrossPointWebServer::getWsUploadStatus() const {
  WsUploadStatus status;
  status.inProgress = wsUploadInProgress;
  status.received = wsUploadReceived;
  status.total = wsUploadSize;
  status.filename = wsUploadFileName.c_str();
  status.lastCompleteName = wsLastCompleteName.c_str();
  status.lastCompleteSize = wsLastCompleteSize;
  status.lastCompleteAt = wsLastCompleteAt;
  return status;
}

static void sendHtmlContent(WebServer* server, const char* data, size_t len) {
  server->sendHeader("Content-Encoding", "gzip");
  server->send_P(200, "text/html", data, len);
}

void CrossPointWebServer::handleRoot() const {
  sendHtmlContent(server.get(), HomePageHtml, sizeof(HomePageHtml));
  LOG_DBG("WEB", "Served root page");
}

void CrossPointWebServer::handleJszip() const {
  server->sendHeader("Content-Encoding", "gzip");
  server->send_P(200, "application/javascript", jszip_minJs, jszip_minJsCompressedSize);
  LOG_DBG("WEB", "Served jszip.min.js");
}

void CrossPointWebServer::handleNotFound() const {
  // CORS preflight: routes are registered per-method, so OPTIONS requests land
  // here. The Access-Control-Allow-* headers are added by enableCORS().
  if (server->method() == HTTP_OPTIONS) {
    server->send(204, "text/plain", "");
    return;
  }

  // in AP mode, redirect unmatched browser/captive-portal requests to "/" so the OS auto-opens the browser
  // API requests (/api/*) still return 404 so XHR errors surface correctly
  // see https://en.wikipedia.org/wiki/Captive_portal#Detection
  if (apMode && !server->uri().startsWith("/api/")) {
    server->sendHeader("Location", "/", true);
    server->send(302, "text/plain", "");
    return;
  }

  String message = "404 Not Found\n\n";
  message += "URI: " + server->uri() + "\n";
  server->send(404, "text/plain", message);
}

void CrossPointWebServer::handleStatus() const {
  // Get correct IP based on AP vs STA mode
  const String ipAddr = apMode ? WiFi.softAPIP().toString() : WiFi.localIP().toString();

  JsonDocument doc;
  doc["version"] = CROSSPOINT_VERSION;
  doc["ip"] = ipAddr;
  doc["mode"] = apMode ? "AP" : "STA";
  doc["rssi"] = apMode ? 0 : WiFi.RSSI();
  doc["freeHeap"] = ESP.getFreeHeap();
  doc["uptime"] = millis() / 1000;
  doc["device"] = gpio.deviceIsX3() ? "X3" : "X4";

  // Safe, read-only wake diagnostics. File Transfer is intentionally
  // unauthenticated, so never include SSIDs, bearer material, card contents or
  // hidden cache paths here.
  doc["xtinctRelease"] = XTINCT_RELEASE_LABEL;
  doc["xtinctBuildId"] = XTINCT_BUILD_ID;
  const XtinctWakePlan wakePlan = calculateXtinctWakePlan();
  JsonObject wake = doc["dailyWake"].to<JsonObject>();
  wake["auto_sync_enabled"] = XTINCT_FEED_CONFIG.isAutoSyncRequested();
  wake["credential_installed"] = XTINCT_FEED_CONFIG.hasReadToken();
  wake["clock_synchronized"] = SETTINGS.clockHasBeenSynced != 0;
  wake["schedule_ready"] = wakePlan.ready;
  wake["schedule_reason"] = xtinctWakeReasonCode(wakePlan.reason);
  wake["schedule_reason_text"] = xtinctWakeReasonLabel(wakePlan.reason);
  char timezone[16] = "invalid";
  if (formatXtinctUtcOffset(SETTINGS.clockUtcOffsetQ, timezone, sizeof(timezone))) {
    wake["timezone"] = timezone;
  } else {
    wake["timezone"] = "invalid";
  }
  wake["timezone_brisbane_warning"] = SETTINGS.clockUtcOffsetQ != 88;
  JsonArray windows = wake["windows_local"].to<JsonArray>();
  const auto configuredWindows =
      xtinct::wake_schedule::buildWindows(XTINCT_FEED_CONFIG.getWakeHour(), XTINCT_FEED_CONFIG.getWakeMinute());
  for (size_t i = 0; i < configuredWindows.count; ++i) {
    char window[8];
    if (formatXtinctLocalTime(configuredWindows.values[i].hour, configuredWindows.values[i].minute, window,
                              sizeof(window))) {
      windows.add(window);
    }
  }
  if (wakePlan.nextLocalKnown) {
    char nextWake[8];
    if (formatXtinctLocalTime(wakePlan.nextHour, wakePlan.nextMinute, nextWake, sizeof(nextWake))) {
      wake["next_wake_local"] = nextWake;
    }
  } else {
    wake["next_wake_local"] = nullptr;
  }
  wake["last_timer_arm_state"] = xtinctTimerArmStateCode(XTINCT_WAKE_STATUS.getLastTimerState());
  wake["last_timer_arm_reason"] = xtinctWakeReasonCode(XTINCT_WAKE_STATUS.getLastTimerReason());
  wake["last_timer_arm_error"] = XTINCT_WAKE_STATUS.getLastTimerError();
  if (XTINCT_WAKE_STATUS.isLastTimerNextLocalKnown()) {
    char lastTimerWake[8];
    if (formatXtinctLocalTime(XTINCT_WAKE_STATUS.getLastTimerNextHour(),
                              XTINCT_WAKE_STATUS.getLastTimerNextMinute(), lastTimerWake,
                              sizeof(lastTimerWake))) {
      wake["last_timer_next_wake_local"] = lastTimerWake;
    }
  } else {
    wake["last_timer_next_wake_local"] = nullptr;
  }
  wake["last_wake_cause"] = xtinctWakeCauseCode(XTINCT_WAKE_STATUS.getLastWakeCause());

  char snBuf[33] = {0};
  bool valid = false;
#if !CONFIG_IDF_TARGET_ESP32
  // Classic ESP32's efuse table has no USER_DATA block (C3/S3 only)
  if (esp_efuse_read_field_blob(ESP_EFUSE_USER_DATA, snBuf, 256) == ESP_OK) {
    valid = snBuf[0] != '\0' && snBuf[0] != (char)0xFF;
    for (int i = 0; i < 32 && snBuf[i] != '\0'; i++) {
      if (!std::isprint(static_cast<unsigned char>(snBuf[i]))) {
        valid = false;
        break;
      }
    }
  }
#endif

  if (valid) {
    doc["serial"] = snBuf;
  } else {
    doc["serial"] = "Not found";
  }

  String response;
  serializeJson(doc, response);
  server->send(200, "application/json", response);
}

void CrossPointWebServer::scanFiles(const char* path, const std::function<void(FileInfo)>& callback) const {
  HalFile root = Storage.open(path);
  if (!root) {
    LOG_DBG("WEB", "Failed to open directory: %s", path);
    return;
  }

  if (!root.isDirectory()) {
    LOG_DBG("WEB", "Not a directory: %s", path);
    root.close();
    return;
  }

  LOG_DBG("WEB", "Scanning files in: %s", path);

  HalFile file = root.openNextFile();
  char name[xtinct::file_transfer::MAX_LFN_UTF8_BYTES + 1] = {};
  while (file) {
    const size_t nameLength = file.getName(name, sizeof(name));
    const bool validCanonicalName = nameLength > 0 &&
                                    nameLength <= xtinct::file_transfer::MAX_LFN_UTF8_BYTES &&
                                    name[nameLength] == '\0';
    const String fileName = validCanonicalName ? String(name) : String();

    // The transfer policy rejects every dot/protected component. Hide those
    // same canonical long names unconditionally so an inaccessible retained
    // transaction backup never leaks through a public listing.
    bool shouldHide = !validCanonicalName || isProtectedItemName(fileName);

    // Check against explicitly hidden items list
    if (!shouldHide) {
      for (const auto* item : HIDDEN_ITEMS) {
        if (fileName.equalsIgnoreCase(item)) {
          shouldHide = true;
          break;
        }
      }
    }

    if (!shouldHide) {
      FileInfo info;
      info.name = fileName;
      info.isDirectory = file.isDirectory();

      if (info.isDirectory) {
        info.size = 0;
        info.isEpub = false;
      } else {
        info.size = file.size();
        info.isEpub = isEpubFile(info.name);
      }

      callback(info);
    }

    file.close();
    yield();                          // Yield to allow WiFi and other tasks to process during long scans
    resetTaskWatchdogIfSubscribed();  // Reset watchdog to prevent timeout on large directories
    file = root.openNextFile();
  }
  root.close();
}

bool CrossPointWebServer::isEpubFile(const String& filename) const { return FsHelpers::hasEpubExtension(filename); }

void CrossPointWebServer::handleFileList() const {
  sendHtmlContent(server.get(), FilesPageHtml, sizeof(FilesPageHtml));
}

void CrossPointWebServer::handleFileListData() const {
  // Get current path from query string (default to root)
  String currentPath = "/";
  if (server->hasArg("path")) {
    currentPath = normalizeWebPath(server->arg("path"));
  }
  if (isProtectedWebPath(currentPath)) {
    server->send(403, "text/plain", "Cannot access system files");
    return;
  }

  server->setContentLength(CONTENT_LENGTH_UNKNOWN);
  server->send(200, "application/json", "");
  server->sendContent("[");
  char output[512];
  constexpr size_t outputSize = sizeof(output);
  bool seenFirst = false;
  JsonDocument doc;

  scanFiles(currentPath.c_str(), [this, &output, &doc, seenFirst](const FileInfo& info) mutable {
    doc.clear();
    doc["name"] = info.name;
    doc["size"] = info.size;
    doc["isDirectory"] = info.isDirectory;
    doc["isEpub"] = info.isEpub;

    const size_t written = serializeJson(doc, output, outputSize);
    if (written >= outputSize) {
      // JSON output truncated; skip this entry to avoid sending malformed JSON
      LOG_DBG("WEB", "Skipping file entry with oversized JSON for name: %s", info.name.c_str());
      return;
    }

    if (seenFirst) {
      server->sendContent(",");
    } else {
      seenFirst = true;
    }
    server->sendContent(output);
  });
  server->sendContent("]");
  // End of streamed response, empty chunk to signal client
  server->sendContent("");
  LOG_DBG("WEB", "Served file listing page for path: %s", currentPath.c_str());
}

void CrossPointWebServer::handleDownload() const {
  if (!server->hasArg("path")) {
    server->send(400, "text/plain", "Missing path");
    return;
  }

  String itemPath = normalizeWebPath(server->arg("path"));
  if (itemPath.isEmpty() || itemPath == "/") {
    server->send(400, "text/plain", "Invalid path");
    return;
  }
  if (isProtectedWebPath(itemPath)) {
    server->send(403, "text/plain", "Cannot access system files");
    return;
  }
  const String itemName = itemPath.substring(itemPath.lastIndexOf('/') + 1);
  for (const auto* item : HIDDEN_ITEMS) {
    if (itemName.equalsIgnoreCase(item)) {
      server->send(403, "text/plain", "Cannot access protected items");
      return;
    }
  }

  if (!Storage.exists(itemPath.c_str())) {
    server->send(404, "text/plain", "Item not found");
    return;
  }

  HalFile file = Storage.open(itemPath.c_str());
  if (!file) {
    server->send(500, "text/plain", "Failed to open file");
    return;
  }
  if (file.isDirectory()) {
    file.close();
    server->send(400, "text/plain", "Path is a directory");
    return;
  }

  String contentType = "application/octet-stream";
  if (isEpubFile(itemPath)) {
    contentType = "application/epub+zip";
  }

  char nameBuf[128] = {0};
  String filename = "download";
  if (file.getName(nameBuf, sizeof(nameBuf))) {
    filename = nameBuf;
  }

  server->setContentLength(file.size());
  server->sendHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
  server->send(200, contentType.c_str(), "");

  NetworkClient client = server->client();
  const size_t chunkSize = 4096;
  uint8_t buffer[chunkSize];

  bool downloadOk = true;
  while (downloadOk && file.available()) {
    int result = file.read(buffer, chunkSize);
    if (result <= 0) break;
    size_t bytesRead = static_cast<size_t>(result);
    size_t totalWritten = 0;
    while (totalWritten < bytesRead) {
      resetTaskWatchdogIfSubscribed();
      size_t wrote = client.write(buffer + totalWritten, bytesRead - totalWritten);
      if (wrote == 0) {
        downloadOk = false;
        break;
      }
      totalWritten += wrote;
    }
  }
  client.clear();
  file.close();
}

// Diagnostic counters for upload performance analysis
static unsigned long uploadStartTime = 0;
static unsigned long totalWriteTime = 0;
static size_t writeCount = 0;

static bool flushUploadBuffer(CrossPointWebServer::UploadState& state) {
  if (state.bufferPos > 0 && state.file) {
    resetTaskWatchdogIfSubscribed();  // Reset watchdog before potentially slow SD write
    const unsigned long writeStart = millis();
    const size_t written = state.file.write(state.buffer.data(), state.bufferPos);
    totalWriteTime += millis() - writeStart;
    writeCount++;
    resetTaskWatchdogIfSubscribed();  // Reset watchdog after SD write

    if (written != state.bufferPos || state.file.getWriteError()) {
      LOG_DBG("WEB", "[UPLOAD] Buffer flush failed: expected %d, wrote %d", state.bufferPos, written);
      state.bufferPos = 0;
      return false;
    }
    state.bufferPos = 0;
  }
  return true;
}

static bool discardUploadPartial(CrossPointWebServer::UploadState& state) {
  if (state.file) state.file.close();
  state.bufferPos = 0;
  if (!state.ownsPartial) return true;
  const bool removed = Storage.remove(state.targetPath.c_str()) || !Storage.exists(state.targetPath.c_str());
  if (removed) {
    state.ownsPartial = false;
    state.targetPath = "";
  }
  return removed;
}

void CrossPointWebServer::handleUpload(UploadState& state) const {
  static size_t lastLoggedSize = 0;

  // Reset watchdog at start of every upload callback - HTTP parsing can be slow
  resetTaskWatchdogIfSubscribed();

  // Safety check: ensure server is still valid
  if (!running || !server) {
    LOG_DBG("WEB", "[UPLOAD] ERROR: handleUpload called but server not running!");
    return;
  }

  const HTTPUpload& upload = server->upload();

  if (upload.status == UPLOAD_FILE_START) {
    // Reset watchdog - this is the critical 1% crash point
    resetTaskWatchdogIfSubscribed();

    if (state.ownsPartial && !discardUploadPartial(state)) {
      state.error = "Previous incomplete upload could not be removed";
      return;
    }
    if (upload.filename.length() > xtinct::file_transfer::MAX_COMPONENT_BYTES) {
      state.error = "Upload filename is too long";
      return;
    }
    state.fileName = upload.filename;
    state.targetPath = "";
    state.ownsPartial = false;
    state.size = 0;
    state.success = false;
    state.error = "";
    uploadStartTime = millis();
    lastLoggedSize = 0;
    state.bufferPos = 0;
    totalWriteTime = 0;
    writeCount = 0;

    // Get upload path from query parameter (defaults to root if not specified)
    // Note: We use query parameter instead of form data because multipart form
    // fields aren't available until after file upload completes
    if (server->hasArg("path")) {
      state.path = normalizeWebPath(server->arg("path"));
    } else {
      state.path = "/";
    }

    if (state.path.isEmpty() || state.fileName.isEmpty() || state.fileName.indexOf('/') >= 0 ||
        state.fileName.indexOf('\\') >= 0 || isProtectedItemName(state.fileName) || isProtectedWebPath(state.path)) {
      state.error = "Cannot upload to a protected path";
      return;
    }

    LOG_DBG("WEB", "[UPLOAD] START: %s to path: %s", state.fileName.c_str(), state.path.c_str());
    LOG_DBG("WEB", "[UPLOAD] Free heap: %d bytes", ESP.getFreeHeap());

    String filePath = state.path;
    if (!filePath.endsWith("/")) filePath += "/";
    filePath += state.fileName;
    if (isProtectedWebPath(filePath, xtinct::file_transfer::PathIntent::CreateLeaf)) {
      state.error = "Cannot upload to a protected path";
      return;
    }

    // Check if file already exists - SD operations can be slow
    resetTaskWatchdogIfSubscribed();
    if (Storage.exists(filePath.c_str())) {
      state.error = "File already exists: " + state.fileName;
      LOG_DBG("WEB", "[UPLOAD] Collision: %s", filePath.c_str());
      return;
    }

    // Open file for writing - this can be slow due to FAT cluster allocation
    resetTaskWatchdogIfSubscribed();
    state.targetPath = filePath;
    // The target was just verified absent. Claim the exact request-created
    // path before open so a create-then-error result is still cleaned even if
    // a subsequent exists() probe fails.
    state.ownsPartial = true;
    const bool opened = Storage.openFileForWrite("WEB", state.targetPath, state.file);
    const bool existenceVerified = Storage.exists(state.targetPath.c_str());
    if (!opened || !existenceVerified) {
      discardUploadPartial(state);
      state.error = "Failed to create file on SD card";
      LOG_DBG("WEB", "[UPLOAD] FAILED to create file: %s", filePath.c_str());
      return;
    }
    resetTaskWatchdogIfSubscribed();

    LOG_DBG("WEB", "[UPLOAD] File created successfully: %s", filePath.c_str());
  } else if (upload.status == UPLOAD_FILE_WRITE) {
    if (state.file && state.error.isEmpty()) {
      const uint64_t received = static_cast<uint64_t>(state.size);
      const uint64_t chunkBytes = static_cast<uint64_t>(upload.currentSize);
      if (!xtinct::file_transfer::canAppendTransferBytes(received, chunkBytes)) {
        state.error = "Upload exceeds the supported file-size limit";
        if (!discardUploadPartial(state)) state.error += "; partial cleanup failed";
        return;
      }

      // Buffer incoming data and flush when buffer is full
      // This reduces SD card write operations and improves throughput
      const uint8_t* data = upload.buf;
      size_t remaining = upload.currentSize;

      while (remaining > 0) {
        const size_t space = UploadState::UPLOAD_BUFFER_SIZE - state.bufferPos;
        const size_t toCopy = (remaining < space) ? remaining : space;

        memcpy(state.buffer.data() + state.bufferPos, data, toCopy);
        state.bufferPos += toCopy;
        data += toCopy;
        remaining -= toCopy;

        // Flush buffer when full
        if (state.bufferPos >= UploadState::UPLOAD_BUFFER_SIZE) {
          if (!flushUploadBuffer(state)) {
            state.error = "Failed to write to SD card - disk may be full";
            if (!discardUploadPartial(state)) state.error += "; partial cleanup failed";
            return;
          }
        }
      }

      state.size += upload.currentSize;

      // Log progress every 100KB
      if (state.size - lastLoggedSize >= 102400) {
        const unsigned long elapsed = millis() - uploadStartTime;
        const float kbps = (elapsed > 0) ? (state.size / 1024.0) / (elapsed / 1000.0) : 0;
        LOG_DBG("WEB", "[UPLOAD] %d bytes (%.1f KB), %.1f KB/s, %d writes", state.size, state.size / 1024.0, kbps,
                writeCount);
        lastLoggedSize = state.size;
      }
    }
  } else if (upload.status == UPLOAD_FILE_END) {
    if (state.file) {
      // Flush any remaining buffered data
      const bool durable = xtinct::file_transfer::finishDurableWrite(state.file, flushUploadBuffer(state));
      if (!durable) {
        state.error = "Failed to write final data to SD card";
        if (!discardUploadPartial(state)) state.error += "; partial cleanup failed";
      }

      if (state.error.isEmpty()) {
        state.ownsPartial = false;
        state.success = true;
        const unsigned long elapsed = millis() - uploadStartTime;
        const float avgKbps = (elapsed > 0) ? (state.size / 1024.0) / (elapsed / 1000.0) : 0;
        const float writePercent = (elapsed > 0) ? (totalWriteTime * 100.0 / elapsed) : 0;
        LOG_DBG("WEB", "[UPLOAD] Complete: %s (%d bytes in %lu ms, avg %.1f KB/s)", state.fileName.c_str(), state.size,
                elapsed, avgKbps);
        LOG_DBG("WEB", "[UPLOAD] Diagnostics: %d writes, total write time: %lu ms (%.1f%%)", writeCount, totalWriteTime,
                writePercent);

        // Clear epub cache after uploading the file
        clearBookCache(state.targetPath.c_str());
      }
    }
  } else if (upload.status == UPLOAD_FILE_ABORTED) {
    const bool removed = discardUploadPartial(state);
    state.error = removed ? "Upload aborted" : "Upload aborted; partial cleanup failed";
    LOG_DBG("WEB", "Upload aborted");
  }
}

void CrossPointWebServer::handleUploadPost(UploadState& state) const {
  if (state.success) {
    server->send(200, "text/plain", "File uploaded successfully: " + state.fileName);
  } else {
    const String error = state.error.isEmpty() ? "Unknown error during upload" : state.error;
    server->send(400, "text/plain", error);
  }
  // A request which never produced a multipart START callback must not replay
  // the previous request's success response.
  state.success = false;
  state.error = "";
}

void CrossPointWebServer::handleCreateFolder() const {
  // Get folder name from form data
  if (!server->hasArg("name")) {
    server->send(400, "text/plain", "Missing folder name");
    return;
  }

  const String folderName = server->arg("name");

  // Validate folder name
  if (folderName.isEmpty() || folderName.length() > xtinct::file_transfer::MAX_COMPONENT_BYTES) {
    server->send(400, "text/plain", "Folder name cannot be empty");
    return;
  }

  // Get parent path
  String parentPath = "/";
  if (server->hasArg("path")) {
    parentPath = normalizeWebPath(server->arg("path"));
  }

  if (folderName.indexOf('/') >= 0 || folderName.indexOf('\\') >= 0 || isProtectedItemName(folderName) ||
      isProtectedWebPath(parentPath)) {
    server->send(403, "text/plain", "Cannot create a protected folder");
    return;
  }

  // Build full folder path
  String folderPath = parentPath;
  if (!folderPath.endsWith("/")) folderPath += "/";
  folderPath += folderName;
  if (isProtectedWebPath(folderPath, xtinct::file_transfer::PathIntent::CreateLeaf)) {
    server->send(403, "text/plain", "Cannot create a protected folder");
    return;
  }

  LOG_DBG("WEB", "Creating folder: %s", folderPath.c_str());

  // Check if already exists
  if (Storage.exists(folderPath.c_str())) {
    server->send(400, "text/plain", "Folder already exists");
    return;
  }

  // Create the folder
  if (Storage.mkdir(folderPath.c_str())) {
    LOG_DBG("WEB", "Folder created successfully: %s", folderPath.c_str());
    server->send(200, "text/plain", "Folder created: " + folderName);
  } else {
    LOG_DBG("WEB", "Failed to create folder: %s", folderPath.c_str());
    server->send(500, "text/plain", "Failed to create folder");
  }
}

void CrossPointWebServer::handleRename() const {
  if (!server->hasArg("path") || !server->hasArg("name")) {
    server->send(400, "text/plain", "Missing path or new name");
    return;
  }

  const String rawItemPath = server->arg("path");
  const String rawNewName = server->arg("name");
  if (rawItemPath.length() > xtinct::file_transfer::MAX_PATH_BYTES ||
      rawNewName.length() > xtinct::file_transfer::MAX_COMPONENT_BYTES) {
    server->send(414, "text/plain", "Path or name is too long");
    return;
  }
  String itemPath = normalizeWebPath(rawItemPath);
  String newName = rawNewName;
  newName.trim();

  if (itemPath.isEmpty() || itemPath == "/") {
    server->send(400, "text/plain", "Invalid path");
    return;
  }
  if (isProtectedWebPath(itemPath)) {
    server->send(403, "text/plain", "Cannot rename protected item");
    return;
  }
  if (newName.isEmpty()) {
    server->send(400, "text/plain", "New name cannot be empty");
    return;
  }
  if (newName.indexOf('/') >= 0 || newName.indexOf('\\') >= 0) {
    server->send(400, "text/plain", "Invalid file name");
    return;
  }
  if (isProtectedItemName(newName)) {
    server->send(403, "text/plain", "Cannot rename to protected name");
    return;
  }

  const String itemName = itemPath.substring(itemPath.lastIndexOf('/') + 1);
  if (isProtectedItemName(itemName)) {
    server->send(403, "text/plain", "Cannot rename protected item");
    return;
  }
  if (newName == itemName) {
    server->send(200, "text/plain", "Name unchanged");
    return;
  }

  if (!Storage.exists(itemPath.c_str())) {
    server->send(404, "text/plain", "Item not found");
    return;
  }

  HalFile file = Storage.open(itemPath.c_str());
  if (!file) {
    server->send(500, "text/plain", "Failed to open file");
    return;
  }
  if (file.isDirectory()) {
    file.close();
    server->send(400, "text/plain", "Only files can be renamed");
    return;
  }

  String parentPath = itemPath.substring(0, itemPath.lastIndexOf('/'));
  if (parentPath.isEmpty()) {
    parentPath = "/";
  }
  String newPath = parentPath;
  if (!newPath.endsWith("/")) {
    newPath += "/";
  }
  newPath += newName;

  if (isProtectedWebPath(newPath, xtinct::file_transfer::PathIntent::CreateLeaf)) {
    file.close();
    server->send(403, "text/plain", "Cannot rename to protected path");
    return;
  }

  if (Storage.exists(newPath.c_str())) {
    file.close();
    server->send(409, "text/plain", "Target already exists");
    return;
  }

  clearBookCache(itemPath.c_str());
  const bool success = file.rename(newPath.c_str());
  file.close();

  if (success) {
    LOG_DBG("WEB", "Renamed file: %s -> %s", itemPath.c_str(), newPath.c_str());
    server->send(200, "text/plain", "Renamed successfully");
  } else {
    LOG_ERR("WEB", "Failed to rename file: %s -> %s", itemPath.c_str(), newPath.c_str());
    server->send(500, "text/plain", "Failed to rename file");
  }
}

void CrossPointWebServer::handleMove() const {
  if (!server->hasArg("path") || !server->hasArg("dest")) {
    server->send(400, "text/plain", "Missing path or destination");
    return;
  }

  const String rawItemPath = server->arg("path");
  const String rawDestPath = server->arg("dest");
  if (rawItemPath.length() > xtinct::file_transfer::MAX_PATH_BYTES ||
      rawDestPath.length() > xtinct::file_transfer::MAX_PATH_BYTES) {
    server->send(414, "text/plain", "Path is too long");
    return;
  }
  String itemPath = normalizeWebPath(rawItemPath);
  String destPath = normalizeWebPath(rawDestPath);

  if (itemPath.isEmpty() || itemPath == "/") {
    server->send(400, "text/plain", "Invalid path");
    return;
  }
  if (destPath.isEmpty()) {
    server->send(400, "text/plain", "Invalid destination");
    return;
  }
  if (isProtectedWebPath(itemPath) || isProtectedWebPath(destPath)) {
    server->send(403, "text/plain", "Cannot move protected items");
    return;
  }

  const String itemName = itemPath.substring(itemPath.lastIndexOf('/') + 1);
  if (isProtectedItemName(itemName)) {
    server->send(403, "text/plain", "Cannot move protected item");
    return;
  }
  if (destPath != "/") {
    const String destName = destPath.substring(destPath.lastIndexOf('/') + 1);
    if (isProtectedItemName(destName)) {
      server->send(403, "text/plain", "Cannot move into protected folder");
      return;
    }
  }

  if (!Storage.exists(itemPath.c_str())) {
    server->send(404, "text/plain", "Item not found");
    return;
  }

  HalFile file = Storage.open(itemPath.c_str());
  if (!file) {
    server->send(500, "text/plain", "Failed to open file");
    return;
  }
  if (file.isDirectory()) {
    file.close();
    server->send(400, "text/plain", "Only files can be moved");
    return;
  }

  if (!Storage.exists(destPath.c_str())) {
    file.close();
    server->send(404, "text/plain", "Destination not found");
    return;
  }
  HalFile destDir = Storage.open(destPath.c_str());
  if (!destDir || !destDir.isDirectory()) {
    if (destDir) {
      destDir.close();
    }
    file.close();
    server->send(400, "text/plain", "Destination is not a folder");
    return;
  }
  destDir.close();

  String newPath = destPath;
  if (!newPath.endsWith("/")) {
    newPath += "/";
  }
  newPath += itemName;

  if (isProtectedWebPath(newPath, xtinct::file_transfer::PathIntent::CreateLeaf)) {
    file.close();
    server->send(403, "text/plain", "Cannot move to protected path");
    return;
  }

  if (newPath == itemPath) {
    file.close();
    server->send(200, "text/plain", "Already in destination");
    return;
  }
  if (Storage.exists(newPath.c_str())) {
    file.close();
    server->send(409, "text/plain", "Target already exists");
    return;
  }

  clearBookCache(itemPath.c_str());
  const bool success = file.rename(newPath.c_str());
  file.close();

  if (success) {
    LOG_DBG("WEB", "Moved file: %s -> %s", itemPath.c_str(), newPath.c_str());
    server->send(200, "text/plain", "Moved successfully");
  } else {
    LOG_ERR("WEB", "Failed to move file: %s -> %s", itemPath.c_str(), newPath.c_str());
    server->send(500, "text/plain", "Failed to move file");
  }
}

void CrossPointWebServer::handleDelete() const {
  // To ensure backwards compatibility, plain `path` is mapped
  // to a single element JSON array.
  bool hasPathArg = server->hasArg("path");
  bool hasPathsArg = server->hasArg("paths");
  // Check 'paths' or `path` argument is provided
  if (!(hasPathArg || hasPathsArg)) {
    server->send(400, "text/plain", "Missing `path` or `paths` argument");
    return;
  }
  if (hasPathArg && hasPathsArg) {
    server->send(400, "text/plain", "Provide either 'path' or 'paths', not both");
    return;
  }

  // Parse paths
  String pathsArg;
  JsonDocument doc;
  DeserializationError error = DeserializationError(DeserializationError::Code::Ok);
  if (hasPathsArg) {
    pathsArg = server->arg("paths");
    if (pathsArg.length() > MAX_DELETE_REQUEST_BYTES) {
      server->send(413, "text/plain", "Delete request is too large");
      return;
    }
    error = deserializeJson(doc, pathsArg);
  } else {
    pathsArg = server->arg("path");
    if (pathsArg.length() > xtinct::file_transfer::MAX_PATH_BYTES) {
      server->send(414, "text/plain", "Path is too long");
      return;
    }
    doc.add(pathsArg);
  }
  if (error) {
    server->send(400, "text/plain", "Invalid paths format");
    return;
  }

  auto paths = doc.as<JsonArray>();
  if (paths.isNull() || paths.size() == 0 || paths.size() > MAX_DELETE_ITEMS) {
    server->send(400, "text/plain", "No paths provided");
    return;
  }

  // Iterate over paths and delete each item
  bool allSuccess = true;
  char failedItems[MAX_DELETE_FAILURE_BYTES + 1] = {};
  size_t failedBytes = 0;

  for (const auto& p : paths) {
    const JsonString rawJsonPath = p.as<JsonString>();
    String itemPath;
    if (rawJsonPath.isNull() ||
        !xtinct::file_transfer::isBoundedRawPath(
            std::string_view(rawJsonPath.c_str(), rawJsonPath.size()))) {
      appendDeleteFailure(failedItems, sizeof(failedItems), failedBytes, "", " (invalid path); ");
      allSuccess = false;
      continue;
    }
    String rawPath;
    if (!rawPath.reserve(rawJsonPath.size() + 1) || !rawPath.concat(rawJsonPath.c_str(), rawJsonPath.size())) {
      appendDeleteFailure(failedItems, sizeof(failedItems), failedBytes, "", " (path allocation failed); ");
      allSuccess = false;
      continue;
    }
    itemPath = normalizeWebPath(rawPath);

    // Validate path
    if (itemPath.isEmpty() || itemPath == "/") {
      appendDeleteFailure(failedItems, sizeof(failedItems), failedBytes, itemPath, " (cannot delete root); ");
      allSuccess = false;
      continue;
    }

    if (isProtectedWebPath(itemPath)) {
      appendDeleteFailure(failedItems, sizeof(failedItems), failedBytes, itemPath, " (protected path); ");
      allSuccess = false;
      continue;
    }

    // Ensure path starts with /
    if (!itemPath.startsWith("/")) {
      itemPath = "/" + itemPath;
    }

    // Security check: prevent deletion of protected items
    const String itemName = itemPath.substring(itemPath.lastIndexOf('/') + 1);

    // Hidden/system files are protected
    if (itemName.startsWith(".")) {
      appendDeleteFailure(failedItems, sizeof(failedItems), failedBytes, itemPath, " (hidden/system file); ");
      allSuccess = false;
      continue;
    }

    // Check against explicitly protected items
    bool isProtected = false;
    for (const auto* item : HIDDEN_ITEMS) {
      if (itemName.equalsIgnoreCase(item)) {
        isProtected = true;
        break;
      }
    }
    if (isProtected) {
      appendDeleteFailure(failedItems, sizeof(failedItems), failedBytes, itemPath, " (protected file); ");
      allSuccess = false;
      continue;
    }

    // Check if item exists
    if (!Storage.exists(itemPath.c_str())) {
      appendDeleteFailure(failedItems, sizeof(failedItems), failedBytes, itemPath, " (not found); ");
      allSuccess = false;
      continue;
    }

    // Decide whether it's a directory or file by opening it
    bool success = false;
    HalFile f = Storage.open(itemPath.c_str());
    if (f && f.isDirectory()) {
      // For folders, ensure empty before removing
      HalFile entry = f.openNextFile();
      if (entry) {
        entry.close();
        f.close();
        appendDeleteFailure(failedItems, sizeof(failedItems), failedBytes, itemPath, " (folder not empty); ");
        allSuccess = false;
        continue;
      }
      f.close();
      success = Storage.rmdir(itemPath.c_str());
    } else {
      // It's a file (or couldn't open as dir) — remove file
      if (f) f.close();
      success = Storage.remove(itemPath.c_str());
      clearBookCache(itemPath.c_str());
    }

    if (!success) {
      appendDeleteFailure(failedItems, sizeof(failedItems), failedBytes, itemPath, " (deletion failed); ");
      allSuccess = false;
    }
  }

  if (allSuccess) {
    server->send(200, "text/plain", "All items deleted successfully");
  } else {
    String response("Failed to delete some items: ");
    if (!response.reserve(response.length() + failedBytes + 1) || !response.concat(failedItems, failedBytes)) {
      server->send(500, "text/plain", "Failed to delete one or more items");
      return;
    }
    server->send(500, "text/plain", response);
  }
}

void CrossPointWebServer::handleSettingsPage() const {
  sendHtmlContent(server.get(), SettingsPageHtml, sizeof(SettingsPageHtml));
  LOG_DBG("WEB", "Served settings page");
}

void CrossPointWebServer::handleGetSettings() const {
  // Pass the SD font registry so the fontFamily setting's enumStringValues
  // includes SD-resident families — otherwise the web API only exposes the
  // three built-in fonts.
  const auto& settings = getSettingsList(&sdFontSystem.registry());

  server->setContentLength(CONTENT_LENGTH_UNKNOWN);
  server->send(200, "application/json", "");
  server->sendContent("[");

  char output[512];
  constexpr size_t outputSize = sizeof(output);
  bool seenFirst = false;
  JsonDocument doc;

  for (const auto& s : settings) {
    if (!s.key) continue;  // Skip ACTION-only entries
    if (isProtectedFileTransferSetting(s.key)) continue;

    doc.clear();
    doc["key"] = s.key;
    doc["name"] = I18N.get(s.nameId);
    doc["category"] = I18N.get(s.category);

    switch (s.type) {
      case SettingType::TOGGLE: {
        doc["type"] = "toggle";
        if (s.valuePtr) {
          doc["value"] = static_cast<int>(SETTINGS.*(s.valuePtr));
        }
        break;
      }
      case SettingType::ENUM: {
        doc["type"] = "enum";
        if (s.valuePtr) {
          doc["value"] = static_cast<int>(SETTINGS.*(s.valuePtr));
        } else if (s.valueGetter) {
          doc["value"] = static_cast<int>(s.valueGetter());
        }
        JsonArray options = doc["options"].to<JsonArray>();
        if (!s.enumStringValues.empty()) {
          for (const auto& opt : s.enumStringValues) {
            options.add(opt);
          }
        } else {
          for (const auto& opt : s.enumValues) {
            options.add(I18N.get(opt));
          }
        }
        break;
      }
      case SettingType::VALUE: {
        doc["type"] = "value";
        if (s.valuePtr) {
          doc["value"] = static_cast<int>(SETTINGS.*(s.valuePtr));
        }
        doc["min"] = s.valueRange.min;
        doc["max"] = s.valueRange.max;
        doc["step"] = s.valueRange.step;
        break;
      }
      case SettingType::STRING: {
        doc["type"] = "string";
        if (s.stringGetter) {
          doc["value"] = s.stringGetter();
        } else if (s.stringMaxLen > 0) {
          doc["value"] = reinterpret_cast<const char*>(&SETTINGS) + s.stringOffset;
        }
        break;
      }
      default:
        continue;
    }

    const size_t written = serializeJson(doc, output, outputSize);
    if (written >= outputSize) {
      LOG_DBG("WEB", "Skipping oversized setting JSON for: %s", s.key);
      continue;
    }

    if (seenFirst) {
      server->sendContent(",");
    } else {
      seenFirst = true;
    }
    server->sendContent(output);
    yield();                          // Yield to allow WiFi and other tasks to process during a slow send
    resetTaskWatchdogIfSubscribed();  // Reset watchdog: each sendContent() is a blocking network write
  }

  server->sendContent("]");
  server->sendContent("");
  LOG_DBG("WEB", "Served settings API");
}

void CrossPointWebServer::handlePostSettings() {
  if (!server->hasArg("plain")) {
    server->send(400, "text/plain", "Missing JSON body");
    return;
  }

  const String body = server->arg("plain");
  JsonDocument doc;
  const DeserializationError err = deserializeJson(doc, body);
  if (err) {
    server->send(400, "text/plain", String("Invalid JSON: ") + err.c_str());
    return;
  }

  // Reject the whole request before applying unrelated settings. This keeps
  // partial updates explicit and prevents File Transfer clients from forging a
  // synchronized clock or changing the Daily Cards wake timezone.
  for (JsonPairConst requested : doc.as<JsonObjectConst>()) {
    if (isProtectedFileTransferSetting(requested.key().c_str())) {
      server->send(403, "text/plain", "Use Phone Wi-Fi Setup to change Daily Cards clock settings");
      return;
    }
  }

  const auto& settings = getSettingsList(&sdFontSystem.registry());
  int applied = 0;

  for (const auto& s : settings) {
    if (!s.key) continue;
    if (isProtectedFileTransferSetting(s.key)) continue;  // Defense in depth.
    if (!doc[s.key].is<JsonVariant>()) continue;

    switch (s.type) {
      case SettingType::TOGGLE: {
        const int val = doc[s.key].as<int>() ? 1 : 0;
        if (s.valuePtr) {
          SETTINGS.*(s.valuePtr) = val;
        }
        applied++;
        break;
      }
      case SettingType::ENUM: {
        const int val = doc[s.key].as<int>();
        const int maxVal = s.enumStringValues.empty() ? static_cast<int>(s.enumValues.size())
                                                      : static_cast<int>(s.enumStringValues.size());
        if (val >= 0 && val < maxVal) {
          if (s.valuePtr) {
            SETTINGS.*(s.valuePtr) = static_cast<uint8_t>(val);
          } else if (s.valueSetter) {
            s.valueSetter(static_cast<uint8_t>(val));
          }
          applied++;
        }
        break;
      }
      case SettingType::VALUE: {
        const int val = doc[s.key].as<int>();
        if (val >= s.valueRange.min && val <= s.valueRange.max) {
          if (s.valuePtr) {
            SETTINGS.*(s.valuePtr) = static_cast<uint8_t>(val);
          }
          applied++;
        }
        break;
      }
      case SettingType::STRING: {
        const std::string val = doc[s.key].as<std::string>();
        if (s.stringSetter) {
          s.stringSetter(val);
        } else if (s.stringMaxLen > 0) {
          char* ptr = reinterpret_cast<char*>(&SETTINGS) + s.stringOffset;
          strncpy(ptr, val.c_str(), s.stringMaxLen - 1);
          ptr[s.stringMaxLen - 1] = '\0';
        }
        applied++;
        break;
      }
      default:
        break;
    }
  }

  SETTINGS.saveToFile();

  LOG_DBG("WEB", "Applied %d setting(s)", applied);
  server->send(200, "text/plain", String("Applied ") + String(applied) + " setting(s)");
}

// WebSocket callback trampoline
void CrossPointWebServer::wsEventCallback(uint8_t num, WStype_t type, uint8_t* payload, size_t length) {
  if (wsInstance) {
    wsInstance->onWebSocketEvent(num, type, payload, length);
  }
}

// WebSocket event handler for fast binary uploads
// Protocol:
//   1. Client sends TEXT message: "START:<filename>:<size>:<path>"
//   2. Client sends BINARY messages with file data chunks
//   3. Server sends TEXT "PROGRESS:<received>:<total>" after each chunk
//   4. Server sends TEXT "DONE" or "ERROR:<message>" when complete
void CrossPointWebServer::onWebSocketEvent(uint8_t num, WStype_t type, uint8_t* payload, size_t length) {
  switch (type) {
    case WStype_DISCONNECTED:
      LOG_DBG("WS", "Client %u disconnected", num);
      // Only clean up if this is the client that owns the active upload.
      // A new client may have already started a fresh upload before this
      // DISCONNECTED event fires (race condition on quick cancel + retry).
      if (num == wsUploadClientNum && wsUploadInProgress) {
        abortWsUpload("WS");
      }
      break;

    case WStype_CONNECTED: {
      LOG_DBG("WS", "Client %u connected", num);
      break;
    }

    case WStype_TEXT: {
      xtinct::file_transfer::WsStartControl start;
      if (payload != nullptr &&
          xtinct::file_transfer::parseWsStartControl(
              std::string_view(reinterpret_cast<const char*>(payload), length), start)) {
        // Reject any START while an upload is already active to prevent
        // leaking the open wsUploadFile handle (owning client re-START included)
        if (wsUploadInProgress) {
          wsServer->sendTXT(num, "ERROR:Upload already in progress");
          break;
        }
        if (wsUploadOwnsPartial) {
          abortWsUpload("WS");
          if (wsUploadOwnsPartial) {
            wsServer->sendTXT(num, "ERROR:Previous partial upload cleanup failed");
            break;
          }
        }

          wsUploadFileName = start.filename;
          wsUploadSize = static_cast<size_t>(start.bytes);
          wsUploadPath = start.path;
          wsUploadReceived = 0;
          wsLastProgressSent = 0;
          wsUploadStartTime = millis();

          wsUploadPath = normalizeWebPath(wsUploadPath);

          if (wsUploadPath.isEmpty() || wsUploadFileName.isEmpty() || wsUploadFileName.indexOf('/') >= 0 ||
              wsUploadFileName.indexOf('\\') >= 0 || isProtectedItemName(wsUploadFileName) ||
              isProtectedWebPath(wsUploadPath)) {
            wsServer->sendTXT(num, "ERROR:Protected upload path");
            return;
          }

          String filePath = wsUploadPath;
          if (!filePath.endsWith("/")) filePath += "/";
          filePath += wsUploadFileName;
          if (isProtectedWebPath(filePath, xtinct::file_transfer::PathIntent::CreateLeaf)) {
            wsServer->sendTXT(num, "ERROR:Protected upload path");
            return;
          }

          resetTaskWatchdogIfSubscribed();
          if (Storage.exists(filePath.c_str())) {
            LOG_DBG("WS", "Upload collision: %s", filePath.c_str());
            wsServer->sendTXT(num, "ERROR:File already exists: " + wsUploadFileName);
            return;
          }

          LOG_DBG("WS", "Starting upload: %s (%llu bytes) to %s", wsUploadFileName.c_str(),
                  static_cast<unsigned long long>(start.bytes),
                  filePath.c_str());

          // Open file for writing
          resetTaskWatchdogIfSubscribed();
          wsUploadFilePath = filePath;
          // As with multipart, own the just-verified-absent path before open;
          // failed creation is cleaned by exact path, not an exists() guess.
          wsUploadOwnsPartial = true;
          const bool opened = Storage.openFileForWrite("WS", wsUploadFilePath, wsUploadFile);
          const bool existenceVerified = Storage.exists(wsUploadFilePath.c_str());
          if (!opened || !existenceVerified) {
            abortWsUpload("WS");
            wsServer->sendTXT(num, "ERROR:Failed to create file");
            wsUploadInProgress = false;
            wsUploadClientNum = 255;
            return;
          }
          resetTaskWatchdogIfSubscribed();

          // Zero-byte upload: complete immediately without waiting for BIN frames
          if (wsUploadSize == 0) {
            const bool durable = xtinct::file_transfer::finishDurableWrite(wsUploadFile);
            if (!durable) {
              abortWsUpload("WS");
              wsServer->sendTXT(num, "ERROR:Zero-byte upload flush failed");
              return;
            }
            wsUploadOwnsPartial = false;
            wsLastCompleteName = wsUploadFileName;
            wsLastCompleteSize = 0;
            wsLastCompleteAt = millis();
            LOG_DBG("WS", "Zero-byte upload complete: %s", filePath.c_str());
            clearBookCache(filePath.c_str());
            wsServer->sendTXT(num, "DONE");
            wsLastProgressSent = 0;
            break;
          }

          wsUploadClientNum = num;
          wsUploadInProgress = true;
          wsServer->sendTXT(num, "READY");
      } else {
        wsServer->sendTXT(num, "ERROR:Invalid or oversized START frame");
      }
      break;
    }

    case WStype_BIN: {
      if (!wsUploadInProgress || !wsUploadFile || num != wsUploadClientNum) {
        wsServer->sendTXT(num, "ERROR:No upload in progress");
        return;
      }

      // Write binary data directly to file
      if ((payload == nullptr && length != 0) || wsUploadReceived > wsUploadSize ||
          !xtinct::file_transfer::canAppendTransferBytes(wsUploadReceived, length)) {
        abortWsUpload("WS");
        wsServer->sendTXT(num, "ERROR:Invalid upload frame");
        return;
      }
      size_t remaining = wsUploadSize - wsUploadReceived;
      if (length > remaining) {
        abortWsUpload("WS");
        wsServer->sendTXT(num, "ERROR:Upload overflow");
        return;
      }
      resetTaskWatchdogIfSubscribed();
      size_t written = wsUploadFile.write(payload, length);
      resetTaskWatchdogIfSubscribed();

      if (written != length || wsUploadFile.getWriteError()) {
        abortWsUpload("WS");
        wsServer->sendTXT(num, "ERROR:Write failed - disk full?");
        return;
      }

      wsUploadReceived += written;

      // Send progress update (every 64KB or at end)
      if (wsUploadReceived - wsLastProgressSent >= 65536 || wsUploadReceived >= wsUploadSize) {
        String progress = "PROGRESS:" + String(wsUploadReceived) + ":" + String(wsUploadSize);
        wsServer->sendTXT(num, progress);
        wsLastProgressSent = wsUploadReceived;
      }

      // Check if upload complete
      if (wsUploadReceived >= wsUploadSize) {
        const bool durable = xtinct::file_transfer::finishDurableWrite(wsUploadFile);
        if (!durable) {
          abortWsUpload("WS");
          wsServer->sendTXT(num, "ERROR:Upload flush failed");
          return;
        }
        wsUploadOwnsPartial = false;
        wsUploadInProgress = false;
        wsUploadClientNum = 255;

        wsLastCompleteName = wsUploadFileName;
        wsLastCompleteSize = wsUploadSize;
        wsLastCompleteAt = millis();

        unsigned long elapsed = millis() - wsUploadStartTime;
        float kbps = (elapsed > 0) ? (wsUploadSize / 1024.0) / (elapsed / 1000.0) : 0;

        LOG_DBG("WS", "Upload complete: %s (%d bytes in %lu ms, %.1f KB/s)", wsUploadFileName.c_str(), wsUploadSize,
                elapsed, kbps);

        // Clear epub cache after uploading the file
        clearBookCache(wsUploadFilePath.c_str());

        wsServer->sendTXT(num, "DONE");
        wsLastProgressSent = 0;
      }
      break;
    }

    default:
      break;
  }
}

// --- Font management handlers ---

void CrossPointWebServer::handleFontsPage() const {
  sendHtmlContent(server.get(), FontsPageHtml, sizeof(FontsPageHtml));
  LOG_DBG("WEB", "Served fonts page");
}

void CrossPointWebServer::handleFontList() const {
  // Pick up any uploads/deletes that happened since the last reader load.
  const_cast<SdCardFontSystem&>(sdFontSystem).refreshIfDirty();
  const auto& families = sdFontSystem.registry().getFamilies();

  JsonDocument doc;
  JsonArray arr = doc["families"].to<JsonArray>();
  doc["maxFamilies"] = SdCardFontRegistry::MAX_SD_FAMILIES;

  for (const auto& family : families) {
    JsonObject fObj = arr.add<JsonObject>();
    fObj["name"] = family.name;

    JsonArray sizes = fObj["sizes"].to<JsonArray>();
    for (uint8_t s : family.availableSizes()) {
      sizes.add(s);
    }

    JsonArray files = fObj["files"].to<JsonArray>();
    for (const auto& file : family.files) {
      JsonObject fileObj = files.add<JsonObject>();
      // Extract filename from full path
      const char* name = strrchr(file.path.c_str(), '/');
      fileObj["name"] = name ? name + 1 : file.path.c_str();

      // Stat the file for size
      HalFile f;
      if (Storage.openFileForRead("WEB", file.path.c_str(), f)) {
        fileObj["size"] = static_cast<unsigned long>(f.size());
        f.close();
      } else {
        fileObj["size"] = 0;
      }
    }
  }

  String json;
  serializeJson(doc, json);
  server->send(200, "application/json", json);
}

bool CrossPointWebServer::flushFontUploadBuffer() {
  if (fontUpload.bufferPos == 0) return true;
  if (!fontUpload.file) return false;
  resetTaskWatchdogIfSubscribed();
  const size_t expected = fontUpload.bufferPos;
  const size_t written = fontUpload.file.write(fontUpload.buffer.data(), expected);
  const bool ok = written == expected && !fontUpload.file.getWriteError();
  fontUpload.bufferPos = 0;
  if (ok) fontUpload.bytesWritten += written;
  resetTaskWatchdogIfSubscribed();
  return ok;
}

bool CrossPointWebServer::discardFontUploadPartial() {
  if (fontUpload.file) fontUpload.file.close();
  fontUpload.bufferPos = 0;
  if (!fontUpload.ownsTemp) return true;
  // Remove the exact request-owned path even when an earlier exists() probe
  // failed. Absence after the remove attempt is also successful cleanup.
  const bool removed = Storage.remove(fontUpload.tempPath.c_str()) || !Storage.exists(fontUpload.tempPath.c_str());
  if (removed) {
    fontUpload.ownsTemp = false;
    fontUpload.tempPath = "";
  }
  return removed;
}

void CrossPointWebServer::handleFontUploadData() {
  HTTPUpload& upload = server->upload();

  switch (upload.status) {
    case UPLOAD_FILE_START: {
      resetTaskWatchdogIfSubscribed();
      if ((fontUpload.file || fontUpload.ownsTemp) && !discardFontUploadPartial()) {
        LOG_ERR("WEB", "Previous partial font upload could not be removed");
        fontUpload.valid = false;
        fontUpload.committed = false;
        break;
      }
      String family = server->arg("family");
      fontUpload.file = HalFile();
      fontUpload.familyName.clear();
      fontUpload.filePath = "";
      fontUpload.tempPath = "";
      fontUpload.backupPath = "";
      fontUpload.valid = false;
      fontUpload.committed = false;
      fontUpload.ownsTemp = false;
      fontUpload.destinationExisted = false;
      fontUpload.magic = {};
      fontUpload.bytesReceived = 0;
      fontUpload.bytesWritten = 0;
      fontUpload.bufferPos = 0;

      if (family.length() > xtinct::file_transfer::MAX_COMPONENT_BYTES ||
          !FontInstaller::isValidFamilyName(family.c_str())) {
        LOG_ERR("WEB", "Invalid font family name: %s", family.c_str());
        break;
      }

      String filename = upload.filename;
      if (filename.length() > xtinct::file_transfer::MAX_COMPONENT_BYTES) {
        LOG_ERR("WEB", "Font filename is too long");
        break;
      }
      filename.replace(' ', '_');
      // Validate filename: rejects path traversal (../, /, \) and enforces
      // a .cpfont basename of alphanumeric + hyphen + underscore. Without
      // this an attacker could supply "../../.crosspoint/settings.json" as
      // a "filename" and have it written outside the fonts directory.
      if (!FontInstaller::isValidCpfontFilename(filename.c_str())) {
        LOG_ERR("WEB", "Invalid font filename: %s", filename.c_str());
        break;
      }

      fontUpload.familyName = family.c_str();

      // Create a temporary FontInstaller for directory creation
      FontInstaller installer(sdFontSystem.registry());
      if (!installer.ensureFamilyDir(family.c_str())) {
        LOG_ERR("WEB", "Failed to create font family dir");
        break;
      }

      const char* root = SdCardFontRegistry::findFamilyRoot(family.c_str());
      if (!root) root = SdCardFontRegistry::defaultWriteRoot();
      const size_t pathBytes = strlen(root) + 1U + family.length() + 1U + filename.length();
      if (pathBytes > xtinct::file_transfer::MAX_PATH_BYTES) {
        LOG_ERR("WEB", "Font destination path is too long");
        break;
      }
      char path[xtinct::file_transfer::MAX_PATH_BYTES + 1];
      FontInstaller::buildFontPath(family.c_str(), filename.c_str(), path, sizeof(path));
      fontUpload.filePath = path;
      fontUpload.destinationExisted = Storage.exists(path);

      if (fontUpload.destinationExisted) {
        HalFile existing = Storage.open(path);
        const bool replaceableFile = existing && !existing.isDirectory();
        const bool closeOk = !existing || existing.close();
        if (!replaceableFile || !closeOk) {
          LOG_ERR("WEB", "Font destination is not a replaceable file: %s", path);
          break;
        }
      }

      if (!makeUniqueWebSibling(fontUpload.filePath, "font", fontUpload.tempPath)) {
        LOG_ERR("WEB", "Could not allocate a unique font staging path");
        break;
      }

      const bool opened = Storage.openFileForWrite("WEB", fontUpload.tempPath, fontUpload.file);
      const bool existenceVerified = Storage.exists(fontUpload.tempPath.c_str());
      fontUpload.ownsTemp = opened || existenceVerified;
      if (!opened || !existenceVerified) {
        LOG_ERR("WEB", "Failed to establish owned font staging file: %s", fontUpload.tempPath.c_str());
        if (!discardFontUploadPartial()) LOG_ERR("WEB", "Font staging cleanup failed");
        break;
      }

      fontUpload.valid = true;
      LOG_DBG("WEB", "Font upload staged: %s -> %s", filename.c_str(), fontUpload.tempPath.c_str());
      break;
    }

    case UPLOAD_FILE_WRITE: {
      if (!fontUpload.valid) break;
      resetTaskWatchdogIfSubscribed();

      const uint64_t chunkBytes = static_cast<uint64_t>(upload.currentSize);
      if (!xtinct::file_transfer::canAppendTransferBytes(fontUpload.bytesReceived, chunkBytes)) {
        LOG_ERR("WEB", "Font upload exceeds the supported file-size limit");
        fontUpload.valid = false;
        if (!discardFontUploadPartial()) LOG_ERR("WEB", "Oversized font staging cleanup failed");
        break;
      }
      fontUpload.bytesReceived += chunkBytes;

      if (!fontUpload.magic.feed(upload.buf, upload.currentSize)) {
        LOG_ERR("WEB", "Invalid .cpfont magic bytes");
        fontUpload.valid = false;
        if (!discardFontUploadPartial()) LOG_ERR("WEB", "Invalid font staging cleanup failed");
        break;
      }

      // Buffer writes for efficiency
      size_t remaining = upload.currentSize;
      const uint8_t* src = upload.buf;
      while (remaining > 0) {
        size_t space = FontUploadState::BUFFER_SIZE - fontUpload.bufferPos;
        size_t chunk = (remaining < space) ? remaining : space;
        memcpy(fontUpload.buffer.data() + fontUpload.bufferPos, src, chunk);
        fontUpload.bufferPos += chunk;
        src += chunk;
        remaining -= chunk;

        if (fontUpload.bufferPos >= FontUploadState::BUFFER_SIZE) {
          if (!flushFontUploadBuffer()) {
            LOG_ERR("WEB", "Font staging write failed");
            fontUpload.valid = false;
            if (!discardFontUploadPartial()) LOG_ERR("WEB", "Failed font staging cleanup failed");
            break;
          }
        }
      }
      break;
    }

    case UPLOAD_FILE_END: {
      const bool completeMagic = fontUpload.magic.complete();
      const bool flushed = fontUpload.valid && completeMagic && flushFontUploadBuffer();
      const bool exactBytes =
          flushed && xtinct::file_transfer::isCompleteFontPayload(
                         completeMagic, fontUpload.bytesReceived, fontUpload.bytesWritten);
      const bool durable = fontUpload.file
                               ? xtinct::file_transfer::finishDurableWrite(fontUpload.file, exactBytes)
                               : false;
      if (!fontUpload.valid || !completeMagic || !exactBytes || !durable) {
        LOG_ERR("WEB", "Font upload was incomplete or not durably written");
        fontUpload.valid = false;
        if (!discardFontUploadPartial()) LOG_ERR("WEB", "Incomplete font staging cleanup failed");
        break;
      }

      FontInstaller installer(sdFontSystem.registry());
      if (!installer.validateCpfontFile(fontUpload.tempPath.c_str())) {
        fontUpload.valid = false;
        if (!discardFontUploadPartial()) LOG_ERR("WEB", "Rejected font staging cleanup failed");
        break;
      }

      if (fontUpload.destinationExisted &&
          !makeUniqueWebSibling(fontUpload.filePath, "font-old", fontUpload.backupPath)) {
        LOG_ERR("WEB", "Could not allocate a font rollback path");
        fontUpload.valid = false;
        if (!discardFontUploadPartial()) LOG_ERR("WEB", "Unpromoted font staging cleanup failed");
        break;
      }

      WebReplaceOps ops;
      const auto promoted = xtinct::file_transfer::promotePrepared(
          ops, fontUpload.tempPath.c_str(), fontUpload.filePath.c_str(),
          fontUpload.destinationExisted ? fontUpload.backupPath.c_str() : nullptr, fontUpload.destinationExisted);
      fontUpload.committed = xtinct::file_transfer::isCommitted(promoted);
      if (!fontUpload.committed) {
        LOG_ERR("WEB", "Font staging promotion failed (%d)", static_cast<int>(promoted));
        fontUpload.valid = false;
        if (!discardFontUploadPartial()) LOG_ERR("WEB", "Failed-promotion font staging cleanup failed");
        break;
      }

      fontUpload.ownsTemp = false;
      fontUpload.tempPath = "";
      if (promoted == xtinct::file_transfer::ReplaceResult::CommittedBackupRetained) {
        LOG_ERR("WEB", "Font committed; old backup retained at %s", fontUpload.backupPath.c_str());
      } else {
        fontUpload.backupPath = "";
      }
      LOG_DBG("WEB", "Font upload committed: %s (%zu bytes)", fontUpload.filePath.c_str(),
              fontUpload.bytesWritten);
      break;
    }

    case UPLOAD_FILE_ABORTED: {
      const bool removed = discardFontUploadPartial();
      fontUpload.valid = false;
      fontUpload.committed = false;
      LOG_DBG("WEB", "Font upload aborted; partial removed=%d", removed);
      break;
    }
  }
}

void CrossPointWebServer::handleFontUpload() {
  const bool committed = xtinct::file_transfer::mayReportCommittedUploadSuccess(
      fontUpload.valid, fontUpload.committed, fontUpload.ownsTemp);
  if (committed) {
    sdFontSystem.markRegistryDirty();
    server->send(200, "application/json", "{\"ok\":true}");
    LOG_DBG("WEB", "Font upload complete: %s", fontUpload.filePath.c_str());
  } else {
    server->send(400, "application/json", "{\"error\":\"Invalid .cpfont file\"}");
  }
  // A request with no multipart file must never replay the previous request's
  // success latch.
  fontUpload.valid = false;
  fontUpload.committed = false;
}

void CrossPointWebServer::handleFontDelete() {
  String body = server->arg("plain");
  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, body);

  if (err || !doc["family"].is<const char*>()) {
    server->send(400, "application/json", "{\"error\":\"Invalid request\"}");
    return;
  }

  const char* familyName = doc["family"];
  FontInstaller installer(sdFontSystem.registry());
  auto result = installer.deleteFamily(familyName);

  if (result == FontInstaller::Error::OK) {
    sdFontSystem.markRegistryDirty();
    server->send(200, "application/json", "{\"ok\":true}");
    LOG_DBG("WEB", "Deleted font family: %s", familyName);
  } else {
    server->send(500, "application/json", "{\"error\":\"Delete failed\"}");
    LOG_ERR("WEB", "Failed to delete font family: %s", familyName);
  }
}
