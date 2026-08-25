#include "WifiProvisioningServer.h"

#include <ArduinoJson.h>
#include <HalClock.h>
#include <I18n.h>
#include <Logging.h>
#include <Memory.h>
#include <WiFi.h>

#include <cctype>
#include <cstring>
#include <string>

#include "CrossPointSettings.h"
#include "WifiCredentialStore.h"
#include "XtinctFeedConfigStore.h"
#include "XtinctWakePlan.h"
#include "XtinctWakeStatusStore.h"
#include "html/WifiProvisioningPageHtml.generated.h"

namespace {
constexpr size_t MAX_CONNECT_BODY_BYTES = 512;
constexpr size_t MAX_CONFIG_BODY_BYTES = 1024;
constexpr unsigned long CONNECT_TIMEOUT_MS = 15000;

String jsonEscaped(const char* value) {
  JsonDocument doc;
  doc.set(value ? value : "");
  String result;
  serializeJson(doc, result);
  return result;
}
}  // namespace

WifiProvisioningServer::WifiProvisioningServer(const char* token) {
  snprintf(sessionToken, sizeof(sessionToken), "%s", token ? token : "");
}

bool WifiProvisioningServer::begin() {
  if (running) return true;
  server = makeUniqueNoThrow<WebServer>(80);
  if (!server) {
    LOG_ERR("WPROV", "OOM: web server");
    return false;
  }

  server->on("/", HTTP_GET, [this] { handleRoot(); });
  server->on("/api/session", HTTP_GET, [this] { handleSession(); });
  server->on("/api/networks", HTTP_GET, [this] { handleNetworks(); });
  server->on("/api/saved", HTTP_GET, [this] { handleSavedNetworks(); });
  server->on("/api/saved/delete", HTTP_POST, [this] { handleDeleteSavedNetwork(); });
  server->on("/api/config", HTTP_GET, [this] { handleGetConfig(); });
  server->on("/api/config", HTTP_POST, [this] { handlePostConfig(); });
  server->on("/api/connect", HTTP_POST, [this] { handleConnect(); });

  // Common OS captive-portal probes. Returning the setup page (rather than
  // their expected success sentinel) prompts the phone to open its mini browser.
  server->on("/generate_204", HTTP_ANY, [this] { handleRoot(); });
  server->on("/gen_204", HTTP_ANY, [this] { handleRoot(); });
  server->on("/hotspot-detect.html", HTTP_ANY, [this] { handleRoot(); });
  server->on("/library/test/success.html", HTTP_ANY, [this] { handleRoot(); });
  server->on("/ncsi.txt", HTTP_ANY, [this] { handleRoot(); });
  server->on("/connecttest.txt", HTTP_ANY, [this] { handleRoot(); });
  server->onNotFound([this] { handleNotFound(); });
  const char* requestHeaders[] = {"Content-Type", "X-XTINCT-Setup"};
  server->collectHeaders(requestHeaders, 2);
  server->begin();
  running = true;
  return true;
}

void WifiProvisioningServer::stop() {
  if (!server) return;
  server->stop();
  server.reset();
  running = false;
}

void WifiProvisioningServer::handleClient() {
  if (running && server) server->handleClient();
}

bool WifiProvisioningServer::requireApClient() const {
  if (!server) return false;
  const IPAddress apIp = WiFi.softAPIP();
  NetworkClient client = server->client();
  if (apIp != IPAddress(0, 0, 0, 0) && client.localIP() == apIp) return true;

  // WebServer listens on every active interface. Once the STA test succeeds,
  // reject requests arriving from the home LAN and keep the setup surface
  // reachable only through the short-lived, password-protected setup AP.
  addSecurityHeaders();
  server->send(403, "text/plain", "Phone setup is available only on the XTINCT setup network");
  return false;
}

bool WifiProvisioningServer::requireJsonMutation() const {
  if (!requireApClient()) return false;
  const String contentType = server->header("Content-Type");
  if (!contentType.startsWith("application/json")) {
    sendError(415, "Use application/json");
    return false;
  }
  if (sessionToken[0] == '\0' || server->header("X-XTINCT-Setup") != sessionToken) {
    sendError(403, "Setup session check failed. Reload the page.");
    return false;
  }
  return true;
}

void WifiProvisioningServer::addSecurityHeaders() const {
  server->sendHeader("Cache-Control", "no-store");
  server->sendHeader("X-Content-Type-Options", "nosniff");
  server->sendHeader("X-Frame-Options", "DENY");
  server->sendHeader("Referrer-Policy", "no-referrer");
  server->sendHeader("Content-Security-Policy",
                     "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; "
                     "frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
}

void WifiProvisioningServer::sendJson(const int status, const String& payload) const {
  addSecurityHeaders();
  server->send(status, "application/json", payload);
}

void WifiProvisioningServer::sendError(const int status, const char* message) const {
  sendJson(status, String("{\"error\":") + jsonEscaped(message) + "}");
}

void WifiProvisioningServer::handleRoot() const {
  if (!requireApClient()) return;
  addSecurityHeaders();
  server->sendHeader("Content-Encoding", "gzip");
  server->send_P(200, "text/html", WifiProvisioningPageHtml, WifiProvisioningPageHtmlCompressedSize);
}

void WifiProvisioningServer::handleSession() const {
  if (!requireApClient()) return;
  JsonDocument doc;
  doc["token"] = sessionToken;
  String response;
  serializeJson(doc, response);
  sendJson(200, response);
}

void WifiProvisioningServer::handleNetworks() const {
  if (!requireApClient()) return;
  const int16_t count = WiFi.scanNetworks(false, true);
  if (count < 0) {
    sendError(503, "Wi-Fi scan failed. Try again.");
    return;
  }

  addSecurityHeaders();
  server->setContentLength(CONTENT_LENGTH_UNKNOWN);
  server->send(200, "application/json", "");
  server->sendContent("[");
  bool sentAny = false;
  for (int i = 0; i < count; ++i) {
    const String ssid = WiFi.SSID(i);
    if (ssid.isEmpty()) continue;
    bool duplicate = false;
    for (int j = 0; j < i; ++j) {
      if (WiFi.SSID(j) == ssid) {
        duplicate = true;
        break;
      }
    }
    if (duplicate) continue;

    JsonDocument doc;
    doc["ssid"] = ssid;
    doc["rssi"] = WiFi.RSSI(i);
    doc["secure"] = WiFi.encryptionType(i) != WIFI_AUTH_OPEN;
    doc["saved"] = WIFI_STORE.hasSavedCredential(ssid.c_str());
    char output[192];
    const size_t written = serializeJson(doc, output, sizeof(output));
    if (written == 0 || written >= sizeof(output)) continue;
    if (sentAny) server->sendContent(",");
    server->sendContent(output);
    sentAny = true;
    yield();
  }
  server->sendContent("]");
  server->sendContent("");
  WiFi.scanDelete();
}

void WifiProvisioningServer::handleSavedNetworks() const {
  if (!requireApClient()) return;
  addSecurityHeaders();
  server->setContentLength(CONTENT_LENGTH_UNKNOWN);
  server->send(200, "application/json", "");
  server->sendContent("[");
  const auto& credentials = WIFI_STORE.getCredentials();
  const std::string& preferred = WIFI_STORE.getLastConnectedSsid();
  bool sentAny = false;
  for (size_t i = 0; i < credentials.size(); ++i) {
    JsonDocument doc;
    doc["ssid"] = credentials[i].ssid;
    doc["preferred"] = credentials[i].ssid == preferred;
    char output[160];
    const size_t written = serializeJson(doc, output, sizeof(output));
    if (written == 0 || written >= sizeof(output)) continue;
    if (sentAny) server->sendContent(",");
    server->sendContent(output);
    sentAny = true;
  }
  server->sendContent("]");
  server->sendContent("");
}

void WifiProvisioningServer::handleDeleteSavedNetwork() {
  if (!requireJsonMutation()) return;
  if (!server->hasArg("plain")) {
    sendError(400, "Missing JSON body");
    return;
  }
  const String body = server->arg("plain");
  if (body.length() > MAX_CONNECT_BODY_BYTES) {
    sendError(413, "Delete request is too large");
    return;
  }
  JsonDocument doc;
  if (deserializeJson(doc, body)) {
    sendError(400, "Invalid JSON");
    return;
  }
  const char* ssidValue = doc["ssid"] | "";
  const std::string ssid(ssidValue);
  if (ssid.empty() || ssid.size() > 32) {
    sendError(400, "SSID length is invalid");
    return;
  }
  if (!WIFI_STORE.hasSavedCredential(ssid)) {
    sendError(404, "Saved network was not found");
    return;
  }
  if (!WIFI_STORE.removeCredential(ssid)) {
    sendError(507, "The saved network could not be removed from storage");
    return;
  }
  sendJson(200, "{\"ok\":true}");
}

void WifiProvisioningServer::handleGetConfig() const {
  if (!requireApClient()) return;
  JsonDocument doc;
  doc["base_url"] = XTINCT_FEED_CONFIG.getBaseUrl();
  doc["has_token"] = XTINCT_FEED_CONFIG.hasReadToken();
  doc["enabled"] = XTINCT_FEED_CONFIG.isAutoSyncRequested();
  doc["effective_enabled"] = XTINCT_FEED_CONFIG.isEnabled();
  doc["wake_hour"] = XTINCT_FEED_CONFIG.getWakeHour();
  doc["wake_minute"] = XTINCT_FEED_CONFIG.getWakeMinute();
  doc["utc_offset_quarter_hours"] = SETTINGS.clockUtcOffsetQ;
  const XtinctWakePlan plan = calculateXtinctWakePlan();
  doc["schedule_ready"] = plan.ready;
  doc["schedule_reason"] = xtinctWakeReasonCode(plan.reason);
  doc["schedule_reason_text"] = xtinctWakeReasonLabel(plan.reason);
  doc["timezone_brisbane_warning"] = SETTINGS.clockUtcOffsetQ != 88;
  if (plan.nextLocalKnown) {
    char nextWake[8];
    if (formatXtinctLocalTime(plan.nextHour, plan.nextMinute, nextWake, sizeof(nextWake))) {
      doc["next_wake_local"] = nextWake;
    }
  } else {
    doc["next_wake_local"] = nullptr;
  }
  doc["last_timer_arm_state"] = xtinctTimerArmStateCode(XTINCT_WAKE_STATUS.getLastTimerState());
  doc["last_wake_cause"] = xtinctWakeCauseCode(XTINCT_WAKE_STATUS.getLastWakeCause());
  String response;
  serializeJson(doc, response);
  sendJson(200, response);
}

void WifiProvisioningServer::handlePostConfig() {
  if (!requireJsonMutation()) return;
  if (!server->hasArg("plain")) {
    sendError(400, "Missing JSON body");
    return;
  }
  const String body = server->arg("plain");
  if (body.length() > MAX_CONFIG_BODY_BYTES) {
    sendError(413, "Settings are too large");
    return;
  }
  JsonDocument doc;
  if (deserializeJson(doc, body)) {
    sendError(400, "Invalid JSON");
    return;
  }
  if (!doc["base_url"].isNull() || !doc["read_token"].isNull()) {
    sendError(400, "The feed origin and token can be changed only over physical USB");
    return;
  }

  const bool enabled = doc["enabled"] | false;
  const int wakeHour = doc["wake_hour"] | 4;
  const int wakeMinute = doc["wake_minute"] | static_cast<int>(XTINCT_FEED_CONFIG.getWakeMinute());
  const int utcOffset = doc["utc_offset_quarter_hours"] | -1;
  if (wakeHour < 0 || wakeHour > 23 || wakeMinute < 0 || wakeMinute > 59 || wakeMinute % 15 != 0 ||
      utcOffset < 0 || utcOffset > 104) {
    sendError(400, "Use valid Daily Cards schedule settings");
    return;
  }
  // Persist the timezone first so the feed can never become enabled with a
  // stale offset. The explicit ON request may be saved while another
  // prerequisite is unavailable, but effective timer/network readiness still
  // fails closed in calculateXtinctWakePlan(). Restore the offset if the later
  // feed settings write fails.
  const uint8_t oldUtcOffset = SETTINGS.clockUtcOffsetQ;
  if (oldUtcOffset != static_cast<uint8_t>(utcOffset)) {
    SETTINGS.clockUtcOffsetQ = static_cast<uint8_t>(utcOffset);
    if (!SETTINGS.saveToFile()) {
      SETTINGS.clockUtcOffsetQ = oldUtcOffset;
      sendError(507, "The local UTC offset could not be saved");
      return;
    }
  }
  if (!XTINCT_FEED_CONFIG.updateSettings(enabled, static_cast<uint8_t>(wakeHour),
                                         static_cast<uint8_t>(wakeMinute))) {
    SETTINGS.clockUtcOffsetQ = oldUtcOffset;
    if (!SETTINGS.saveToFile()) LOG_ERR("WPROV", "Could not restore UTC offset after feed settings failure");
    sendError(507, "Daily Cards settings could not be saved");
    return;
  }

  JsonDocument response;
  response["ok"] = true;
  response["enabled"] = XTINCT_FEED_CONFIG.isAutoSyncRequested();
  response["effective_enabled"] = XTINCT_FEED_CONFIG.isEnabled();
  response["wake_hour"] = XTINCT_FEED_CONFIG.getWakeHour();
  response["wake_minute"] = XTINCT_FEED_CONFIG.getWakeMinute();
  const XtinctWakePlan plan = calculateXtinctWakePlan();
  response["schedule_ready"] = plan.ready;
  response["schedule_reason"] = xtinctWakeReasonCode(plan.reason);
  response["schedule_reason_text"] = xtinctWakeReasonLabel(plan.reason);
  response["timezone_brisbane_warning"] = SETTINGS.clockUtcOffsetQ != 88;
  if (plan.nextLocalKnown) {
    char nextWake[8];
    if (formatXtinctLocalTime(plan.nextHour, plan.nextMinute, nextWake, sizeof(nextWake))) {
      response["next_wake_local"] = nextWake;
    }
  } else {
    response["next_wake_local"] = nullptr;
  }
  String output;
  serializeJson(response, output);
  sendJson(200, output);
}

void WifiProvisioningServer::handleConnect() {
  if (!requireJsonMutation()) return;
  if (!server->hasArg("plain")) {
    sendError(400, "Missing JSON body");
    return;
  }
  const String body = server->arg("plain");
  if (body.length() > MAX_CONNECT_BODY_BYTES) {
    sendError(413, "Connection request is too large");
    return;
  }
  JsonDocument doc;
  if (deserializeJson(doc, body)) {
    sendError(400, "Invalid JSON");
    return;
  }

  const char* ssidValue = doc["ssid"] | "";
  const char* passwordValue = doc["password"] | "";
  const std::string ssid(ssidValue);
  const std::string password(passwordValue);
  if (ssid.empty() || ssid.size() > 32 || password.size() > 64) {
    sendError(400, "SSID or password length is invalid");
    return;
  }
  bool isHexPsk = password.size() == 64;
  if (isHexPsk) {
    for (const unsigned char value : password) {
      if (!std::isxdigit(value)) {
        isHexPsk = false;
        break;
      }
    }
  }
  if ((!password.empty() && password.size() < 8) || (password.size() == 64 && !isHexPsk)) {
    sendError(400, "Use an 8-63 character password, a 64-digit hex PSK, or empty for open Wi-Fi");
    return;
  }

  WiFi.persistent(false);
  WiFi.disconnect(false, true);  // STA only; the provisioning AP remains available.
  delay(100);
  WiFi.setScanMethod(WIFI_ALL_CHANNEL_SCAN);
  WiFi.setSortMethod(WIFI_CONNECT_AP_BY_SIGNAL);
  if (password.empty()) {
    WiFi.begin(ssid.c_str());
  } else {
    WiFi.begin(ssid.c_str(), password.c_str());
  }

  const unsigned long started = millis();
  bool connected = false;
  while (millis() - started < CONNECT_TIMEOUT_MS) {
    const wl_status_t status = WiFi.status();
    if (status == WL_CONNECTED) {
      connected = true;
      break;
    }
    if (status == WL_CONNECT_FAILED || status == WL_NO_SSID_AVAIL) break;
    delay(100);
    yield();
  }
  if (!connected) {
    WiFi.disconnect(false, true);
    sendError(409, "Could not connect. The existing saved password was kept.");
    return;
  }

  // Commit only after association and DHCP succeed. addCredential updates an
  // existing SSID in place; a failed test above never mutates the store.
  if (!WIFI_STORE.addCredential(ssid, password)) {
    sendError(507, "Connected, but the credential could not be saved");
    return;
  }
  WIFI_STORE.setLastConnectedSsid(ssid);

  // A daily timer is armed only after the UTC RTC has been synchronized and
  // that fact has been persisted. This keeps a freshly provisioned reader from
  // scheduling against an unset/stale clock.
  const bool previouslySynced = SETTINGS.clockHasBeenSynced != 0;
  const bool previouslyValid = halClock.hasValidTime();
  bool clockSynced = previouslySynced && previouslyValid;
  if (halClock.isAvailable()) {
    // Phone setup is an explicit maintenance session, so refresh the RTC even
    // if an older sync flag exists. A transient NTP failure does not invalidate
    // an otherwise valid battery-backed RTC.
    if (halClock.syncFromNTP()) {
      SETTINGS.clockHasBeenSynced = 1;
      if (SETTINGS.saveToFile()) {
        clockSynced = true;
      } else {
        SETTINGS.clockHasBeenSynced = (previouslySynced && previouslyValid) ? 1 : 0;
        clockSynced = previouslySynced && previouslyValid;
        LOG_ERR("WPROV", "Clock synchronized, but sync state could not be saved");
      }
    } else if (!previouslyValid && previouslySynced) {
      SETTINGS.clockHasBeenSynced = 0;
      if (!SETTINGS.saveToFile()) LOG_ERR("WPROV", "Could not clear invalid clock sync state");
    }
  } else {
    clockSynced = false;
    if (previouslySynced) {
      SETTINGS.clockHasBeenSynced = 0;
      if (!SETTINGS.saveToFile()) LOG_ERR("WPROV", "Could not clear unavailable clock sync state");
    }
  }

  const IPAddress ip = WiFi.localIP();
  snprintf(connectedSsid, sizeof(connectedSsid), "%s", ssid.c_str());
  snprintf(connectedIp, sizeof(connectedIp), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  provisioned = true;

  JsonDocument response;
  response["ok"] = true;
  response["ssid"] = connectedSsid;
  response["ip"] = connectedIp;
  response["clock_synced"] = clockSynced;
  String output;
  serializeJson(response, output);
  sendJson(200, output);
}

void WifiProvisioningServer::handleNotFound() const {
  if (!requireApClient()) return;
  if (server->uri().startsWith("/api/")) {
    sendError(404, "Not found");
    return;
  }
  server->sendHeader("Location", "http://192.168.4.1/", true);
  server->send(302, "text/plain", "");
}
