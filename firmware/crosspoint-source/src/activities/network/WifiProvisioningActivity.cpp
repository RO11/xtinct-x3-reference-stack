#include "WifiProvisioningActivity.h"

#include <GfxRenderer.h>
#include <I18n.h>
#include <Logging.h>
#include <Memory.h>
#include <WiFi.h>
#include <esp_system.h>

#include <string>

#include "MappedInputManager.h"
#include "SilentRestart.h"
#include "WifiCredentialStore.h"
#include "components/UITheme.h"
#include "fontIds.h"
#include "util/QrUtils.h"

namespace {
constexpr uint16_t DNS_PORT = 53;
constexpr uint8_t AP_CHANNEL = 1;
constexpr uint8_t AP_MAX_CONNECTIONS = 1;
constexpr char PASSWORD_ALPHABET[] = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
}  // namespace

void WifiProvisioningActivity::generateCredentials() {
  uint8_t mac[6] = {0};
  WiFi.macAddress(mac);
  snprintf(apSsid, sizeof(apSsid), "XTINCT-X3-%02X%02X%02X", mac[3], mac[4], mac[5]);
  for (size_t i = 0; i < sizeof(apPassword) - 1; ++i) {
    apPassword[i] = PASSWORD_ALPHABET[esp_random() % (sizeof(PASSWORD_ALPHABET) - 1)];
  }
  apPassword[sizeof(apPassword) - 1] = '\0';
  for (size_t i = 0; i < sizeof(sessionToken) - 1; ++i) {
    sessionToken[i] = PASSWORD_ALPHABET[esp_random() % (sizeof(PASSWORD_ALPHABET) - 1)];
  }
  sessionToken[sizeof(sessionToken) - 1] = '\0';
}

bool WifiProvisioningActivity::startProvisioning() {
  WIFI_STORE.loadFromFile();
  generateCredentials();

  WiFi.persistent(false);
  WiFi.mode(WIFI_AP_STA);
  WiFi.disconnect(false, true);
  delay(100);
  if (!WiFi.softAP(apSsid, apPassword, AP_CHANNEL, false, AP_MAX_CONNECTIONS)) {
    LOG_ERR("WPROV", "Failed to start protected setup AP");
    stopProvisioning();
    return false;
  }

  const IPAddress apIp = WiFi.softAPIP();
  dnsServer = makeUniqueNoThrow<DNSServer>();
  if (!dnsServer) {
    LOG_ERR("WPROV", "OOM: DNS server");
    stopProvisioning();
    return false;
  }
  dnsServer->setErrorReplyCode(DNSReplyCode::NoError);
  if (!dnsServer->start(DNS_PORT, "*", apIp)) {
    LOG_ERR("WPROV", "Failed to start captive DNS");
    stopProvisioning();
    return false;
  }

  provisioningServer = makeUniqueNoThrow<WifiProvisioningServer>(sessionToken);
  if (!provisioningServer || !provisioningServer->begin()) {
    LOG_ERR("WPROV", "Failed to start setup web server");
    stopProvisioning();
    return false;
  }
  LOG_INF("WPROV", "Protected phone setup started (credentials shown on device only)");
  return true;
}

void WifiProvisioningActivity::stopProvisioning() {
  if (provisioningServer) {
    provisioningServer->stop();
    provisioningServer.reset();
  }
  if (dnsServer) {
    dnsServer->stop();
    dnsServer.reset();
  }
  if (WiFi.getMode() != WIFI_MODE_NULL) {
    WiFi.softAPdisconnect(true);
    WiFi.disconnect(true, true);
    WiFi.mode(WIFI_OFF);
    delay(30);
  }
}

void WifiProvisioningActivity::onEnter() {
  Activity::onEnter();
  sessionStartedAt = millis();
  started = startProvisioning();
  startFailed = !started;
  requestUpdate();
}

void WifiProvisioningActivity::onExit() {
  Activity::onExit();
  const bool wifiWasStarted = started;
  stopProvisioning();
  if (wifiWasStarted) silentRestart();
}

void WifiProvisioningActivity::loop() {
  if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
    onGoHome();
    return;
  }
  if (millis() - sessionStartedAt >= SESSION_TIMEOUT_MS) {
    LOG_INF("WPROV", "Phone setup session expired");
    onGoHome();
    return;
  }
  if (!started) {
    if (mappedInput.wasPressed(MappedInputManager::Button::Confirm)) onGoHome();
    return;
  }

  dnsServer->processNextRequest();
  provisioningServer->handleClient();
  const bool provisioned = provisioningServer->hasProvisionedNetwork();
  if (provisioned != lastProvisionedState) {
    lastProvisionedState = provisioned;
    requestUpdate();
  }
}

void WifiProvisioningActivity::render(RenderLock&&) {
  renderer.clearScreen();
  const auto& metrics = UITheme::getInstance().getMetrics();
  const int width = renderer.getScreenWidth();
  const int height = renderer.getScreenHeight();
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, width, metrics.headerHeight}, tr(STR_PHONE_WIFI_SETUP));

  if (startFailed) {
    UITheme::drawCenteredWrappedText(renderer, Rect{metrics.contentSidePadding, metrics.headerHeight,
                                                    width - 2 * metrics.contentSidePadding, height - metrics.headerHeight},
                                     UI_12_FONT_ID, tr(STR_PHONE_WIFI_START_FAILED), 3, true, EpdFontFamily::BOLD);
    const auto labels = mappedInput.mapLabels(tr(STR_BACK), tr(STR_DONE), "", "");
    GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
    renderer.displayBuffer();
    return;
  }

  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;
  const int qrSize = std::min(190, (width - metrics.contentSidePadding * 3) / 2);
  const int leftX = metrics.contentSidePadding;
  const int rightX = width - metrics.contentSidePadding - qrSize;

  const std::string wifiQr = std::string("WIFI:T:WPA;S:") + apSsid + ";P:" + apPassword + ";;";
  QrUtils::drawQrCode(renderer, Rect{leftX, contentTop, qrSize, qrSize}, wifiQr);
  QrUtils::drawQrCode(renderer, Rect{rightX, contentTop, qrSize, qrSize}, "http://192.168.4.1/");

  const int labelY = contentTop + qrSize + metrics.verticalSpacing;
  UITheme::drawCenteredWrappedText(renderer, Rect{leftX, labelY, qrSize, 42}, SMALL_FONT_ID,
                                   tr(STR_SCAN_TO_JOIN_SETUP), 2);
  UITheme::drawCenteredWrappedText(renderer, Rect{rightX, labelY, qrSize, 42}, SMALL_FONT_ID,
                                   tr(STR_SCAN_TO_OPEN_SETUP), 2);

  char ssidLine[64];
  char passwordLine[64];
  snprintf(ssidLine, sizeof(ssidLine), "%s: %s", tr(STR_NETWORK_PREFIX_SHORT), apSsid);
  snprintf(passwordLine, sizeof(passwordLine), "%s: %s", tr(STR_PASSWORD), apPassword);
  const int detailsY = labelY + 52;
  renderer.drawCenteredText(UI_10_FONT_ID, detailsY, ssidLine);
  renderer.drawCenteredText(UI_10_FONT_ID, detailsY + renderer.getLineHeight(UI_10_FONT_ID), passwordLine);

  if (lastProvisionedState) {
    char connected[96];
    snprintf(connected, sizeof(connected), tr(STR_PHONE_WIFI_CONNECTED_FMT), provisioningServer->getConnectedSsid(),
             provisioningServer->getConnectedIp());
    UITheme::drawCenteredWrappedText(
        renderer, Rect{metrics.contentSidePadding, detailsY + 55, width - 2 * metrics.contentSidePadding, 60},
        UI_10_FONT_ID, connected, 2, true, EpdFontFamily::BOLD);
  } else if (recoveryMode) {
    UITheme::drawCenteredWrappedText(
        renderer, Rect{metrics.contentSidePadding, detailsY + 55, width - 2 * metrics.contentSidePadding, 60},
        SMALL_FONT_ID, tr(STR_PHONE_WIFI_RECOVERY_HINT), 2);
  }

  const auto labels = mappedInput.mapLabels(tr(STR_BACK), "", "", "");
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}
