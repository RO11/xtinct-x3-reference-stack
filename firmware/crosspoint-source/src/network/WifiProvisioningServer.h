#pragma once

#include <WebServer.h>

#include <memory>

class WifiProvisioningServer {
 public:
  explicit WifiProvisioningServer(const char* sessionToken);
  bool begin();
  void stop();
  void handleClient();
  bool isRunning() const { return running; }
  bool hasProvisionedNetwork() const { return provisioned; }
  const char* getConnectedSsid() const { return connectedSsid; }
  const char* getConnectedIp() const { return connectedIp; }

 private:
  std::unique_ptr<WebServer> server;
  bool running = false;
  bool provisioned = false;
  char connectedSsid[33] = {0};
  char connectedIp[16] = {0};
  char sessionToken[25] = {0};

  bool requireApClient() const;
  bool requireJsonMutation() const;
  void addSecurityHeaders() const;
  void sendJson(int status, const String& payload) const;
  void sendError(int status, const char* message) const;
  void handleRoot() const;
  void handleSession() const;
  void handleNetworks() const;
  void handleSavedNetworks() const;
  void handleDeleteSavedNetwork();
  void handleGetConfig() const;
  void handlePostConfig();
  void handleConnect();
  void handleNotFound() const;
};
