#include "WebDAVHandler.h"

#include <FsHelpers.h>
#include <HalStorage.h>
#include <Logging.h>
#include <esp_system.h>

#include "FileTransferPathPolicy.h"
#include "FileTransferSafety.h"
#include "util/BookCacheUtils.h"
#include "util/TaskWatchdog.h"

namespace {
struct HalRenameOps {
  bool exists(const char* path) const { return Storage.exists(path); }
  bool rename(const char* source, const char* destination) const { return Storage.rename(source, destination); }
  bool remove(const char* path) const { return Storage.remove(path); }
};

struct DavCopySource {
  HalFile& file;
  int read(void* buffer, const size_t bytes) {
    resetTaskWatchdogIfSubscribed();
    return file.read(buffer, bytes);
  }
};

struct DavCopyDestination {
  HalFile& file;
  size_t write(const void* buffer, const size_t bytes) {
    resetTaskWatchdogIfSubscribed();
    return file.write(buffer, bytes);
  }
  bool sync() {
    resetTaskWatchdogIfSubscribed();
    return file.sync();
  }
  bool getWriteError() const { return file.getWriteError(); }
};

bool makeUniqueDavSibling(const String& destination, const char* purpose, String& path) {
  const int slash = destination.lastIndexOf('/');
  String parent = slash <= 0 ? "/" : destination.substring(0, slash);
  if (!parent.endsWith("/")) parent += "/";
  for (uint8_t attempt = 0; attempt < 16; ++attempt) {
    char leaf[48];
    const int leafBytes = snprintf(leaf, sizeof(leaf), ".xtinct-dav-%s-%08lx.tmp", purpose,
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

bool removeOwnedDavPath(String& path) {
  if (path.isEmpty()) return true;
  // Try the exact request-owned path even if an earlier exists() probe lied or
  // failed; an absent path is still a successful cleanup.
  const bool removed = Storage.remove(path.c_str()) || !Storage.exists(path.c_str());
  if (removed) path = "";
  return removed;
}

// RFC 1123 date format helper: "Sun, 06 Nov 1994 08:49:37 GMT"
// ESP32 doesn't have real-time clock set by default, so we use a fixed epoch date
// as a fallback. The date is not critical for WebDAV Class 1 operations.
const char* FIXED_DATE = "Thu, 01 Jan 2024 00:00:00 GMT";
}  // namespace

// ── RequestHandler interface ─────────────────────────────────────────────────

bool WebDAVHandler::canHandle(WebServer& server, HTTPMethod method, const String& uri) {
  (void)server;
  (void)uri;
  switch (method) {
    case HTTP_OPTIONS:
    case HTTP_PROPFIND:
    case HTTP_GET:
    case HTTP_HEAD:
    case HTTP_PUT:
    case HTTP_DELETE:
    case HTTP_MKCOL:
    case HTTP_MOVE:
    case HTTP_COPY:
    case HTTP_LOCK:
    case HTTP_UNLOCK:
      return true;
    default:
      return false;
  }
}

bool WebDAVHandler::canRaw(WebServer& server, const String& uri) {
  (void)uri;
  return server.method() == HTTP_PUT;
}

void WebDAVHandler::raw(WebServer& server, const String& uri, HTTPRaw& raw) {
  (void)uri;
  if (raw.status == RAW_START) {
    if (_putFile) _putFile.close();
    if (_putOwnsTemp && !removeOwnedDavPath(_putTempPath)) {
      _putOk = false;
      _putReceivedEnd = false;
      return;
    }
    _putTempPath = "";
    _putBackupPath = "";
    _putOwnsTemp = false;
    _putReceivedEnd = false;
    _putOk = false;
    _putCommitted = false;
    _putExisted = false;
    _putPath = getRequestPath(server);
    if (isProtectedPath(_putPath, xtinct::file_transfer::PathIntent::CreateLeaf)) return;

    _putExisted = Storage.exists(_putPath.c_str());

    if (_putExisted) {
      HalFile existing = Storage.open(_putPath.c_str());
      if (!existing || existing.isDirectory()) {
        if (existing) existing.close();
        return;
      }
      existing.close();
    }

    // Write only to a unique hidden sibling owned by this request. Never
    // unlink a predictable shared .davtmp path created by another client.
    if (!makeUniqueDavSibling(_putPath, "put", _putTempPath)) return;
    _putOwnsTemp = true;
    const bool opened = Storage.openFileForWrite("DAV", _putTempPath, _putFile);
    const bool existenceVerified = Storage.exists(_putTempPath.c_str());
    _putOk = opened && existenceVerified;
    if (!_putOk) {
      if (_putFile) _putFile.close();
      if (_putOwnsTemp && removeOwnedDavPath(_putTempPath)) _putOwnsTemp = false;
      return;
    }
    LOG_DBG("DAV", "PUT START: %s", _putPath.c_str());

  } else if (raw.status == RAW_WRITE) {
    if (_putFile && _putOk) {
      resetTaskWatchdogIfSubscribed();
      const size_t written = _putFile.write(raw.buf, raw.currentSize);
      if (written != raw.currentSize || _putFile.getWriteError()) _putOk = false;
    }

  } else if (raw.status == RAW_END) {
    _putReceivedEnd = true;
    if (_putFile) {
      _putOk = xtinct::file_transfer::finishDurableWrite(_putFile, _putOk);
    }
    if (_putOk && _putOwnsTemp) {
      if (_putExisted && !makeUniqueDavSibling(_putPath, "old", _putBackupPath)) {
        _putOk = false;
      } else {
        HalRenameOps ops;
        const auto promoted = xtinct::file_transfer::promotePrepared(
            ops, _putTempPath.c_str(), _putPath.c_str(),
            _putBackupPath.isEmpty() ? nullptr : _putBackupPath.c_str(), _putExisted);
        _putOk = xtinct::file_transfer::isCommitted(promoted);
        if (_putOk) {
          _putCommitted = true;
          _putOwnsTemp = false;
          _putTempPath = "";
          if (promoted == xtinct::file_transfer::ReplaceResult::CommittedBackupRetained) {
            LOG_ERR("DAV", "PUT committed but old-file backup cleanup failed: %s", _putBackupPath.c_str());
          } else {
            _putBackupPath = "";
          }
        } else if (promoted == xtinct::file_transfer::ReplaceResult::RestoreFailed) {
          LOG_ERR("DAV", "PUT promote and destination restore both failed; preserved backup=%s",
                  _putBackupPath.c_str());
        }
      }
    }
    if (!_putOk && _putOwnsTemp && removeOwnedDavPath(_putTempPath)) _putOwnsTemp = false;
    LOG_DBG("DAV", "PUT END: %u bytes, ok=%d", raw.totalSize, _putOk);

  } else if (raw.status == RAW_ABORTED) {
    if (_putFile) _putFile.close();
    if (_putOwnsTemp && removeOwnedDavPath(_putTempPath)) _putOwnsTemp = false;
    _putOk = false;
    _putCommitted = false;
    _putReceivedEnd = true;
  }
}

bool WebDAVHandler::handle(WebServer& server, HTTPMethod method, const String& uri) {
  (void)uri;
  switch (method) {
    case HTTP_OPTIONS:
      handleOptions(server);
      return true;
    case HTTP_PROPFIND:
      handlePropfind(server);
      return true;
    case HTTP_GET:
      handleGet(server);
      return true;
    case HTTP_HEAD:
      handleHead(server);
      return true;
    case HTTP_PUT:
      handlePut(server);
      return true;
    case HTTP_DELETE:
      handleDelete(server);
      return true;
    case HTTP_MKCOL:
      handleMkcol(server);
      return true;
    case HTTP_MOVE:
      handleMove(server);
      return true;
    case HTTP_COPY:
      handleCopy(server);
      return true;
    case HTTP_LOCK:
      handleLock(server);
      return true;
    case HTTP_UNLOCK:
      handleUnlock(server);
      return true;
    default:
      return false;
  }
}

// ── OPTIONS ──────────────────────────────────────────────────────────────────

void WebDAVHandler::handleOptions(WebServer& s) {
  s.sendHeader("DAV", "1");
  s.sendHeader("Allow",
               "OPTIONS, GET, HEAD, PUT, DELETE, "
               "PROPFIND, MKCOL, MOVE, COPY, LOCK, UNLOCK");
  s.sendHeader("MS-Author-Via", "DAV");
  s.send(200);
  LOG_DBG("DAV", "OPTIONS %s", s.uri().c_str());
}

// ── PROPFIND ─────────────────────────────────────────────────────────────────

void WebDAVHandler::handlePropfind(WebServer& s) {
  String path = getRequestPath(s);
  int depth = getDepth(s);

  LOG_DBG("DAV", "PROPFIND %s depth=%d", path.c_str(), depth);

  if (isProtectedPath(path, xtinct::file_transfer::PathIntent::Existing)) {
    s.send(403, "text/plain", "Forbidden");
    return;
  }

  // Check if path exists
  if (!Storage.exists(path.c_str()) && path != "/") {
    s.send(404, "text/plain", "Not Found");
    return;
  }

  HalFile root = Storage.open(path.c_str());
  if (!root) {
    if (path == "/") {
      // Root should always work — send minimal response
      s.setContentLength(CONTENT_LENGTH_UNKNOWN);
      s.send(207, "application/xml; charset=\"utf-8\"", "");
      s.sendContent(
          "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
          "<D:multistatus xmlns:D=\"DAV:\">\n");
      sendPropEntry(s, "/", true, 0, FIXED_DATE);
      s.sendContent("</D:multistatus>\n");
      s.sendContent("");
      return;
    }
    s.send(500, "text/plain", "Failed to open");
    return;
  }

  bool isDir = root.isDirectory();

  s.setContentLength(CONTENT_LENGTH_UNKNOWN);
  s.send(207, "application/xml; charset=\"utf-8\"", "");
  s.sendContent(
      "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
      "<D:multistatus xmlns:D=\"DAV:\">\n");

  // Entry for the resource itself
  if (isDir) {
    sendPropEntry(s, path, true, 0, FIXED_DATE);
  } else {
    sendPropEntry(s, path, false, root.size(), FIXED_DATE);
    root.close();
    s.sendContent("</D:multistatus>\n");
    s.sendContent("");
    return;
  }

  // If depth > 0 and it's a directory, list children
  if (depth > 0) {
    HalFile file = root.openNextFile();
    char name[xtinct::file_transfer::MAX_LFN_UTF8_BYTES + 1] = {};
    while (file) {
      const size_t nameLength = file.getName(name, sizeof(name));
      const bool validCanonicalName = nameLength > 0 &&
                                      nameLength <= xtinct::file_transfer::MAX_LFN_UTF8_BYTES &&
                                      name[nameLength] == '\0';
      String fileName = validCanonicalName ? String(name) : String();

      // getName() returns the actual LFN even when the request reached this
      // directory through an SFN alias. A failed/truncated canonical name is
      // hidden rather than exposed under ambiguous bytes.
      const bool shouldHide =
          !validCanonicalName || xtinct::file_transfer::isProtectedTransferComponent(fileName);

      if (!shouldHide) {
        String childPath = path;
        if (!childPath.endsWith("/")) childPath += "/";
        childPath += fileName;

        if (file.isDirectory()) {
          sendPropEntry(s, childPath, true, 0, FIXED_DATE);
        } else {
          sendPropEntry(s, childPath, false, file.size(), FIXED_DATE);
        }
      }

      file.close();
      yield();
      resetTaskWatchdogIfSubscribed();
      file = root.openNextFile();
    }
  }

  root.close();
  s.sendContent("</D:multistatus>\n");
  s.sendContent("");
}

void WebDAVHandler::sendPropEntry(WebServer& s, const String& path, bool isDir, size_t size,
                                  const String& lastModified) const {
  String href;
  urlEncodePath(path, href);
  // Ensure directory hrefs end with /
  if (isDir && !href.endsWith("/")) href += "/";

  String xml = "<D:response><D:href>";
  xml += href;
  xml += "</D:href><D:propstat><D:prop>";

  if (isDir) {
    xml += "<D:resourcetype><D:collection/></D:resourcetype>";
  } else {
    xml += "<D:resourcetype/>";
    xml += "<D:getcontentlength>";
    xml += String(size);
    xml += "</D:getcontentlength>";
    String mime = getMimeType(path);
    xml += "<D:getcontenttype>";
    xml += mime;
    xml += "</D:getcontenttype>";
  }

  xml += "<D:getlastmodified>";
  xml += lastModified;
  xml += "</D:getlastmodified>";

  xml += "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>\n";

  s.sendContent(xml);
}

// ── GET ──────────────────────────────────────────────────────────────────────

void WebDAVHandler::handleGet(WebServer& s) {
  String path = getRequestPath(s);
  LOG_DBG("DAV", "GET %s", path.c_str());

  if (isProtectedPath(path, xtinct::file_transfer::PathIntent::Existing)) {
    s.send(403, "text/plain", "Forbidden");
    return;
  }

  if (!Storage.exists(path.c_str())) {
    s.send(404, "text/plain", "Not Found");
    return;
  }

  HalFile file = Storage.open(path.c_str());
  if (!file) {
    s.send(500, "text/plain", "Failed to open file");
    return;
  }
  if (file.isDirectory()) {
    file.close();
    // For directories, return a PROPFIND-like response or redirect
    s.send(405, "text/plain", "Method Not Allowed");
    return;
  }

  String contentType = getMimeType(path);
  s.setContentLength(file.size());
  s.send(200, contentType.c_str(), "");

  NetworkClient client = s.client();
  uint8_t buffer[1024];
  while (file.available()) {
    resetTaskWatchdogIfSubscribed();
    int bytesRead = file.read(buffer, sizeof(buffer));
    if (bytesRead <= 0) break;
    size_t totalWritten = 0;
    while (totalWritten < static_cast<size_t>(bytesRead)) {
      resetTaskWatchdogIfSubscribed();
      size_t wrote = client.write(buffer + totalWritten, bytesRead - totalWritten);
      if (wrote == 0) break; // Client disconnected
      totalWritten += wrote;
    }
    if (totalWritten < static_cast<size_t>(bytesRead)) break; // Client disconnected
  }
  file.close();
}

// ── HEAD ─────────────────────────────────────────────────────────────────────

void WebDAVHandler::handleHead(WebServer& s) {
  String path = getRequestPath(s);
  LOG_DBG("DAV", "HEAD %s", path.c_str());

  if (isProtectedPath(path, xtinct::file_transfer::PathIntent::Existing)) {
    s.send(403, "text/plain", "");
    return;
  }

  if (!Storage.exists(path.c_str())) {
    s.send(404, "text/plain", "");
    return;
  }

  HalFile file = Storage.open(path.c_str());
  if (!file) {
    s.send(500, "text/plain", "");
    return;
  }

  if (file.isDirectory()) {
    file.close();
    s.send(200, "text/html", "");
    return;
  }

  String contentType = getMimeType(path);
  s.setContentLength(file.size());
  s.send(200, contentType.c_str(), "");
  file.close();
}

// ── PUT ──────────────────────────────────────────────────────────────────────

void WebDAVHandler::handlePut(WebServer& s) {
  // Body was already received via canRaw/raw callbacks
  String path = getRequestPath(s);
  LOG_DBG("DAV", "PUT %s", path.c_str());

  if (isProtectedPath(path, xtinct::file_transfer::PathIntent::CreateLeaf)) {
    s.send(403, "text/plain", "Forbidden");
    return;
  }

  if (!xtinct::file_transfer::mayReportPutSuccess(_putReceivedEnd, _putPath == path, _putOk,
                                                   _putCommitted, _putOwnsTemp)) {
    if (_putOwnsTemp && removeOwnedDavPath(_putTempPath)) _putOwnsTemp = false;
    s.send(500, "text/plain", "Write failed - incomplete upload or disk full");
    return;
  }

  clearBookCache(path.c_str());
  s.send(_putExisted ? 204 : 201);
  LOG_DBG("DAV", "PUT complete: %s", path.c_str());
}

// ── DELETE ───────────────────────────────────────────────────────────────────

void WebDAVHandler::handleDelete(WebServer& s) {
  String path = getRequestPath(s);
  LOG_DBG("DAV", "DELETE %s", path.c_str());

  if (path == "/" || path.isEmpty()) {
    s.send(403, "text/plain", "Cannot delete root");
    return;
  }

  if (isProtectedPath(path, xtinct::file_transfer::PathIntent::Existing)) {
    s.send(403, "text/plain", "Forbidden");
    return;
  }

  if (!Storage.exists(path.c_str())) {
    s.send(404, "text/plain", "Not Found");
    return;
  }

  HalFile file = Storage.open(path.c_str());
  if (!file) {
    s.send(500, "text/plain", "Failed to open");
    return;
  }

  if (file.isDirectory()) {
    // Check if directory is empty
    HalFile entry = file.openNextFile();
    if (entry) {
      entry.close();
      file.close();
      s.send(409, "text/plain", "Directory not empty");
      return;
    }
    file.close();
    if (Storage.rmdir(path.c_str())) {
      s.send(204);
    } else {
      s.send(500, "text/plain", "Failed to remove directory");
    }
  } else {
    file.close();
    clearBookCache(path.c_str());
    if (Storage.remove(path.c_str())) {
      s.send(204);
    } else {
      s.send(500, "text/plain", "Failed to delete file");
    }
  }
}

// ── MKCOL ────────────────────────────────────────────────────────────────────

void WebDAVHandler::handleMkcol(WebServer& s) {
  String path = getRequestPath(s);
  LOG_DBG("DAV", "MKCOL %s", path.c_str());

  if (isProtectedPath(path, xtinct::file_transfer::PathIntent::CreateLeaf)) {
    s.send(403, "text/plain", "Forbidden");
    return;
  }

  // MKCOL must not have a body (RFC 4918)
  if (s.clientContentLength() > 0) {
    s.send(415, "text/plain", "Unsupported Media Type");
    return;
  }

  if (Storage.exists(path.c_str())) {
    s.send(405, "text/plain", "Already exists");
    return;
  }

  // Check parent exists
  int lastSlash = path.lastIndexOf('/');
  if (lastSlash > 0) {
    String parentPath = path.substring(0, lastSlash);
    if (!parentPath.isEmpty() && !Storage.exists(parentPath.c_str())) {
      s.send(409, "text/plain", "Parent directory does not exist");
      return;
    }
  }

  if (Storage.mkdir(path.c_str())) {
    s.send(201);
    LOG_DBG("DAV", "Created directory: %s", path.c_str());
  } else {
    s.send(500, "text/plain", "Failed to create directory");
  }
}

// ── MOVE ─────────────────────────────────────────────────────────────────────

void WebDAVHandler::handleMove(WebServer& s) {
  String srcPath = getRequestPath(s);
  String dstPath = getDestinationPath(s);
  bool overwrite = getOverwrite(s);

  LOG_DBG("DAV", "MOVE %s -> %s (overwrite=%d)", srcPath.c_str(), dstPath.c_str(), overwrite);

  if (srcPath == "/" || srcPath.isEmpty()) {
    s.send(403, "text/plain", "Cannot move root");
    return;
  }

  if (dstPath.isEmpty()) {
    s.send(400, "text/plain", "Missing Destination header");
    return;
  }

  if (isProtectedPath(srcPath, xtinct::file_transfer::PathIntent::Existing) ||
      isProtectedPath(dstPath, xtinct::file_transfer::PathIntent::CreateLeaf)) {
    s.send(403, "text/plain", "Forbidden");
    return;
  }

  if (srcPath == dstPath) {
    s.send(204);
    return;
  }

  if (!Storage.exists(srcPath.c_str())) {
    s.send(404, "text/plain", "Source not found");
    return;
  }

  // Check destination parent exists
  int lastSlash = dstPath.lastIndexOf('/');
  if (lastSlash > 0) {
    String parentPath = dstPath.substring(0, lastSlash);
    if (!parentPath.isEmpty() && !Storage.exists(parentPath.c_str())) {
      s.send(409, "text/plain", "Destination parent does not exist");
      return;
    }
  }

  const bool dstExists = Storage.exists(dstPath.c_str());
  if (dstExists && !overwrite) {
    s.send(412, "text/plain", "Destination exists and Overwrite is F");
    return;
  }

  HalFile source = Storage.open(srcPath.c_str());
  if (!source) {
    s.send(500, "text/plain", "Failed to open source");
    return;
  }
  source.close();

  if (dstExists) {
    HalFile destination = Storage.open(dstPath.c_str());
    if (!destination || destination.isDirectory()) {
      if (destination) destination.close();
      s.send(409, "text/plain", "Cannot overwrite a directory");
      return;
    }
    destination.close();
  }

  String backupPath;
  if (dstExists && !makeUniqueDavSibling(dstPath, "old", backupPath)) {
    s.send(500, "text/plain", "Move backup allocation failed");
    return;
  }
  HalRenameOps ops;
  const auto moved = xtinct::file_transfer::promotePrepared(
      ops, srcPath.c_str(), dstPath.c_str(), backupPath.isEmpty() ? nullptr : backupPath.c_str(), dstExists);

  if (xtinct::file_transfer::isCommitted(moved)) {
    clearBookCache(srcPath.c_str());
    if (moved == xtinct::file_transfer::ReplaceResult::CommittedBackupRetained) {
      LOG_ERR("DAV", "MOVE committed but old-file backup cleanup failed: %s", backupPath.c_str());
    }
    s.send(dstExists ? 204 : 201);
  } else {
    if (moved == xtinct::file_transfer::ReplaceResult::RestoreFailed) {
      LOG_ERR("DAV", "MOVE failed and destination restore failed; preserved backup=%s", backupPath.c_str());
    }
    s.send(500, "text/plain", "Move failed");
  }
}

// ── COPY ─────────────────────────────────────────────────────────────────────

void WebDAVHandler::handleCopy(WebServer& s) {
  String srcPath = getRequestPath(s);
  String dstPath = getDestinationPath(s);
  bool overwrite = getOverwrite(s);

  LOG_DBG("DAV", "COPY %s -> %s (overwrite=%d)", srcPath.c_str(), dstPath.c_str(), overwrite);

  if (dstPath.isEmpty()) {
    s.send(400, "text/plain", "Missing Destination header");
    return;
  }

  if (isProtectedPath(srcPath, xtinct::file_transfer::PathIntent::Existing) ||
      isProtectedPath(dstPath, xtinct::file_transfer::PathIntent::CreateLeaf)) {
    s.send(403, "text/plain", "Forbidden");
    return;
  }

  if (srcPath == dstPath) {
    s.send(204);
    return;
  }

  if (!Storage.exists(srcPath.c_str())) {
    s.send(404, "text/plain", "Source not found");
    return;
  }

  HalFile srcFile = Storage.open(srcPath.c_str());
  if (!srcFile) {
    s.send(500, "text/plain", "Failed to open source");
    return;
  }

  if (srcFile.isDirectory()) {
    srcFile.close();
    s.send(403, "text/plain", "Cannot copy directories");
    return;
  }

  // Check destination parent exists
  int lastSlash = dstPath.lastIndexOf('/');
  if (lastSlash > 0) {
    String parentPath = dstPath.substring(0, lastSlash);
    if (!parentPath.isEmpty() && !Storage.exists(parentPath.c_str())) {
      srcFile.close();
      s.send(409, "text/plain", "Destination parent does not exist");
      return;
    }
  }

  const bool dstExists = Storage.exists(dstPath.c_str());
  if (dstExists && !overwrite) {
    srcFile.close();
    s.send(412, "text/plain", "Destination exists and Overwrite is F");
    return;
  }

  if (dstExists) {
    HalFile destination = Storage.open(dstPath.c_str());
    if (!destination || destination.isDirectory()) {
      if (destination) destination.close();
      srcFile.close();
      s.send(409, "text/plain", "Cannot overwrite a directory");
      return;
    }
    destination.close();
  }

  String tempPath;
  if (!makeUniqueDavSibling(dstPath, "copy", tempPath)) {
    srcFile.close();
    s.send(500, "text/plain", "Copy temp allocation failed");
    return;
  }
  HalFile dstFile;
  bool ownsTemp = true;
  const bool opened = Storage.openFileForWrite("DAV", tempPath, dstFile);
  const bool existenceVerified = Storage.exists(tempPath.c_str());
  if (!opened || !existenceVerified) {
    if (dstFile) dstFile.close();
    srcFile.close();
    removeOwnedDavPath(tempPath);
    s.send(500, "text/plain", "Failed to create destination");
    return;
  }

  const uint64_t expectedBytes = srcFile.fileSize64();
  uint8_t buf[4096];
  DavCopySource source{srcFile};
  DavCopyDestination destination{dstFile};
  bool copyOk = xtinct::file_transfer::copyExactly(source, destination, expectedBytes, buf, sizeof(buf));
  const bool sourceCloseOk = srcFile.close();
  const bool destinationCloseOk = dstFile.close();
  copyOk = copyOk && sourceCloseOk && destinationCloseOk;
  if (!copyOk) {
    removeOwnedDavPath(tempPath);
    s.send(500, "text/plain", "Copy failed - read, write or flush error");
    return;
  }

  String backupPath;
  if (dstExists && !makeUniqueDavSibling(dstPath, "old", backupPath)) {
    removeOwnedDavPath(tempPath);
    s.send(500, "text/plain", "Copy backup allocation failed");
    return;
  }
  HalRenameOps ops;
  const auto promoted = xtinct::file_transfer::promotePrepared(
      ops, tempPath.c_str(), dstPath.c_str(), backupPath.isEmpty() ? nullptr : backupPath.c_str(), dstExists);
  if (xtinct::file_transfer::isCommitted(promoted)) {
    ownsTemp = false;
    tempPath = "";
    if (promoted == xtinct::file_transfer::ReplaceResult::CommittedBackupRetained) {
      LOG_ERR("DAV", "COPY committed but old-file backup cleanup failed: %s", backupPath.c_str());
    }
    s.send(dstExists ? 204 : 201);
  } else {
    if (ownsTemp) removeOwnedDavPath(tempPath);
    if (promoted == xtinct::file_transfer::ReplaceResult::RestoreFailed) {
      LOG_ERR("DAV", "COPY promote failed and destination restore failed; preserved backup=%s", backupPath.c_str());
    }
    s.send(500, "text/plain", "Copy promotion failed");
  }
}

// ── LOCK / UNLOCK (dummy for client compatibility) ───────────────────────────

void WebDAVHandler::handleLock(WebServer& s) {
  String path = getRequestPath(s);
  LOG_DBG("DAV", "LOCK %s (dummy)", path.c_str());

  // Return a dummy lock token for client compatibility
  String xml =
      "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
      "<D:prop xmlns:D=\"DAV:\">\n"
      "<D:lockdiscovery><D:activelock>\n"
      "<D:locktype><D:write/></D:locktype>\n"
      "<D:lockscope><D:exclusive/></D:lockscope>\n"
      "<D:depth>infinity</D:depth>\n"
      "<D:owner><D:href>crosspoint</D:href></D:owner>\n"
      "<D:timeout>Second-3600</D:timeout>\n"
      "<D:locktoken><D:href>urn:uuid:dummy-lock-token</D:href></D:locktoken>\n"
      "<D:lockroot><D:href>/</D:href></D:lockroot>\n"
      "</D:activelock></D:lockdiscovery>\n"
      "</D:prop>\n";

  s.sendHeader("Lock-Token", "<urn:uuid:dummy-lock-token>");
  s.send(200, "application/xml; charset=\"utf-8\"", xml);
}

void WebDAVHandler::handleUnlock(WebServer& s) {
  LOG_DBG("DAV", "UNLOCK %s (dummy)", s.uri().c_str());
  s.send(204);
}

// ── Utility functions ────────────────────────────────────────────────────────

String WebDAVHandler::getRequestPath(WebServer& s) const {
  const String& uri = s.uri();
  String result;
  return xtinct::file_transfer::normalizeTransferPath(uri, result) ? result : String();
}

String WebDAVHandler::getDestinationPath(WebServer& s) const {
  String dest = s.header("Destination");
  if (dest.isEmpty() || dest.length() > xtinct::file_transfer::MAX_PATH_BYTES + 128) return "";

  // Extract path from full URL: http://host/path -> /path
  // Find the third slash (after http://)
  int schemeEnd = dest.indexOf("://");
  if (schemeEnd >= 0) {
    int pathStart = dest.indexOf('/', schemeEnd + 3);
    if (pathStart >= 0) {
      dest = dest.substring(pathStart);
    } else {
      dest = "/";
    }
  }

  String result;
  return xtinct::file_transfer::normalizeTransferPath(dest, result) ? result : String();
}

void WebDAVHandler::urlEncodePath(const String& path, String& out) const {
  out = "";
  for (unsigned int i = 0; i < path.length(); i++) {
    char c = path.charAt(i);
    if (c == '/') {
      out += '/';
    } else if (c == ' ') {
      out += "%20";
    } else if (c == '%') {
      out += "%25";
    } else if (c == '#') {
      out += "%23";
    } else if (c == '?') {
      out += "%3F";
    } else if (c == '&') {
      out += "%26";
    } else if ((uint8_t)c > 127) {
      // Encode non-ASCII bytes
      char hex[4];
      snprintf(hex, sizeof(hex), "%%%02X", (uint8_t)c);
      out += hex;
    } else {
      out += c;
    }
  }
}

bool WebDAVHandler::isProtectedPath(const String& path, const xtinct::file_transfer::PathIntent intent) const {
  return xtinct::file_transfer::checkTransferPath(path, intent) !=
         xtinct::file_transfer::PathDecision::Allowed;
}

int WebDAVHandler::getDepth(WebServer& s) const {
  String depth = s.header("Depth");
  if (depth == "0") return 0;
  if (depth == "1") return 1;
  // "infinity" or missing → treat as 1 (Class 1 servers don't need to support infinity)
  return 1;
}

bool WebDAVHandler::getOverwrite(WebServer& s) const {
  String ow = s.header("Overwrite");
  if (ow == "F" || ow == "f") return false;
  return true;  // Default is T
}

String WebDAVHandler::getMimeType(const String& path) const {
  if (FsHelpers::hasEpubExtension(path)) return "application/epub+zip";
  if (FsHelpers::checkFileExtension(path, ".pdf")) return "application/pdf";
  if (FsHelpers::hasTxtExtension(path)) return "text/plain";
  if (FsHelpers::checkFileExtension(path, ".html") || FsHelpers::checkFileExtension(path, ".htm")) return "text/html";
  if (FsHelpers::checkFileExtension(path, ".css")) return "text/css";
  if (FsHelpers::checkFileExtension(path, ".js")) return "application/javascript";
  if (FsHelpers::checkFileExtension(path, ".json")) return "application/json";
  if (FsHelpers::checkFileExtension(path, ".xml")) return "application/xml";
  if (FsHelpers::hasJpgExtension(path)) return "image/jpeg";
  if (FsHelpers::hasPngExtension(path)) return "image/png";
  if (FsHelpers::hasGifExtension(path)) return "image/gif";
  if (FsHelpers::checkFileExtension(path, ".svg")) return "image/svg+xml";
  if (FsHelpers::checkFileExtension(path, ".zip")) return "application/zip";
  if (FsHelpers::checkFileExtension(path, ".gz")) return "application/gzip";
  return "application/octet-stream";
}
