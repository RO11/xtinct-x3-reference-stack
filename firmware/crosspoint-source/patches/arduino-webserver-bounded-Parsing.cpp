/*
  Parsing.cpp - HTTP request parsing.

  Copyright (c) 2015 Ivan Grokhotkov. All rights reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
  Modified 8 May 2015 by Hristo Gochkov (proper post and file upload handling)
*/

#include <Arduino.h>
#include <esp32-hal-log.h>
#include "NetworkServer.h"
#include "NetworkClient.h"
#include "WebServer.h"
#include "detail/mimetable.h"

#include <algorithm>
#include <climits>
#include <cstring>
#include <new>
#include <utility>

#ifndef WEBSERVER_MAX_POST_ARGS
#define WEBSERVER_MAX_POST_ARGS 32
#endif

#define __STR(a) #a
#define _STR(a)  __STR(a)
static const char *_http_method_str[] = {
#define XX(num, name, string) _STR(string),
  HTTP_METHOD_MAP(XX)
#undef XX
};

static const char Content_Type[] PROGMEM = "Content-Type";
static const char filename[] PROGMEM = "filename";

namespace {
constexpr size_t XTINCT_HTTP_REQUEST_LINE_BYTES = 1024;
constexpr size_t XTINCT_HTTP_TARGET_BYTES = 768;
constexpr size_t XTINCT_HTTP_HEADER_LINE_BYTES = 1024;
constexpr size_t XTINCT_HTTP_HEADER_COUNT = 32;
constexpr size_t XTINCT_HTTP_QUERY_BYTES = 4096;
constexpr size_t XTINCT_HTTP_QUERY_ARGS = 32;
constexpr size_t XTINCT_HTTP_PLAIN_BODY_BYTES = 64U * 1024U;
constexpr size_t XTINCT_HTTP_FORM_FIELD_BYTES = 4096;
constexpr size_t XTINCT_HTTP_FORM_FIELD_WIRE_BYTES = 8192;
constexpr size_t XTINCT_HTTP_FORM_RETAINED_BYTES = 8192;
constexpr size_t XTINCT_HTTP_BOUNDARY_BYTES = 128;

bool xtinctBytesEqual(const String &value, const char *expected, const size_t length) {
  if (!expected || value.length() != length) return false;
  return length == 0U || memcmp(value.c_str(), expected, length) == 0;
}

bool xtinctAssignExact(String &destination, const char *source, const size_t length) {
  if (!source || length > static_cast<size_t>(UINT_MAX - 1U)) return false;
  destination.clear();
  if (!destination.reserve(static_cast<unsigned int>(length + 1U))) return false;
  if (length != 0U && !destination.concat(source, static_cast<unsigned int>(length))) {
    destination.clear();
    return false;
  }
  if (!xtinctBytesEqual(destination, source, length)) {
    destination.clear();
    return false;
  }
  return true;
}

bool xtinctAssignExact(String &destination, const char *source) {
  return source && xtinctAssignExact(destination, source, strlen(source));
}

bool xtinctAssignExact(String &destination, const String &source) {
  return xtinctAssignExact(destination, source.c_str(), source.length());
}

bool xtinctAssignSlice(String &destination, const String &source, size_t begin, size_t end) {
  if (begin > end || end > source.length()) return false;
  return xtinctAssignExact(destination, source.c_str() + begin, end - begin);
}

bool xtinctAssignTrimmedSlice(String &destination, const String &source, size_t begin, size_t end) {
  if (begin > end || end > source.length()) return false;
  while (begin < end && (source.charAt(begin) == ' ' || source.charAt(begin) == '\t')) ++begin;
  while (end > begin && (source.charAt(end - 1U) == ' ' || source.charAt(end - 1U) == '\t')) --end;
  return xtinctAssignSlice(destination, source, begin, end);
}

bool xtinctAppendExact(String &destination, const char *source, const size_t length) {
  if (!source || length > static_cast<size_t>(UINT_MAX - 1U)) return false;
  const size_t originalLength = destination.length();
  if (originalLength > static_cast<size_t>(UINT_MAX - 1U) - length) return false;
  if (!destination.reserve(static_cast<unsigned int>(originalLength + length + 1U))) return false;
  if (length != 0U && !destination.concat(source, static_cast<unsigned int>(length))) return false;
  return destination.length() == originalLength + length &&
         (length == 0U || memcmp(destination.c_str() + originalLength, source, length) == 0);
}

bool xtinctAppendExact(String &destination, const String &source) {
  return xtinctAppendExact(destination, source.c_str(), source.length());
}

bool xtinctAppendExact(String &destination, const char value) {
  return xtinctAppendExact(destination, &value, 1U);
}

uint32_t xtinctStringHash(const String &value) {
  uint32_t hash = 2166136261U;
  for (size_t index = 0; index < value.length(); ++index) {
    hash ^= static_cast<uint8_t>(value.charAt(index));
    hash *= 16777619U;
  }
  return hash;
}

bool xtinctMoveExact(String &destination, String &source) {
  const size_t expectedLength = source.length();
  const uint32_t expectedHash = xtinctStringHash(source);
  destination = std::move(source);
  return destination.length() == expectedLength && xtinctStringHash(destination) == expectedHash;
}

char xtinctAsciiLower(const char value) {
  return value >= 'A' && value <= 'Z' ? static_cast<char>(value + ('a' - 'A')) : value;
}

bool xtinctStartsWithIgnoreCase(const String &value, const char *prefix) {
  if (!prefix) return false;
  const size_t length = strlen(prefix);
  if (value.length() < length) return false;
  for (size_t index = 0; index < length; ++index) {
    if (xtinctAsciiLower(value.charAt(index)) != xtinctAsciiLower(prefix[index])) return false;
  }
  return true;
}

bool xtinctIsHexDigit(const char value) {
  return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') ||
         (value >= 'A' && value <= 'F');
}
uint8_t xtinctHexValue(const char value) {
  return value >= '0' && value <= '9' ? static_cast<uint8_t>(value - '0')
         : value >= 'a' && value <= 'f' ? static_cast<uint8_t>(10 + value - 'a')
                                        : static_cast<uint8_t>(10 + value - 'A');
}

bool xtinctValidHeaderName(const String &name) {
  if (name.isEmpty()) return false;
  for (size_t index = 0; index < name.length(); ++index) {
    const uint8_t value = static_cast<uint8_t>(name.charAt(index));
    if ((value >= '0' && value <= '9') || (value >= 'A' && value <= 'Z') ||
        (value >= 'a' && value <= 'z')) continue;
    switch (value) {
      case '!':
      case '#':
      case '$':
      case '%':
      case '&':
      case '\'':
      case '*':
      case '+':
      case '-':
      case '.':
      case '^':
      case '_':
      case '`':
      case '|':
      case '~':
        break;
      default:
        return false;
    }
  }
  return true;
}

template <size_t Capacity>
bool xtinctReadBoundedLine(NetworkClient &client, String &line, const bool allowTab = false,
                           size_t *consumed = nullptr, const size_t limit = 0) {
  char buffer[Capacity];
  size_t count = 0;
  size_t readTotal = consumed ? *consumed : 0U;
  if (consumed && readTotal > limit) return false;
  while (true) {
    if (consumed && readTotal >= limit) return false;
    char byte = 0;
    if (client.readBytes(&byte, 1) != 1) return false;
    ++readTotal;
    if (byte == '\r') {
      if (consumed && readTotal >= limit) return false;
      char terminator = 0;
      if (client.readBytes(&terminator, 1) != 1 || terminator != '\n') return false;
      ++readTotal;
      break;
    }
    const uint8_t value = static_cast<uint8_t>(byte);
    if (value == 0 || value == 0x7fU ||
        (value < 0x20U && !(allowTab && value == '\t')) || count >= Capacity) return false;
    buffer[count++] = byte;
  }
  if (consumed) *consumed = readTotal;
  return xtinctAssignExact(line, buffer, count);
}

bool xtinctValidArgumentData(const String &data, const size_t maximumBytes = XTINCT_HTTP_QUERY_BYTES) {
  if (data.length() > maximumBytes) return false;
  size_t arguments = data.isEmpty() ? 0U : 1U;
  for (size_t index = 0; index < data.length(); ++index) {
    const uint8_t byte = static_cast<uint8_t>(data.charAt(index));
    if (byte == 0 || byte == 0x7fU || byte < 0x20U) return false;
    if (byte == '&' && ++arguments > XTINCT_HTTP_QUERY_ARGS) return false;
    if (byte != '%') continue;
    if (index + 2U >= data.length() || !xtinctIsHexDigit(data.charAt(index + 1U)) ||
        !xtinctIsHexDigit(data.charAt(index + 2U))) return false;
    const uint8_t decoded = static_cast<uint8_t>((xtinctHexValue(data.charAt(index + 1U)) << 4U) |
                                                  xtinctHexValue(data.charAt(index + 2U)));
    if (decoded == 0 || decoded == 0x7fU || decoded < 0x20U) return false;
    index += 2U;
  }
  return arguments <= XTINCT_HTTP_QUERY_ARGS;
}

bool xtinctParseContentLength(const String &value, int &parsed) {
  if (value.isEmpty()) return false;
  uint64_t length = 0;
  for (size_t index = 0; index < value.length(); ++index) {
    const char digit = value.charAt(index);
    if (digit < '0' || digit > '9') return false;
    const uint8_t number = static_cast<uint8_t>(digit - '0');
    if (length > (static_cast<uint64_t>(INT_MAX) - number) / 10U) return false;
    length = length * 10U + number;
  }
  parsed = static_cast<int>(length);
  return true;
}

bool xtinctValidBoundary(const String &candidate, String &boundary) {
  String trimmed;
  if (!xtinctAssignTrimmedSlice(trimmed, candidate, 0U, candidate.length())) return false;
  if (trimmed.length() >= 2U && trimmed.charAt(0) == '"' &&
      trimmed.charAt(trimmed.length() - 1U) == '"') {
    if (!xtinctAssignSlice(boundary, trimmed, 1U, trimmed.length() - 1U)) return false;
  } else if (!xtinctAssignExact(boundary, trimmed)) {
    return false;
  }
  if (boundary.isEmpty() || boundary.length() > XTINCT_HTTP_BOUNDARY_BYTES) return false;
  for (size_t index = 0; index < boundary.length(); ++index) {
    const uint8_t byte = static_cast<uint8_t>(boundary.charAt(index));
    if (byte <= 0x20U || byte >= 0x7fU || byte == '"' || byte == '\\') return false;
  }
  return true;
}

bool xtinctExtractMultipartBoundary(const String &contentType, String &boundary) {
  bool found = false;
  int cursor = contentType.indexOf(';');
  while (cursor >= 0) {
    const int next = contentType.indexOf(';', cursor + 1);
    const size_t parameterEnd = next < 0 ? contentType.length() : static_cast<size_t>(next);
    String parameter;
    if (!xtinctAssignTrimmedSlice(parameter, contentType, static_cast<size_t>(cursor + 1),
                                  parameterEnd)) return false;
    const int equals = parameter.indexOf('=');
    if (parameter.isEmpty() || equals <= 0) return false;
    String name;
    String value;
    if (!xtinctAssignTrimmedSlice(name, parameter, 0U, static_cast<size_t>(equals)) ||
        !xtinctAssignTrimmedSlice(value, parameter, static_cast<size_t>(equals + 1),
                                  parameter.length())) return false;
    if (!xtinctValidHeaderName(name)) return false;
    if (name.equalsIgnoreCase(F("boundary"))) {
      if (found || !xtinctValidBoundary(value, boundary)) return false;
      found = true;
    }
    if (next < 0) break;
    cursor = next;
  }
  return found;
}

bool xtinctExtractMediaType(const String &contentType, String &mediaType) {
  const int delimiter = contentType.indexOf(';');
  const size_t end = delimiter < 0 ? contentType.length() : static_cast<size_t>(delimiter);
  return xtinctAssignTrimmedSlice(mediaType, contentType, 0U, end) && !mediaType.isEmpty();
}

bool xtinctValidParameterValue(const String &parameter, const size_t begin, String &value) {
  if (begin >= parameter.length()) return false;
  String trimmed;
  if (!xtinctAssignTrimmedSlice(trimmed, parameter, begin, parameter.length()) || trimmed.isEmpty()) {
    return false;
  }
  if (trimmed.charAt(0) == '"') {
    if (trimmed.length() < 2U || trimmed.charAt(trimmed.length() - 1U) != '"') return false;
    if (!xtinctAssignSlice(value, trimmed, 1U, trimmed.length() - 1U)) return false;
  } else if (!xtinctAssignExact(value, trimmed)) {
    return false;
  }
  for (size_t index = 0; index < value.length(); ++index) {
    const uint8_t byte = static_cast<uint8_t>(value.charAt(index));
    if (byte < 0x20U || byte >= 0x7fU || byte == '"' || byte == '\\' || byte == ';') return false;
  }
  return true;
}

bool xtinctValidFallbackFilename(const String &value) {
  if (value.isEmpty() || value.length() > 255U) return false;
  for (size_t index = 0; index < value.length(); ++index) {
    const uint8_t byte = static_cast<uint8_t>(value.charAt(index));
    if (byte < 0x20U || byte >= 0x7fU || byte == '"' || byte == '\\' || byte == ';') return false;
  }
  return true;
}

bool xtinctParseContentDisposition(const String &line, String &argName, String &argFilename,
                                   bool &argIsFile) {
  const int divider = line.indexOf(':');
  if (divider <= 0) return false;
  String headerName;
  if (!xtinctAssignSlice(headerName, line, 0U, static_cast<size_t>(divider)) ||
      !xtinctValidHeaderName(headerName) ||
      !headerName.equalsIgnoreCase(F("Content-Disposition"))) return false;
  String value;
  if (!xtinctAssignTrimmedSlice(value, line, static_cast<size_t>(divider + 1), line.length()) ||
      value.isEmpty()) return false;
  const int firstDelimiter = value.indexOf(';');
  if (firstDelimiter < 0) return false;
  String disposition;
  if (!xtinctAssignTrimmedSlice(disposition, value, 0U, static_cast<size_t>(firstDelimiter)) ||
      !disposition.equalsIgnoreCase(F("form-data"))) return false;

  bool sawName = false;
  bool sawFilename = false;
  int cursor = firstDelimiter;
  while (cursor >= 0) {
    const int next = value.indexOf(';', cursor + 1);
    const size_t parameterEnd = next < 0 ? value.length() : static_cast<size_t>(next);
    String parameter;
    if (!xtinctAssignTrimmedSlice(parameter, value, static_cast<size_t>(cursor + 1), parameterEnd) ||
        parameter.isEmpty()) return false;
    const int equals = parameter.indexOf('=');
    if (equals <= 0) return false;
    String parameterName;
    String parameterValue;
    if (!xtinctAssignTrimmedSlice(parameterName, parameter, 0U, static_cast<size_t>(equals)) ||
        !xtinctValidHeaderName(parameterName) ||
        !xtinctValidParameterValue(parameter, static_cast<size_t>(equals + 1), parameterValue)) {
      return false;
    }
    if (parameterName.equalsIgnoreCase(F("name"))) {
      if (sawName || parameterValue.isEmpty() || parameterValue.length() > 255U ||
          !xtinctMoveExact(argName, parameterValue)) return false;
      sawName = true;
    } else if (parameterName.equalsIgnoreCase(F("filename"))) {
      if (sawFilename || parameterValue.length() > 255U ||
          !xtinctMoveExact(argFilename, parameterValue)) return false;
      sawFilename = true;
    }
    if (next < 0) break;
    cursor = next;
  }
  argIsFile = sawFilename;
  return sawName && !argName.isEmpty();
}

bool xtinctUrlDecodeExact(const String &text, String &decoded) {
  if (text.length() >= UINT_MAX || !xtinctAssignExact(decoded, "", 0U) ||
      !decoded.reserve(text.length() + 1U)) return false;
  size_t index = 0;
  while (index < text.length()) {
    char value = text.charAt(index++);
    if (value == '%') {
      if (index + 1U >= text.length() || !xtinctIsHexDigit(text.charAt(index)) ||
          !xtinctIsHexDigit(text.charAt(index + 1U))) return false;
      value = static_cast<char>((xtinctHexValue(text.charAt(index)) << 4U) |
                                xtinctHexValue(text.charAt(index + 1U)));
      index += 2U;
    } else if (value == '+') {
      value = ' ';
    }
    if (!xtinctAppendExact(decoded, value)) return false;
  }
  return decoded.length() <= text.length();
}
}  // namespace

static char *readBytesWithTimeout(NetworkClient &client, size_t maxLength, size_t &dataLength, int timeout_ms) {
  dataLength = 0;
  if (maxLength == 0 || maxLength > XTINCT_HTTP_PLAIN_BODY_BYTES) return nullptr;
  char *buffer = static_cast<char *>(malloc(maxLength + 1U));
  if (!buffer) return nullptr;
  while (dataLength < maxLength) {
    int tries = timeout_ms;
    size_t available = 0;
    while (!(available = client.available()) && tries-- > 0) delay(1);
    if (available == 0) break;
    const size_t request = std::min(available, maxLength - dataLength);
    const size_t received = client.readBytes(buffer + dataLength, request);
    if (received == 0 || received > request) break;
    dataLength += received;
  }
  buffer[dataLength] = '\0';
  return buffer;
}

bool WebServer::_parseRequest(NetworkClient &client) {
  String req;
  if (!xtinctReadBoundedLine<XTINCT_HTTP_REQUEST_LINE_BYTES>(client, req)) {
    log_e("Invalid or oversized request line");
    return false;
  }
  if (_collectAllHeaders) {
    collectAllHeaders();
  } else {
    for (RequestArgument *header = _currentHeaders; header; header = header->next) {
      if (!xtinctAssignExact(header->value, "", 0U)) return false;
    }
  }

  const int addr_start = req.indexOf(' ');
  const int addr_end = req.indexOf(' ', addr_start + 1);
  if (addr_start <= 0 || addr_end <= addr_start + 1 ||
      req.indexOf(' ', addr_end + 1) >= 0 || addr_end + 1 >= static_cast<int>(req.length())) return false;
  String methodStr;
  String url;
  String version;
  if (!xtinctAssignSlice(methodStr, req, 0U, static_cast<size_t>(addr_start)) ||
      !xtinctAssignSlice(url, req, static_cast<size_t>(addr_start + 1), static_cast<size_t>(addr_end)) ||
      !xtinctAssignSlice(version, req, static_cast<size_t>(addr_end + 1), req.length())) return false;
  if (url.isEmpty() || url.length() > XTINCT_HTTP_TARGET_BYTES) return false;
  if (version == F("HTTP/1.0")) {
    _currentVersion = 0;
  } else if (version == F("HTTP/1.1")) {
    _currentVersion = 1;
  } else {
    return false;
  }
  String searchStr;
  const int hasSearch = url.indexOf('?');
  if (hasSearch != -1) {
    String route;
    if (!xtinctAssignSlice(searchStr, url, static_cast<size_t>(hasSearch + 1), url.length()) ||
        !xtinctAssignSlice(route, url, 0U, static_cast<size_t>(hasSearch)) ||
        !xtinctMoveExact(url, route)) return false;
  }
  if (url.isEmpty() || !xtinctValidArgumentData(searchStr) ||
      !xtinctAssignExact(_currentUri, url) || !xtinctAssignExact(_hostHeader, "", 0U)) return false;
  _chunked = false;
  _clientContentLength = 0;

  HTTPMethod method = HTTP_ANY;
  const size_t num_methods = sizeof(_http_method_str) / sizeof(const char *);
  for (size_t index = 0; index < num_methods; ++index) {
    if (methodStr == _http_method_str[index]) {
      method = static_cast<HTTPMethod>(index);
      break;
    }
  }
  if (method == HTTP_ANY) return false;
  _currentMethod = method;
  RequestHandler *handler = nullptr;
  for (handler = _firstHandler; handler; handler = handler->next()) {
    if (handler->canHandle(*this, _currentMethod, _currentUri)) break;
  }
  _currentHandler = handler;

  String boundaryStr;
  bool isForm = false;
  bool isEncoded = false;
  bool sawContentLength = false;
  bool sawContentType = false;
  size_t headerLines = 0;
  while (true) {
    if (!xtinctReadBoundedLine<XTINCT_HTTP_HEADER_LINE_BYTES>(client, req, true)) return false;
    if (req.isEmpty()) break;
    if (++headerLines > XTINCT_HTTP_HEADER_COUNT) return false;
    const int headerDiv = req.indexOf(':');
    if (headerDiv <= 0) return false;
    String headerName;
    String headerValue;
    if (!xtinctAssignSlice(headerName, req, 0U, static_cast<size_t>(headerDiv)) ||
        !xtinctAssignTrimmedSlice(headerValue, req, static_cast<size_t>(headerDiv + 1),
                                  req.length())) return false;
    if (!xtinctValidHeaderName(headerName)) return false;
    bool mustCollect = _collectAllHeaders;
    if (!mustCollect) {
      for (RequestArgument *header = _currentHeaders; header; header = header->next) {
        if (header->key.equalsIgnoreCase(headerName)) {
          mustCollect = true;
          break;
        }
      }
    }
    if (mustCollect && !_collectHeader(headerName.c_str(), headerValue.c_str())) return false;
    if (headerName.equalsIgnoreCase(F("Transfer-Encoding"))) return false;
    if (headerName.equalsIgnoreCase(F("Content-Length"))) {
      if (sawContentLength || !xtinctParseContentLength(headerValue, _clientContentLength)) return false;
      sawContentLength = true;
    } else if (headerName.equalsIgnoreCase(FPSTR(Content_Type))) {
      if (sawContentType) return false;
      sawContentType = true;
      isForm = false;
      isEncoded = false;
      if (!xtinctAssignExact(boundaryStr, "", 0U)) return false;
      String mediaType;
      if (!xtinctExtractMediaType(headerValue, mediaType)) return false;
      if (mediaType.equalsIgnoreCase(F("text/plain"))) {
        // Plain request body.
      } else if (mediaType.equalsIgnoreCase(F("application/x-www-form-urlencoded"))) {
        isEncoded = true;
      } else if (mediaType.equalsIgnoreCase(F("multipart/form-data"))) {
        if (!xtinctExtractMultipartBoundary(headerValue, boundaryStr)) return false;
        isForm = true;
      } else if (xtinctStartsWithIgnoreCase(mediaType, "text/plain") ||
                 xtinctStartsWithIgnoreCase(mediaType, "application/x-www-form-urlencoded") ||
                 xtinctStartsWithIgnoreCase(mediaType, "multipart/")) {
        return false;
      }
    } else if (headerName.equalsIgnoreCase(F("Host"))) {
      if (!xtinctAssignExact(_hostHeader, headerValue)) return false;
    }
  }

  const bool bodyMethod =
      method == HTTP_POST || method == HTTP_PUT || method == HTTP_PATCH || method == HTTP_DELETE;
  if (!bodyMethod) {
    _parseArguments(searchStr);
    if (!_currentArgs) return false;
    client.clear();
    return true;
  }

  if (!isForm && _currentHandler && _currentHandler->canRaw(*this, _currentUri)) {
    _currentRaw.reset(new (std::nothrow) HTTPRaw());
    if (!_currentRaw) return false;
    _currentRaw->status = RAW_START;
    _currentRaw->totalSize = 0;
    _currentRaw->currentSize = 0;
    _currentHandler->raw(*this, _currentUri, *_currentRaw);
    _currentRaw->status = RAW_WRITE;
    while (_currentRaw->totalSize < static_cast<size_t>(_clientContentLength)) {
      const size_t request = std::min(static_cast<size_t>(_clientContentLength) - _currentRaw->totalSize,
                                      static_cast<size_t>(HTTP_RAW_BUFLEN));
      _currentRaw->currentSize = client.readBytes(_currentRaw->buf, request);
      if (_currentRaw->currentSize == 0 || _currentRaw->currentSize > request) {
        _currentRaw->status = RAW_ABORTED;
        _currentHandler->raw(*this, _currentUri, *_currentRaw);
        return false;
      }
      _currentRaw->totalSize += _currentRaw->currentSize;
      _currentHandler->raw(*this, _currentUri, *_currentRaw);
    }
    _currentRaw->status = RAW_END;
    _currentHandler->raw(*this, _currentUri, *_currentRaw);
  } else if (!isForm) {
    if (static_cast<size_t>(_clientContentLength) > XTINCT_HTTP_PLAIN_BODY_BYTES ||
        (isEncoded && static_cast<size_t>(_clientContentLength) > XTINCT_HTTP_FORM_FIELD_BYTES)) return false;
    size_t plainLength = 0;
    char *plainBuf = readBytesWithTimeout(client, static_cast<size_t>(_clientContentLength), plainLength,
                                          HTTP_MAX_POST_WAIT);
    if (plainLength != static_cast<size_t>(_clientContentLength) ||
        (_clientContentLength > 0 && !plainBuf)) {
      free(plainBuf);
      return false;
    }
    if (_clientContentLength > 0) {
      for (size_t index = 0; index < plainLength; ++index) {
        const uint8_t byte = static_cast<uint8_t>(plainBuf[index]);
        if (byte == 0 || byte == 0x7fU || (isEncoded && byte < 0x20U)) {
          free(plainBuf);
          return false;
        }
      }
      if (isEncoded) {
        if ((!searchStr.isEmpty() && !xtinctAppendExact(searchStr, '&')) ||
            !xtinctAppendExact(searchStr, plainBuf, plainLength) ||
            !xtinctValidArgumentData(searchStr)) {
          free(plainBuf);
          return false;
        }
      }
      _parseArguments(searchStr);
      if (!_currentArgs) {
        free(plainBuf);
        return false;
      }
      if (!isEncoded) {
        RequestArgument *expanded =
            new (std::nothrow) RequestArgument[static_cast<size_t>(_currentArgCount) + 2U];
        if (!expanded) {
          free(plainBuf);
          return false;
        }
        bool moved = true;
        for (int index = 0; index < _currentArgCount && moved; ++index) {
          moved = xtinctMoveExact(expanded[index].key, _currentArgs[index].key) &&
                  xtinctMoveExact(expanded[index].value, _currentArgs[index].value);
        }
        if (!moved) {
          delete[] expanded;
          delete[] _currentArgs;
          _currentArgs = nullptr;
          _currentArgCount = 0;
          free(plainBuf);
          return false;
        }
        delete[] _currentArgs;
        _currentArgs = expanded;
        RequestArgument &arg = _currentArgs[_currentArgCount++];
        if (!xtinctAssignExact(arg.key, "plain") ||
            !xtinctAssignExact(arg.value, plainBuf, plainLength)) {
          free(plainBuf);
          delete[] _currentArgs;
          _currentArgs = nullptr;
          _currentArgCount = 0;
          return false;
        }
      }
      free(plainBuf);
    } else {
      _parseArguments(searchStr);
      if (!_currentArgs) return false;
    }
  } else {
    _parseArguments(searchStr);
    if (!_currentArgs || !_parseForm(client, boundaryStr, static_cast<uint32_t>(_clientContentLength))) return false;
  }
  client.clear();
  return true;
}

bool WebServer::_collectHeader(const char *headerName, const char *headerValue) {
  if (!headerName || !headerValue) return false;
  RequestArgument *last = nullptr;
  for (RequestArgument *header = _currentHeaders; header; header = header->next) {
    if (header->next == nullptr) last = header;
    if (header->key.equalsIgnoreCase(headerName)) {
      return xtinctAssignExact(header->value, headerValue);
    }
  }
  if (!last) return false;
  if (_collectAllHeaders) {
    // collectAllHeaders() pre-seeds Authorization and If-None-Match.  They are
    // not wire-header lines and must not reduce the 32-line request limit.
    const int preseededHeaders = 2;
    const int userHeaders = _headerKeysCount - preseededHeaders;
    if (userHeaders < 0 || userHeaders >= static_cast<int>(XTINCT_HTTP_HEADER_COUNT)) return false;
    RequestArgument *next = new (std::nothrow) RequestArgument();
    if (!next) return false;
    if (!xtinctAssignExact(next->key, headerName) ||
        !xtinctAssignExact(next->value, headerValue)) {
      delete next;
      return false;
    }
    last->next = next;
    ++_headerKeysCount;
    return true;
  }
  return false;
}

void WebServer::_parseArguments(const String &data) {
  delete[] _currentArgs;
  _currentArgs = nullptr;
  _currentArgCount = 0;
  if (!xtinctValidArgumentData(data)) return;
  if (data.isEmpty()) {
    _currentArgs = new (std::nothrow) RequestArgument[1];
    return;
  }
  int count = 1;
  for (int index = 0; index < static_cast<int>(data.length());) {
    index = data.indexOf('&', index);
    if (index < 0) break;
    ++index;
    ++count;
  }
  if (count > static_cast<int>(XTINCT_HTTP_QUERY_ARGS)) return;
  _currentArgs = new (std::nothrow) RequestArgument[static_cast<size_t>(count) + 1U];
  if (!_currentArgs) return;
  int position = 0;
  int parsed = 0;
  while (parsed < count) {
    const int equal = data.indexOf('=', position);
    const int next = data.indexOf('&', position);
    if (equal < 0 || (next >= 0 && equal > next)) {
      if (next < 0) break;
      position = next + 1;
      continue;
    }
    RequestArgument &arg = _currentArgs[parsed];
    const size_t valueEnd = next < 0 ? data.length() : static_cast<size_t>(next);
    String encodedKey;
    String encodedValue;
    if (!xtinctAssignSlice(encodedKey, data, static_cast<size_t>(position),
                           static_cast<size_t>(equal)) ||
        !xtinctAssignSlice(encodedValue, data, static_cast<size_t>(equal + 1), valueEnd) ||
        !xtinctUrlDecodeExact(encodedKey, arg.key) ||
        !xtinctUrlDecodeExact(encodedValue, arg.value)) {
      delete[] _currentArgs;
      _currentArgs = nullptr;
      _currentArgCount = 0;
      return;
    }
    bool valid = true;
    for (size_t index = 0; index < arg.key.length(); ++index) {
      const uint8_t byte = static_cast<uint8_t>(arg.key.charAt(index));
      valid = valid && byte >= 0x20U && byte != 0x7fU;
    }
    for (size_t index = 0; index < arg.value.length(); ++index) {
      const uint8_t byte = static_cast<uint8_t>(arg.value.charAt(index));
      valid = valid && byte >= 0x20U && byte != 0x7fU;
    }
    if (!valid) {
      delete[] _currentArgs;
      _currentArgs = nullptr;
      _currentArgCount = 0;
      return;
    }
    ++parsed;
    if (next < 0) break;
    position = next + 1;
  }
  _currentArgCount = parsed;
}

void WebServer::_uploadWriteByte(uint8_t b) {
  if (_currentUpload->currentSize == HTTP_UPLOAD_BUFLEN) {
    if (_currentHandler && _currentHandler->canUpload(*this, _currentUri)) {
      _currentHandler->upload(*this, _currentUri, *_currentUpload);
    }
    _currentUpload->totalSize += _currentUpload->currentSize;
    _currentUpload->currentSize = 0;
  }
  _currentUpload->buf[_currentUpload->currentSize++] = b;
}

int WebServer::_uploadReadByte(NetworkClient &client) {
  int res = client.read();

  if (res < 0) {
    // keep trying until you either read a valid byte or timeout
    const unsigned long startMillis = millis();
    const long timeoutIntervalMillis = client.getTimeout();
    bool timedOut = false;
    for (;;) {
      if (!client.connected()) {
        return -1;
      }
      // loosely modeled after blinkWithoutDelay pattern
      while (!timedOut && !client.available() && client.connected()) {
        delay(2);
        timedOut = (millis() - startMillis) >= timeoutIntervalMillis;
      }

      res = client.read();
      if (res >= 0) {
        return res;  // exit on a valid read
      }
      // NOTE: it is possible to get here and have all of the following
      //       assertions hold true
      //
      //       -- client.available() > 0
      //       -- client.connected == true
      //       -- res == -1
      //
      //       a simple retry strategy overcomes this which is to say the
      //       assertion is not permanent, but the reason that this works
      //       is elusive, and possibly indicative of a more subtle underlying
      //       issue

      timedOut = (millis() - startMillis) >= timeoutIntervalMillis;
      if (timedOut) {
        return res;  // exit on a timeout
      }
    }
  }

  return res;
}

bool WebServer::_parseForm(NetworkClient &client, const String &boundary, uint32_t len) {
  delete[] _postArgs;
  _postArgs = nullptr;
  _postArgsLen = 0;
  _currentUpload.reset();
  bool uploadStarted = false;
  auto fail = [&]() -> bool {
    if (uploadStarted && _currentUpload) {
      _currentUpload->status = UPLOAD_FILE_ABORTED;
      if (_currentHandler && _currentHandler->canUpload(*this, _currentUri)) {
        _currentHandler->upload(*this, _currentUri, *_currentUpload);
      }
      uploadStarted = false;
    }
    delete[] _postArgs;
    _postArgs = nullptr;
    _postArgsLen = 0;
    delete[] _currentArgs;
    _currentArgs = nullptr;
    _currentArgCount = 0;
    _currentUpload.reset();
    return false;
  };
  if (len == 0 || boundary.isEmpty() || boundary.length() > XTINCT_HTTP_BOUNDARY_BYTES) return fail();

  size_t retainedBytes = 0;
  for (int index = 0; index < _currentArgCount; ++index) {
    const size_t entryBytes = _currentArgs[index].key.length() + _currentArgs[index].value.length();
    if (entryBytes > XTINCT_HTTP_FORM_RETAINED_BYTES - retainedBytes) return fail();
    retainedBytes += entryBytes;
  }
  bool argumentsFinalized = false;
  auto finalizeArguments = [&]() -> bool {
    if (argumentsFinalized) return true;
    if (_currentArgCount < 0 || _postArgsLen < 0 ||
        _currentArgCount > WEBSERVER_MAX_POST_ARGS - _postArgsLen) return false;
    const int combinedCount = _currentArgCount + _postArgsLen;
    const size_t allocation = combinedCount == 0 ? 1U : static_cast<size_t>(combinedCount);
    RequestArgument *combined = new (std::nothrow) RequestArgument[allocation];
    if (!combined) return false;
    bool moved = true;
    int destination = 0;
    for (int index = 0; index < _postArgsLen && moved; ++index, ++destination) {
      moved = xtinctMoveExact(combined[destination].key, _postArgs[index].key) &&
              xtinctMoveExact(combined[destination].value, _postArgs[index].value);
    }
    for (int index = 0; index < _currentArgCount && moved; ++index, ++destination) {
      moved = xtinctMoveExact(combined[destination].key, _currentArgs[index].key) &&
              xtinctMoveExact(combined[destination].value, _currentArgs[index].value);
    }
    if (!moved) {
      delete[] combined;
      return false;
    }
    delete[] _currentArgs;
    delete[] _postArgs;
    _currentArgs = combined;
    _currentArgCount = combinedCount;
    _postArgs = nullptr;
    _postArgsLen = 0;
    argumentsFinalized = true;
    return true;
  };

  size_t consumed = 0;
  String line;
  String opening;
  String closing;
  if (!xtinctAssignExact(opening, "--") || !xtinctAppendExact(opening, boundary) ||
      !xtinctAssignExact(closing, opening) || !xtinctAppendExact(closing, "--", 2U) ||
      !xtinctReadBoundedLine<XTINCT_HTTP_HEADER_LINE_BYTES>(client, line, false, &consumed, len) ||
      line != opening) return fail();

  _postArgs = new (std::nothrow) RequestArgument[WEBSERVER_MAX_POST_ARGS];
  if (!_postArgs) return fail();
  bool finished = false;
  while (!finished) {
    if (!xtinctReadBoundedLine<XTINCT_HTTP_HEADER_LINE_BYTES>(client, line, true, &consumed, len) ||
        line.isEmpty()) return fail();

    String argName;
    String argValue;
    using namespace mime;
    String argType;
    String argFilename;
    bool argIsFile = false;
    if (!xtinctAssignExact(argType, FPSTR(mimeTable[txt].mimeType)) ||
        !xtinctParseContentDisposition(line, argName, argFilename, argIsFile)) return fail();
    if (argIsFile && argFilename == F("blob")) {
      for (int index = 0; index < _currentArgCount; ++index) {
        if (_currentArgs[index].key == FPSTR(filename)) {
          if (!xtinctAssignExact(argFilename, _currentArgs[index].value) ||
              !xtinctValidFallbackFilename(argFilename)) return fail();
          break;
        }
      }
    }

    size_t partHeaderCount = 1U;  // Content-Disposition is wire header one.
    bool sawPartContentType = false;
    while (true) {
      if (!xtinctReadBoundedLine<XTINCT_HTTP_HEADER_LINE_BYTES>(
              client, line, true, &consumed, len)) return fail();
      if (line.isEmpty()) break;
      if (++partHeaderCount > XTINCT_HTTP_HEADER_COUNT) return fail();
      const int divider = line.indexOf(':');
      if (divider <= 0) return fail();
      String partHeaderName;
      String partHeaderValue;
      if (!xtinctAssignSlice(partHeaderName, line, 0U, static_cast<size_t>(divider)) ||
          !xtinctAssignTrimmedSlice(partHeaderValue, line, static_cast<size_t>(divider + 1),
                                    line.length()) ||
          !xtinctValidHeaderName(partHeaderName)) return fail();
      if (partHeaderName.equalsIgnoreCase(FPSTR(Content_Type))) {
        if (sawPartContentType || partHeaderValue.isEmpty() || partHeaderValue.length() > 255U ||
            !xtinctMoveExact(argType, partHeaderValue)) return fail();
        sawPartContentType = true;
      }
    }

    if (!argIsFile) {
      const size_t fieldWireStart = consumed;
      bool sawValueLine = false;
      while (true) {
        if (!xtinctReadBoundedLine<XTINCT_HTTP_HEADER_LINE_BYTES>(client, line, true, &consumed, len) ||
            consumed - fieldWireStart > XTINCT_HTTP_FORM_FIELD_WIRE_BYTES) return fail();
        if (line == opening || line == closing) break;
        const size_t separator = sawValueLine ? 1U : 0U;
        if (argValue.length() > XTINCT_HTTP_FORM_FIELD_BYTES ||
            line.length() + separator > XTINCT_HTTP_FORM_FIELD_BYTES - argValue.length() ||
            (separator != 0U && !xtinctAppendExact(argValue, '\n')) ||
            !xtinctAppendExact(argValue, line)) return fail();
        sawValueLine = true;
      }
      const size_t entryBytes = argName.length() + argValue.length();
      if (_postArgsLen >= WEBSERVER_MAX_POST_ARGS ||
          entryBytes > XTINCT_HTTP_FORM_RETAINED_BYTES - retainedBytes ||
          !xtinctMoveExact(_postArgs[_postArgsLen].key, argName) ||
          !xtinctMoveExact(_postArgs[_postArgsLen].value, argValue)) return fail();
      retainedBytes += entryBytes;
      ++_postArgsLen;
      if (line == closing) finished = true;
      continue;
    }

    _currentUpload.reset(new (std::nothrow) HTTPUpload());
    if (!_currentUpload || !xtinctMoveExact(_currentUpload->name, argName) ||
        !xtinctMoveExact(_currentUpload->filename, argFilename) ||
        !xtinctMoveExact(_currentUpload->type, argType)) return fail();
    _currentUpload->status = UPLOAD_FILE_START;
    _currentUpload->totalSize = 0;
    _currentUpload->currentSize = 0;
    if (_currentHandler && _currentHandler->canUpload(*this, _currentUri)) {
      _currentHandler->upload(*this, _currentUri, *_currentUpload);
    }
    uploadStarted = true;
    _currentUpload->status = UPLOAD_FILE_WRITE;

    char fastBoundary[4U + XTINCT_HTTP_BOUNDARY_BYTES + 1U];
    const int fastBoundaryLen = snprintf(fastBoundary, sizeof(fastBoundary), "\r\n--%s", boundary.c_str());
    if (fastBoundaryLen <= 0 || static_cast<size_t>(fastBoundaryLen) >= sizeof(fastBoundary)) {
      return fail();
    }
    size_t boundaryPtr = 0;
    bool foundBoundary = false;
    while (consumed < len) {
      const int ret = _uploadReadByte(client);
      if (ret < 0) return fail();
      ++consumed;
      const char incoming = static_cast<char>(ret);
      if (incoming == fastBoundary[boundaryPtr]) {
        ++boundaryPtr;
        if (boundaryPtr == static_cast<size_t>(fastBoundaryLen)) {
          foundBoundary = true;
          break;
        }
      } else {
        for (size_t index = 0; index < boundaryPtr; ++index) {
          _uploadWriteByte(static_cast<uint8_t>(fastBoundary[index]));
        }
        if (incoming == fastBoundary[0]) {
          boundaryPtr = 1;
        } else {
          _uploadWriteByte(static_cast<uint8_t>(incoming));
          boundaryPtr = 0;
        }
      }
    }
    if (!foundBoundary) return fail();

    if (_currentHandler && _currentHandler->canUpload(*this, _currentUri)) {
      _currentHandler->upload(*this, _currentUri, *_currentUpload);
    }
    if (_currentUpload->totalSize > SIZE_MAX - _currentUpload->currentSize) {
      return fail();
    }
    _currentUpload->totalSize += _currentUpload->currentSize;

    // XTINCT accepts one file per multipart request.  Do not emit END until
    // the closing boundary and the declared Content-Length have both been
    // consumed exactly: the route commits its owned temporary file on END, so
    // accepting a later malformed part would otherwise publish partial input.
    if (!xtinctReadBoundedLine<XTINCT_HTTP_HEADER_LINE_BYTES>(client, line, false, &consumed, len) ||
        line != "--" || consumed != len || !finalizeArguments()) {
      return fail();
    }
    _currentUpload->status = UPLOAD_FILE_END;
    if (_currentHandler && _currentHandler->canUpload(*this, _currentUri)) {
      _currentHandler->upload(*this, _currentUri, *_currentUpload);
    }
    uploadStarted = false;
    finished = true;
  }
  if (consumed != len || !finalizeArguments()) return fail();
  return true;
}

String WebServer::urlDecode(const String &text) {
  String decoded;
  if (!xtinctUrlDecodeExact(text, decoded)) decoded.clear();
  return decoded;
}

bool WebServer::_parseFormUploadAborted() {
  delete[] _postArgs;
  _postArgs = nullptr;
  _postArgsLen = 0;
  _currentUpload.reset();
  return false;
}
