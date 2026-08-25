#pragma once

#include <cstddef>
#include <string>
#include <utility>

namespace xtinct::feed_credential {

constexpr size_t MAX_ORIGIN_LENGTH = 192;
constexpr size_t MIN_TOKEN_LENGTH = 32;
constexpr size_t MAX_TOKEN_LENGTH = 256;
constexpr char RECORD_PREFIX[] = "v1\n";

struct Credential {
  std::string origin;
  std::string token;
};

inline bool isLowerAsciiLetter(const char value) { return value >= 'a' && value <= 'z'; }
inline bool isUpperAsciiLetter(const char value) { return value >= 'A' && value <= 'Z'; }
inline bool isAsciiDigit(const char value) { return value >= '0' && value <= '9'; }

inline std::string canonicalizeOrigin(std::string candidate) {
  while (candidate.size() > 8 && candidate.back() == '/') candidate.pop_back();
  for (char& value : candidate) {
    if (isUpperAsciiLetter(value)) value = static_cast<char>(value - 'A' + 'a');
  }
  return candidate;
}

inline bool isValidToken(const std::string& candidate) {
  if (candidate.size() < MIN_TOKEN_LENGTH || candidate.size() > MAX_TOKEN_LENGTH) return false;
  for (const unsigned char value : candidate) {
    if (value < 0x21 || value > 0x7e) return false;
  }
  return true;
}

inline bool isValidWorkerOrigin(const std::string& candidate) {
  if (candidate.empty() || candidate.size() > MAX_ORIGIN_LENGTH) return false;
  if (candidate.size() > 1 && candidate.back() == '/' && candidate[candidate.size() - 2] == '/') return false;

  const std::string origin = canonicalizeOrigin(candidate);
  constexpr char SCHEME[] = "https://";
  if (origin.rfind(SCHEME, 0) != 0) return false;

  const std::string host = origin.substr(sizeof(SCHEME) - 1);
  constexpr char WORKERS_SUFFIX[] = ".workers.dev";
  constexpr size_t SUFFIX_LENGTH = sizeof(WORKERS_SUFFIX) - 1;
  if (host.size() <= SUFFIX_LENGTH ||
      host.compare(host.size() - SUFFIX_LENGTH, SUFFIX_LENGTH, WORKERS_SUFFIX) != 0) {
    return false;
  }

  const std::string deployment = host.substr(0, host.size() - SUFFIX_LENGTH);
  if (deployment.find('.') == std::string::npos) return false;
  if (host.find_first_of("/@:?#\\%") != std::string::npos || host.find("..") != std::string::npos) return false;

  bool labelStart = true;
  size_t labelLength = 0;
  for (size_t index = 0; index < host.size(); ++index) {
    const char value = host[index];
    if (value == '.') {
      if (labelStart || host[index - 1] == '-' || labelLength > 63) return false;
      labelStart = true;
      labelLength = 0;
      continue;
    }
    if (!isLowerAsciiLetter(value) && !isAsciiDigit(value) && value != '-') return false;
    if (labelStart && value == '-') return false;
    labelStart = false;
    ++labelLength;
  }
  return !labelStart && host.back() != '-' && labelLength <= 63;
}

inline std::string serialize(const std::string& origin, const std::string& token) {
  if (!isValidWorkerOrigin(origin) || !isValidToken(token)) return {};
  return std::string(RECORD_PREFIX) + canonicalizeOrigin(origin) + "\n" + token;
}

inline bool parse(const std::string& record, Credential& output) {
  if (record.rfind(RECORD_PREFIX, 0) != 0) return false;
  const size_t originStart = sizeof(RECORD_PREFIX) - 1;
  const size_t separator = record.find('\n', originStart);
  if (separator == std::string::npos || record.find('\n', separator + 1) != std::string::npos) return false;
  std::string origin = record.substr(originStart, separator - originStart);
  std::string token = record.substr(separator + 1);
  if (canonicalizeOrigin(origin) != origin || !isValidWorkerOrigin(origin) || !isValidToken(token)) return false;
  output = {std::move(origin), std::move(token)};
  return true;
}

}  // namespace xtinct::feed_credential
