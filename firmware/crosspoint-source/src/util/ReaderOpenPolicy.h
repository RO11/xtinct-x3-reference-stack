#pragma once

#include <string_view>

namespace xtinct::reader_open_policy {

// The end-of-book screen is an in-session state. Current firmware never writes
// a progress record with spine == spineCount, so that value (or anything larger)
// is legacy/corrupt state and must not strand a reopened book on the end screen.
constexpr bool savedSpineNeedsReset(const int savedSpine, const int spineCount) {
  return spineCount > 0 && (savedSpine < 0 || savedSpine >= spineCount);
}

constexpr int normalizeSavedSpine(const int savedSpine, const int spineCount) {
  return savedSpineNeedsReset(savedSpine, spineCount) ? 0 : savedSpine;
}

// XTINCT Inbox artifacts are content-addressed. Their filenames are SHA-256
// storage identities, not titles, and the directory also mixes EPUBs with
// cards/actions stored as .txt. Raw sibling suggestions would therefore expose
// hashes and recommend semantically unrelated content.
constexpr bool allowSiblingBookSuggestions(const std::string_view currentBookPath) {
  constexpr std::string_view managedArtifacts = "/.crosspoint/xtinct-v2/artifacts/";
  return currentBookPath.size() < managedArtifacts.size() ||
         currentBookPath.substr(0, managedArtifacts.size()) != managedArtifacts;
}

}  // namespace xtinct::reader_open_policy
