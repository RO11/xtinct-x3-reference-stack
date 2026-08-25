#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace xtinct::report_cache {

inline constexpr char DIRECTORY[] = "/.crosspoint/xtinct/reports";
inline constexpr const char* TASK_IDS[] = {
    "market-briefing",
    "weekday-freelancer-scan",
    "3d-job-search",
    "outlook-attention-watch",
};
inline constexpr size_t TASK_COUNT = sizeof(TASK_IDS) / sizeof(TASK_IDS[0]);
inline constexpr size_t REVISION_LENGTH = 32;

enum class FileKind : uint8_t { FINAL, TEMP, BACKUP };

struct ManagedFile {
  uint8_t taskIndex = 0;
  char revision[REVISION_LENGTH + 1] = {0};
  FileKind kind = FileKind::FINAL;
};

inline bool isLowerHexRevision(const char* revision) {
  if (!revision || strlen(revision) != REVISION_LENGTH) return false;
  for (size_t i = 0; i < REVISION_LENGTH; ++i) {
    const char value = revision[i];
    if (!((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'))) return false;
  }
  return true;
}

// Parse only filenames created by XTINCT itself. Directory components,
// unknown tasks, uppercase/truncated revisions and extra suffixes all fail.
inline bool parseManagedFilename(const char* name, ManagedFile& out) {
  if (!name || name[0] == '\0') return false;
  const size_t nameLength = strlen(name);
  for (size_t taskIndex = 0; taskIndex < TASK_COUNT; ++taskIndex) {
    const size_t taskLength = strlen(TASK_IDS[taskIndex]);
    constexpr size_t FINAL_SUFFIX_LENGTH = 4;  // .txt
    constexpr size_t SIDECAR_SUFFIX_LENGTH = 4;  // .tmp or .bak
    const size_t finalLength = taskLength + 1 + REVISION_LENGTH + FINAL_SUFFIX_LENGTH;
    if (nameLength != finalLength && nameLength != finalLength + SIDECAR_SUFFIX_LENGTH) continue;
    if (strncmp(name, TASK_IDS[taskIndex], taskLength) != 0 || name[taskLength] != '-') continue;

    const char* revisionStart = name + taskLength + 1;
    bool lowerHex = true;
    for (size_t i = 0; i < REVISION_LENGTH; ++i) {
      const char value = revisionStart[i];
      if (!((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'))) {
        lowerHex = false;
        break;
      }
    }
    if (!lowerHex || strncmp(revisionStart + REVISION_LENGTH, ".txt", FINAL_SUFFIX_LENGTH) != 0) continue;

    FileKind kind = FileKind::FINAL;
    if (nameLength != finalLength) {
      const char* sidecar = revisionStart + REVISION_LENGTH + FINAL_SUFFIX_LENGTH;
      if (strcmp(sidecar, ".tmp") == 0) {
        kind = FileKind::TEMP;
      } else if (strcmp(sidecar, ".bak") == 0) {
        kind = FileKind::BACKUP;
      } else {
        continue;
      }
    }

    out = {};
    out.taskIndex = static_cast<uint8_t>(taskIndex);
    memcpy(out.revision, revisionStart, REVISION_LENGTH);
    out.revision[REVISION_LENGTH] = '\0';
    out.kind = kind;
    return true;
  }
  return false;
}

// Build paths exclusively from an allowlisted task index, a strict revision
// and a fixed suffix. The enumerated/raw filename is never used as a path.
inline bool buildPath(const ManagedFile& file, char* output, const size_t outputSize) {
  if (!output || outputSize == 0 || file.taskIndex >= TASK_COUNT || !isLowerHexRevision(file.revision)) return false;
  const char* suffix = "";
  if (file.kind == FileKind::TEMP) {
    suffix = ".tmp";
  } else if (file.kind == FileKind::BACKUP) {
    suffix = ".bak";
  } else if (file.kind != FileKind::FINAL) {
    return false;
  }
  const int written = snprintf(output, outputSize, "%s/%s-%s.txt%s", DIRECTORY, TASK_IDS[file.taskIndex],
                               file.revision, suffix);
  return written > 0 && written < static_cast<int>(outputSize);
}

inline bool buildFinalPath(const char* taskId, const char* revision, char* output, const size_t outputSize) {
  if (!taskId || !isLowerHexRevision(revision)) return false;
  for (size_t taskIndex = 0; taskIndex < TASK_COUNT; ++taskIndex) {
    if (strcmp(taskId, TASK_IDS[taskIndex]) != 0) continue;
    ManagedFile file;
    file.taskIndex = static_cast<uint8_t>(taskIndex);
    memcpy(file.revision, revision, REVISION_LENGTH + 1);
    return buildPath(file, output, outputSize);
  }
  return false;
}

}  // namespace xtinct::report_cache
