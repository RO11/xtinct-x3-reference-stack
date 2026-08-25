#include <gtest/gtest.h>

#include <cstring>

#include "src/util/XtinctReportCacheNaming.h"

namespace {
constexpr char REVISION[] = "0123456789abcdef0123456789abcdef";
}

TEST(XtinctReportCacheNaming, AcceptsOnlyManagedFinalAndSidecars) {
  xtinct::report_cache::ManagedFile file;
  ASSERT_TRUE(xtinct::report_cache::parseManagedFilename(
      "market-briefing-0123456789abcdef0123456789abcdef.txt", file));
  EXPECT_EQ(file.kind, xtinct::report_cache::FileKind::FINAL);
  EXPECT_STREQ(file.revision, REVISION);

  ASSERT_TRUE(xtinct::report_cache::parseManagedFilename(
      "weekday-freelancer-scan-0123456789abcdef0123456789abcdef.txt.tmp", file));
  EXPECT_EQ(file.kind, xtinct::report_cache::FileKind::TEMP);

  ASSERT_TRUE(xtinct::report_cache::parseManagedFilename(
      "outlook-attention-watch-0123456789abcdef0123456789abcdef.txt.bak", file));
  EXPECT_EQ(file.kind, xtinct::report_cache::FileKind::BACKUP);
}

TEST(XtinctReportCacheNaming, RejectsTraversalUnknownAndMalformedNames) {
  xtinct::report_cache::ManagedFile file;
  EXPECT_FALSE(xtinct::report_cache::parseManagedFilename(
      "../market-briefing-0123456789abcdef0123456789abcdef.txt", file));
  EXPECT_FALSE(xtinct::report_cache::parseManagedFilename(
      "market-briefing-0123456789abcdef0123456789abcdef.txt/escape", file));
  EXPECT_FALSE(xtinct::report_cache::parseManagedFilename(
      "unknown-0123456789abcdef0123456789abcdef.txt", file));
  EXPECT_FALSE(xtinct::report_cache::parseManagedFilename(
      "market-briefing-0123456789ABCDEF0123456789ABCDEF.txt", file));
  EXPECT_FALSE(xtinct::report_cache::parseManagedFilename(
      "market-briefing-0123456789abcdef0123456789abcde.txt", file));
  EXPECT_FALSE(xtinct::report_cache::parseManagedFilename(
      "market-briefing-0123456789abcdef0123456789abcdef.txt.old", file));
}

TEST(XtinctReportCacheNaming, BuildsOnlyFixedDirectoryPaths) {
  xtinct::report_cache::ManagedFile file;
  ASSERT_TRUE(xtinct::report_cache::parseManagedFilename(
      "3d-job-search-0123456789abcdef0123456789abcdef.txt.tmp", file));
  char path[160];
  ASSERT_TRUE(xtinct::report_cache::buildPath(file, path, sizeof(path)));
  EXPECT_STREQ(path, "/.crosspoint/xtinct/reports/3d-job-search-0123456789abcdef0123456789abcdef.txt.tmp");

  file.taskIndex = 255;
  EXPECT_FALSE(xtinct::report_cache::buildPath(file, path, sizeof(path)));

  file.taskIndex = 0;
  file.kind = static_cast<xtinct::report_cache::FileKind>(255);
  EXPECT_FALSE(xtinct::report_cache::buildPath(file, path, sizeof(path)));
}
