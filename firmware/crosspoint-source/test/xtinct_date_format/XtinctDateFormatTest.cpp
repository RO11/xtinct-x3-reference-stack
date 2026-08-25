#include <gtest/gtest.h>

#include <cstring>

#include "src/util/XtinctDateFormat.h"

TEST(XtinctDateFormat, UsesDayMonthNameYear) {
  char output[32];
  ASSERT_TRUE(xtinct::formatGeneratedDate("2026-08-06T04:15:00+10:00", output, sizeof(output)));
  EXPECT_STREQ(output, "6 August 2026");
}

TEST(XtinctDateFormat, AcceptsLeapDay) {
  char output[32];
  ASSERT_TRUE(xtinct::formatGeneratedDate("2028-02-29T00:00:00Z", output, sizeof(output)));
  EXPECT_STREQ(output, "29 February 2028");
}

TEST(XtinctDateFormat, RejectsInvalidOrIncompleteDates) {
  char output[32];
  EXPECT_FALSE(xtinct::formatGeneratedDate("2026-02-29T00:00:00Z", output, sizeof(output)));
  EXPECT_FALSE(xtinct::formatGeneratedDate("2026-13-01T00:00:00Z", output, sizeof(output)));
  EXPECT_FALSE(xtinct::formatGeneratedDate("2026-04-31T00:00:00Z", output, sizeof(output)));
  EXPECT_FALSE(xtinct::formatGeneratedDate("2026-08-06", output, sizeof(output)));
}

TEST(XtinctDateFormat, RejectsTooSmallOutputBuffer) {
  char output[8];
  EXPECT_FALSE(xtinct::formatGeneratedDate("2026-08-06T04:15:00+10:00", output, sizeof(output)));
}
