#include <gtest/gtest.h>

#include "src/util/ReaderOpenPolicy.h"

namespace policy = xtinct::reader_open_policy;

TEST(ReaderOpenPolicy, KeepsValidSavedSpines) {
  EXPECT_FALSE(policy::savedSpineNeedsReset(0, 5));
  EXPECT_FALSE(policy::savedSpineNeedsReset(4, 5));
  EXPECT_EQ(policy::normalizeSavedSpine(4, 5), 4);
}

TEST(ReaderOpenPolicy, ResetsPersistedEndOrOutOfRangeSpines) {
  EXPECT_TRUE(policy::savedSpineNeedsReset(5, 5));
  EXPECT_TRUE(policy::savedSpineNeedsReset(9, 5));
  EXPECT_TRUE(policy::savedSpineNeedsReset(-1, 5));
  EXPECT_EQ(policy::normalizeSavedSpine(5, 5), 0);
  EXPECT_EQ(policy::normalizeSavedSpine(9, 5), 0);
  EXPECT_EQ(policy::normalizeSavedSpine(-1, 5), 0);
}

TEST(ReaderOpenPolicy, DoesNotMisclassifyAnInvalidEmptyBookAsSavedProgress) {
  EXPECT_FALSE(policy::savedSpineNeedsReset(0, 0));
  EXPECT_EQ(policy::normalizeSavedSpine(0, 0), 0);
}

TEST(ReaderOpenPolicy, SuppressesOnlyManagedInboxArtifactSuggestions) {
  EXPECT_FALSE(policy::allowSiblingBookSuggestions(
      "/.crosspoint/xtinct-v2/artifacts/0123456789abcdef.epub"));
  EXPECT_TRUE(policy::allowSiblingBookSuggestions("/Books/Daily Brief.epub"));
  EXPECT_TRUE(policy::allowSiblingBookSuggestions("/.crosspoint/other/book.epub"));
  EXPECT_TRUE(policy::allowSiblingBookSuggestions("/.crosspoint/xtinct-v2/artifacts"));
}
