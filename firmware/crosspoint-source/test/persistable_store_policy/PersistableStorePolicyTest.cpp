#include <gtest/gtest.h>

#include <cstdint>

#include "Serialization/PersistableStorePolicy.h"

namespace policy = persistable_store_policy;

TEST(PersistableStorePolicy, CapsStateAndSettingsBeforeParserAllocation) {
  EXPECT_TRUE(policy::validPersistedJsonFileSize(1));
  EXPECT_TRUE(policy::validPersistedJsonFileSize(policy::MAX_PERSISTED_JSON_BYTES));
  EXPECT_FALSE(policy::validPersistedJsonFileSize(0));
  EXPECT_FALSE(policy::validPersistedJsonFileSize(policy::MAX_PERSISTED_JSON_BYTES + 1U));
  EXPECT_FALSE(policy::validPersistedJsonFileSize(UINT64_MAX));
}
