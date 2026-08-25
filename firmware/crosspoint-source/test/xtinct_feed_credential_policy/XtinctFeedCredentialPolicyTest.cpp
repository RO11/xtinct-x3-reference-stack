#include <gtest/gtest.h>

#include <string>

#include "src/util/XtinctFeedCredentialPolicy.h"

using namespace xtinct::feed_credential;

TEST(XtinctFeedCredentialPolicy, AcceptsAndCanonicalizesCloudflareWorkerOrigins) {
  EXPECT_TRUE(isValidWorkerOrigin("https://reader.account.workers.dev"));
  EXPECT_TRUE(isValidWorkerOrigin("HTTPS://Reader.Account.Workers.Dev/"));
  EXPECT_EQ(canonicalizeOrigin("HTTPS://Reader.Account.Workers.Dev///"),
            "https://reader.account.workers.dev");
}

TEST(XtinctFeedCredentialPolicy, RejectsRedirectAndAmbiguousOriginShapes) {
  EXPECT_FALSE(isValidWorkerOrigin(""));
  EXPECT_FALSE(isValidWorkerOrigin("http://reader.account.workers.dev"));
  EXPECT_FALSE(isValidWorkerOrigin("https://@reader.account.workers.dev"));
  EXPECT_FALSE(isValidWorkerOrigin("https://reader.account.workers.dev/path"));
  EXPECT_FALSE(isValidWorkerOrigin("https://reader.account.workers.dev//"));
  EXPECT_FALSE(isValidWorkerOrigin("https://reader.account.workers.dev:443"));
  EXPECT_FALSE(isValidWorkerOrigin("https://127.0.0.1"));
  EXPECT_FALSE(isValidWorkerOrigin("https://workers.dev"));
  EXPECT_FALSE(isValidWorkerOrigin("https://account.workers.dev"));
  EXPECT_FALSE(isValidWorkerOrigin("https://reader.account.workers.dev.example.org"));
  EXPECT_FALSE(isValidWorkerOrigin("https://reader..account.workers.dev"));
  EXPECT_FALSE(isValidWorkerOrigin("https://reader%2eaccount.workers.dev"));
  EXPECT_FALSE(isValidWorkerOrigin(std::string("https://") + std::string(193, 'a') + ".workers.dev"));
}

TEST(XtinctFeedCredentialPolicy, RoundTripsOneAtomicVersionedCredential) {
  const std::string token(48, 'x');
  const std::string record = serialize("HTTPS://Reader.Account.Workers.Dev/", token);
  ASSERT_FALSE(record.empty());
  Credential parsed;
  ASSERT_TRUE(parse(record, parsed));
  EXPECT_EQ(parsed.origin, "https://reader.account.workers.dev");
  EXPECT_EQ(parsed.token, token);
}

TEST(XtinctFeedCredentialPolicy, RejectsMalformedOrMixedRecords) {
  const std::string token(48, 'x');
  Credential parsed;
  EXPECT_FALSE(parse("v2\nhttps://reader.account.workers.dev\n" + token, parsed));
  EXPECT_FALSE(parse("v1\nhttps://reader.account.workers.dev", parsed));
  EXPECT_FALSE(parse("v1\nhttps://reader.account.workers.dev\n" + token + "\nextra", parsed));
  EXPECT_FALSE(parse("v1\nHTTPS://reader.account.workers.dev\n" + token, parsed));
  EXPECT_FALSE(parse("v1\nhttps://reader.account.workers.dev\nshort", parsed));
  EXPECT_FALSE(parse("v1\nhttps://reader.account.workers.dev\n" + std::string(32, ' '), parsed));
}
