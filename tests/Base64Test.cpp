#include <gtest/gtest.h>
#include "crypto/Base64.h"
#include <string>

TEST(Base64Test, EncodeDecode) {
    std::string original = "Hello, World!";
    std::string encoded = crypto::Base64::Encode(original);
    std::string decoded = crypto::Base64::Decode(encoded);
    EXPECT_EQ(original, decoded);
}

TEST(Base64Test, EmptyString) {
    std::string original = "";
    std::string encoded = crypto::Base64::Encode(original);
    std::string decoded = crypto::Base64::Decode(encoded);
    EXPECT_EQ(original, decoded);
}

TEST(Base64Test, Padding) {
    std::string s1 = "a";
    std::string s2 = "ab";
    std::string s3 = "abc";

    EXPECT_EQ(crypto::Base64::Decode(crypto::Base64::Encode(s1)), s1);
    EXPECT_EQ(crypto::Base64::Decode(crypto::Base64::Encode(s2)), s2);
    EXPECT_EQ(crypto::Base64::Decode(crypto::Base64::Encode(s3)), s3);
}
