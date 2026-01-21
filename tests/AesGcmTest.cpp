#include <gtest/gtest.h>
#include "crypto/AesGcm.h"
#include <vector>
#include <string>

TEST(AesGcmTest, EncryptDecrypt) {
    std::vector<uint8_t> key(32, 0x41); // 256-bit key
    std::string plaintext = "Secret message";
    std::string ciphertext = crypto::AesGcm::Encrypt(plaintext, key);
    
    EXPECT_FALSE(ciphertext.empty());
    EXPECT_NE(plaintext, ciphertext);

    std::string decrypted = crypto::AesGcm::Decrypt(ciphertext, key);
    EXPECT_EQ(plaintext, decrypted);
}

TEST(AesGcmTest, WrongKeyFails) {
    std::vector<uint8_t> key1(32, 0x41);
    std::vector<uint8_t> key2(32, 0x42);
    std::string plaintext = "Secret message";
    std::string ciphertext = crypto::AesGcm::Encrypt(plaintext, key1);
    
    std::string decrypted = crypto::AesGcm::Decrypt(ciphertext, key2);
    EXPECT_TRUE(decrypted.empty());
}
