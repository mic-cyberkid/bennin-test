#include "AesGcm.h"
#include <stdexcept>

namespace crypto {

AesGcm::AesGcm(const std::vector<BYTE>& key) {
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&algHandle_, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Failed to open AES algorithm provider.");
    }

    status = BCryptSetProperty(algHandle_, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(algHandle_, 0);
        throw std::runtime_error("Failed to set GCM chaining mode.");
    }

    status = BCryptGenerateSymmetricKey(algHandle_, &keyHandle_, NULL, 0, (PBYTE)key.data(), key.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(algHandle_, 0);
        throw std::runtime_error("Failed to generate symmetric key.");
    }
}

AesGcm::~AesGcm() {
    if (keyHandle_) {
        BCryptDestroyKey(keyHandle_);
    }
    if (algHandle_) {
        BCryptCloseAlgorithmProvider(algHandle_, 0);
    }
}

std::vector<BYTE> AesGcm::encrypt(const std::vector<BYTE>& plaintext, const std::vector<BYTE>& nonce) {
    NTSTATUS status;
    DWORD ciphertextLen = 0;
    std::vector<BYTE> ciphertext;
    std::vector<BYTE> tag(16); // GCM tag is 16 bytes

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PBYTE)nonce.data();
    authInfo.cbNonce = nonce.size();
    authInfo.pbTag = tag.data();
    authInfo.cbTag = tag.size();

    // First call to get the required buffer size
    status = BCryptEncrypt(keyHandle_, (PBYTE)plaintext.data(), plaintext.size(), &authInfo, NULL, 0, NULL, 0, &ciphertextLen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Failed to get encrypted buffer size.");
    }

    ciphertext.resize(ciphertextLen);

    // Second call to perform encryption
    status = BCryptEncrypt(keyHandle_, (PBYTE)plaintext.data(), plaintext.size(), &authInfo, NULL, 0, ciphertext.data(), ciphertext.size(), &ciphertextLen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Encryption failed.");
    }

    // Append the tag to the ciphertext
    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());

    return ciphertext;
}

std::vector<BYTE> AesGcm::decrypt(const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& nonce) {
    if (ciphertext.size() < 16) {
        throw std::runtime_error("Invalid ciphertext: too short to contain a tag.");
    }

    NTSTATUS status;
    DWORD plaintextLen = 0;
    std::vector<BYTE> plaintext;

    std::vector<BYTE> encryptedData(ciphertext.begin(), ciphertext.end() - 16);
    std::vector<BYTE> tag(ciphertext.end() - 16, ciphertext.end());

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PBYTE)nonce.data();
    authInfo.cbNonce = nonce.size();
    authInfo.pbTag = tag.data();
    authInfo.cbTag = tag.size();

    // First call to get the required buffer size
    status = BCryptDecrypt(keyHandle_, (PBYTE)encryptedData.data(), encryptedData.size(), &authInfo, NULL, 0, NULL, 0, &plaintextLen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Failed to get decrypted buffer size.");
    }

    plaintext.resize(plaintextLen);

    // Second call to perform decryption and authentication
    status = BCryptDecrypt(keyHandle_, (PBYTE)encryptedData.data(), encryptedData.size(), &authInfo, NULL, 0, plaintext.data(), plaintext.size(), &plaintextLen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        // This can fail if the tag is invalid (authentication failure)
        throw std::runtime_error("Decryption failed. The data may be tampered with.");
    }

    return plaintext;
}

} // namespace crypto
