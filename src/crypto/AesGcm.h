#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include <bcrypt.h>

namespace crypto {

class AesGcm {
public:
    AesGcm(const std::vector<BYTE>& key);
    ~AesGcm();

    std::vector<BYTE> encrypt(const std::vector<BYTE>& plaintext, const std::vector<BYTE>& nonce);
    std::vector<BYTE> decrypt(const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& nonce);

private:
    BCRYPT_ALG_HANDLE algHandle_ = nullptr;
    BCRYPT_KEY_HANDLE keyHandle_ = nullptr;
};

} // namespace crypto
