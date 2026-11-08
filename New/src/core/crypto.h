// ============================================================
//  密码学：scrypt + AES-256-GCM + BCH(127,64) + SHA-256
//  纯软件实现，不依赖系统加密提供程序的可用性
// ============================================================
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace gf {

using Bytes = std::vector<uint8_t>;

Bytes RandomBytes(size_t n);

// SHA-256
Bytes Sha256Bytes(const Bytes& data);

// HMAC-SHA256（scrypt 内部使用，也供外部调用）
Bytes HmacSha256(const Bytes& key, const Bytes& data);

// scrypt(password, salt, N=2^14, r=8, p=1, dkLen=32)
Bytes Scrypt(const Bytes& password, const Bytes& salt, uint32_t n = 0,
             uint32_t r = 0, uint32_t p = 0, size_t dkLen = 32);

// AES-256-GCM，返回 nonce || tag || ciphertext（与 Python 版保持一致）
bool AesGcmEncrypt(const Bytes& key, const Bytes& plain, const Bytes& aad, Bytes* out,
                   std::wstring* error);
bool AesGcmDecrypt(const Bytes& key, const Bytes& payload, const Bytes& aad, Bytes* out,
                   std::wstring* error);

// 指定 nonce 的版本（单元测试 / 互通测试使用）
bool AesGcmEncryptWithNonce(const Bytes& key, const Bytes& nonce, const Bytes& plain,
                            const Bytes& aad, Bytes* cipher, Bytes* tag);
bool AesGcmDecryptWithNonce(const Bytes& key, const Bytes& nonce, const Bytes& cipher,
                            const Bytes& aad, const Bytes& tag, Bytes* plain);

// ---- BCH(127,64) ----
constexpr int kBchN = 127;
constexpr int kBchK = 64;

Bytes BchEncode64(const Bytes& key8);        // 8 字节 -> 16 字节码字
Bytes BchDecode64(const Bytes& codeword16);  // 16 字节码字 -> 8 字节
int BchErrorCapacity();                      // t

// ---- Base64 ----
std::string Base64Encode(const Bytes& data);
bool Base64Decode(const std::string& text, Bytes* out);

}  // namespace gf
