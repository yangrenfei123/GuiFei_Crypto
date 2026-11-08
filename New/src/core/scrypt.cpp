// scrypt 实现（独立编译单元）
//   算法顺序严格对照 RFC 7914 / pyscrypt 参考实现
#include "common.h"

#include "crypto.h"

#include <cstring>

namespace gf {

namespace {

inline uint32_t Rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

// Salsa20/8 核心：b 既是输入也是输出（16 个小端 32 位字）
void Salsa208(uint32_t b[16]) {
  uint32_t x[16];
  memcpy(x, b, sizeof(x));
  for (int i = 0; i < 4; i++) {
    // 列轮
    x[4] ^= Rotl32(x[0] + x[12], 7);
    x[8] ^= Rotl32(x[4] + x[0], 9);
    x[12] ^= Rotl32(x[8] + x[4], 13);
    x[0] ^= Rotl32(x[12] + x[8], 18);
    x[9] ^= Rotl32(x[5] + x[1], 7);
    x[13] ^= Rotl32(x[9] + x[5], 9);
    x[1] ^= Rotl32(x[13] + x[9], 13);
    x[5] ^= Rotl32(x[1] + x[13], 18);
    x[14] ^= Rotl32(x[10] + x[6], 7);
    x[2] ^= Rotl32(x[14] + x[10], 9);
    x[6] ^= Rotl32(x[2] + x[14], 13);
    x[10] ^= Rotl32(x[6] + x[2], 18);
    x[3] ^= Rotl32(x[15] + x[11], 7);
    x[7] ^= Rotl32(x[3] + x[15], 9);
    x[11] ^= Rotl32(x[7] + x[3], 13);
    x[15] ^= Rotl32(x[11] + x[7], 18);
    // 行轮
    x[1] ^= Rotl32(x[0] + x[3], 7);
    x[2] ^= Rotl32(x[1] + x[0], 9);
    x[3] ^= Rotl32(x[2] + x[1], 13);
    x[0] ^= Rotl32(x[3] + x[2], 18);
    x[6] ^= Rotl32(x[5] + x[4], 7);
    x[7] ^= Rotl32(x[6] + x[5], 9);
    x[4] ^= Rotl32(x[7] + x[6], 13);
    x[5] ^= Rotl32(x[4] + x[7], 18);
    x[11] ^= Rotl32(x[10] + x[9], 7);
    x[8] ^= Rotl32(x[11] + x[10], 9);
    x[9] ^= Rotl32(x[8] + x[11], 13);
    x[10] ^= Rotl32(x[9] + x[8], 18);
    x[12] ^= Rotl32(x[15] + x[14], 7);
    x[13] ^= Rotl32(x[12] + x[15], 9);
    x[14] ^= Rotl32(x[13] + x[12], 13);
    x[15] ^= Rotl32(x[14] + x[13], 18);
  }
  for (int i = 0; i < 16; i++) b[i] += x[i];
}

// BlockMix：B 就地更新（2r 个 16 字块），Y 为工作缓冲区
void BlockMix(uint32_t* B, uint32_t* Y, int r) {
  uint32_t X[16];
  memcpy(X, B + (size_t)(2 * r - 1) * 16, sizeof(X));
  for (int i = 0; i < 2 * r; i++) {
    for (int j = 0; j < 16; j++) X[j] ^= B[i * 16 + j];
    Salsa208(X);
    memcpy(Y + (size_t)i * 16, X, sizeof(X));
  }
  for (int i = 0; i < r; i++) memcpy(B + (size_t)i * 16, Y + (size_t)(i * 2) * 16, 64);
  for (int i = 0; i < r; i++)
    memcpy(B + (size_t)(r + i) * 16, Y + (size_t)(i * 2 + 1) * 16, 64);
}

// ROMix：就地更新 X
void Romix(uint32_t* X, std::vector<uint32_t>& V, uint32_t N, int r) {
  const size_t blockWords = (size_t)32 * (size_t)r;
  std::vector<uint32_t> Y(blockWords);
  for (uint32_t i = 0; i < N; i++) {
    memcpy(&V[(size_t)i * blockWords], X, blockWords * sizeof(uint32_t));
    BlockMix(X, Y.data(), r);
  }
  for (uint32_t i = 0; i < N; i++) {
    const uint32_t j = X[(size_t)(2 * r - 1) * 16] & (N - 1);
    for (size_t k = 0; k < blockWords; k++) X[k] ^= V[(size_t)j * blockWords + k];
    BlockMix(X, Y.data(), r);
  }
}

// PBKDF2-HMAC-SHA256（scrypt 内部轮数为 1）
Bytes Pbkdf2(const Bytes& password, const Bytes& salt, size_t dkLen, uint32_t rounds = 1) {
  Bytes out;
  out.reserve(dkLen);
  for (uint32_t block = 1; out.size() < dkLen; block++) {
    Bytes msg = salt;
    msg.push_back((uint8_t)(block >> 24));
    msg.push_back((uint8_t)(block >> 16));
    msg.push_back((uint8_t)(block >> 8));
    msg.push_back((uint8_t)block);
    Bytes u = HmacSha256(password, msg);
    Bytes t = u;
    for (uint32_t i = 1; i < rounds; i++) {
      u = HmacSha256(password, u);
      for (size_t k = 0; k < t.size(); k++) t[k] ^= u[k];
    }
    out.insert(out.end(), t.begin(), t.end());
  }
  out.resize(dkLen);
  return out;
}

}  // namespace

void DbRomix0(const Bytes& in, uint32_t n, int r, Bytes* xOut, Bytes* v0) {
  std::vector<uint32_t> X(in.size() / 4);
  memcpy(X.data(), in.data(), in.size());
  std::vector<uint32_t> V((size_t)n * 32 * (size_t)r);
  Romix(X.data(), V, n, r);
  xOut->resize(in.size());
  memcpy(xOut->data(), X.data(), in.size());
  v0->resize(in.size());
  memcpy(v0->data(), V.data(), in.size());
}

Bytes DbHmac(const Bytes& key, const Bytes& data) { return HmacSha256(key, data); }

void DbSalsa(const Bytes& in, Bytes* out) {
  uint32_t b[16];
  memcpy(b, in.data(), 64);
  Salsa208(b);
  out->resize(64);
  memcpy(out->data(), b, 64);
}

void DbBlockMix(const Bytes& in, int r, Bytes* out) {
  Bytes work = in;
  std::vector<uint32_t> y((size_t)32 * r);
  BlockMix((uint32_t*)work.data(), y.data(), r);
  out->assign(work.begin(), work.end());
}

Bytes Scrypt(const Bytes& password, const Bytes& salt, uint32_t n, uint32_t r, uint32_t p,
             size_t dkLen) {
  if (!n) n = 1u << 14;
  if (!r) r = 8;
  if (!p) p = 1;
  const size_t blockSize = (size_t)128 * r;
  Bytes B = Pbkdf2(password, salt, blockSize * p);

  std::vector<uint32_t> v((size_t)n * 32 * (size_t)r);
  for (uint32_t k = 0; k < p; k++) {
    uint32_t* X = (uint32_t*)(B.data() + blockSize * k);
    Romix(X, v, n, (int)r);
  }
  return Pbkdf2(password, B, dkLen);
}

}  // namespace gf
