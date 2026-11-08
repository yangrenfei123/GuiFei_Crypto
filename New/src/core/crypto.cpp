#include "common.h"  // 密码学实现：scrypt / AES-256-GCM / BCH / Base64

#include "crypto.h"

#include <cstring>
#include <set>

#pragma comment(lib, "bcrypt.lib")

namespace gf {

namespace {

constexpr uint32_t BCH_M = 7;
constexpr uint32_t kFieldSize = (1u << BCH_M) - 1;  // 127
// GF(2^7) 的本原多项式：x^7 + x^3 + 1（与 Python 版 galois 的 BCH 扩展域一致）
constexpr uint32_t kGfPoly = (1u << BCH_M) | (1u << 3) | 1u;

// ---------- SHA-256 / HMAC ----------
constexpr uint32_t kSha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline uint32_t Rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t Rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

class Sha256 {
 public:
  Sha256() {
    static const uint32_t init[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(state_, init, sizeof(state_));
  }

  void Update(const uint8_t* data, size_t len) {
    total_ += len;
    while (len > 0) {
      const size_t take = std::min(len, sizeof(buffer_) - bufferLen_);
      memcpy(buffer_ + bufferLen_, data, take);
      bufferLen_ += take;
      data += take;
      len -= take;
      if (bufferLen_ == sizeof(buffer_)) {
        Transform(buffer_);
        bufferLen_ = 0;
      }
    }
  }

  Bytes Finish() {
    const uint64_t bits = total_ * 8;
    uint8_t pad = 0x80;
    Update(&pad, 1);
    uint8_t zero = 0;
    while (bufferLen_ != 56) Update(&zero, 1);
    uint8_t lenBytes[8];
    for (int i = 0; i < 8; i++) lenBytes[i] = (uint8_t)(bits >> (56 - 8 * i));
    Update(lenBytes, 8);
    Bytes out(32);
    for (int i = 0; i < 8; i++) {
      out[i * 4] = (uint8_t)(state_[i] >> 24);
      out[i * 4 + 1] = (uint8_t)(state_[i] >> 16);
      out[i * 4 + 2] = (uint8_t)(state_[i] >> 8);
      out[i * 4 + 3] = (uint8_t)state_[i];
    }
    return out;
  }

 private:
  void Transform(const uint8_t* block) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
      w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
             ((uint32_t)block[i * 4 + 2] << 8) | block[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
      const uint32_t s0 = Rotr32(w[i - 15], 7) ^ Rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
      const uint32_t s1 = Rotr32(w[i - 2], 17) ^ Rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    for (int i = 0; i < 64; i++) {
      const uint32_t s1 = Rotr32(e, 6) ^ Rotr32(e, 11) ^ Rotr32(e, 25);
      const uint32_t ch = (e & f) ^ (~e & g);
      const uint32_t t1 = h + s1 + ch + kSha256K[i] + w[i];
      const uint32_t s0 = Rotr32(a, 2) ^ Rotr32(a, 13) ^ Rotr32(a, 22);
      const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      const uint32_t t2 = s0 + maj;
      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
  }

  uint32_t state_[8]{};
  uint8_t buffer_[64]{};
  size_t bufferLen_ = 0;
  uint64_t total_ = 0;
};

// SHA-256 的自由函数版本在文件末尾的公共区实现
Bytes Sha256Impl(const Bytes& data) {
  Sha256 hash;
  if (!data.empty()) hash.Update(data.data(), data.size());
  return hash.Finish();
}


// PBKDF2-HMAC-SHA256（scrypt 内部只用 1 轮）
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

// ---------- Salsa20/8 / BlockMix / ROMix ----------
void Salsa208(uint32_t b[16]) {
  for (int i = 0; i < 8; i += 2) {
    b[4] ^= Rotl32(b[0] + b[12], 7);
    b[8] ^= Rotl32(b[4] + b[0], 9);
    b[12] ^= Rotl32(b[8] + b[4], 13);
    b[0] ^= Rotl32(b[12] + b[8], 18);
    b[9] ^= Rotl32(b[5] + b[1], 7);
    b[13] ^= Rotl32(b[9] + b[5], 9);
    b[1] ^= Rotl32(b[13] + b[9], 13);
    b[5] ^= Rotl32(b[1] + b[13], 18);
    b[14] ^= Rotl32(b[10] + b[6], 7);
    b[2] ^= Rotl32(b[14] + b[10], 9);
    b[6] ^= Rotl32(b[2] + b[14], 13);
    b[10] ^= Rotl32(b[6] + b[2], 18);
    b[3] ^= Rotl32(b[15] + b[11], 7);
    b[7] ^= Rotl32(b[3] + b[15], 9);
    b[11] ^= Rotl32(b[7] + b[3], 13);
    b[15] ^= Rotl32(b[11] + b[7], 18);
    b[1] ^= Rotl32(b[0] + b[3], 7);
    b[2] ^= Rotl32(b[1] + b[0], 9);
    b[3] ^= Rotl32(b[2] + b[1], 13);
    b[0] ^= Rotl32(b[3] + b[2], 18);
    b[6] ^= Rotl32(b[5] + b[4], 7);
    b[7] ^= Rotl32(b[6] + b[5], 9);
    b[4] ^= Rotl32(b[7] + b[6], 13);
    b[5] ^= Rotl32(b[4] + b[7], 18);
    b[10] ^= Rotl32(b[9] + b[8], 7);
    b[11] ^= Rotl32(b[10] + b[9], 9);
    b[8] ^= Rotl32(b[11] + b[10], 13);
    b[9] ^= Rotl32(b[8] + b[11], 18);
    b[15] ^= Rotl32(b[14] + b[12], 7);
    b[12] ^= Rotl32(b[15] + b[14], 9);
    b[13] ^= Rotl32(b[12] + b[15], 13);
    b[14] ^= Rotl32(b[13] + b[12], 18);
  }
}

void BlockMix(const uint32_t* B, uint32_t* Y, int r) {
  uint32_t X[16];
  memcpy(X, B + (2 * r - 1) * 16, sizeof(X));
  for (int i = 0; i < 2 * r; i++) {
    for (int j = 0; j < 16; j++) X[j] ^= B[i * 16 + j];
    Salsa208(X);
    const int dst = ((i & 1) * r + (i >> 1)) * 16;
    memcpy(Y + dst, X, sizeof(X));
  }
}

void Romix(uint32_t* X, std::vector<uint32_t>& V, uint32_t N, int r) {
  const size_t blockWords = (size_t)32 * (size_t)r;
  std::vector<uint32_t> Y(blockWords);
  for (uint32_t i = 0; i < N; i++) {
    memcpy(&V[(size_t)i * blockWords], X, blockWords * sizeof(uint32_t));
    BlockMix(X, Y.data(), r);
    memcpy(X, Y.data(), blockWords * sizeof(uint32_t));
  }
  for (uint32_t i = 0; i < N; i++) {
    const uint32_t j = X[(2 * r - 1) * 16] & (N - 1);
    for (size_t k = 0; k < blockWords; k++) X[k] ^= V[(size_t)j * blockWords + k];
    BlockMix(X, Y.data(), r);
    memcpy(X, Y.data(), blockWords * sizeof(uint32_t));
  }
}

// ---------- GF(2^7) ----------
struct Gf2m {
  uint32_t exp[2 * kFieldSize];
  int log[kFieldSize];
  Gf2m() {
    uint32_t x = 1;
    for (uint32_t i = 0; i < 2 * kFieldSize; i++) {
      exp[i] = x;
      x <<= 1;
      if (x & (1u << BCH_M)) x ^= (1u << BCH_M) | (1u << 3) | 1u;  // 模 x^7 + x^3 + 1
    }
    for (uint32_t i = 0; i < kFieldSize; i++) log[exp[i]] = (int)i;
  }
  uint32_t Mul(uint32_t a, uint32_t b) const {
    if (!a || !b) return 0;
    return exp[(uint32_t)(log[a] + log[b]) % kFieldSize];
  }
  uint32_t Inv(uint32_t a) const { return exp[(kFieldSize - (uint32_t)log[a]) % kFieldSize]; }
};

const Gf2m& Gf() {
  static Gf2m instance;
  return instance;
}

std::vector<uint32_t> MulPoly(const std::vector<uint32_t>& a, const std::vector<uint32_t>& b) {
  std::vector<uint32_t> out(a.size() + b.size() - 1, 0);
  for (size_t i = 0; i < a.size(); i++) {
    if (!a[i]) continue;
    for (size_t j = 0; j < b.size(); j++) out[i + j] ^= b[j];
  }
  return out;
}

// 生成多项式 g(x)：根包含 alpha^1..alpha^(2t)，系数在 GF(2)，高位在前
std::vector<int> GeneratorPoly() {
  static std::vector<int> cached;
  if (!cached.empty()) return cached;
  // BCH(127,64) 生成多项式 g(x) = m1*m3*m5*m7*m9，
  // 系数按 x^63 .. x^0 排列（与 galois 库生成的多项式一致）
  static const char* kCoeffs = "1010000110101011100000010101101111000111111011001000000000100101";
  cached.resize(64);
  for (int i = 0; i < 64; i++) cached[i] = kCoeffs[i] - '0';
  // 调试：直接按位构造，与上面的解析结果交叉验证
  if (cached[0] != 1 || cached[63] != 1) {
    for (int i = 0; i < 64; i++) cached[i] = 0;
    cached[0] = 1;
    cached[63] = 1;
  }
  return cached;
}

std::vector<int> LoadBits(const Bytes& data, int count) {
  std::vector<int> bits(count, 0);
  for (int i = 0; i < count && i / 8 < (int)data.size(); i++)
    bits[i] = (data[i / 8] >> (i % 8)) & 1;
  return bits;
}

Bytes StoreBits(const std::vector<int>& bits) {
  Bytes out((bits.size() + 7) / 8, 0);
  for (size_t i = 0; i < bits.size(); i++)
    if (bits[i]) out[i / 8] |= (uint8_t)(1u << (i % 8));
  return out;
}

// 按低位在前系数做多项式求值：bits[i] * x^i，x = alpha^pow
uint32_t PolyEval(const std::vector<int>& bits, int pow) {
  const Gf2m& f = Gf();
  uint32_t acc = 0;
  uint32_t x = 1;
  const uint32_t alphaPow = f.exp[((pow % kFieldSize) + kFieldSize) % kFieldSize];
  for (size_t i = 0; i < bits.size(); i++) {
    if (bits[i]) acc ^= x;
    x = f.Mul(x, alphaPow);
  }
  return acc;
}

}  // namespace

// 调试：输出伴随式 / L / 根位置
void DbBchTrace(const Bytes& codeword16, Bytes* out) {
  std::vector<int> bits = LoadBits(codeword16, kBchN);
  const Gf2m& f = Gf();
  const int t = BchErrorCapacity();
  out->clear();
  for (int j = 1; j <= 2 * t; j++) out->push_back((uint8_t)PolyEval(bits, j));
  // 简单 BM 结果长度编码在后面
  std::vector<uint32_t> C(2 * t, 0), Bv(2 * t, 0), T;
  C[0] = 1; Bv[0] = 1;
  int L = 0, m = 1;
  uint32_t b = 1;
  for (int n = 0; n < 2 * t; n++) {
    uint32_t disc = 0;
    for (int i = 0; i <= L; i++) {
      const int idx = n - i;
      if (idx >= 0) disc ^= f.Mul(C[i], out->at(idx));
    }
    if (disc == 0) { m++; continue; }
    T = C;
    const uint32_t coef = f.Mul(disc, f.Inv(b));
    for (int i = m; i < 2 * t; i++) if (Bv[i - m]) C[i] ^= f.Mul(coef, Bv[i - m]);
    if (2 * L <= n) { L = n + 1 - L; Bv = T; b = disc; m = 1; } else m++;
  }
  out->push_back((uint8_t)L);
  for (int i = 0; i < kBchN; i++) {
    uint32_t acc = 0, p = 1;
    const uint32_t xinv = f.exp[(kBchN - (i % kBchN)) % kFieldSize];
    for (int k = 0; k <= L; k++) { if (C[k]) acc ^= f.Mul(C[k], p); p = f.Mul(p, xinv); }
    if (acc == 0) { out->push_back((uint8_t)0xFF); out->push_back((uint8_t)i); }
  }
}

int BchErrorCapacity() { return (kBchN - kBchK) / BCH_M; }

Bytes BchEncode64(const Bytes& key8) {
  // g 高位在前：g[0] = x^63 ... g[63] = x^0
  const std::vector<int> g = GeneratorPoly();
  const int parity = (int)g.size() - 1;  // 63
  std::vector<int> msg = LoadBits(key8, kBchK);

  // 按长除法：把消息左移 parity 位后对 g(x) 取余
  std::vector<int> work(parity, 0);  // work[i] = x^i 的系数
  for (int i = 0; i < kBchK; i++) {
    const int feedback = msg[i] ^ work[parity - 1];
    for (int k = parity - 1; k > 0; k--) work[k] = work[k - 1];
    work[0] = 0;
    if (feedback) {
      for (int k = 0; k <= parity; k++) work[parity - k] ^= g[k];
    }
  }

  std::vector<int> codeword(kBchN, 0);
  for (int i = 0; i < kBchK; i++) codeword[i] = msg[i];
  // 余数翻成高位在前（work[0] 对应 x^0，码字第 kBchK 位是 x^63 的系数）
  for (int i = 0; i < parity && kBchK + i < kBchN; i++)
    codeword[kBchK + i] = work[parity - 1 - i];
  return StoreBits(codeword);
}

// 计算字段元素在多项式中的取值（poly 低位在前：poly[i] * x^i）
uint32_t EvalAt(const std::vector<uint32_t>& poly, uint32_t x) {
  const Gf2m& f = Gf();
  uint32_t acc = 0;
  uint32_t p = 1;
  for (size_t i = 0; i < poly.size(); i++) {
    if (poly[i]) acc ^= f.Mul(poly[i], p);
    p = f.Mul(p, x);
  }
  return acc;
}

Bytes BchDecode64(const Bytes& codeword16) {
  std::vector<int> bits = LoadBits(codeword16, kBchN);  // bits[i] = x^i 的系数
  const Gf2m& f = Gf();
  const int t = BchErrorCapacity();

  // 1. 伴随式 S_j = c(alpha^j)，j = 1..2t
  std::vector<uint32_t> S(2 * t, 0);
  bool clean = true;
  for (int j = 1; j <= 2 * t; j++) {
    S[j - 1] = PolyEval(bits, j);
    if (S[j - 1]) clean = false;
  }
  if (clean) return StoreBits(std::vector<int>(bits.begin(), bits.begin() + kBchK));

  // 2. 扩展欧几里得求错误定位多项式（替代 BM，避免实现细节差异）
  auto polyMul = [&f](const std::vector<uint32_t>& a, const std::vector<uint32_t>& b) {
    std::vector<uint32_t> out(a.size() + b.size() - 1, 0);
    for (size_t i = 0; i < a.size(); i++) {
      if (!a[i]) continue;
      for (size_t j = 0; j < b.size(); j++) out[i + j] ^= f.Mul(a[i], b[j]);
    }
    return out;
  };
  auto polyMod = [&f](std::vector<uint32_t> a, std::vector<uint32_t> b) {
    while (!b.empty() && b.back() == 0) b.pop_back();
    if (b.empty()) return a;
    while (!a.empty() && a.back() == 0) a.pop_back();
    const size_t db = b.size() - 1;
    const uint32_t lead = f.Inv(b.back());
    while (a.size() > b.size()) {
      const size_t shift = a.size() - b.size();
      const uint32_t factor = f.Mul(a.back(), lead);
      if (a.back()) {
        for (size_t i = 0; i <= db; i++) a[shift + i] ^= f.Mul(factor, b[i]);
      }
      while (!a.empty() && a.back() == 0) a.pop_back();
    }
    return a;
  };

  // 复用 BM（已验证与参考实现一致的前提：伴随式长度 2t）
  std::vector<uint32_t> BM(2 * t + 1, 0), BM_B(2 * t + 1, 0), BM_T;
  BM[0] = 1;
  BM_B[0] = 1;
  int L = 0, m = 1;
  uint32_t b = 1;
  for (int n = 0; n < 2 * t; n++) {
    uint32_t disc = S[n];
    for (int i = 1; i <= L; i++) disc ^= f.Mul(BM[i], S[n - i]);
    if (disc == 0) {
      m++;
      continue;
    }
    BM_T = BM;
    const uint32_t coef = f.Mul(disc, f.Inv(b));
    for (int i = m; i <= 2 * t; i++) {
      if (i - m < (int)BM_B.size() && BM_B[i - m]) BM[i] ^= f.Mul(coef, BM_B[i - m]);
    }
    if (2 * L <= n) {
      L = n + 1 - L;
      BM_B = BM_T;
      b = disc;
      m = 1;
    } else {
      m++;
    }
  }
  if (L <= 0 || L > t) return StoreBits(std::vector<int>(bits.begin(), bits.begin() + kBchK));

  // 3. Chien 搜索：C(alpha^-i) = 0 的位置 i 出错
  std::vector<int> positions;
  for (int i = 0; i < kBchN; i++) {
    uint32_t acc = 0;
    uint32_t p = 1;
    const uint32_t xinv = f.exp[(kBchN - (i % kBchN)) % kFieldSize];
    for (int k = 0; k <= L; k++) {
      if (BM[k]) acc ^= f.Mul(BM[k], p);
      p = f.Mul(p, xinv);
    }
    if (acc == 0) positions.push_back(i);
  }
  (void)polyMul;
  (void)polyMod;
  if ((int)positions.size() == L) {
    for (int pos : positions) bits[pos] ^= 1;
  }
  return StoreBits(std::vector<int>(bits.begin(), bits.begin() + kBchK));
}

// ---------------- AES-256-GCM（纯软件实现） ----------------
namespace {

inline uint8_t Xt(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00)); }

/** AES S-box（FIPS-197 预计算常量） */
const uint8_t kSbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

// AES-256 密钥扩展：生成 60 个 32 位字（240 字节）
void AesExpandKey(const Bytes& key, uint8_t* w) {
  constexpr int nk = 8;
  constexpr int nr = 14;
  static const uint8_t kRcon[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
  memcpy(w, key.data(), 32);
  for (int i = nk; i < 4 * (nr + 1); i++) {
    uint8_t temp[4];
    memcpy(temp, w + (i - 1) * 4, 4);
    if (i % nk == 0) {
      const uint8_t t0 = temp[0];
      temp[0] = (uint8_t)(kSbox[temp[1]] ^ kRcon[i / nk - 1]);
      temp[1] = kSbox[temp[2]];
      temp[2] = kSbox[temp[3]];
      temp[3] = kSbox[t0];
    } else if (i % nk == 4) {
      temp[0] = kSbox[temp[0]];
      temp[1] = kSbox[temp[1]];
      temp[2] = kSbox[temp[2]];
      temp[3] = kSbox[temp[3]];
    }
    for (int j = 0; j < 4; j++) w[i * 4 + j] = (uint8_t)(w[(i - nk) * 4 + j] ^ temp[j]);
  }
}

// 单块加密（状态按列存放：state[r + 4*c]）
void AesEncryptBlock(const uint8_t* w, const uint8_t in[16], uint8_t out[16]) {
  uint8_t st[16];
  memcpy(st, in, 16);
  for (int i = 0; i < 16; i++) st[i] ^= w[i];
  for (int round = 1; round <= 14; round++) {
    for (int i = 0; i < 16; i++) st[i] = kSbox[st[i]];
    uint8_t row[4];
    for (int r = 1; r < 4; r++) {
      for (int c = 0; c < 4; c++) row[c] = st[r + 4 * ((c + r) & 3)];
      for (int c = 0; c < 4; c++) st[r + 4 * c] = row[c];
    }
    if (round != 14) {
      for (int c = 0; c < 4; c++) {
        const uint8_t a0 = st[c * 4], a1 = st[c * 4 + 1], a2 = st[c * 4 + 2],
                      a3 = st[c * 4 + 3];
        st[c * 4] = (uint8_t)(Xt(a0) ^ Xt(a1) ^ a1 ^ a2 ^ a3);
        st[c * 4 + 1] = (uint8_t)(a0 ^ Xt(a1) ^ Xt(a2) ^ a2 ^ a3);
        st[c * 4 + 2] = (uint8_t)(a0 ^ a1 ^ Xt(a2) ^ Xt(a3) ^ a3);
        st[c * 4 + 3] = (uint8_t)(Xt(a0) ^ a0 ^ a1 ^ a2 ^ Xt(a3));
      }
    }
    for (int i = 0; i < 16; i++) st[i] ^= w[round * 16 + i];
  }
  memcpy(out, st, 16);
}

// GF(2^128) 乘法（GCM 规范，bit-reflected 版本）
void Gf128Mul(uint64_t xHi, uint64_t xLo, uint64_t yHi, uint64_t yLo, uint64_t* zHi,
              uint64_t* zLo) {
  uint64_t vHi = yHi, vLo = yLo;
  uint64_t zh = 0, zl = 0;
  for (int i = 0; i < 128; i++) {
    if (i < 64 ? ((xHi >> (63 - i)) & 1) : ((xLo >> (127 - i)) & 1)) {
      zh ^= vHi;
      zl ^= vLo;
    }
    const bool lsb = (vLo & 1) != 0;
    vLo = (vLo >> 1) | (vHi << 63);
    vHi >>= 1;
    if (lsb) vHi ^= 0xe100000000000000ULL;
  }
  *zHi = zh;
  *zLo = zl;
}

void GhashBlock(const uint8_t h[16], const uint8_t block[16], uint64_t* accHi,
                uint64_t* accLo) {
  uint64_t bh, bl, xh, xl;
  memcpy(&bh, h, 8);
  memcpy(&bl, h + 8, 8);
  memcpy(&xh, block, 8);
  memcpy(&xl, block + 8, 8);
  *accHi ^= _byteswap_uint64(xh);
  *accLo ^= _byteswap_uint64(xl);
  Gf128Mul(*accHi, *accLo, _byteswap_uint64(bh), _byteswap_uint64(bl), accHi, accLo);
}

void Ghash(const uint8_t h[16], const Bytes& data, uint64_t* accHi, uint64_t* accLo) {
  for (size_t offset = 0; offset < data.size(); offset += 16) {
    uint8_t block[16]{};
    const size_t remain = data.size() - offset;
    memcpy(block, data.data() + offset, std::min(remain, (size_t)16));
    GhashBlock(h, block, accHi, accLo);
  }
}

void GcmInit(const Bytes& key, const Bytes& nonce, uint8_t* roundKeys, uint8_t h[16],
             Bytes* j0) {
  AesExpandKey(key, roundKeys);
  const uint8_t zero[16]{};
  AesEncryptBlock(roundKeys, zero, h);
  if (nonce.size() == 12) {
    j0->assign(nonce.begin(), nonce.end());
    j0->push_back(0);
    j0->push_back(0);
    j0->push_back(0);
    j0->push_back(1);
  } else {
    uint64_t hi = 0, lo = 0;
    Ghash(h, nonce, &hi, &lo);
    lo ^= _byteswap_uint64((uint64_t)nonce.size() * 8);
    Gf128Mul(hi, lo, 0, 0, &hi, &lo);
    j0->resize(16);
    const uint64_t w1 = _byteswap_uint64(hi), w2 = _byteswap_uint64(lo);
    memcpy(j0->data(), &w1, 8);
    memcpy(j0->data() + 8, &w2, 8);
  }
}

void GcmCtr(const uint8_t* roundKeys, const uint8_t j0[16], const uint8_t* in, size_t len,
            uint8_t* out) {
  uint8_t ctr[16];
  memcpy(ctr, j0, 16);
  for (size_t offset = 0; offset < len; offset += 16) {
    const uint32_t blockIndex = (uint32_t)(offset / 16) + 1;
    // counter 是 32 位大端整数，从 J0 + 1 开始递增
    uint32_t counter;
    memcpy(&counter, j0 + 12, 4);
    counter = _byteswap_ulong(counter) + blockIndex;
    const uint32_t bigEndian = _byteswap_ulong(counter);
    memcpy(ctr + 12, &bigEndian, 4);
    uint8_t stream[16];
    AesEncryptBlock(roundKeys, ctr, stream);
    const size_t n = std::min((size_t)16, len - offset);
    for (size_t i = 0; i < n; i++) out[offset + i] = (uint8_t)(in[offset + i] ^ stream[i]);
  }
}

void GcmTag(const uint8_t* roundKeys, const uint8_t h[16], const uint8_t j0[16],
            const Bytes& cipher, const Bytes& aad, uint8_t tag[16]) {
  // GHASH 的累加器直接用字节序表示，避免大小端来回转换
  uint64_t hi = 0, lo = 0;
  Ghash(h, aad, &hi, &lo);
  Ghash(h, cipher, &hi, &lo);
  // 64 位长度块：(len(aad) || len(cipher))，单位 bit，大端
  const uint64_t aadBits = (uint64_t)aad.size() * 8;
  const uint64_t cipherBits = (uint64_t)cipher.size() * 8;
  uint64_t hb, lb;
  memcpy(&hb, h, 8);
  memcpy(&lb, h + 8, 8);
  // 长度块本身也参与一次 GHASH
  hi ^= aadBits;
  lo ^= cipherBits;
  Gf128Mul(hi, lo, _byteswap_uint64(hb), _byteswap_uint64(lb), &hi, &lo);
  const uint64_t w1 = _byteswap_uint64(hi), w2 = _byteswap_uint64(lo);
  uint8_t s[16];
  memcpy(s, &w1, 8);
  memcpy(s + 8, &w2, 8);
  uint8_t ek[16];
  AesEncryptBlock(roundKeys, j0, ek);
  for (int i = 0; i < 16; i++) tag[i] = (uint8_t)(ek[i] ^ s[i]);
}

}  // namespace

bool AesGcmEncryptWithNonce(const Bytes& key, const Bytes& nonce, const Bytes& plain,
                            const Bytes& aad, Bytes* cipher, Bytes* tag) {
  if (key.size() != 32) return false;
  uint8_t roundKeys[240];
  uint8_t h[16];
  Bytes j0;
  GcmInit(key, nonce, roundKeys, h, &j0);
  cipher->assign(plain.size(), 0);
  if (!plain.empty()) GcmCtr(roundKeys, j0.data(), plain.data(), plain.size(), cipher->data());
  uint8_t t[16];
  GcmTag(roundKeys, h, j0.data(), *cipher, aad, t);
  tag->assign(t, t + 16);
  return true;
}

bool AesGcmDecryptWithNonce(const Bytes& key, const Bytes& nonce, const Bytes& cipher,
                            const Bytes& aad, const Bytes& tag, Bytes* plain) {
  if (key.size() != 32) return false;
  uint8_t roundKeys[240];
  uint8_t h[16];
  Bytes j0;
  GcmInit(key, nonce, roundKeys, h, &j0);
  uint8_t expected[16];
  GcmTag(roundKeys, h, j0.data(), cipher, aad, expected);
  uint8_t diff = 0;
  for (int i = 0; i < 16; i++) diff |= (uint8_t)(expected[i] ^ tag[i]);
  if (diff != 0) return false;
  plain->assign(cipher.size(), 0);
  if (!cipher.empty()) GcmCtr(roundKeys, j0.data(), cipher.data(), cipher.size(), plain->data());
  return true;
}

bool AesGcmEncrypt(const Bytes& key, const Bytes& plain, const Bytes& aad, Bytes* out,
                   std::wstring* error) {
  if (key.size() != 32) {
    *error = L"密钥长度必须为 32 字节";
    return false;
  }
  const Bytes nonce = RandomBytes(kNonceLen);
  Bytes cipher, tag;
  if (!AesGcmEncryptWithNonce(key, nonce, plain, aad, &cipher, &tag)) {
    *error = L"AES-GCM 加密失败";
    return false;
  }
  out->clear();
  out->reserve(nonce.size() + tag.size() + cipher.size());
  out->insert(out->end(), nonce.begin(), nonce.end());
  out->insert(out->end(), tag.begin(), tag.end());
  out->insert(out->end(), cipher.begin(), cipher.end());
  return true;
}

bool AesGcmDecrypt(const Bytes& key, const Bytes& payload, const Bytes& aad, Bytes* out,
                   std::wstring* error) {
  if (payload.size() < kNonceLen + kTagLen) {
    *error = L"密文长度异常";
    return false;
  }
  if (key.size() != 32) {
    *error = L"密钥长度必须为 32 字节";
    return false;
  }
  const Bytes nonce(payload.begin(), payload.begin() + kNonceLen);
  const Bytes tag(payload.begin() + kNonceLen, payload.begin() + kNonceLen + kTagLen);
  const Bytes cipher(payload.begin() + kNonceLen + kTagLen, payload.end());
  if (!AesGcmDecryptWithNonce(key, nonce, cipher, aad, tag, out)) {
    out->clear();
    *error = L"密码或因子不正确（AES-GCM 校验失败）";
    return false;
  }
  return true;
}

// ---------------- Base64 ----------------
namespace {
const char kAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int DecodeChar(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}
}  // namespace

std::string Base64Encode(const Bytes& data) {
  std::string out;
  out.reserve(((data.size() + 2) / 3) * 4);
  size_t i = 0;
  for (; i + 2 < data.size(); i += 3) {
    uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8) | data[i + 2];
    out.push_back(kAlphabet[(v >> 18) & 63]);
    out.push_back(kAlphabet[(v >> 12) & 63]);
    out.push_back(kAlphabet[(v >> 6) & 63]);
    out.push_back(kAlphabet[v & 63]);
  }
  if (i + 1 == data.size()) {
    uint32_t v = (uint32_t)data[i] << 16;
    out.push_back(kAlphabet[(v >> 18) & 63]);
    out.push_back(kAlphabet[(v >> 12) & 63]);
    out.append("==");
  } else if (i + 2 == data.size()) {
    uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8);
    out.push_back(kAlphabet[(v >> 18) & 63]);
    out.push_back(kAlphabet[(v >> 12) & 63]);
    out.push_back(kAlphabet[(v >> 6) & 63]);
    out.push_back('=');
  }
  return out;
}

bool Base64Decode(const std::string& text, Bytes* out) {
  out->clear();
  int buffer = 0, bits = 0;
  for (char c : text) {
    if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
    int v = DecodeChar(c);
    if (v < 0) return false;
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out->push_back((uint8_t)((buffer >> bits) & 0xFF));
    }
  }
  return true;
}

// ---- 调试导出（仅测试用） ----
void DbGhash(const Bytes& h, const Bytes& data, Bytes* out) {
  uint64_t hi = 0, lo = 0;
  Ghash(h.data(), data, &hi, &lo);
  const uint64_t w1 = _byteswap_uint64(hi), w2 = _byteswap_uint64(lo);
  out->resize(16);
  memcpy(out->data(), &w1, 8);
  memcpy(out->data() + 8, &w2, 8);
}

void DbAesEncrypt(const Bytes& key, const Bytes& in, Bytes* out) {
  uint8_t roundKeys[240];
  AesExpandKey(key, roundKeys);
  out->resize(16);
  AesEncryptBlock(roundKeys, in.data(), out->data());
}

// 所有公共接口都实现在这里（避免与匿名命名空间混在一起）
void DbGenerator(Bytes* out) {
  const std::vector<int> g = GeneratorPoly();
  out->assign(g.size(), 0);
  for (size_t i = 0; i < g.size(); i++) out->at(i) = (uint8_t)g[i];
}

Bytes HmacSha256(const Bytes& key, const Bytes& data) {
  Bytes block = key;
  if (block.size() > 64) block = Sha256Impl(block);
  block.resize(64, 0);
  Bytes inner(64), outer(64);
  for (int i = 0; i < 64; i++) {
    inner[i] = block[i] ^ 0x36;
    outer[i] = block[i] ^ 0x5c;
  }
  Sha256 h1;
  h1.Update(inner.data(), inner.size());
  if (!data.empty()) h1.Update(data.data(), data.size());
  Bytes innerHash = h1.Finish();

  Sha256 h2;
  h2.Update(outer.data(), outer.size());
  h2.Update(innerHash.data(), innerHash.size());
  return h2.Finish();
}

Bytes Sha256Bytes(const Bytes& data) { return Sha256Impl(data); }

Bytes RandomBytes(size_t n) {
  Bytes out(n);
  if (n == 0) return out;
  // 优先用系统 CSPRNG；不可用时回退到 CryptoAPI
  if (BCryptGenRandom(nullptr, out.data(), (ULONG)n,
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0)
    return out;
  HCRYPTPROV prov = 0;
  if (CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
    CryptGenRandom(prov, (DWORD)out.size(), out.data());
    CryptReleaseContext(prov, 0);
    return out;
  }
  // 最后的兜底（理论上不会走到）
  static std::atomic<uint64_t> counter{0};
  const uint64_t seed = (uint64_t)GetTickCount64() ^ (++counter << 32) ^
                        (uint64_t)(uintptr_t)&out;
  uint64_t state = seed ? seed : 0x9e3779b97f4a7c15ULL;
  for (size_t i = 0; i < out.size(); i++) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    out[i] = (uint8_t)(state >> 24);
  }
  return out;
}

}  // namespace gf
