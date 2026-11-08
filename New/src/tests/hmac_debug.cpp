// 临时调试：Salsa / BlockMix 对照
#include "core/common.h"

#include "core/crypto.h"

#include <cstdio>
#include <string>

namespace gf {
Bytes DbHmac(const Bytes& key, const Bytes& data);
void DbSalsa(const Bytes& in, Bytes* out);
void DbBlockMix(const Bytes& in, int r, Bytes* out);
}  // namespace gf

using namespace gf;

static std::string Hex(const Bytes& b) {
  static const char* digits = "0123456789abcdef";
  std::string s;
  for (uint8_t c : b) {
    s.push_back(digits[c >> 4]);
    s.push_back(digits[c & 15]);
  }
  return s;
}

int wmain() {
  Bytes salsaIn(64);
  for (int i = 0; i < 16; i++) salsaIn[i * 4] = (uint8_t)i;
  Bytes salsaOut;
  DbSalsa(salsaIn, &salsaOut);
  printf("salsa=%s\n", Hex(salsaOut).c_str());

  Bytes bmIn(128);
  for (size_t i = 0; i < bmIn.size(); i++) bmIn[i] = (uint8_t)i;
  Bytes bmOut;
  DbBlockMix(bmIn, 1, &bmOut);
  printf("blockmix=%s\n", Hex(bmOut).c_str());
  return 0;
}
