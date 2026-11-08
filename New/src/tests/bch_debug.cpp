#include "core/common.h"

#include "core/crypto.h"

#include <cstdio>

namespace gf {
void DbBchTrace(const Bytes& codeword16, Bytes* out);
}  // namespace gf

using namespace gf;

int wmain() {
  // 单比特码字：只有 x^0 位为 1
  Bytes bits(16, 0);
  bits[0] = 0x01;  // 只有第 0 位（x^0）为 1
  Bytes trace;
  DbBchTrace(bits, &trace);
  printf("x^0 codeword syndromes:");
  for (int i = 0; i < 6; i++) printf(" %02x", trace[i]);
  printf("\n");

  // 只有 x^1 位
  Bytes bits2(16, 0);
  bits2[0] = 0x02;
  DbBchTrace(bits2, &trace);
  printf("x^1 codeword syndromes:");
  for (int i = 0; i < 6; i++) printf(" %02x", trace[i]);
  printf("\n");

  // 只有 x^3 位
  Bytes bits3(16, 0);
  bits3[0] = 0x08;
  DbBchTrace(bits3, &trace);
  printf("x^3 codeword syndromes:");
  for (int i = 0; i < 6; i++) printf(" %02x", trace[i]);
  printf("\n");
  // 期望：x^0 -> 1，x^1 -> alpha(=2)，x^3 -> 8
  return 0;
}
