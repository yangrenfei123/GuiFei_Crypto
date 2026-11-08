#include "core/common.h"

#include "core/crypto.h"

#include <cstdio>

using namespace gf;

namespace gf {
void DbGhash(const Bytes& h, const Bytes& data, Bytes* out);
void DbAesEncrypt(const Bytes& key, const Bytes& in, Bytes* out);
}  // namespace gf

int wmain() {
  Bytes key(32);
  for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;

  Bytes h(16, 0);
  h[0] = 0x66;
  h[15] = 0x63;
  Bytes data(16, 0);
  data[0] = 0x80;
  Bytes ghashOut;
  DbGhash(h, data, &ghashOut);
  printf("ghash_80=");
  for (auto c : ghashOut) printf("%02x", c);
  printf("\n");

  Bytes block(16);
  for (int i = 0; i < 16; i++) block[i] = (uint8_t)(0x10 + i);
  Bytes aesOut;
  DbAesEncrypt(key, block, &aesOut);
  printf("aes_block=");
  for (auto c : aesOut) printf("%02x", c);
  printf("\n");
  return 0;
}
