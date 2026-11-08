#include "core/common.h"

#include "core/crypto.h"

#include <cstdio>

using namespace gf;


int wmain() {
  Bytes data = {0x61, 0x62, 0x63};
  Bytes hash = Sha256Bytes(data);
  printf("sha256(abc)=");
  for (auto c : hash) printf("%02x", c);
  printf("\n");

  Bytes key(32);
  for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
  Bytes nonce(12);
  for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)i;
  Bytes aad = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'};
  Bytes plain(40);
  for (int i = 0; i < 40; i++) plain[i] = (uint8_t)i;

  Bytes cipher, tag;
  if (AesGcmEncryptWithNonce(key, nonce, plain, aad, &cipher, &tag)) {
    printf("ct=");
    for (auto c : cipher) printf("%02x", c);
    printf("\ntag=");
    for (auto c : tag) printf("%02x", c);
    printf("\n");

    Bytes back;
    printf("roundtrip=%d\n",
           AesGcmDecryptWithNonce(key, nonce, cipher, aad, tag, &back) && back == plain);
  }
  return 0;
}

