// minimal probe for bcrypt.h include issues
#include <windows.h>
#include <bcrypt.h>

int main() {
  BCRYPT_ALG_HANDLE h = nullptr;
  BCryptOpenAlgorithmProvider(&h, L"AES", nullptr, 0);
  return 0;
}
