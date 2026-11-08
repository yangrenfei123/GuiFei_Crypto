// ============================================================
//  Windows 密码学接口兼容探测
//  有些环境（精简系统 / LSA 未启动）里 bcrypt 的算法提供程序不可用，
//  测试程序会探测出可用的实现，生成 define 写进二进制。
// ============================================================
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <cstdio>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

int main() {
  // 1) BCrypt 打开 AES
  BCRYPT_ALG_HANDLE h = nullptr;
  NTSTATUS st = BCryptOpenAlgorithmProvider(&h, L"AES", nullptr, 0);
  printf("BCryptOpenAlgorithmProvider(AES): 0x%08lx\n", (unsigned long)st);
  if (h) {
    char mode[32] = "ChainingModeGCM";
    st = BCryptSetProperty(h, BCRYPT_CHAINING_MODE, (PUCHAR)mode, sizeof(mode), 0);
    printf("BCryptSetProperty(ChainingModeGCM): 0x%08lx\n", (unsigned long)st);
    BCryptCloseAlgorithmProvider(h, 0);
  }

  // 2) BCrypt 打开 SHA256 / HMAC
  st = BCryptOpenAlgorithmProvider(&h, L"SHA256", nullptr, 0);
  printf("BCryptOpenAlgorithmProvider(SHA256): 0x%08lx\n", (unsigned long)st);
  if (h) BCryptCloseAlgorithmProvider(h, 0);
  st = BCryptOpenAlgorithmProvider(&h, L"HMAC", nullptr, 0);
  printf("BCryptOpenAlgorithmProvider(HMAC): 0x%08lx\n", (unsigned long)st);
  if (h) BCryptCloseAlgorithmProvider(h, 0);

  // 3) BCryptGenRandom
  unsigned char random[16]{};
  st = BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  printf("BCryptGenRandom: 0x%08lx\n", (unsigned long)st);

  // 4) CryptoAPI
  HCRYPTPROV prov = 0;
  BOOL ok = CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
  printf("CryptAcquireContextW(PROV_RSA_AES): %d err=%lu\n", ok, GetLastError());
  if (ok) {
    BYTE buf[16]{};
    printf("CryptGenRandom: %d\n", CryptGenRandom(prov, sizeof(buf), buf));
    HCRYPTHASH sha = 0;
    printf("CryptCreateHash(SHA256): %d err=%lu\n",
           CryptCreateHash(prov, CALG_SHA_256, 0, 0, &sha), GetLastError());
    if (sha) CryptDestroyHash(sha);
    CryptReleaseContext(prov, 0);
  }

  // 5) BCryptGenRandom 底层接口（ntdll ProcessPrng）
  typedef BOOL(WINAPI * ProcessPrngFn)(PBYTE, SIZE_T);
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  auto processPrng = (ProcessPrngFn)GetProcAddress(ntdll, "ProcessPrng");
  printf("ntdll ProcessPrng: %s\n", processPrng ? "available" : "missing");

  return 0;
}
