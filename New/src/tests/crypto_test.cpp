// scrypt / BCH / Base64 对照工具（供 Python 交叉验证使用）
#include "core/common.h"

#include "core/crypto.h"

#include <cstdio>
#include <string>

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

static Bytes FromHex(const std::string& s) {
  Bytes out;
  for (size_t i = 0; i + 1 < s.size(); i += 2)
    out.push_back((uint8_t)strtoul(s.substr(i, 2).c_str(), nullptr, 16));
  return out;
}

static void WriteFile(const wchar_t* path, const std::string& data) {
  FILE* fp = _wfopen(path, L"wb");
  if (!fp) return;
  fwrite(data.data(), 1, data.size(), fp);
  fclose(fp);
}

int wmain(int argc, wchar_t** argv) {
  if (argc < 2) {
    wprintf(L"usage: crypto_test <command> ...\n");
    return 0;
  }
  const std::wstring cmd = argv[1];
  if (cmd == L"scrypt" && argc >= 5) {
    Bytes pwd = FromHex(WideToUtf8(argv[2]));
    Bytes salt = FromHex(WideToUtf8(argv[3]));
    Bytes out = Scrypt(pwd, salt);
    WriteFile(argv[4], Hex(out));
    return 0;
  }
  if (cmd == L"scryptN" && argc >= 8) {
    Bytes pwd = FromHex(WideToUtf8(argv[2]));
    Bytes salt = FromHex(WideToUtf8(argv[3]));
    Bytes out = Scrypt(pwd, salt, (uint32_t)_wtoi(argv[4]), (uint32_t)_wtoi(argv[5]),
                       (uint32_t)_wtoi(argv[6]));
    WriteFile(argv[7], Hex(out));
    return 0;
  }
  if (cmd == L"bch-enc" && argc >= 4) {
    Bytes key = FromHex(WideToUtf8(argv[2]));
    Bytes out = BchEncode64(key);
    WriteFile(argv[3], Hex(out));
    return 0;
  }
  if (cmd == L"bch-dec" && argc >= 4) {
    Bytes cw = FromHex(WideToUtf8(argv[2]));
    Bytes out = BchDecode64(cw);
    WriteFile(argv[3], Hex(out));
    return 0;
  }
  if (cmd == L"b64-enc" && argc >= 4) {
    Bytes data = FromHex(WideToUtf8(argv[2]));
    WriteFile(argv[3], Base64Encode(data));
    return 0;
  }
  if (cmd == L"b64-dec" && argc >= 4) {
    Bytes out;
    if (!Base64Decode(WideToUtf8(argv[2]), &out)) return 2;
    WriteFile(argv[3], Hex(out));
    return 0;
  }
  wprintf(L"unknown command\n");
  return 1;
}
