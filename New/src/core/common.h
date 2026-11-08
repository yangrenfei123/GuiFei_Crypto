// ============================================================
//  GuiFei C++ 重写版 —— 公共头文件
//  目标：零 Python 依赖，纯 Win32 + D3D11 + WebView2
// ============================================================
#pragma once

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <windowsx.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sal.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <objbase.h>
#include <ws2def.h>
#include <sal.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <d3d11.h>
#include <dxgi.h>
#include <wrl/client.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ws2_32.lib")

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#ifndef NCrypt
#pragma comment(lib, "ncrypt.lib")
#endif

using Microsoft::WRL::ComPtr;

// ---------------- 全局常量（与 Python 版保持一致） ----------------
namespace gf {

constexpr char kMagic[] = "guifeiCRYPT3";
constexpr size_t kMagicLen = 12;
constexpr uint8_t kVersion = 3;
constexpr size_t kAesKeyLen = 32;
constexpr size_t kNonceLen = 12;
constexpr size_t kSaltLen = 16;
constexpr size_t kTagLen = 16;

// scrypt: N=2^14, r=8, p=1
constexpr uint32_t kScryptN = 1u << 14;
constexpr uint32_t kScryptR = 8;
constexpr uint32_t kScryptP = 1;

constexpr uint8_t kFactorPassword = 0x01;
constexpr uint8_t kFactorGrid = 0x02;
constexpr uint8_t kFactorFace = 0x04;
constexpr uint8_t kFactorVoice = 0x08;

constexpr int kGridSize = 5;
constexpr int kGridPointSize = 24;
constexpr int kGridSpacing = 8;

constexpr double kFaceSimilarityThreshold = 0.75;
constexpr double kVoiceEmbeddingThreshold = 0.75;

// BCH(127,64) 的参数定义在 crypto.h

constexpr const wchar_t* kAppName = L"GuìFē! :) 超级加密工具";
constexpr const wchar_t* kAppVersion = L"v18.1.0 (native)";

// 简易断言式日志
void Log(const wchar_t* fmt, ...);
void LogError(const wchar_t* fmt, ...);

std::wstring Utf8ToWide(const std::string& s);
std::string WideToUtf8(const std::wstring& s);

}  // namespace gf
