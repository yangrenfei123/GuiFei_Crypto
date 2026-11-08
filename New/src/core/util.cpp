// ============================================================
//  公共工具实现
// ============================================================
#include "common.h"

#include <cstdarg>

namespace gf {

namespace {
std::wstring g_logPath;
std::mutex g_logMutex;
bool g_logReady = false;

void InitLog() {
  wchar_t buffer[MAX_PATH]{};
  const DWORD n = ::GetTempPathW(MAX_PATH, buffer);
  std::wstring dir(buffer, n);
  g_logPath = dir + L"guifei_native_error.log";
  g_logReady = true;
}

void WriteLog(const wchar_t* level, const wchar_t* message) {
  if (!g_logReady) InitLog();
  SYSTEMTIME st;
  ::GetLocalTime(&st);
  wchar_t line[4096]{};
  _snwprintf_s(line, _TRUNCATE,
               L"%04d-%02d-%02d %02d:%02d:%02d [%s] %s\r\n", st.wYear, st.wMonth,
               st.wDay, st.wHour, st.wMinute, st.wSecond, level, message);
  std::lock_guard<std::mutex> lock(g_logMutex);
  FILE* fp = nullptr;
  if (_wfopen_s(&fp, g_logPath.c_str(), L"a, ccs=UTF-8") == 0 && fp) {
    fputws(line, fp);
    fclose(fp);
  }
}
}  // namespace

void Log(const wchar_t* fmt, ...) {
  wchar_t message[3500]{};
  va_list args;
  va_start(args, fmt);
  _vsnwprintf_s(message, _TRUNCATE, fmt, args);
  va_end(args);
  WriteLog(L"INFO", message);
}

void LogError(const wchar_t* fmt, ...) {
  wchar_t message[3500]{};
  va_list args;
  va_start(args, fmt);
  _vsnwprintf_s(message, _TRUNCATE, fmt, args);
  va_end(args);
  WriteLog(L"ERROR", message);
}

std::wstring Utf8ToWide(const std::string& s) {
  if (s.empty()) return std::wstring();
  int len = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
  std::wstring out(len, L'\0');
  ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), len);
  return out;
}

std::string WideToUtf8(const std::wstring& s) {
  if (s.empty()) return std::string();
  int len = ::WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr,
                                  0, nullptr, nullptr);
  std::string out(len, '\0');
  ::WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), len,
                        nullptr, nullptr);
  return out;
}

}  // namespace gf
