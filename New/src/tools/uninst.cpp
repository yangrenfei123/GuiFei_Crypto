// GuifeiCrypto 卸载程序：
//   1) 把自身复制到临时目录再运行，避免“卸载程序占用安装目录”导致删不干净
//   2) 结束正在运行的主程序（含托盘后台）
//   3) 清理右键菜单、开机启动、卸载项、快捷方式、配置
//   4) 删除整个安装目录
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <cwchar>
#include <string>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "user32.lib")

namespace {

std::wstring Join(const std::wstring& a, const std::wstring& b) {
  if (a.empty()) return b;
  if (a.back() == L'\\') return a + b;
  return a + L"\\" + b;
}

std::wstring ExePath() {
  wchar_t buf[32768];
  DWORD n = GetModuleFileNameW(nullptr, buf, 32768);
  return std::wstring(buf, n ? n : 0);
}

std::wstring ExeDir() {
  std::wstring p = ExePath();
  size_t pos = p.find_last_of(L"\\/");
  return pos == std::wstring::npos ? p : p.substr(0, pos);
}

std::wstring TempDir() {
  wchar_t buf[MAX_PATH];
  DWORD n = GetTempPathW(MAX_PATH, buf);
  return std::wstring(buf, n ? n : 0);
}

std::wstring KnownFolder(REFKNOWNFOLDERID id) {
  PWSTR raw = nullptr;
  if (SHGetKnownFolderPath(id, 0, nullptr, &raw) != S_OK) return L"";
  std::wstring value(raw);
  CoTaskMemFree(raw);
  return value;
}

bool DeleteTree(const std::wstring& path) {
  WIN32_FIND_DATAW fd;
  HANDLE find = FindFirstFileW(Join(path, L"*").c_str(), &fd);
  if (find == INVALID_HANDLE_VALUE) return RemoveDirectoryW(path.c_str()) != 0;

  do {
    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
    std::wstring full = Join(path, fd.cFileName);
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      DeleteTree(full);
    } else {
      SetFileAttributesW(full.c_str(), FILE_ATTRIBUTE_NORMAL);
      DeleteFileW(full.c_str());
    }
  } while (FindNextFileW(find, &fd));
  FindClose(find);
  SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
  return RemoveDirectoryW(path.c_str()) != 0;
}

int KillProcesses(const wchar_t* exeName) {
  int killed = 0;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return 0;
  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof(pe);
  if (Process32FirstW(snap, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, exeName) != 0) continue;
      if (pe.th32ProcessID == GetCurrentProcessId()) continue;
      HANDLE proc = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pe.th32ProcessID);
      if (proc) {
        TerminateProcess(proc, 0);
        WaitForSingleObject(proc, 4000);
        CloseHandle(proc);
        killed++;
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return killed;
}

void DeleteShellMenus() {
  const wchar_t* decryptExts[] = {L".guifei", L".guifeinext", L".guifeitext", L".msc"};
  for (const wchar_t* ext : decryptExts) {
    std::wstring key = std::wstring(L"Software\\Classes\\SystemFileAssociations\\") + ext +
                       L"\\shell\\GuifeiDecrypt";
    RegDeleteTreeW(HKEY_CURRENT_USER, key.c_str());
  }

  HKEY root = nullptr;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\SystemFileAssociations", 0,
                    KEY_READ, &root) == ERROR_SUCCESS) {
    wchar_t name[256];
    for (DWORD index = 0;; index++) {
      DWORD length = 255;
      if (RegEnumKeyExW(root, index, name, &length, nullptr, nullptr, nullptr, nullptr) !=
          ERROR_SUCCESS)
        break;
      std::wstring key = std::wstring(L"Software\\Classes\\SystemFileAssociations\\") + name +
                         L"\\shell\\GuifeiEncrypt";
      RegDeleteTreeW(HKEY_CURRENT_USER, key.c_str());
    }
    RegCloseKey(root);
  }
}

void RunHidden(const std::wstring& command, const std::wstring& workDir) {
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION pi{};
  std::wstring mutableCommand = command;
  if (CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, FALSE,
                     CREATE_NO_WINDOW, nullptr, workDir.c_str(), &si, &pi)) {
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
  }
}

}  // namespace

int wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
  CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

  int argc = 0;
  LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  bool silent = false;
  bool relocated = false;
  std::wstring dirArg;
  for (int i = 1; i < argc; i++) {
    std::wstring arg = argv[i];
    if (_wcsicmp(arg.c_str(), L"/S") == 0) silent = true;
    if (_wcsicmp(arg.c_str(), L"--relocated") == 0) relocated = true;
    if (_wcsicmp(arg.c_str(), L"--dir") == 0 && i + 1 < argc) dirArg = argv[++i];
  }
  if (argv) LocalFree(argv);

  if (!relocated) {
    std::wstring dir = ExeDir();
    std::wstring self = ExePath();
    std::wstring tempExe =
        Join(TempDir(), L"guifei_uninst_" + std::to_wstring(GetCurrentProcessId()) + L".exe");
    if (CopyFileW(self.c_str(), tempExe.c_str(), FALSE)) {
      std::wstring cmd = L"\"" + tempExe + L"\" --relocated --dir \"" + dir + L"\"";
      if (silent) cmd += L" /S";
      RunHidden(cmd, TempDir());
      CoUninitialize();
      return 0;
    }
    // 复制失败时退化为原地卸载（跳过自身）
    relocated = true;
    dirArg = dir;
  }

  std::wstring dir = dirArg.empty() ? ExeDir() : dirArg;
  std::wstring self = ExePath();

  Sleep(700);  // 等待原进程退出

  if (!silent) {
    std::wstring text =
        L"确定要卸载 GuifeiCrypto 吗？\n\n"
        L"安装目录：" + dir +
        L"\n\n卸载会先关闭正在运行的程序，再删除程序和右键菜单。";
    if (MessageBoxW(nullptr, text.c_str(), L"卸载 GuifeiCrypto",
                    MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES) {
      DeleteFileW(self.c_str());
      CoUninitialize();
      return 0;
    }
  }

  KillProcesses(L"GuifeiCrypto.exe");
  KillProcesses(L"GuifeiCrypto_Full.exe");
  Sleep(600);

  DeleteShellMenus();
  RegDeleteTreeW(HKEY_CURRENT_USER,
                 L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\GuifeiCrypto");
  HKEY run = nullptr;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    0, KEY_SET_VALUE, &run) == ERROR_SUCCESS) {
    RegDeleteValueW(run, L"GuifeiCrypto");
    RegCloseKey(run);
  }

  std::wstring desktop = KnownFolder(FOLDERID_Desktop);
  if (!desktop.empty()) DeleteFileW(Join(desktop, L"GuifeiCrypto.lnk").c_str());

  std::wstring programs = KnownFolder(FOLDERID_Programs);
  if (!programs.empty()) DeleteTree(Join(programs, L"GuifeiCrypto"));

  std::wstring appdata = KnownFolder(FOLDERID_RoamingAppData);
  if (!appdata.empty()) DeleteTree(Join(appdata, L"GuifeiCrypto"));

  DeleteTree(dir);

  // 延时清理临时副本并再删一次目录，防止个别文件短暂占用
  std::wstring cleanup = L"cmd.exe /c ping -n 3 127.0.0.1 >nul & del /f /q \"" + self +
                         L"\" & rmdir /s /q \"" + dir + L"\"";
  RunHidden(cleanup, TempDir());

  if (!silent) {
    MessageBoxW(nullptr, L"卸载完成。", L"GuifeiCrypto", MB_OK | MB_ICONINFORMATION);
  }
  CoUninitialize();
  return 0;
}
