using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace SetupApp;

public sealed class PayloadInfo
{
    public string Mode { get; set; } = "";
    public string ExeName { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string ShortcutName { get; set; } = "";
    public string Version { get; set; } = "";
    public string Note { get; set; } = "";
    public long Offset { get; set; }
    public long Length { get; set; }
}

public sealed record ProgressInfo(double Fraction, string Message);

public static class InstallerCore
{
    private const string Magic = "GFSTUP01";
    private const int TrailerSize = 12;

    public static string DefaultInstallDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Programs", "GuifeiCrypto");

    public static PayloadInfo? TryReadPayloadInfo(string exePath)
    {
        try
        {
            using var fs = File.OpenRead(exePath);
            if (fs.Length < TrailerSize) return null;
            var trailer = new byte[TrailerSize];
            fs.Seek(-TrailerSize, SeekOrigin.End);
            fs.ReadExactly(trailer);
            if (Encoding.ASCII.GetString(trailer, 0, 8) != Magic) return null;
            int jsonLen = BitConverter.ToInt32(trailer, 8);
            if (jsonLen <= 0 || jsonLen > 64 * 1024) return null;
            long jsonOffset = fs.Length - TrailerSize - jsonLen;
            if (jsonOffset < 0) return null;
            fs.Seek(jsonOffset, SeekOrigin.Begin);
            var buf = new byte[jsonLen];
            fs.ReadExactly(buf);
            var info = JsonSerializer.Deserialize<PayloadInfo>(buf,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (info == null || string.IsNullOrEmpty(info.ExeName)) return null;
            info.Offset = jsonOffset - info.Length;
            if (info.Offset < 0) return null;
            return info;
        }
        catch
        {
            return null;
        }
    }

    public static void Install(
        PayloadInfo info,
        string exePath,
        string destDir,
        IProgress<ProgressInfo> progress,
        CancellationToken token,
        bool desktopShortcut,
        bool startMenuShortcut)
    {
        Directory.CreateDirectory(destDir);
        using var fs = File.OpenRead(exePath);
        using var bounded = new BoundedStream(fs, info.Offset, info.Length);
        using var zip = new ZipArchive(bounded, ZipArchiveMode.Read);
        long total = 0;
        foreach (var e in zip.Entries) total += Math.Max(e.Length, 1);
        if (total <= 0) total = 1;
        long done = 0;
        string destRoot = Path.GetFullPath(destDir);

        foreach (var entry in zip.Entries)
        {
            token.ThrowIfCancellationRequested();
            string relative = entry.FullName.Replace('/', Path.DirectorySeparatorChar);
            string target = Path.GetFullPath(Path.Combine(destDir, relative));
            if (!target.StartsWith(destRoot, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("压缩包内包含非法路径");
            if (entry.FullName.EndsWith('/'))
            {
                Directory.CreateDirectory(target);
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            using (var input = entry.Open())
            using (var output = File.Create(target))
            {
                var buffer = new byte[1 << 20];
                int read;
                long entryDone = 0;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    token.ThrowIfCancellationRequested();
                    output.Write(buffer, 0, read);
                    entryDone += read;
                    done += read;
                    progress.Report(new ProgressInfo(
                        Math.Clamp((double)done / total, 0, 0.96),
                        $"正在释放 {Path.GetFileName(target)}"));
                }
                if (entryDone == 0) done += 1;
            }
        }

        progress.Report(new ProgressInfo(0.97, "正在创建快捷方式…"));
        string exeTarget = Path.Combine(destDir, info.ExeName);
        if (desktopShortcut)
        {
            CreateShortcut(
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), info.ShortcutName + ".lnk"),
                exeTarget, destDir);
        }
        if (startMenuShortcut)
        {
            try
            {
                string programs = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Programs), "GuifeiCrypto");
                Directory.CreateDirectory(programs);
                CreateShortcut(Path.Combine(programs, info.ShortcutName + ".lnk"), exeTarget, destDir);
            }
            catch
            {
                // 开始菜单不可写时忽略，不影响安装
            }
        }

        progress.Report(new ProgressInfo(0.99, "正在写入卸载信息…"));
        WriteUninstallEntry(info, destDir, exeTarget);
        progress.Report(new ProgressInfo(0.995, "正在注册右键菜单…"));
        RegisterShell(exeTarget);
        progress.Report(new ProgressInfo(1.0, "安装完成"));
    }

    private static void RegisterShell(string exePath)
    {
        try
        {
            var psi = new ProcessStartInfo(exePath, "--register-shell")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(exePath)!
            };
            using var proc = Process.Start(psi);
            proc?.WaitForExit(20000);
        }
        catch
        {
            // 注册失败不影响安装
        }
    }

    public static void CreateShortcut(string lnkPath, string target, string workDir)
    {
        try
        {
            var shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType == null) return;
            dynamic shell = Activator.CreateInstance(shellType)!;
            dynamic lnk = shell.CreateShortcut(lnkPath);
            lnk.TargetPath = target;
            lnk.WorkingDirectory = workDir;
            lnk.IconLocation = target + ",0";
            lnk.Description = "GuifeiCrypto";
            lnk.Save();
        }
        catch
        {
            // 快捷方式失败不影响主流程
        }
    }

    private static void WriteUninstallEntry(PayloadInfo info, string destDir, string exeTarget)
    {
        // 用 reg.exe 写入：部分环境对 .NET 直接写 Uninstall 键有额外的注册表限制
        const string key = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\GuifeiCrypto";
        string uninstall = $"\"{Path.Combine(destDir, "uninst.exe")}\"";
        try
        {
            RunReg("add", key, "/v", "DisplayName", "/d", info.DisplayName, "/f");
            RunReg("add", key, "/v", "DisplayVersion", "/d", info.Version, "/f");
            RunReg("add", key, "/v", "InstallLocation", "/d", destDir, "/f");
            RunReg("add", key, "/v", "DisplayIcon", "/d", exeTarget, "/f");
            RunReg("add", key, "/v", "Publisher", "/d", "GuifeiCrypto", "/f");
            RunReg("add", key, "/v", "NoModify", "/t", "REG_DWORD", "/d", "1", "/f");
            RunReg("add", key, "/v", "NoRepair", "/t", "REG_DWORD", "/d", "1", "/f");
            RunReg("add", key, "/v", "UninstallString", "/d", uninstall, "/f");
            try
            {
                long size = 0;
                foreach (var f in Directory.EnumerateFiles(destDir, "*", SearchOption.AllDirectories))
                    size += new FileInfo(f).Length;
                RunReg("add", key, "/v", "EstimatedSize", "/t", "REG_DWORD",
                    "/d", Math.Min(size / 1024, int.MaxValue).ToString(), "/f");
            }
            catch
            {
                // 体积信息失败不影响安装
            }
        }
        catch
        {
            // 卸载项写入失败不影响安装
        }
    }

    private static void RunReg(params string[] args)
    {
        var psi = new ProcessStartInfo("reg.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var arg in args) psi.ArgumentList.Add(arg);
        using var proc = Process.Start(psi);
        proc?.WaitForExit(15000);
    }
}

public sealed class BoundedStream : Stream
{
    private readonly Stream _base;
    private readonly long _start;
    private readonly long _length;
    private long _position;

    public BoundedStream(Stream baseStream, long start, long length)
    {
        _base = baseStream;
        _start = start;
        _length = length;
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => _length;

    public override long Position
    {
        get => _position;
        set => _position = value;
    }

    public override int Read(byte[] buffer, int offset, int count)
        => Read(new Span<byte>(buffer, offset, count));

    public override int Read(Span<byte> buffer)
    {
        long remain = _length - _position;
        if (remain <= 0) return 0;
        int toRead = (int)Math.Min(buffer.Length, remain);
        _base.Position = _start + _position;
        int read = _base.Read(buffer[..toRead]);
        _position += read;
        return read;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        long next = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => _length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin))
        };
        _position = Math.Clamp(next, 0, _length);
        return _position;
    }

    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
