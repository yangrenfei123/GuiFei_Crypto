using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;

namespace SetupApp;

public partial class MainWindow : Window
{
    private PayloadInfo? _info;
    private string? _installedExe;
    private int _step;
    private bool _installing;
    private bool _finished;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        string? exePath = Environment.ProcessPath;
        _info = exePath == null ? null : InstallerCore.TryReadPayloadInfo(exePath);
        if (_info == null)
        {
            HeaderTitle.Text = "安装包不完整";
            HeaderSubtitle.Text = "没有找到内置的安装数据";
            NextButton.IsEnabled = false;
            return;
        }

        HeaderTitle.Text = _info.DisplayName;
        HeaderSubtitle.Text = $"版本 {_info.Version} · {_info.Note}";
        ModeText.Text = _info.Mode;
        InstallDirBox.Text = InstallerCore.DefaultInstallDir;
        UpdateDiskInfo();
        ShowStep(0);
    }

    private void UpdateDiskInfo()
    {
        try
        {
            string root = Path.GetPathRoot(Path.GetFullPath(InstallDirBox.Text)) ?? "C:\\";
            var drive = new DriveInfo(root);
            DiskInfoText.Text = $"该磁盘剩余空间：{drive.AvailableFreeSpace / 1024.0 / 1024.0 / 1024.0:0.0} GB";
        }
        catch
        {
            DiskInfoText.Text = string.Empty;
        }
    }

    private void ShowStep(int step)
    {
        _step = step;
        WelcomePanel.Visibility = step == 0 ? Visibility.Visible : Visibility.Collapsed;
        PathPanel.Visibility = step == 1 ? Visibility.Visible : Visibility.Collapsed;
        ProgressPanel.Visibility = step == 2 ? Visibility.Visible : Visibility.Collapsed;
        FinishPanel.Visibility = step == 3 ? Visibility.Visible : Visibility.Collapsed;

        BackButton.IsEnabled = step == 1 && !_installing;
        NextButton.Content = step == 1 ? "安装" : step == 3 ? "完成" : "下一步";
        NextButton.IsEnabled = !_installing;
        CancelButton.IsEnabled = !_installing || step == 2;
        CancelButton.Content = step == 3 ? "关闭" : "取消";
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title = "选择安装位置",
            InitialDirectory = Directory.Exists(InstallDirBox.Text)
                ? InstallDirBox.Text
                : Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
        };
        if (dialog.ShowDialog() == true)
        {
            InstallDirBox.Text = dialog.FolderName;
            UpdateDiskInfo();
        }
    }

    private void Back_Click(object sender, RoutedEventArgs e)
    {
        if (_installing) return;
        if (_step == 1) ShowStep(0);
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        if (_installing)
        {
            var result = MessageBox.Show(this, "安装正在进行，确定要退出吗？", "确认退出",
                MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (result != MessageBoxResult.Yes) return;
            Environment.Exit(1);
        }
        Close();
    }

    private async void Next_Click(object sender, RoutedEventArgs e)
    {
        if (_finished)
        {
            Close();
            return;
        }

        if (_step == 0)
        {
            ShowStep(1);
            return;
        }

        if (_step == 3)
        {
            if (_installedExe != null && RunAfterCheck.IsChecked == true)
            {
                TryStart(_installedExe);
            }
            Close();
            return;
        }

        if (_step != 1 || _info == null) return;

        string dir = InstallDirBox.Text.Trim();
        if (dir.Length == 0)
        {
            MessageBox.Show(this, "请先选择安装位置。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        try
        {
            dir = Path.GetFullPath(dir);
        }
        catch
        {
            MessageBox.Show(this, "安装路径无效。", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (Directory.Exists(dir) && Directory.EnumerateFileSystemEntries(dir).Any())
        {
            var result = MessageBox.Show(this,
                "该目录不是空目录，继续安装会覆盖同名文件。是否继续？",
                "确认安装", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (result != MessageBoxResult.Yes) return;
        }

        _installing = true;
        ShowStep(2);
        InstallProgress.Value = 0;
        StatusText.Text = "正在准备安装…";
        DetailText.Text = dir;

        var progress = new Progress<ProgressInfo>(p =>
        {
            InstallProgress.Value = p.Fraction * 100;
            StatusText.Text = p.Message;
        });

        try
        {
            string exePath = Environment.ProcessPath!;
            bool desktop = DesktopShortcutCheck.IsChecked == true;
            bool startMenu = StartMenuCheck.IsChecked == true;
            await Task.Run(() => InstallerCore.Install(
                _info, exePath, dir, progress, CancellationToken.None, desktop, startMenu));

            _installedExe = Path.Combine(dir, _info.ExeName);
            InstallProgress.Value = 100;
            StatusText.Text = "安装完成";
            FinishPathText.Text = $"安装位置：{dir}";
            _installing = false;
            _finished = true;
            ShowStep(3);
        }
        catch (Exception ex)
        {
            _installing = false;
            MessageBox.Show(this, "安装失败：" + ex.Message, "错误",
                MessageBoxButton.OK, MessageBoxImage.Error);
            ShowStep(1);
        }
    }

    private static void TryStart(string exe)
    {
        try
        {
            Process.Start(new ProcessStartInfo(exe)
            {
                UseShellExecute = true,
                WorkingDirectory = Path.GetDirectoryName(exe)!
            });
        }
        catch
        {
            // ignore
        }
    }
}
