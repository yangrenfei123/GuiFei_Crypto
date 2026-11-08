using System.Windows;

namespace SetupApp;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        bool silent = e.Args.Any(a =>
            a.Equals("/S", StringComparison.OrdinalIgnoreCase) ||
            a.Equals("/SILENT", StringComparison.OrdinalIgnoreCase));

        if (silent)
        {
            int code = RunSilent(e.Args);
            Shutdown(code);
            return;
        }

        var window = new MainWindow();
        MainWindow = window;
        window.Show();
    }

    private static int RunSilent(string[] args)
    {
        try
        {
            string exePath = Environment.ProcessPath!;
            var info = InstallerCore.TryReadPayloadInfo(exePath);
            if (info == null) return 2;
            string dir = InstallerCore.DefaultInstallDir;
            foreach (var arg in args)
            {
                if (arg.StartsWith("/D=", StringComparison.OrdinalIgnoreCase))
                    dir = arg[3..].Trim('"');
            }
            var progress = new Progress<ProgressInfo>(_ => { });
            InstallerCore.Install(info, exePath, dir, progress, CancellationToken.None, true, true);
            return 0;
        }
        catch (Exception ex)
        {
            try
            {
                System.IO.File.WriteAllText(
                    System.IO.Path.Combine(System.IO.Path.GetTempPath(), "guifei_setup_error.log"),
                    ex.ToString());
            }
            catch
            {
                // ignore
            }
            return 1;
        }
    }
}
