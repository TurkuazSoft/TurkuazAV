// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Desktop/App.xaml.cs
// # 📌 Amac: WinUI acilis asamalarini kaydetmek ve kritik hatalari gorunur kilmak
// # 📌 Modul - FileType: CSharp
// # Version: 0.3.1
// # Aciklama: WinUI acilis asamalarini kaydetmek ve kritik hatalari gorunur kilmak
// # Bagimli Oldugu Katman: View | Tool

using Microsoft.UI.Xaml;
using TurkuazAV.Desktop.Tools;

namespace TurkuazAV.Desktop;

public partial class App : Application
{
    private Window? _mainWindow;

    public App()
    {
        DesktopDiagnostics.Record("APP_CONSTRUCTOR");
        UnhandledException += OnUnhandledException;
        InitializeComponent();
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        DesktopDiagnostics.Record("LAUNCH_BEGIN");
        try
        {
            _mainWindow = new MainWindow();
            DesktopDiagnostics.Record("WINDOW_CREATED");
            _mainWindow.Activate();
            DesktopDiagnostics.Record("WINDOW_ACTIVATED");
        }
        catch (Exception exception)
        {
            DesktopDiagnostics.Record("LAUNCH_FAILED", exception);
            throw;
        }
    }

    private static void OnUnhandledException(
        object sender,
        Microsoft.UI.Xaml.UnhandledExceptionEventArgs args)
    {
        DesktopDiagnostics.Record("UNHANDLED_EXCEPTION", args.Exception);
        // Do not mark exceptions as handled; a real crash remains visible.
    }
}
