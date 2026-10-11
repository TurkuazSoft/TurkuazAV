// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Desktop/App.xaml.cs
// # 📌 Amac: Deneysel tarayicinin ana penceresini baslatmak
// # 📌 Modul - FileType: CSharp
// # Version: 0.3.0
// # Aciklama: Deneysel tarayicinin ana penceresini baslatmak
// # Bagimli Oldugu Katman: View

using Microsoft.UI.Xaml;

namespace TurkuazAV.Desktop;

public partial class App : Application
{
    private Window? _mainWindow;

    public App()
    {
        InitializeComponent();
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        _mainWindow = new MainWindow();
        _mainWindow.Activate();
    }
}
