// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Desktop/MainWindow.xaml.cs
// # 📌 Amac: WinUI dosya secimi, guvenli tek dosya taramasi ve bellek ici raporu yonetmek
// # 📌 Modul - FileType: CSharp
// # Version: 0.3.0
// # Aciklama: WinUI dosya secimi, guvenli tek dosya taramasi ve bellek ici raporu yonetmek
// # Bagimli Oldugu Katman: View | Controller | Service | Repo | Tool | Language

using Microsoft.UI.Xaml;
using TurkuazAV.Core.Config;
using TurkuazAV.Core.Repositories;
using TurkuazAV.Core.Services;
using TurkuazAV.Core.Tools;
using TurkuazAV.Desktop.Config;
using TurkuazAV.Desktop.Controllers;
using TurkuazAV.Desktop.Language;
using TurkuazAV.Desktop.Views;
using Windows.Storage.Pickers;

namespace TurkuazAV.Desktop;

public sealed partial class MainWindow : Window
{
    private readonly HashScanController _controller;
    private CancellationTokenSource? _scanCancellation;
    private string? _selectedFile;

    public MainWindow()
    {
        InitializeComponent();
        _controller = new HashScanController(new ScanService(
            new LocalFileRepository(), new Sha256FileHashTool(), ScanOptions.Default));
    }

    private async void OnSelectFile(object sender, RoutedEventArgs args)
    {
        try
        {
            var picker = new FileOpenPicker();
            picker.FileTypeFilter.Add(DesktopSettings.FilePickerWildcard);

            // WinUI 3 desktop legacy file picker requires an HWND association.
            var windowHandle = WinRT.Interop.WindowNative.GetWindowHandle(this);
            WinRT.Interop.InitializeWithWindow.Initialize(picker, windowHandle);
            var file = await picker.PickSingleFileAsync();
            if (file is null)
                return;

            _selectedFile = file.Path;
            SelectedFileText.Text = _selectedFile;
            StatusText.Text = DesktopMessages.Ready;
            ScanButton.IsEnabled = true;
        }
        catch (Exception error)
        {
            StatusText.Text = DesktopMessages.SelectError + error.Message;
        }
    }

    private async void OnScanFile(object sender, RoutedEventArgs args)
    {
        if (string.IsNullOrWhiteSpace(_selectedFile) || _scanCancellation is not null)
            return;

        var path = _selectedFile;
        using var tokenSource = new CancellationTokenSource();
        _scanCancellation = tokenSource;
        SelectButton.IsEnabled = false;
        ScanButton.IsEnabled = false;
        CancelButton.IsEnabled = true;
        ActivityRing.IsActive = true;
        StatusText.Text = DesktopMessages.Reading;

        try
        {
            var result = await _controller.ScanAsync(path, tokenSource.Token);
            var report = ScanReportFormatter.Format(result);
            ResultStatusText.Text = report.Status;
            ResultSizeText.Text = report.Size;
            ResultHashText.Text = report.Hash;
            StatusText.Text = DesktopMessages.Finished;
            HistoryList.Items.Insert(0, DateTime.Now.ToString("g")
                + DesktopMessages.HistorySeparator
                + System.IO.Path.GetFileName(result.Path)
                + DesktopMessages.HistorySeparator
                + report.Status);
        }
        catch (OperationCanceledException)
        {
            StatusText.Text = DesktopMessages.Cancelled;
        }
        catch (Exception error)
        {
            StatusText.Text = DesktopMessages.ScanError + error.Message;
        }
        finally
        {
            _scanCancellation = null;
            SelectButton.IsEnabled = true;
            ScanButton.IsEnabled = _selectedFile is not null;
            CancelButton.IsEnabled = false;
            ActivityRing.IsActive = false;
        }
    }

    private void OnCancelScan(object sender, RoutedEventArgs args)
    {
        if (_scanCancellation is null)
            return;

        StatusText.Text = DesktopMessages.CancelRequested;
        _scanCancellation.Cancel();
        CancelButton.IsEnabled = false;
    }
}
