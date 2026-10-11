// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Desktop/MainWindow.xaml.cs
// # 📌 Amac: Hash raporunu kopyalama, gecmis temizleme ve arayuz hata kaydini yonetmek
// # 📌 Modul - FileType: CSharp
// # Version: 0.3.1
// # Aciklama: Hash raporunu kopyalama, gecmis temizleme ve arayuz hata kaydini yonetmek
// # Bagimli Oldugu Katman: View | Controller | Service | Repo | Tool | Language

using Microsoft.UI.Xaml;
using TurkuazAV.Core.Config;
using TurkuazAV.Core.Repositories;
using TurkuazAV.Core.Services;
using TurkuazAV.Core.Tools;
using TurkuazAV.Desktop.Config;
using TurkuazAV.Desktop.Controllers;
using TurkuazAV.Desktop.Language;
using TurkuazAV.Desktop.Tools;
using TurkuazAV.Desktop.Views;
using Windows.ApplicationModel.DataTransfer;
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
            var windowHandle = WinRT.Interop.WindowNative.GetWindowHandle(this);
            WinRT.Interop.InitializeWithWindow.Initialize(picker, windowHandle);
            var file = await picker.PickSingleFileAsync();
            if (file is null)
                return;

            _selectedFile = file.Path;
            SelectedFileText.Text = _selectedFile;
            StatusText.Text = DesktopMessages.Ready;
            ResetReport();
            ScanButton.IsEnabled = true;
        }
        catch (Exception error)
        {
            DesktopDiagnostics.Record("PICKER_FAILED", error);
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
        ResetReport();
        StatusText.Text = DesktopMessages.Reading;

        try
        {
            var result = await _controller.ScanAsync(path, tokenSource.Token);
            var report = ScanReportFormatter.Format(result);
            ResultStatusText.Text = report.Status;
            ResultSizeText.Text = report.Size;
            ResultHashText.Text = report.Hash;
            CopyHashButton.IsEnabled = !string.IsNullOrEmpty(report.Hash);
            StatusText.Text = DesktopMessages.Finished;

            HistoryList.Items.Insert(0, DateTime.Now.ToString("g")
                + DesktopMessages.HistorySeparator
                + System.IO.Path.GetFileName(result.Path)
                + DesktopMessages.HistorySeparator
                + report.Status);
            while (HistoryList.Items.Count > DesktopSettings.MaxSessionHistoryEntries)
                HistoryList.Items.RemoveAt(HistoryList.Items.Count - 1);
        }
        catch (OperationCanceledException)
        {
            StatusText.Text = DesktopMessages.Cancelled;
        }
        catch (Exception error)
        {
            DesktopDiagnostics.Record("SCAN_FAILED", error);
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

    private void OnCopyHash(object sender, RoutedEventArgs args)
    {
        if (string.IsNullOrWhiteSpace(ResultHashText.Text))
            return;

        try
        {
            var data = new DataPackage();
            data.SetText(ResultHashText.Text);
            Clipboard.SetContent(data);
            StatusText.Text = DesktopMessages.Copied;
        }
        catch (Exception error)
        {
            DesktopDiagnostics.Record("COPY_FAILED", error);
            StatusText.Text = DesktopMessages.CopyFailed + error.Message;
        }
    }

    private void OnClearHistory(object sender, RoutedEventArgs args)
    {
        HistoryList.Items.Clear();
        StatusText.Text = DesktopMessages.HistoryCleared;
    }

    private void OnCancelScan(object sender, RoutedEventArgs args)
    {
        if (_scanCancellation is null)
            return;

        StatusText.Text = DesktopMessages.CancelRequested;
        _scanCancellation.Cancel();
        CancelButton.IsEnabled = false;
    }

    private void ResetReport()
    {
        ResultStatusText.Text = DesktopMessages.NoResult;
        ResultSizeText.Text = DesktopMessages.UnknownSize;
        ResultHashText.Text = string.Empty;
        CopyHashButton.IsEnabled = false;
    }
}
