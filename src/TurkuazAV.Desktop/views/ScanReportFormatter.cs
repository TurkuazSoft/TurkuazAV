// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Desktop/views/ScanReportFormatter.cs
// # 📌 Amac: Servis sonucunu kullaniciya anlasilir ve zararlilik iddiasi olmadan sunmak
// # 📌 Modul - FileType: CSharp
// # Version: 0.3.0
// # Aciklama: Servis sonucunu kullaniciya anlasilir ve zararlilik iddiasi olmadan sunmak
// # Bagimli Oldugu Katman: View | Language

using System.Globalization;
using TurkuazAV.Core.Models;
using TurkuazAV.Desktop.Config;
using TurkuazAV.Desktop.Language;

namespace TurkuazAV.Desktop.Views;

public sealed record ScanReportDisplay(string Status, string Size, string Hash);

public static class ScanReportFormatter
{
    public static ScanReportDisplay Format(FileScanResult item)
    {
        var state = item.Status switch
        {
            ScanStatus.Hashed => DesktopMessages.Success,
            ScanStatus.Skipped => DesktopMessages.Skipped + item.Details,
            _ => DesktopMessages.Failed + item.Details
        };

        var size = item.SizeBytes is long length
            ? length.ToString(DesktopSettings.DecimalSizeFormat, CultureInfo.CurrentCulture)
              + DesktopMessages.ByteUnit
            : DesktopMessages.UnknownSize;

        return new ScanReportDisplay(state, size, item.Sha256 ?? string.Empty);
    }
}
