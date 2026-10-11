// # 📄 Dosya Yolu: /TurkuazAV/tests/TurkuazAV.DesktopLogicTests/Program.cs
// # 📌 Amac: Hash sonucunda temiz hukmu verilmedigini, skip/error ve boyut gorunumunu test etmek
// # 📌 Modul - FileType: CSharp
// # Version: 0.3.1
// # Aciklama: Hash sonucunda temiz hukmu verilmedigini, skip/error ve boyut gorunumunu test etmek
// # Bagimli Oldugu Katman: View | Model | Language

using TurkuazAV.Core.Models;
using TurkuazAV.Desktop.Config;
using TurkuazAV.Desktop.Language;
using TurkuazAV.Desktop.Views;

const string validHash = "A3B5C8D6F7E901234567890ABCDEF1234567890ABCDEF1234567890ABCDEF0000";
const string file = "sample.txt";

var good = ScanReportFormatter.Format(new FileScanResult(
    file, ScanStatus.Hashed, validHash, 4096, null));
if (good.Hash != validHash || !good.Size.EndsWith(DesktopMessages.ByteUnit, StringComparison.Ordinal)
    || good.Status != DesktopMessages.Success || good.Status.Contains("temiz", StringComparison.OrdinalIgnoreCase))
    throw new InvalidOperationException("A successful hash is not an antivirus clean verdict.");

var skipped = ScanReportFormatter.Format(new FileScanResult(
    file, ScanStatus.Skipped, null, 110_000_000, "size limit"));
if (skipped.Hash.Length > 0 || !skipped.Status.StartsWith(
    DesktopMessages.Skipped, StringComparison.Ordinal))
    throw new InvalidOperationException("Skipped files must never show a hash.");

var failed = ScanReportFormatter.Format(new FileScanResult(
    file, ScanStatus.Failed, null, null, "access denied"));
if (failed.Hash.Length > 0 || failed.Size != DesktopMessages.UnknownSize
    || !failed.Status.StartsWith(DesktopMessages.Failed, StringComparison.Ordinal))
    throw new InvalidOperationException("Failed files must never show a previous result.");

if (DesktopSettings.MaxSessionHistoryEntries > 100
    || DesktopSettings.MaxSessionHistoryEntries < 1)
    throw new InvalidOperationException("Session history must have a bounded size.");

Console.WriteLine("TURKUAZAV_DESKTOP_LOGIC_TESTS_PASSED");
return 0;
