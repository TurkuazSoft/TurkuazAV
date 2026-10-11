// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Cli/views/ConsoleScanView.cs
// # 📌 Amac: Tarama sonuclarini konsola yazmak
// # 📌 Modul - FileType: View - CSharp
// # Version: 0.1.0
// # Aciklama: Tarama sonuclarini konsola yazmak
// # Bagimli Oldugu Katman: View | Language

using System.Globalization;
using TurkuazAV.Cli.Config;
using TurkuazAV.Cli.Language;
using TurkuazAV.Core.Models;

namespace TurkuazAV.Cli.Views;

public sealed class ConsoleScanView
{
    public void ShowUsage() => Console.WriteLine(CliMessages.Usage);

    public void ShowError(string message) =>
        Console.Error.WriteLine(string.Format(CultureInfo.InvariantCulture, CliMessages.Fatal, message));

    public async Task<int> WriteResultsAsync(IAsyncEnumerable<FileScanResult> results)
    {
        var hashed = 0;
        var skipped = 0;
        var failed = 0;

        await foreach (var result in results)
        {
            switch (result.Status)
            {
                case ScanStatus.Hashed:
                    hashed++;
                    Console.WriteLine(string.Format(
                        CultureInfo.InvariantCulture,
                        CliMessages.Hashed,
                        result.Path,
                        result.Sha256,
                        result.SizeBytes));
                    break;

                case ScanStatus.Skipped:
                    skipped++;
                    Console.WriteLine(string.Format(
                        CultureInfo.InvariantCulture,
                        CliMessages.Skipped,
                        result.Path,
                        result.Details));
                    break;

                case ScanStatus.Failed:
                    failed++;
                    Console.WriteLine(string.Format(
                        CultureInfo.InvariantCulture,
                        CliMessages.Failed,
                        result.Path,
                        result.Details));
                    break;
            }
        }

        Console.WriteLine(string.Format(
            CultureInfo.InvariantCulture,
            CliMessages.Summary,
            hashed,
            skipped,
            failed));

        return failed > 0 ? ExitCodes.ScanFailed : ExitCodes.Success;
    }
}
