// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Desktop/controllers/HashScanController.cs
// # 📌 Amac: Tek dosya SHA-256 istegini tarama servisine iletmek
// # 📌 Modul - FileType: CSharp
// # Version: 0.3.0
// # Aciklama: Tek dosya SHA-256 istegini tarama servisine iletmek
// # Bagimli Oldugu Katman: Controller | Service

using TurkuazAV.Core.Models;
using TurkuazAV.Core.Services;

namespace TurkuazAV.Desktop.Controllers;

public sealed class HashScanController(IScanService scanService)
{
    public async Task<FileScanResult> ScanAsync(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        await foreach (var result in scanService.ScanAsync(filePath, cancellationToken))
        {
            return result;
        }

        throw new InvalidDataException("Tarama herhangi bir sonuç üretmedi.");
    }
}
