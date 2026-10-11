// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Cli/controllers/ScanController.cs
// # 📌 Amac: Tarama istegini service katmanina iletmek
// # 📌 Modul - FileType: Controller - CSharp
// # Version: 0.1.0
// # Aciklama: Tarama istegini service katmanina iletmek
// # Bagimli Oldugu Katman: Controller | Service

using TurkuazAV.Core.Models;
using TurkuazAV.Core.Services;

namespace TurkuazAV.Cli.Controllers;

public sealed class ScanController(IScanService service)
{
    public IAsyncEnumerable<FileScanResult> ScanAsync(
        string path,
        CancellationToken cancellationToken = default) =>
        service.ScanAsync(path, cancellationToken);
}
