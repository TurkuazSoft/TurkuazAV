// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Cli/controllers/RuleScanController.cs
// # 📌 Amac: Konsol istegini kural servisine aktarmak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.0
// # Aciklama: Konsol istegini kural servisine aktarmak
// # Bagimli Oldugu Katman: Controller | Service

using TurkuazAV.Core.Models;
using TurkuazAV.Core.Services;
namespace TurkuazAV.Cli.Controllers;
public sealed class RuleScanController(IRuleScanService service)
{
    public Task<RuleScanResult> ScanAsync(string filePath, string rulePath,
        string signaturePath, string keyPath, string enginePath,
        CancellationToken cancellationToken = default) =>
        service.ScanAsync(filePath, rulePath, signaturePath, keyPath,
            enginePath, cancellationToken);
}
