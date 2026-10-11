// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/services/IRuleScanService.cs
// # 📌 Amac: Dogrulanmis kural tarama giris noktasini tanimlamak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.0
// # Aciklama: Dogrulanmis kural tarama giris noktasini tanimlamak
// # Bagimli Oldugu Katman: Service

using TurkuazAV.Core.Models;
namespace TurkuazAV.Core.Services;
public interface IRuleScanService
{
    Task<RuleScanResult> ScanAsync(string targetPath, string rulesPath,
        string signaturePath, string publicKeyPath, string enginePath,
        CancellationToken cancellationToken = default);
}
