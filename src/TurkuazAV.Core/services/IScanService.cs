// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/services/IScanService.cs
// # 📌 Amac: Tarama is kurallarinin cagri sozlesmesini tanimlamak
// # 📌 Modul - FileType: Service - CSharp
// # Version: 0.1.0
// # Aciklama: Tarama is kurallarinin cagri sozlesmesini tanimlamak
// # Bagimli Oldugu Katman: Service

using TurkuazAV.Core.Models;

namespace TurkuazAV.Core.Services;

public interface IScanService
{
    IAsyncEnumerable<FileScanResult> ScanAsync(
        string path,
        CancellationToken cancellationToken = default);
}
