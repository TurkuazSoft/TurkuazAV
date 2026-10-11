// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/models/FileScanResult.cs
// # 📌 Amac: Tarama sonucunu ve durumunu tip guvenli tasimak
// # 📌 Modul - FileType: Model - CSharp
// # Version: 0.1.0
// # Aciklama: Tarama sonucunu ve durumunu tip guvenli tasimak
// # Bagimli Oldugu Katman: Repo | Service | View

namespace TurkuazAV.Core.Models;

public enum ScanStatus
{
    Hashed,
    Skipped,
    Failed
}

public sealed record FileScanResult(
    string Path,
    ScanStatus Status,
    string? Sha256,
    long? SizeBytes,
    string? Details);
