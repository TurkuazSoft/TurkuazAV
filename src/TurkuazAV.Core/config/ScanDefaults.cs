// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/config/ScanDefaults.cs
// # 📌 Amac: Tarama sinirlarini ve dosya esleme ayarlarini merkezilestirmek
// # 📌 Modul - FileType: Config - CSharp
// # Version: 0.1.0
// # Aciklama: Tarama sinirlarini ve dosya esleme ayarlarini merkezilestirmek
// # Bagimli Oldugu Katman: Config

namespace TurkuazAV.Core.Config;

public static class ScanDefaults
{
    public const long MaxFileSizeBytes = 104_857_600L;
    public const int StreamBufferSizeBytes = 81_920;
    public const string AllFilesPattern = "*";
}

public sealed record ScanOptions(long MaxFileSizeBytes)
{
    public static ScanOptions Default { get; } = new(ScanDefaults.MaxFileSizeBytes);
}
