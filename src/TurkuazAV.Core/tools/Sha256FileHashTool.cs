// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/tools/Sha256FileHashTool.cs
// # 📌 Amac: Akis uzerinden SHA-256 ozeti hesaplamak
// # 📌 Modul - FileType: Tool - CSharp
// # Version: 0.1.0
// # Aciklama: Akis uzerinden SHA-256 ozeti hesaplamak
// # Bagimli Oldugu Katman: Tool

using System.Security.Cryptography;

namespace TurkuazAV.Core.Tools;

public sealed class Sha256FileHashTool : IFileHashTool
{
    public async Task<string> ComputeSha256Async(
        Stream input,
        CancellationToken cancellationToken = default)
    {
        var digest = await SHA256.HashDataAsync(input, cancellationToken);
        return Convert.ToHexString(digest);
    }
}
