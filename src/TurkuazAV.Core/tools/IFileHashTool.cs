// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/tools/IFileHashTool.cs
// # 📌 Amac: Dosya ozeti motorunun arayuzunu sunmak
// # 📌 Modul - FileType: Tool - CSharp
// # Version: 0.1.0
// # Aciklama: Dosya ozeti motorunun arayuzunu sunmak
// # Bagimli Oldugu Katman: Tool

namespace TurkuazAV.Core.Tools;

public interface IFileHashTool
{
    Task<string> ComputeSha256Async(Stream input, CancellationToken cancellationToken = default);
}
