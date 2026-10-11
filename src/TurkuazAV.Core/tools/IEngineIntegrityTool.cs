// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/tools/IEngineIntegrityTool.cs
// # 📌 Amac: Motor calistirilabilir dosyasini guven politikasina gore denetleyen arayuz
// # 📌 Modul - FileType: Tool - CSharp
// # Version: 0.2.2
// # Aciklama: Motor calistirilabilir dosyasini guven politikasina gore denetleyen arayuz
// # Bagimli Oldugu Katman: Tool

namespace TurkuazAV.Core.Tools;

public interface IEngineIntegrityTool
{
    Task VerifyAsync(string executablePath, CancellationToken cancellationToken = default);
}
