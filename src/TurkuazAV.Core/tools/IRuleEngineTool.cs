// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/tools/IRuleEngineTool.cs
// # 📌 Amac: Harici YARA-X motoru ile Service arasinda arayuz olusturmak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.0
// # Aciklama: Harici YARA-X motoru ile Service arasinda arayuz olusturmak
// # Bagimli Oldugu Katman: Tool

namespace TurkuazAV.Core.Tools;
public interface IRuleEngineTool
{
    Task<IReadOnlyList<string>> ScanAsync(
        string executablePath, string verifiedRulePath, string targetPath,
        CancellationToken cancellationToken = default);
}
