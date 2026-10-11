// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/services/RuleScanService.cs
// # 📌 Amac: Guvenilir imza kontrolu sonrasi YARA-X kural taramasini yonetmek
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.0
// # Aciklama: Guvenilir imza kontrolu sonrasi YARA-X kural taramasini yonetmek
// # Bagimli Oldugu Katman: Service | Repo | Tool | Config

using TurkuazAV.Core.Config;
using TurkuazAV.Core.Language;
using TurkuazAV.Core.Models;
using TurkuazAV.Core.Repositories;
using TurkuazAV.Core.Tools;
namespace TurkuazAV.Core.Services;
public sealed class RuleScanService(
    IRuleRepository repository, IRuleSignatureTool signatureTool,
    IRuleEngineTool engineTool) : IRuleScanService
{
    public async Task<RuleScanResult> ScanAsync(string targetPath, string rulesPath,
        string signaturePath, string publicKeyPath, string enginePath,
        CancellationToken cancellationToken = default)
    {
        var target = Path.GetFullPath(targetPath);
        var flags = File.GetAttributes(target);
        if ((flags & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new InvalidDataException(RuleMessages.InvalidPath);
        if (new FileInfo(target).Length > ScanDefaults.MaxFileSizeBytes)
            throw new InvalidDataException(RuleMessages.Oversized);

        var package = await repository.LoadAsync(
            rulesPath, signaturePath, publicKeyPath, cancellationToken);
        if (!signatureTool.Verify(package.Rules, package.Signature, package.PublicKeyPem))
            throw new InvalidDataException(RuleMessages.InvalidSignature);

        var tempRoot = Path.Combine(Path.GetTempPath(),
            RuleSettings.TempPrefix + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);
        try
        {
            var trustedPath = Path.Combine(tempRoot, RuleSettings.VerifiedRuleName);
            await File.WriteAllBytesAsync(trustedPath, package.Rules, cancellationToken);
            var matches = await engineTool.ScanAsync(
                enginePath, trustedPath, target, cancellationToken);
            return new RuleScanResult(target, matches);
        }
        finally
        {
            Directory.Delete(tempRoot, recursive: true);
        }
    }
}
