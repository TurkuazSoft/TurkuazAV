// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/services/RuleScanService.cs
// # 📌 Amac: Imzali kurallarla degismez hedef snapshot kopyasini taramak
// # 📌 Modul - FileType: Service - CSharp
// # Version: 0.2.1
// # Aciklama: Imzali kurallarla degismez hedef snapshot kopyasini taramak
// # Bagimli Oldugu Katman: Service | Repo | Tool | Config

using TurkuazAV.Core.Config;
using TurkuazAV.Core.Language;
using TurkuazAV.Core.Models;
using TurkuazAV.Core.Repositories;
using TurkuazAV.Core.Tools;

namespace TurkuazAV.Core.Services;

public sealed class RuleScanService(
    IRuleRepository repository,
    IRuleSignatureTool signatureTool,
    IRuleEngineTool engineTool) : IRuleScanService
{
    public async Task<RuleScanResult> ScanAsync(
        string targetPath,
        string rulesPath,
        string signaturePath,
        string publicKeyPath,
        string enginePath,
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

        var temporary = Directory.CreateTempSubdirectory(RuleSettings.TempPrefix);
        try
        {
            var trustedRules = Path.Combine(temporary.FullName, RuleSettings.VerifiedRuleName);
            var stableTarget = Path.Combine(temporary.FullName, RuleSettings.TargetSnapshotName);

            await File.WriteAllBytesAsync(trustedRules, package.Rules, cancellationToken);
            await CreateBoundedSnapshotAsync(target, stableTarget, cancellationToken);

            var matches = await engineTool.ScanAsync(
                enginePath, trustedRules, stableTarget, cancellationToken);

            return new RuleScanResult(target, matches);
        }
        finally
        {
            temporary.Delete(recursive: true);
        }
    }

    private static async Task CreateBoundedSnapshotAsync(
        string inputFile,
        string snapshotFile,
        CancellationToken cancellationToken)
    {
        await using var input = new FileStream(
            inputFile, FileMode.Open, FileAccess.Read, FileShare.Read,
            RuleSettings.ReadBuffer, FileOptions.Asynchronous | FileOptions.SequentialScan);

        await using var output = new FileStream(
            snapshotFile, FileMode.CreateNew, FileAccess.Write, FileShare.None,
            RuleSettings.ReadBuffer, FileOptions.Asynchronous | FileOptions.SequentialScan);

        var buffer = new byte[RuleSettings.ReadBuffer];
        long copiedBytes = 0;
        int count;

        while ((count = await input.ReadAsync(buffer.AsMemory(), cancellationToken)) != 0)
        {
            copiedBytes += count;
            if (copiedBytes > ScanDefaults.MaxFileSizeBytes)
                throw new InvalidDataException(RuleMessages.Oversized);

            await output.WriteAsync(buffer.AsMemory(0, count), cancellationToken);
        }

        await output.FlushAsync(cancellationToken);
    }
}
