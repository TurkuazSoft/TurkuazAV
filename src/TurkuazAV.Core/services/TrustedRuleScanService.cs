// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/services/TrustedRuleScanService.cs
// # 📌 Amac: Guvenilir yayinci kural paketini gercek YARA-X taramasina baglamak ve basariliysa surum kaydetmek
// # 📌 Modul - FileType: Service - CSharp
// # Version: 0.2.4
// # Aciklama: Guvenilir yayinci kural paketini gercek YARA-X taramasina baglamak ve basariliysa surum kaydetmek
// # Bagimli Oldugu Katman: Service | Repo | Tool | Config

using TurkuazAV.Core.Config;
using TurkuazAV.Core.Language;
using TurkuazAV.Core.Models;
using TurkuazAV.Core.Tools;

namespace TurkuazAV.Core.Services;

// The caller must inject a keyring established by a trusted application bootstrap.
// Rule content and target are copied into a private temp workspace, not executed.
// All scan outcomes are informational; they do not imply malware verdicts.
public sealed class TrustedRuleScanService(
    TrustedRulePackageService packages,
    IRuleEngineTool engine)
{
    public async Task<RuleScanResult> ScanAsync(
        string targetPath,
        string rulesPath,
        string manifestPath,
        string signaturePath,
        string enginePath,
        CancellationToken cancellationToken = default)
    {
        var target = Path.GetFullPath(targetPath);
        var attributes = File.GetAttributes(target);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new InvalidDataException(RuleMessages.InvalidPath);

        if (new FileInfo(target).Length > ScanDefaults.MaxFileSizeBytes)
            throw new InvalidDataException(RuleMessages.Oversized);

        var verified = await packages.VerifyAsync(
            rulesPath, manifestPath, signaturePath, cancellationToken);

        var temporary = Directory.CreateTempSubdirectory(RuleSettings.TempPrefix);
        try
        {
            var trustedRules = Path.Combine(temporary.FullName, RuleSettings.VerifiedRuleName);
            var stableTarget = Path.Combine(temporary.FullName, RuleSettings.TargetSnapshotName);

            await File.WriteAllBytesAsync(trustedRules, verified.VerifiedRules, cancellationToken);
            await CreateBoundedSnapshotAsync(target, stableTarget, cancellationToken);

            // YaraXCliTool re-verifies its pinned engine binary before Process.Start.
            var matches = await engine.ScanAsync(
                enginePath, trustedRules, stableTarget, cancellationToken);

            // No update is recorded if engine scan throws, times out, or is cancelled.
            // A state race that detects a newer version prevents results being returned.
            await packages.CommitVerifiedAsync(verified, cancellationToken);
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
        long bytesCopied = 0;
        int count;
        while ((count = await input.ReadAsync(buffer.AsMemory(), cancellationToken)) != 0)
        {
            bytesCopied += count;
            if (bytesCopied > ScanDefaults.MaxFileSizeBytes)
                throw new InvalidDataException(RuleMessages.Oversized);

            await output.WriteAsync(buffer.AsMemory(0, count), cancellationToken);
        }

        await output.FlushAsync(cancellationToken);
    }
}
