// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/repositories/LocalTrustedRuleBundleRepository.cs
// # 📌 Amac: Imzali kural paketini salt okunur ve boyut sinirli yuklemek
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.3
// # Aciklama: Imzali kural paketini salt okunur ve boyut sinirli yuklemek
// # Bagimli Oldugu Katman: Repo | Config | Language

using TurkuazAV.Core.Config;
using TurkuazAV.Core.Language;
using TurkuazAV.Core.Models;

namespace TurkuazAV.Core.Repositories;

public sealed class LocalTrustedRuleBundleRepository : ITrustedRuleBundleRepository
{
    public async Task<SignedRulePackage> ReadAsync(
        string rulesPath,
        string manifestPath,
        string signaturePath,
        CancellationToken cancellationToken = default)
    {
        var rules = await ReadBoundedAsync(
            rulesPath, RuleSettings.MaxRuleBytes, cancellationToken);
        var manifest = await ReadBoundedAsync(
            manifestPath, TrustedRuleSettings.MaximumManifestBytes, cancellationToken);
        var signature = await ReadBoundedAsync(
            signaturePath, TrustedRuleSettings.MaximumSignatureBytes, cancellationToken);
        return new SignedRulePackage(rules, manifest, signature);
    }

    private static async Task<byte[]> ReadBoundedAsync(
        string path, int maxBytes, CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(path);
        if ((File.GetAttributes(fullPath) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new InvalidDataException(TrustedRuleMessages.LinkDenied);

        await using var input = new FileStream(fullPath, FileMode.Open, FileAccess.Read,
            FileShare.Read, RuleSettings.ReadBuffer,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        if (input.Length > maxBytes)
            throw new InvalidDataException(TrustedRuleMessages.FileTooLarge);

        using var buffer = new MemoryStream();
        var chunk = new byte[RuleSettings.ReadBuffer];
        int count;
        while ((count = await input.ReadAsync(chunk.AsMemory(), cancellationToken)) > 0)
        {
            if (buffer.Length + count > maxBytes)
                throw new InvalidDataException(TrustedRuleMessages.FileTooLarge);
            buffer.Write(chunk, 0, count);
        }
        return buffer.ToArray();
    }
}
