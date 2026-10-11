// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/services/TrustedRulePackageService.cs
// # 📌 Amac: Yayinci imzasi, hash, key rotasyonu ve rollback kontrollerini siralamak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.3
// # Aciklama: Yayinci imzasi, hash, key rotasyonu ve rollback kontrollerini siralamak
// # Bagimli Oldugu Katman: Service | Repo | Tool | Config

using System.Security.Cryptography;
using TurkuazAV.Core.Language;
using TurkuazAV.Core.Models;
using TurkuazAV.Core.Repositories;
using TurkuazAV.Core.Tools;

namespace TurkuazAV.Core.Services;

public sealed class TrustedRulePackageService(
    ITrustedRuleBundleRepository repository,
    TrustedRuleKeyring keyring,
    IRuleSignatureTool signatureTool,
    IRuleVersionRepository versions)
{
    public async Task<VerifiedRulePackage> VerifyAndAcceptAsync(
        string rulesPath,
        string manifestPath,
        string signaturePath,
        CancellationToken cancellationToken = default)
    {
        var package = await repository.ReadAsync(
            rulesPath, manifestPath, signaturePath, cancellationToken);
        var manifest = TrustedRuleManifestCodec.Parse(package.ManifestJson);

        // Only keys injected by the trusted application bootstrap may verify publishers.
        var publicKey = keyring.GetRequiredKey(manifest.KeyId);
        var payload = TrustedRuleManifestCodec.SignaturePayload(manifest);
        if (!signatureTool.Verify(payload, package.Signature, publicKey))
            throw new InvalidDataException(TrustedRuleMessages.BadSignature);

        var expectedDigest = Convert.FromHexString(manifest.RulesSha256);
        var actualDigest = SHA256.HashData(package.Rules);
        if (!CryptographicOperations.FixedTimeEquals(expectedDigest, actualDigest))
            throw new InvalidDataException(TrustedRuleMessages.BadRuleHash);

        await versions.AcceptAsync(manifest.Sequence, cancellationToken);
        return new VerifiedRulePackage(manifest.Sequence, manifest.KeyId, package.Rules);
    }
}
