// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/services/TrustedRulePackageService.cs
// # 📌 Amac: Imzali paket guvenini taramadan bagimsiz dogrulamak ve basarili sonuc sonrasi surum islemek
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.4
// # Aciklama: Imzali paket guvenini taramadan bagimsiz dogrulamak ve basarili sonuc sonrasi surum islemek
// # Bagimli Oldugu Katman: Service | Repo | Tool

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
    // Verification must never modify persistent anti-rollback state.
    public async Task<VerifiedRulePackage> VerifyAsync(
        string rulesPath,
        string manifestPath,
        string signaturePath,
        CancellationToken cancellationToken = default)
    {
        var package = await repository.ReadAsync(
            rulesPath, manifestPath, signaturePath, cancellationToken);
        var manifest = TrustedRuleManifestCodec.Parse(package.ManifestJson);

        var publisherKey = keyring.GetRequiredKey(manifest.KeyId);
        var signedPayload = TrustedRuleManifestCodec.SignaturePayload(manifest);
        if (!signatureTool.Verify(signedPayload, package.Signature, publisherKey))
            throw new InvalidDataException(TrustedRuleMessages.BadSignature);

        var expectedRulesDigest = Convert.FromHexString(manifest.RulesSha256);
        var actualRulesDigest = SHA256.HashData(package.Rules);
        if (!CryptographicOperations.FixedTimeEquals(
            expectedRulesDigest, actualRulesDigest))
            throw new InvalidDataException(TrustedRuleMessages.BadRuleHash);

        var manifestFingerprint =
            Convert.ToHexString(SHA256.HashData(signedPayload)).ToLowerInvariant();
        return new VerifiedRulePackage(
            manifest.Sequence, manifest.KeyId, package.Rules, manifestFingerprint);
    }

    public Task CommitVerifiedAsync(
        VerifiedRulePackage verified,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verified);
        return versions.AcceptAsync(
            verified.Sequence, verified.ManifestFingerprint, cancellationToken);
    }

    // Backwards-compatible library entry point. This records a verified package,
    // but callers should use TrustedRuleScanService for scan-before-commit flow.
    public async Task<VerifiedRulePackage> VerifyAndAcceptAsync(
        string rulesPath,
        string manifestPath,
        string signaturePath,
        CancellationToken cancellationToken = default)
    {
        var verified = await VerifyAsync(
            rulesPath, manifestPath, signaturePath, cancellationToken);
        await CommitVerifiedAsync(verified, cancellationToken);
        return verified;
    }
}
