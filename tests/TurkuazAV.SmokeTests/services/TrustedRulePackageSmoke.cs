// # 📄 Dosya Yolu: /TurkuazAV/tests/TurkuazAV.SmokeTests/services/TrustedRulePackageSmoke.cs
// # 📌 Amac: Publisher pinleme anahtar rotasyonu ve surum geri donusunu test etmek
// # 📌 Modul - FileType: Tests - CSharp
// # Version: 0.2.3
// # Aciklama: Publisher pinleme anahtar rotasyonu ve surum geri donusunu test etmek
// # Bagimli Oldugu Katman: Service | Repo | Tool | Config

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TurkuazAV.Core.Config;
using TurkuazAV.Core.Language;
using TurkuazAV.Core.Models;
using TurkuazAV.Core.Repositories;
using TurkuazAV.Core.Services;
using TurkuazAV.Core.Tools;
using TurkuazAV.SmokeTests.Config;

namespace TurkuazAV.SmokeTests.Services;

public static class TrustedRulePackageSmoke
{
    public static async Task RunAsync(string root)
    {
        var directory = Path.Combine(root, TrustedRuleTestSettings.Subdirectory);
        Directory.CreateDirectory(directory);

        var rulesFile = Path.Combine(directory, TrustedRuleTestSettings.RulesFile);
        var manifestFile = Path.Combine(directory, TrustedRuleTestSettings.ManifestFile);
        var signatureFile = Path.Combine(directory, TrustedRuleTestSettings.SignatureFile);
        var stateFile = Path.Combine(directory, TrustedRuleTestSettings.StateFile);

        using var firstKey = RSA.Create();
        firstKey.KeySize = TrustedRuleTestSettings.KeySizeBits;
        using var rotatedKey = RSA.Create();
        rotatedKey.KeySize = TrustedRuleTestSettings.KeySizeBits;

        var trustedBoth = new TrustedRuleKeyring(new Dictionary<string, string>
        {
            [TrustedRuleTestSettings.KeyA] = firstKey.ExportSubjectPublicKeyInfoPem(),
            [TrustedRuleTestSettings.KeyB] = rotatedKey.ExportSubjectPublicKeyInfoPem()
        });
        var firstOnly = new TrustedRuleKeyring(new Dictionary<string, string>
        {
            [TrustedRuleTestSettings.KeyA] = firstKey.ExportSubjectPublicKeyInfoPem()
        });
        var rotatedOnly = new TrustedRuleKeyring(new Dictionary<string, string>
        {
            [TrustedRuleTestSettings.KeyB] = rotatedKey.ExportSubjectPublicKeyInfoPem()
        });

        TrustedRulePackageService Service(TrustedRuleKeyring ring, string? path = null) =>
            new(new LocalTrustedRuleBundleRepository(), ring,
                new RsaPssRuleSignatureTool(),
                new LocalRuleVersionRepository(path ?? stateFile));

        async Task<VerifiedRulePackage> Accept(TrustedRulePackageService service) =>
            await service.VerifyAndAcceptAsync(rulesFile, manifestFile, signatureFile);

        async Task WritePackage(long version, string keyId, RSA signingKey, string ruleText)
        {
            var ruleBytes = Encoding.UTF8.GetBytes(ruleText);
            var digest = Convert.ToHexString(SHA256.HashData(ruleBytes)).ToLowerInvariant();
            var manifest = new TrustedRuleManifest(
                TrustedRuleSettings.Schema, version, keyId, digest);
            var json = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schema = manifest.Schema,
                sequence = manifest.Sequence,
                keyId = manifest.KeyId,
                rulesSha256 = manifest.RulesSha256
            });
            var signature = signingKey.SignData(
                TrustedRuleManifestCodec.SignaturePayload(manifest),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss);

            await File.WriteAllBytesAsync(rulesFile, ruleBytes);
            await File.WriteAllBytesAsync(manifestFile, json);
            await File.WriteAllBytesAsync(signatureFile, signature);
        }

        static async Task MustReject(Func<Task> action, string expectedMessage, string failure)
        {
            try
            {
                await action();
            }
            catch (InvalidDataException error) when (error.Message == expectedMessage)
            {
                return;
            }
            throw new InvalidOperationException(failure);
        }

        var service = Service(trustedBoth);
        await WritePackage(TrustedRuleTestSettings.InitialSequence,
            TrustedRuleTestSettings.KeyA, firstKey, TrustedRuleTestSettings.RuleA);
        var first = await Accept(service);
        if (first.Sequence != TrustedRuleTestSettings.InitialSequence
            || first.PublisherKeyId != TrustedRuleTestSettings.KeyA
            || Encoding.UTF8.GetString(first.VerifiedRules) != TrustedRuleTestSettings.RuleA)
            throw new InvalidOperationException(TrustedRuleTestSettings.ValidPackageRejected);

        // Tampering with rules does not advance version state.
        await File.WriteAllTextAsync(rulesFile, TrustedRuleTestSettings.AlteredRules);
        await MustReject(async () => { await Accept(service); },
            TrustedRuleMessages.BadRuleHash, TrustedRuleTestSettings.AlteredRulesAccepted);

        // Signature must bind the key id, sequence, and rule digest.
        await WritePackage(TrustedRuleTestSettings.RevokedSequence,
            TrustedRuleTestSettings.KeyA, firstKey, TrustedRuleTestSettings.RuleA);
        await File.WriteAllBytesAsync(signatureFile, new byte[256]);
        await MustReject(async () => { await Accept(service); },
            TrustedRuleMessages.BadSignature, TrustedRuleTestSettings.InvalidSignatureAccepted);

        await WritePackage(TrustedRuleTestSettings.RotatedSequence,
            TrustedRuleTestSettings.UnknownKey, firstKey, TrustedRuleTestSettings.RuleB);
        await MustReject(async () => { await Accept(service); },
            TrustedRuleMessages.UntrustedPublisher, TrustedRuleTestSettings.UnknownPublisherAccepted);

        // Rotate to a separately approved key. Both known keys can verify while the
        // application is in the overlap window.
        await WritePackage(TrustedRuleTestSettings.RotatedSequence,
            TrustedRuleTestSettings.KeyB, rotatedKey, TrustedRuleTestSettings.RuleB);
        var rotated = await Accept(service);
        if (rotated.Sequence != TrustedRuleTestSettings.RotatedSequence
            || rotated.PublisherKeyId != TrustedRuleTestSettings.KeyB)
            throw new InvalidOperationException(TrustedRuleTestSettings.ValidPackageRejected);

        // Reload state using another repository object to prove persistence.
        await WritePackage(TrustedRuleTestSettings.InitialSequence,
            TrustedRuleTestSettings.KeyA, firstKey, TrustedRuleTestSettings.RuleA);
        await MustReject(async () => { await Accept(Service(trustedBoth)); },
            TrustedRuleMessages.DowngradeDenied, TrustedRuleTestSettings.RollbackAccepted);

        // Key revocation removes the old publisher even for a higher version.
        await WritePackage(TrustedRuleTestSettings.RevokedSequence,
            TrustedRuleTestSettings.KeyA, firstKey, TrustedRuleTestSettings.RuleA);
        await MustReject(async () => { await Accept(Service(rotatedOnly)); },
            TrustedRuleMessages.UntrustedPublisher, TrustedRuleTestSettings.RevokedKeyAccepted);

        // The former key can remain valid only while explicitly pinned in the policy.
        var rejectedNewPolicy = Service(firstOnly);
        await WritePackage(TrustedRuleTestSettings.RotatedSequence,
            TrustedRuleTestSettings.KeyB, rotatedKey, TrustedRuleTestSettings.RuleB);
        await MustReject(async () => { await Accept(rejectedNewPolicy); },
            TrustedRuleMessages.UntrustedPublisher, TrustedRuleTestSettings.UnknownPublisherAccepted);

        // Corrupted persisted version data must fail closed, not reset to zero.
        var corruptState = Path.Combine(directory, TrustedRuleTestSettings.CorruptStateFile);
        await File.WriteAllBytesAsync(corruptState, new byte[3]);
        await MustReject(async () => { await Accept(Service(trustedBoth, corruptState)); },
            TrustedRuleMessages.CorruptState, TrustedRuleTestSettings.StateCorruptionAccepted);

        await File.WriteAllTextAsync(manifestFile, "{}");
        await MustReject(async () => { await Accept(service); },
            TrustedRuleMessages.MalformedManifest, TrustedRuleTestSettings.InvalidManifestAccepted);
    }
}
