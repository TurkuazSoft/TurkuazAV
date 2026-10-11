// # 📄 Dosya Yolu: /TurkuazAV/tests/TurkuazAV.IntegrationTests/services/TrustedRuleIntegrationTests.cs
// # 📌 Amac: Gercek YARA-X ile trusted scan, anti-rollback, sequence conflict ve hata sonrasi state testleri calistirmak
// # 📌 Modul - FileType: Tests - CSharp
// # Version: 0.2.4
// # Aciklama: Gercek YARA-X ile trusted scan, anti-rollback, sequence conflict ve hata sonrasi state testleri calistirmak
// # Bagimli Oldugu Katman: Service | Repo | Tool | Config

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TurkuazAV.Core.Config;
using TurkuazAV.Core.Language;
using TurkuazAV.Core.Models;
using TurkuazAV.Core.Repositories;
using TurkuazAV.Core.Services;
using TurkuazAV.Core.Tools;
using TurkuazAV.IntegrationTests.Config;

namespace TurkuazAV.IntegrationTests.Services;

public static class TrustedRuleIntegrationTests
{
    public static async Task RunAsync(
        string root,
        string enginePath)
    {
        var directory = Path.Combine(root, IntegrationSettings.TrustedTestDirectory);
        Directory.CreateDirectory(directory);

        var rules = Path.Combine(directory, IntegrationSettings.RulesName);
        var manifestFile = Path.Combine(directory, IntegrationSettings.TrustedManifestName);
        var signature = Path.Combine(directory, IntegrationSettings.SignatureName);
        var target = Path.Combine(directory, IntegrationSettings.PositiveFileName);
        var negative = Path.Combine(directory, IntegrationSettings.NegativeFileName);
        var state = Path.Combine(directory, IntegrationSettings.TrustedStateName);
        var untrustedEngine = Path.Combine(directory, IntegrationSettings.UntrustedEngineFile);

        await File.WriteAllTextAsync(target, IntegrationSettings.MatchMarker);
        await File.WriteAllTextAsync(negative, IntegrationSettings.NegativeContent);
        await File.WriteAllTextAsync(untrustedEngine, IntegrationSettings.UntrustedEngineContent);

        using var signingKey = RSA.Create();
        signingKey.KeySize = IntegrationSettings.SigningKeyBits;

        var ring = new TrustedRuleKeyring(new Dictionary<string, string>
        {
            [IntegrationSettings.TrustedKeyId] = signingKey.ExportSubjectPublicKeyInfoPem()
        });

        var verification = new TrustedRulePackageService(
            new LocalTrustedRuleBundleRepository(),
            ring,
            new RsaPssRuleSignatureTool(),
            new LocalRuleVersionRepository(state));

        var scan = new TrustedRuleScanService(verification, new YaraXCliTool());

        async Task WriteSignedPackage(long sequence, string source)
        {
            var bytes = Encoding.UTF8.GetBytes(source);
            var digest = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            var signedManifest = new TrustedRuleManifest(
                TrustedRuleSettings.Schema, sequence,
                IntegrationSettings.TrustedKeyId, digest);

            var json = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schema = signedManifest.Schema,
                sequence = signedManifest.Sequence,
                keyId = signedManifest.KeyId,
                rulesSha256 = signedManifest.RulesSha256
            });
            var signedPayload = TrustedRuleManifestCodec.SignaturePayload(signedManifest);
            var signatureBytes = signingKey.SignData(
                signedPayload, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

            await File.WriteAllBytesAsync(rules, bytes);
            await File.WriteAllBytesAsync(manifestFile, json);
            await File.WriteAllBytesAsync(signature, signatureBytes);
        }

        Task<RuleScanResult> ScanWith(string path, string yr) =>
            scan.ScanAsync(path, rules, manifestFile, signature, yr);

        static async Task ExpectRejection(
            Func<Task> test,
            string message,
            string failure)
        {
            try
            {
                await test();
            }
            catch (InvalidDataException error) when (error.Message == message)
            {
                return;
            }

            throw new InvalidOperationException(failure);
        }

        await WriteSignedPackage(
            IntegrationSettings.TrustedFirstVersion, IntegrationSettings.ExampleRules);
        var positive = await ScanWith(target, enginePath);
        if (positive.RuleIdentifiers.Count != 1
            || positive.RuleIdentifiers[0] != IntegrationSettings.RuleIdentifier)
            throw new InvalidOperationException(IntegrationSettings.PositiveMatchFailure);

        // Same verified sequence and manifest can be reused for another target.
        var noMatch = await ScanWith(negative, enginePath);
        if (noMatch.RuleIdentifiers.Count != 0)
            throw new InvalidOperationException(IntegrationSettings.NegativeMatchFailure);

        await WriteSignedPackage(
            IntegrationSettings.TrustedFirstVersion, IntegrationSettings.AlternativeRule);
        await ExpectRejection(async () => { await ScanWith(negative, enginePath); },
            TrustedRuleMessages.SequenceConflict, IntegrationSettings.SequenceConflictAccepted);

        await WriteSignedPackage(
            IntegrationSettings.TrustedSecondVersion, IntegrationSettings.AlternativeRule);
        var accepted = await ScanWith(negative, enginePath);
        if (accepted.RuleIdentifiers.Count != 0)
            throw new InvalidOperationException(IntegrationSettings.NegativeMatchFailure);

        await WriteSignedPackage(
            IntegrationSettings.TrustedFirstVersion, IntegrationSettings.ExampleRules);
        await ExpectRejection(async () => { await ScanWith(target, enginePath); },
            TrustedRuleMessages.DowngradeDenied, IntegrationSettings.RollbackAccepted);

        // A failed engine scan cannot advance the trusted sequence.
        await WriteSignedPackage(
            IntegrationSettings.TrustedThirdVersion, IntegrationSettings.ExampleRules);
        await ExpectRejection(async () => { await ScanWith(target, untrustedEngine); },
            RuleMessages.EngineDigestMismatch, IntegrationSettings.UntrustedEngineAccepted);

        var stateBytes = await File.ReadAllBytesAsync(state);
        if (stateBytes.Length != TrustedRuleSettings.VersionStateLengthBytes
            || BinaryPrimitives.ReadInt64LittleEndian(
                stateBytes.AsSpan(0, TrustedRuleSettings.SequenceLengthBytes))
                != IntegrationSettings.TrustedSecondVersion)
            throw new InvalidOperationException(IntegrationSettings.FailedScanAdvancedVersion);

        // Corrupt the rule bytes without changing the signed manifest.
        await File.WriteAllTextAsync(rules, IntegrationSettings.AlternativeRule);
        await ExpectRejection(async () => { await ScanWith(target, enginePath); },
            TrustedRuleMessages.BadRuleHash, IntegrationSettings.ModifiedRuleAccepted);

        Console.WriteLine(IntegrationSettings.TrustedTestsPassed);
    }
}
