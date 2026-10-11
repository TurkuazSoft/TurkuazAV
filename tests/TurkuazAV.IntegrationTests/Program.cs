// # 📄 Dosya Yolu: /TurkuazAV/tests/TurkuazAV.IntegrationTests/Program.cs
// # 📌 Amac: Gercek YARA-X ile pozitif negatif ve bozuk imza akisini dogrulamak
// # 📌 Modul - FileType: Tests - CSharp
// # Version: 0.2.4
// # Aciklama: Gercek YARA-X ile pozitif negatif ve bozuk imza akisini dogrulamak
// # Bagimli Oldugu Katman: Service | Repo | Tool | Config

using System.Security.Cryptography;
using System.Text;
using TurkuazAV.Core.Repositories;
using TurkuazAV.Core.Language;
using TurkuazAV.Core.Services;
using TurkuazAV.Core.Tools;
using TurkuazAV.IntegrationTests.Config;
using TurkuazAV.IntegrationTests.Services;

var enginePath = Environment.GetEnvironmentVariable(IntegrationSettings.EngineEnvironmentVariable);
if (string.IsNullOrWhiteSpace(enginePath) || !File.Exists(enginePath))
{
    Console.Error.WriteLine(IntegrationSettings.MissingEngine);
    return 1;
}

var tempRoot = Path.Combine(
    Path.GetTempPath(), IntegrationSettings.TemporaryDirectoryPrefix +
    Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(tempRoot);

try
{
    var rulePath = Path.Combine(tempRoot, IntegrationSettings.RulesName);
    var signaturePath = Path.Combine(tempRoot, IntegrationSettings.SignatureName);
    var keyPath = Path.Combine(tempRoot, IntegrationSettings.PublicKeyName);
    var positivePath = Path.Combine(tempRoot, IntegrationSettings.PositiveFileName);
    var negativePath = Path.Combine(tempRoot, IntegrationSettings.NegativeFileName);

    var ruleData = Encoding.UTF8.GetBytes(IntegrationSettings.ExampleRules);
    await File.WriteAllBytesAsync(rulePath, ruleData);
    await File.WriteAllTextAsync(positivePath, IntegrationSettings.MatchMarker);
    await File.WriteAllTextAsync(negativePath, IntegrationSettings.NegativeContent);

    using var key = RSA.Create();
    key.KeySize = IntegrationSettings.SigningKeyBits;
    await File.WriteAllTextAsync(keyPath, key.ExportSubjectPublicKeyInfoPem());
    await File.WriteAllBytesAsync(
        signaturePath,
        key.SignData(ruleData, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

    var service = new RuleScanService(
        new LocalRuleRepository(), new RsaPssRuleSignatureTool(), new YaraXCliTool());

    var positive = await service.ScanAsync(
        positivePath, rulePath, signaturePath, keyPath, enginePath);
    if (positive.RuleIdentifiers.Count != 1
        || positive.RuleIdentifiers[0] != IntegrationSettings.RuleIdentifier)
        throw new InvalidOperationException(IntegrationSettings.PositiveMatchFailure);

    var negative = await service.ScanAsync(
        negativePath, rulePath, signaturePath, keyPath, enginePath);
    if (negative.RuleIdentifiers.Count != 0)
        throw new InvalidOperationException(IntegrationSettings.NegativeMatchFailure);

    await File.WriteAllTextAsync(rulePath, IntegrationSettings.NegativeContent);
    var signatureRejected = false;
    try
    {
        await service.ScanAsync(
            positivePath, rulePath, signaturePath, keyPath, enginePath);
    }
    catch (InvalidDataException)
    {
        signatureRejected = true;
    }

    if (!signatureRejected)
        throw new InvalidOperationException(IntegrationSettings.InvalidSignatureFailure);

    // Restore the original, valid signed rule before checking the engine hash.
    await File.WriteAllBytesAsync(rulePath, ruleData);
    var untrustedEngine = Path.Combine(tempRoot, IntegrationSettings.UntrustedEngineFile);
    await File.WriteAllTextAsync(untrustedEngine, IntegrationSettings.UntrustedEngineContent);

    var untrustedRejected = false;
    try
    {
        await service.ScanAsync(
            positivePath, rulePath, signaturePath, keyPath, untrustedEngine);
    }
    catch (InvalidDataException error) when (
        error.Message == RuleMessages.EngineDigestMismatch)
    {
        untrustedRejected = true;
    }

    if (!untrustedRejected)
        throw new InvalidOperationException(IntegrationSettings.UntrustedEngineAccepted);

    await TrustedRuleIntegrationTests.RunAsync(tempRoot, enginePath);

    Console.WriteLine(IntegrationSettings.TestsPassed);
    return 0;
}
catch (Exception error)
{
    Console.Error.WriteLine(error);
    return 1;
}
finally
{
    Directory.Delete(tempRoot, recursive: true);
}
