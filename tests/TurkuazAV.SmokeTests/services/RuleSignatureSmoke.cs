// # 📄 Dosya Yolu: /TurkuazAV/tests/TurkuazAV.SmokeTests/services/RuleSignatureSmoke.cs
// # 📌 Amac: Dogrulanan ve bozulmus kural paketlerini regresyon ile kontrol etmek
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.0
// # Aciklama: Dogrulanan ve bozulmus kural paketlerini regresyon ile kontrol etmek
// # Bagimli Oldugu Katman: Service | Repo | Tool | Config

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TurkuazAV.Core.Repositories;
using TurkuazAV.Core.Services;
using TurkuazAV.Core.Tools;
using TurkuazAV.SmokeTests.Config;
using TurkuazAV.SmokeTests.Tools;
namespace TurkuazAV.SmokeTests.Services;
public static class RuleSignatureSmoke
{
    public static async Task RunAsync(string directory)
    {
        var rulePath = Path.Combine(directory, RuleTestConfig.RulesFileName);
        var sigPath = Path.Combine(directory, RuleTestConfig.SignatureFileName);
        var keyPath = Path.Combine(directory, RuleTestConfig.PublicKeyFileName);
        var targetPath = Path.Combine(directory, RuleTestConfig.TargetFileName);
        var rules = Encoding.UTF8.GetBytes(RuleTestConfig.SampleRule);
        await File.WriteAllBytesAsync(rulePath, rules);
        await File.WriteAllTextAsync(targetPath, TestSettings.TestText);

        using var rsa = RSA.Create();
        rsa.KeySize = RuleTestConfig.KeyBits;
        await File.WriteAllTextAsync(keyPath, rsa.ExportSubjectPublicKeyInfoPem());
        await File.WriteAllBytesAsync(sigPath,
            rsa.SignData(rules, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

        var engine = new FakeRuleEngineTool();
        var service = new RuleScanService(
            new LocalRuleRepository(), new RsaPssRuleSignatureTool(), engine);
        var scanned = await service.ScanAsync(targetPath, rulePath, sigPath, keyPath,
            RuleTestConfig.StubExecutable);
        if (engine.CallCount != 1 || engine.RuleText != RuleTestConfig.SampleRule
            || scanned.RuleIdentifiers.Single() != RuleTestConfig.SampleMatch)
            throw new InvalidOperationException(RuleTestConfig.WrongRuleContent);

        await File.WriteAllTextAsync(rulePath, RuleTestConfig.AlteredRule);
        var rejected = false;
        try
        {
            await service.ScanAsync(targetPath, rulePath, sigPath, keyPath,
                RuleTestConfig.StubExecutable);
        }
        catch (InvalidDataException) { rejected = true; }
        if (!rejected || engine.CallCount != 1)
            throw new InvalidOperationException(RuleTestConfig.InvalidSignatureAccepted);

        var ndjson = JsonSerializer.Serialize(new {
            path = targetPath,
            rules = new[] { new { identifier = RuleTestConfig.SampleMatch } }
        });
        var identifiers = YaraXOutputParser.Parse(ndjson, targetPath);
        if (identifiers.Single() != RuleTestConfig.SampleMatch)
            throw new InvalidOperationException(RuleTestConfig.WrongRuleContent);

        rejected = false;
        try { YaraXOutputParser.Parse("{bad-json}", targetPath); }
        catch (InvalidDataException) { rejected = true; }
        if (!rejected)
            throw new InvalidOperationException(RuleTestConfig.ParserShouldReject);
    }
}
