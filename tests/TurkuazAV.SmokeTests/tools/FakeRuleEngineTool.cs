// # 📄 Dosya Yolu: /TurkuazAV/tests/TurkuazAV.SmokeTests/tools/FakeRuleEngineTool.cs
// # 📌 Amac: Gercek engine binary gerektirmeden Service akisini test etmek
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.0
// # Aciklama: Gercek engine binary gerektirmeden Service akisini test etmek
// # Bagimli Oldugu Katman: Tool | Service

using TurkuazAV.Core.Tools;
using TurkuazAV.SmokeTests.Config;
namespace TurkuazAV.SmokeTests.Tools;
public sealed class FakeRuleEngineTool : IRuleEngineTool
{
    public int CallCount { get; private set; }
    public string? RuleText { get; private set; }
    public async Task<IReadOnlyList<string>> ScanAsync(string exe, string verifiedRulePath,
        string target, CancellationToken cancellationToken = default)
    {
        CallCount++;
        RuleText = await File.ReadAllTextAsync(verifiedRulePath, cancellationToken);
        return new[] { RuleTestConfig.SampleMatch };
    }
}
