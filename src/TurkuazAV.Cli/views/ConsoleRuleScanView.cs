// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Cli/views/ConsoleRuleScanView.cs
// # 📌 Amac: Kural eslesmelerini zararlilik karari vermeden konsola yazmak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.0
// # Aciklama: Kural eslesmelerini zararlilik karari vermeden konsola yazmak
// # Bagimli Oldugu Katman: View | Language

using System.Globalization;
using TurkuazAV.Cli.Language;
using TurkuazAV.Core.Models;
namespace TurkuazAV.Cli.Views;
public sealed class ConsoleRuleScanView
{
    public void Write(RuleScanResult result)
    {
        if (result.RuleIdentifiers.Count == 0)
        {
            Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
                CliMessages.NoRuleMatch, result.FilePath));
            return;
        }
        foreach (var rule in result.RuleIdentifiers)
        {
            Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
                CliMessages.RuleMatch, result.FilePath, rule));
        }
    }
}
