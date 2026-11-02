// Dosya Yolu: REPO_ROOT/src/TurkuazAV.Cli/views/ConsoleRuleScanJsonView.cs
// Amac: TurkuazInstaller icin makine tarafindan okunabilen YARA-X eslesme raporu
// Modul - FileType: View - CSharp
// Version: 0.1.0
// Aciklama: Schema v1; match/no_match, SHA256 ve kurallar; temiz garantisi yok
// Bagimli Oldugu Katman: View | Service | Model

using System.Text.Json;
using TurkuazAV.Core.Models;

namespace TurkuazAV.Cli.Views;

public sealed class ConsoleRuleScanJsonView
{
    public const string Schema = "turkuazav.rule-scan.v1";
    public const string Matched = "match";
    public const string NoMatch = "no_match";

    // BRK-AV-JSON-002: A no_match report MUST NOT be treated as malware-free.
    public void Write(RuleScanResult result, string sha256)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (sha256.Length != 64 || !sha256.All(Uri.IsHexDigit))
            throw new InvalidDataException("Target SHA-256 is invalid.");
        var evidence = new
        {
            schema = Schema,
            status = result.RuleIdentifiers.Count > 0 ? Matched : NoMatch,
            sha256 = sha256.ToLowerInvariant(),
            matches = result.RuleIdentifiers,
        };
        Console.Out.WriteLine(JsonSerializer.Serialize(evidence));
    }
}
