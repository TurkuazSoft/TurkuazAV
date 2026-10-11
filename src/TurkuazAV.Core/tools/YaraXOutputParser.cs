// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/tools/YaraXOutputParser.cs
// # 📌 Amac: NDJSON kural eslesmelerini guvenli olarak ayrismak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.0
// # Aciklama: NDJSON kural eslesmelerini guvenli olarak ayrismak
// # Bagimli Oldugu Katman: Tool | Config | Language

using System.Text.Json;
using TurkuazAV.Core.Config;
using TurkuazAV.Core.Language;
namespace TurkuazAV.Core.Tools;
public static class YaraXOutputParser
{
    public static IReadOnlyList<string> Parse(string ndjson, string expectedFile)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        var comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var target = Path.GetFullPath(expectedFile);
        foreach (var line in ndjson.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                using var doc = JsonDocument.Parse(line);
                var value = doc.RootElement;
                var foundPath = value.GetProperty(RuleSettings.JsonPath).GetString();
                if (string.IsNullOrEmpty(foundPath) ||
                    !string.Equals(Path.GetFullPath(foundPath), target, comparison))
                    throw new InvalidDataException(RuleMessages.BadPath);
                var rules = value.GetProperty(RuleSettings.JsonRules);
                if (rules.ValueKind != JsonValueKind.Array)
                    throw new InvalidDataException(RuleMessages.BadOutput);
                foreach (var rule in rules.EnumerateArray())
                {
                    var id = rule.GetProperty(RuleSettings.JsonIdentifier).GetString();
                    if (string.IsNullOrWhiteSpace(id))
                        throw new InvalidDataException(RuleMessages.BadOutput);
                    result.Add(id);
                }
            }
            catch (Exception error) when (error is JsonException or KeyNotFoundException
                or ArgumentException or InvalidOperationException)
            {
                throw new InvalidDataException(RuleMessages.BadOutput, error);
            }
        }
        return result.OrderBy(item => item, StringComparer.Ordinal).ToArray();
    }
}
