// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Cli/language/CliMessages.cs
// # 📌 Amac: Kullaniciya gosterilen kural tarama mesajlarini saklamak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.0
// # Aciklama: Kullaniciya gosterilen kural tarama mesajlarini saklamak
// # Bagimli Oldugu Katman: Language

namespace TurkuazAV.Cli.Language;
public static class CliMessages
{
    public const string Usage = "Usage: turkuazav scan <file-or-directory> OR " +
        "turkuazav scan-rules <target> <rules.yar> <rules.sig> <public.pem> <absolute-yr-path>";
    public const string Hashed = "OK | {0} | {1} | {2} bytes";
    public const string Skipped = "SKIP | {0} | {1}";
    public const string Failed = "ERROR | {0} | {1}";
    public const string Summary = "Summary: hashed={0}, skipped={1}, failed={2}";
    public const string Fatal = "Scan error: {0}";
    public const string NoRuleMatch = "NO_RULE_MATCH | {0}";
    public const string RuleMatch = "RULE_MATCH | {0} | {1}";
}
