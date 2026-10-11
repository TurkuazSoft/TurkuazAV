// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Cli/language/CliMessages.cs
// # 📌 Amac: Konsol ekraninda gosterilen metinleri tutmak
// # 📌 Modul - FileType: Language - CSharp
// # Version: 0.1.0
// # Aciklama: Konsol ekraninda gosterilen metinleri tutmak
// # Bagimli Oldugu Katman: Language

namespace TurkuazAV.Cli.Language;

public static class CliMessages
{
    public const string Usage = "Usage: turkuazav scan <file-or-directory>";
    public const string Hashed = "OK | {0} | {1} | {2} bytes";
    public const string Skipped = "SKIP | {0} | {1}";
    public const string Failed = "ERROR | {0} | {1}";
    public const string Summary = "Summary: hashed={0}, skipped={1}, failed={2}";
    public const string Fatal = "Scan error: {0}";
}
