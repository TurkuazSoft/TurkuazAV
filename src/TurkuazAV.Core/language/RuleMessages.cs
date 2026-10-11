// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/language/RuleMessages.cs
// # 📌 Amac: Guvenlik denetimi ve motor hata metinlerini saklamak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.0
// # Aciklama: Guvenlik denetimi ve motor hata metinlerini saklamak
// # Bagimli Oldugu Katman: Language

namespace TurkuazAV.Core.Language;
public static class RuleMessages
{
    public const string InvalidSignature = "Rule signature verification failed.";
    public const string InvalidPath = "Only regular non-link files are supported.";
    public const string Oversized = "Input exceeds the configured size limit.";
    public const string EngineNotFound = "YARA-X executable is missing or not absolute.";
    public const string EngineFailure = "YARA-X scan failed.";
    public const string OutputLimit = "Engine output exceeded the configured limit.";
    public const string BadOutput = "Invalid YARA-X NDJSON output.";
    public const string BadPath = "YARA-X returned unexpected target path.";
    public const string WeakKey = "Signing key must be at least 2048 bits.";
}
