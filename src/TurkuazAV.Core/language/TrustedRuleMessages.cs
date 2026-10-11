// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/language/TrustedRuleMessages.cs
// # 📌 Amac: Guvenilir paket entegrasyonu ve surum esitleme hatalarini belirlemek
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.4
// # Aciklama: Guvenilir paket entegrasyonu ve surum esitleme hatalarini belirlemek
// # Bagimli Oldugu Katman: Language

namespace TurkuazAV.Core.Language;

public static class TrustedRuleMessages
{
    public const string MalformedManifest = "Invalid signed rule manifest.";
    public const string UntrustedPublisher = "The rule publisher key is not trusted.";
    public const string BadSignature = "Rule manifest signature verification failed.";
    public const string BadRuleHash = "Rule content hash differs from the signed manifest.";
    public const string DowngradeDenied = "Rule sequence rollback was rejected.";
    public const string SequenceConflict = "Rule sequence was already used for different signed content.";
    public const string CorruptState = "Rule version state is corrupted; refusing update.";
    public const string LinkDenied = "Rule package files must not be symbolic links.";
    public const string FileTooLarge = "Rule package file exceeds the size limit.";
    public const string UnsupportedKey = "The trusted publisher key is invalid.";
}
