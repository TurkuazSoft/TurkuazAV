// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/language/TrustedRuleMessages.cs
// # 📌 Amac: Imzali kural guven modeli hata metinlerini merkezi tanimlamak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.3
// # Aciklama: Imzali kural guven modeli hata metinlerini merkezi tanimlamak
// # Bagimli Oldugu Katman: Language

namespace TurkuazAV.Core.Language;

public static class TrustedRuleMessages
{
    public const string MalformedManifest = "Invalid signed rule manifest.";
    public const string UntrustedPublisher = "The rule publisher key is not trusted.";
    public const string BadSignature = "Rule manifest signature verification failed.";
    public const string BadRuleHash = "Rule content hash differs from the signed manifest.";
    public const string DowngradeDenied = "Rule sequence rollback was rejected.";
    public const string CorruptState = "Rule version state is corrupted; refusing update.";
    public const string LinkDenied = "Rule package files must not be symbolic links.";
    public const string FileTooLarge = "Rule package file exceeds the size limit.";
    public const string UnsupportedKey = "The trusted publisher key is invalid.";
}
