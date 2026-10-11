// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/config/RuleSettings.cs
// # 📌 Amac: Kural taramasinda kullanilan limit ve sabitleri yonetmek
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.0
// # Aciklama: Kural taramasinda kullanilan limit ve sabitleri yonetmek
// # Bagimli Oldugu Katman: Config

namespace TurkuazAV.Core.Config;
public static class RuleSettings
{
    public const int MaxRuleBytes = 524288;
    public const int MaxSignatureBytes = 8192;
    public const int MaxPublicKeyBytes = 16384;
    public const int MaxOutputChars = 262144;
    public const int MinimumRsaKeyBits = 2048;
    public const int ReadBuffer = 4096;
    public const int TimeoutSeconds = 30;
    public const string TempPrefix = "TurkuazAV-Rules-";
    public const string VerifiedRuleName = "verified.yar";
    public const string YrScanVerb = "scan";
    public const string YrJsonOption = "--output-format=ndjson";
    public const string JsonPath = "path";
    public const string JsonRules = "rules";
    public const string JsonIdentifier = "identifier";
}
