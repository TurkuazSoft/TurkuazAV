// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/config/TrustedRuleSettings.cs
// # 📌 Amac: Imzali paket formatini ve guvenlik limitlerini merkezi tanimlamak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.3
// # Aciklama: Imzali paket formatini ve guvenlik limitlerini merkezi tanimlamak
// # Bagimli Oldugu Katman: Config

namespace TurkuazAV.Core.Config;

public static class TrustedRuleSettings
{
    public const string Schema = "turkuazav.rule-package.v1";
    public const string SignatureDomain = "TurkuazAV.rule-package.v1";
    public const int MaximumManifestBytes = 16_384;
    public const int MaximumSignatureBytes = 8_192;
    public const int MaximumKeyIdLength = 64;
    public const int Sha256HexLength = 64;
    public const int VersionStateLengthBytes = sizeof(long);
    public const string ManifestSchemaField = "schema";
    public const string ManifestVersionField = "sequence";
    public const string ManifestKeyIdField = "keyId";
    public const string ManifestHashField = "rulesSha256";
}
