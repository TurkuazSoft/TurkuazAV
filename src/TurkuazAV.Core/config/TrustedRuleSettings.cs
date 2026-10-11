// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/config/TrustedRuleSettings.cs
// # 📌 Amac: Guvenilir paket surum kaydinin v2 formatini tanimlamak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.4
// # Aciklama: Guvenilir paket surum kaydinin v2 formatini tanimlamak
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
    public const int SequenceLengthBytes = sizeof(long);
    public const int FingerprintLengthBytes = 32;
    public const int VersionStateLengthBytes = SequenceLengthBytes + FingerprintLengthBytes;
    public const string ManifestSchemaField = "schema";
    public const string ManifestVersionField = "sequence";
    public const string ManifestKeyIdField = "keyId";
    public const string ManifestHashField = "rulesSha256";
}
