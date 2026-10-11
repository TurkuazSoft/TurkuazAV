// # 📄 Dosya Yolu: /TurkuazAV/tests/TurkuazAV.SmokeTests/config/TrustedRuleTestSettings.cs
// # 📌 Amac: Publisher guven ve rollback test veri sabitlerini tanimlamak
// # 📌 Modul - FileType: Tests - CSharp
// # Version: 0.2.4
// # Aciklama: Publisher guven ve rollback test veri sabitlerini tanimlamak
// # Bagimli Oldugu Katman: Config

namespace TurkuazAV.SmokeTests.Config;

public static class TrustedRuleTestSettings
{
    public const string Subdirectory = "trusted-rule-tests";
    public const string RulesFile = "trusted.yar";
    public const string ManifestFile = "trusted.manifest.json";
    public const string SignatureFile = "trusted.sig";
    public const string StateFile = "publisher-version.bin";
    public const string CorruptStateFile = "corrupt-version.bin";
    public const string KeyA = "publisher-2026-a";
    public const string KeyB = "publisher-2026-b";
    public const string UnknownKey = "unrecognized-key";
    public const string RuleA = "rule safe_sample_v1 { condition: true }";
    public const string RuleB = "rule safe_sample_v2 { condition: true }";
    public const string AlteredRules = "rule altered_without_signature { condition: false }";
    public const string InvalidSignatureAccepted = "Invalid manifest signature was accepted.";
    public const string AlteredRulesAccepted = "Modified rules were accepted.";
    public const string UnknownPublisherAccepted = "Unknown publisher was accepted.";
    public const string RollbackAccepted = "Old signed rule version was accepted.";
    public const string SequenceConflictAccepted = "Reused signed sequence with different rules was accepted.";
    public const string RevokedKeyAccepted = "Revoked publisher key was accepted.";
    public const string StateCorruptionAccepted = "Corrupt local sequence state was accepted.";
    public const string ValidPackageRejected = "Valid signed rule package was rejected.";
    public const string InvalidManifestAccepted = "Malformed rule manifest was accepted.";
    public const int KeySizeBits = 2048;
    public const long InitialSequence = 1;
    public const long RotatedSequence = 2;
    public const long RevokedSequence = 3;
}
