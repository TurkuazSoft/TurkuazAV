// # 📄 Dosya Yolu: /TurkuazAV/tests/TurkuazAV.IntegrationTests/config/IntegrationSettings.cs
// # 📌 Amac: Zararsiz orneklerin ve beklenen kural eslesmelerinin ayarlarini tanimlamak
// # 📌 Modul - FileType: Config - CSharp
// # Version: 0.2.4
// # Aciklama: Zararsiz orneklerin ve beklenen kural eslesmelerinin ayarlarini tanimlamak
// # Bagimli Oldugu Katman: Config

namespace TurkuazAV.IntegrationTests.Config;

public static class IntegrationSettings
{
    public const string EngineEnvironmentVariable = "TURKUAZ_YR_PATH";
    public const string MissingEngine = "TURKUAZ_YR_PATH is missing or invalid.";
    public const string TemporaryDirectoryPrefix = "Turkuaz AV E2E ";
    public const string RulesName = "benign-test.yar";
    public const string SignatureName = "benign-test.sig";
    public const string PublicKeyName = "benign-test.pem";
    public const string PositiveFileName = "positive example.txt";
    public const string NegativeFileName = "negative example.txt";
    public const string MatchMarker = "TURKUAZ_AV_BENIGN_SIGNATURE_TEST_2026";
    public const string NegativeContent = "This file is safe and should not match.";
    public const string RuleIdentifier = "TurkuazAV_Benign_Integration";
    public const string ExampleRules =
        "rule TurkuazAV_Benign_Integration { strings: $marker = " +
        "\"TURKUAZ_AV_BENIGN_SIGNATURE_TEST_2026\" condition: $marker }";
    public const string PositiveMatchFailure = "Real YARA-X failed to find the harmless marker.";
    public const string NegativeMatchFailure = "Real YARA-X reported a match for a clean sample.";
    public const string InvalidSignatureFailure = "A changed rule was accepted by signature verification.";
    public const string UntrustedEngineFile = "untrusted-yr.bin";
    public const string UntrustedEngineContent = "harmless non-engine content";
    public const string UntrustedEngineAccepted = "Untrusted YARA-X executable was not rejected.";
    public const string TrustedTestDirectory = "trusted-scan-tests";
    public const string TrustedManifestName = "trusted-manifest.json";
    public const string TrustedStateName = "trusted-sequence.bin";
    public const string TrustedKeyId = "test-publisher-2026";
    public const string AlternativeRule =
        "rule TurkuazAV_Alternative { strings: $marker = " +
        "\"UNRELATED_BENIGN_PATTERN\" condition: $marker }";
    public const string SequenceConflictAccepted = "Same rule sequence with different content was accepted.";
    public const string RollbackAccepted = "Older signed rule package was accepted.";
    public const string FailedScanAdvancedVersion = "Failed engine scan advanced trusted rule sequence.";
    public const string ModifiedRuleAccepted = "Modified signed rule package was accepted.";
    public const string TrustedTestsPassed = "TRUSTED_YARAX_E2E_TESTS_PASSED";
    public const long TrustedFirstVersion = 1;
    public const long TrustedSecondVersion = 2;
    public const long TrustedThirdVersion = 3;
    public const string TestsPassed = "YARAX_E2E_TESTS_PASSED";
    public const int SigningKeyBits = 2048;
}
