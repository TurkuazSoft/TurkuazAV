// # 📄 Dosya Yolu: /TurkuazAV/tests/TurkuazAV.IntegrationTests/config/IntegrationSettings.cs
// # 📌 Amac: Zararsiz orneklerin ve beklenen kural eslesmelerinin ayarlarini tanimlamak
// # 📌 Modul - FileType: Config - CSharp
// # Version: 0.2.1
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
    public const string TestsPassed = "YARAX_E2E_TESTS_PASSED";
    public const int SigningKeyBits = 2048;
}
