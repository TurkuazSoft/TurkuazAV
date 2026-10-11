// # 📄 Dosya Yolu: /TurkuazAV/tests/TurkuazAV.SmokeTests/config/RuleTestConfig.cs
// # 📌 Amac: Imzali kural smoke test degerlerini merkezilestirmek
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.0
// # Aciklama: Imzali kural smoke test degerlerini merkezilestirmek
// # Bagimli Oldugu Katman: Config

namespace TurkuazAV.SmokeTests.Config;
public static class RuleTestConfig
{
    public const string RulesFileName = "sample.yar";
    public const string SignatureFileName = "sample.sig";
    public const string PublicKeyFileName = "public.pem";
    public const string TargetFileName = "scan-target.txt";
    public const string SampleRule = "rule sample_test { condition: true }";
    public const string AlteredRule = "rule sample_test { condition: false }";
    public const string SampleMatch = "sample_test";
    public const string StubExecutable = "mock";
    public const string InvalidSignatureAccepted = "Invalid rule signature passed validation.";
    public const string WrongRuleContent = "Verified rule bytes did not reach the engine.";
    public const string ParserShouldReject = "Invalid engine output was accepted.";
    public const int KeyBits = 2048;
}
