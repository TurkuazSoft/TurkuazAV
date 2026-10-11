// # 📄 Dosya Yolu: /TurkuazAV/tests/TurkuazAV.SmokeTests/config/TestSettings.cs
// # 📌 Amac: Smoke test verilerini ve sinirlarini merkezilestirmek
// # 📌 Modul - FileType: Config - CSharp
// # Version: 0.1.0
// # Aciklama: Smoke test verilerini ve sinirlarini merkezilestirmek
// # Bagimli Oldugu Katman: Config

namespace TurkuazAV.SmokeTests.Config;

public static class TestSettings
{
    public const long MaxFileSizeBytes = 32;
    public const int OversizedFileBytes = 33;
    public const string SampleFileName = "sample.txt";
    public const string OversizedFileName = "oversized.bin";
    public const string TestText = "TurkuazAV test content";
    public const string Passed = "SMOKE_TESTS_PASSED";
    public const string Failed = "SMOKE_TESTS_FAILED";
    public const string TempDirectoryPrefix = "TurkuazAV-Smoke-";
}
