// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Cli/config/CliSettings.cs
// # 📌 Amac: Konsol komutlarini ve cikis kodlarini merkezi tanimlamak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.0
// # Aciklama: Konsol komutlarini ve cikis kodlarini merkezi tanimlamak
// # Bagimli Oldugu Katman: Config

namespace TurkuazAV.Cli.Config;
public static class CliSettings
{
    public const string ScanCommand = "scan";
    public const string ScanRulesCommand = "scan-rules";
    public const int ScanArgs = 2;
    public const int RuleArgs = 6;
}
public static class ExitCodes
{
    public const int Success = 0;
    public const int InvalidArguments = 2;
    public const int ScanFailed = 3;
}
