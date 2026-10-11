// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Cli/config/CliSettings.cs
// # 📌 Amac: Komutlarin isimlerini ve cikis kodlarini merkezilestirmek
// # 📌 Modul - FileType: Config - CSharp
// # Version: 0.1.0
// # Aciklama: Komutlarin isimlerini ve cikis kodlarini merkezilestirmek
// # Bagimli Oldugu Katman: Config

namespace TurkuazAV.Cli.Config;

public static class CliSettings
{
    public const string ScanCommand = "scan";
    public const int ScanArgumentsCount = 2;
}

public static class ExitCodes
{
    public const int Success = 0;
    public const int InvalidArguments = 2;
    public const int ScanFailed = 3;
}
