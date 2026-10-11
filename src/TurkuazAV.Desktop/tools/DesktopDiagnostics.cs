// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Desktop/tools/DesktopDiagnostics.cs
// # 📌 Amac: Acilis ve kritik UI istisnalarini kullanici verisi olmadan yerelde kaydetmek
// # 📌 Modul - FileType: CSharp
// # Version: 0.3.1
// # Aciklama: Acilis ve kritik UI istisnalarini kullanici verisi olmadan yerelde kaydetmek
// # Bagimli Oldugu Katman: Tool | Config

using System.Text;

namespace TurkuazAV.Desktop.Tools;

public static class DesktopDiagnostics
{
    private const string ApplicationDirectory = "TurkuazAV";
    private const string DiagnosticsDirectory = "diagnostics";
    private const string LogFilePrefix = "desktop-";
    private const string LogFileExtension = ".log";
    private const int RetentionDays = 7;

    // This intentionally records no file paths, hashes, command lines or exception messages.
    // Logging must never itself prevent the program from starting.
    public static void Record(string eventCode, Exception? exception = null)
    {
        try
        {
            var root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                ApplicationDirectory,
                DiagnosticsDirectory);
            Directory.CreateDirectory(root);

            var now = DateTime.UtcNow;
            var logPath = Path.Combine(
                root, LogFilePrefix + now.ToString("yyyyMMdd") + LogFileExtension);
            var exceptionName = exception?.GetType().Name ?? "none";
            var line = $"{now:O} | {eventCode} | {exceptionName}";
            File.AppendAllText(logPath, line + Environment.NewLine, Encoding.UTF8);

            foreach (var file in Directory.EnumerateFiles(
                root, LogFilePrefix + "*" + LogFileExtension))
            {
                if (File.GetLastWriteTimeUtc(file) < now.AddDays(-RetentionDays))
                    File.Delete(file);
            }
        }
        catch
        {
            // Diagnostics is best effort and must not mask the original failure.
        }
    }
}
