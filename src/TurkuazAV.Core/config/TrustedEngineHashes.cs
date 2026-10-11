// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/config/TrustedEngineHashes.cs
// # 📌 Amac: Guvendigimiz resmi YARA-X executable SHA256 degerlerini kod icinde sabitlemek
// # 📌 Modul - FileType: Config - CSharp
// # Version: 0.2.2
// # Aciklama: Guvendigimiz resmi YARA-X executable SHA256 degerlerini kod icinde sabitlemek
// # Bagimli Oldugu Katman: Config

using System.Runtime.InteropServices;
using TurkuazAV.Core.Language;

namespace TurkuazAV.Core.Config;

public static class TrustedEngineHashes
{
    public const string WindowsX64Sha256 = "883c56964e0ffbe25eb0daf5b443914bea9db45d8dc4b6be7abbe59ff6797557";
    public const string LinuxX64Sha256 = "a4b6fec172c813cdfc099a4a392939cfc2c555e9e7745fb4b5ed369ab1edf93b";

    public static string ForCurrentPlatform()
    {
        if (RuntimeInformation.OSArchitecture != Architecture.X64)
            throw new PlatformNotSupportedException(RuleMessages.UnsupportedArchitecture);

        if (OperatingSystem.IsWindows())
            return WindowsX64Sha256;

        if (OperatingSystem.IsLinux())
            return LinuxX64Sha256;

        throw new PlatformNotSupportedException(RuleMessages.UnsupportedOperatingSystem);
    }
}

