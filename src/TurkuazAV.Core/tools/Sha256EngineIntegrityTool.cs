// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/tools/Sha256EngineIntegrityTool.cs
// # 📌 Amac: YARA-X ikili dosyasini pinlenmis SHA256 ozetiyle karsilastirmak
// # 📌 Modul - FileType: Tool - CSharp
// # Version: 0.2.2
// # Aciklama: YARA-X ikili dosyasini pinlenmis SHA256 ozetiyle karsilastirmak
// # Bagimli Oldugu Katman: Tool | Config | Language

using System.Security.Cryptography;
using TurkuazAV.Core.Config;
using TurkuazAV.Core.Language;

namespace TurkuazAV.Core.Tools;

public sealed class Sha256EngineIntegrityTool : IEngineIntegrityTool
{
    public async Task VerifyAsync(
        string executablePath,
        CancellationToken cancellationToken = default)
    {
        if (!Path.IsPathFullyQualified(executablePath) || !File.Exists(executablePath))
            throw new FileNotFoundException(RuleMessages.EngineNotFound, executablePath);

        var attributes = File.GetAttributes(executablePath);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new InvalidDataException(RuleMessages.EngineLinkDenied);

        var expected = Convert.FromHexString(TrustedEngineHashes.ForCurrentPlatform());

        await using var input = new FileStream(
            executablePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            RuleSettings.ReadBuffer,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        var actual = await SHA256.HashDataAsync(input, cancellationToken);
        if (!CryptographicOperations.FixedTimeEquals(actual, expected))
            throw new InvalidDataException(RuleMessages.EngineDigestMismatch);
    }
}
