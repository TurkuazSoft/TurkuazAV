// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/repositories/LocalRuleRepository.cs
// # 📌 Amac: Kurallari ve imzayi dosyadan sinirli boyutta okumak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.0
// # Aciklama: Kurallari ve imzayi dosyadan sinirli boyutta okumak
// # Bagimli Oldugu Katman: Repo | Config | Language

using System.Text;
using TurkuazAV.Core.Config;
using TurkuazAV.Core.Language;
using TurkuazAV.Core.Models;
namespace TurkuazAV.Core.Repositories;
public sealed class LocalRuleRepository : IRuleRepository
{
    public async Task<RuleBundle> LoadAsync(string rulesPath, string signaturePath,
        string publicKeyPath, CancellationToken cancellationToken = default)
    {
        var rules = await ReadLimitedAsync(rulesPath, RuleSettings.MaxRuleBytes, cancellationToken);
        var signature = await ReadLimitedAsync(signaturePath, RuleSettings.MaxSignatureBytes, cancellationToken);
        var key = await ReadLimitedAsync(publicKeyPath, RuleSettings.MaxPublicKeyBytes, cancellationToken);
        return new RuleBundle(rules, signature, Encoding.UTF8.GetString(key));
    }

    private static async Task<byte[]> ReadLimitedAsync(string path, int limit, CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(path);
        var attributes = File.GetAttributes(fullPath);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new InvalidDataException(RuleMessages.InvalidPath);
        await using var input = new FileStream(fullPath, FileMode.Open, FileAccess.Read,
            FileShare.Read, RuleSettings.ReadBuffer, FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (input.Length > limit) throw new InvalidDataException(RuleMessages.Oversized);
        using var output = new MemoryStream();
        var bytes = new byte[RuleSettings.ReadBuffer];
        int read;
        while ((read = await input.ReadAsync(bytes.AsMemory(), cancellationToken)) != 0)
        {
            if (output.Length + read > limit) throw new InvalidDataException(RuleMessages.Oversized);
            output.Write(bytes, 0, read);
        }
        return output.ToArray();
    }
}
