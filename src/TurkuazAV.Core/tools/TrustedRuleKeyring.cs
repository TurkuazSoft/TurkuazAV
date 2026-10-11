// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/tools/TrustedRuleKeyring.cs
// # 📌 Amac: Kullanici girdisi olmayan onayli yayinci anahtari listesi sunmak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.3
// # Aciklama: Kullanici girdisi olmayan onayli yayinci anahtari listesi sunmak
// # Bagimli Oldugu Katman: Tool | Language

using System.Security.Cryptography;
using TurkuazAV.Core.Language;

namespace TurkuazAV.Core.Tools;

// Caller must bootstrap this ring from independently trusted application configuration.
// Never construct it from an unverified downloaded manifest or CLI-supplied key file.
public sealed class TrustedRuleKeyring
{
    private readonly IReadOnlyDictionary<string, string> _publicKeys;

    public TrustedRuleKeyring(IEnumerable<KeyValuePair<string, string>> pinnedPublicKeys)
    {
        ArgumentNullException.ThrowIfNull(pinnedPublicKeys);
        var validated = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in pinnedPublicKeys)
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pair.Value);
            if (rsa.KeySize < 2048 || !validated.TryAdd(pair.Key, pair.Value))
                throw new InvalidDataException(TrustedRuleMessages.UnsupportedKey);
        }
        _publicKeys = validated;
    }

    public string GetRequiredKey(string keyId)
    {
        if (!_publicKeys.TryGetValue(keyId, out var key))
            throw new InvalidDataException(TrustedRuleMessages.UntrustedPublisher);
        return key;
    }
}
