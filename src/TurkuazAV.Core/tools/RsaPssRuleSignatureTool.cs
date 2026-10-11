// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/tools/RsaPssRuleSignatureTool.cs
// # 📌 Amac: RSA PSS SHA256 imzasini dogrulamak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.0
// # Aciklama: RSA PSS SHA256 imzasini dogrulamak
// # Bagimli Oldugu Katman: Tool | Config | Language

using System.Security.Cryptography;
using TurkuazAV.Core.Config;
using TurkuazAV.Core.Language;
namespace TurkuazAV.Core.Tools;
public sealed class RsaPssRuleSignatureTool : IRuleSignatureTool
{
    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, string publicKeyPem)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicKeyPem);
        if (rsa.KeySize < RuleSettings.MinimumRsaKeyBits)
            throw new CryptographicException(RuleMessages.WeakKey);
        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }
}
