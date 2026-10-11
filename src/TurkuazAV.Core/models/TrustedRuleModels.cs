// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/models/TrustedRuleModels.cs
// # 📌 Amac: Imzali kural manifesti, paket ve kabul edilen sonucu tanimlamak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.3
// # Aciklama: Imzali kural manifesti, paket ve kabul edilen sonucu tanimlamak
// # Bagimli Oldugu Katman: Service | Repo | Tool

namespace TurkuazAV.Core.Models;

public sealed record TrustedRuleManifest(
    string Schema,
    long Sequence,
    string KeyId,
    string RulesSha256);

public sealed record SignedRulePackage(
    byte[] Rules,
    byte[] ManifestJson,
    byte[] Signature);

public sealed record VerifiedRulePackage(
    long Sequence,
    string PublisherKeyId,
    byte[] VerifiedRules);
