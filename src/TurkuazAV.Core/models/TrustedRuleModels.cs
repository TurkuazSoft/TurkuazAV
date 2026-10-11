// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/models/TrustedRuleModels.cs
// # 📌 Amac: Imzali kural paketinin dogrulanmis manifest parmak izini tasimak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.4
// # Aciklama: Imzali kural paketinin dogrulanmis manifest parmak izini tasimak
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
    byte[] VerifiedRules,
    string ManifestFingerprint);
