// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/models/RuleModels.cs
// # 📌 Amac: Kural paketini ve imza dogrulama sonucunu tasimak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.0
// # Aciklama: Kural paketini ve imza dogrulama sonucunu tasimak
// # Bagimli Oldugu Katman: Service | Repo | Tool

namespace TurkuazAV.Core.Models;
public sealed record RuleBundle(byte[] Rules, byte[] Signature, string PublicKeyPem);
public sealed record RuleScanResult(string FilePath, IReadOnlyList<string> RuleIdentifiers);
