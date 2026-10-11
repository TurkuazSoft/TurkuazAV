// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/repositories/ITrustedRuleBundleRepository.cs
// # 📌 Amac: Boyut limitli imzali paket okuyucu sozlesmesi sunmak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.3
// # Aciklama: Boyut limitli imzali paket okuyucu sozlesmesi sunmak
// # Bagimli Oldugu Katman: Repo

using TurkuazAV.Core.Models;

namespace TurkuazAV.Core.Repositories;

public interface ITrustedRuleBundleRepository
{
    Task<SignedRulePackage> ReadAsync(
        string rulesPath,
        string manifestPath,
        string signaturePath,
        CancellationToken cancellationToken = default);
}
