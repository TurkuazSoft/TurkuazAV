// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/repositories/IRuleRepository.cs
// # 📌 Amac: Imzali kurallarin kaynak okuma arayuzunu sunmak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.0
// # Aciklama: Imzali kurallarin kaynak okuma arayuzunu sunmak
// # Bagimli Oldugu Katman: Repo

using TurkuazAV.Core.Models;
namespace TurkuazAV.Core.Repositories;
public interface IRuleRepository
{
    Task<RuleBundle> LoadAsync(string rulesPath, string signaturePath, string publicKeyPath,
        CancellationToken cancellationToken = default);
}
