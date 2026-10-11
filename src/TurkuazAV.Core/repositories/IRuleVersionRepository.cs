// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/repositories/IRuleVersionRepository.cs
// # 📌 Amac: Imzali paket surum geri donusunu takip eden kalici depoyu soyutlamak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.3
// # Aciklama: Imzali paket surum geri donusunu takip eden kalici depoyu soyutlamak
// # Bagimli Oldugu Katman: Repo

namespace TurkuazAV.Core.Repositories;

public interface IRuleVersionRepository
{
    Task AcceptAsync(long signedSequence, CancellationToken cancellationToken = default);
}
