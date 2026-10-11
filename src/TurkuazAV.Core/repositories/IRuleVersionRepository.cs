// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/repositories/IRuleVersionRepository.cs
// # 📌 Amac: En yuksek imzali surumu ve manifest parmak izini kalici saklamak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.4
// # Aciklama: En yuksek imzali surumu ve manifest parmak izini kalici saklamak
// # Bagimli Oldugu Katman: Repo

namespace TurkuazAV.Core.Repositories;

public interface IRuleVersionRepository
{
    Task AcceptAsync(
        long signedSequence,
        string signedManifestFingerprint,
        CancellationToken cancellationToken = default);
}
