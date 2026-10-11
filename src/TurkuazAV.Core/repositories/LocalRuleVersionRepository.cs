// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/repositories/LocalRuleVersionRepository.cs
// # 📌 Amac: Bir islemde artan ve diskte saklanan kural surumunu guvencelemek
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.3
// # Aciklama: Bir islemde artan ve diskte saklanan kural surumunu guvencelemek
// # Bagimli Oldugu Katman: Repo | Config | Language

using System.Buffers.Binary;
using TurkuazAV.Core.Config;
using TurkuazAV.Core.Language;

namespace TurkuazAV.Core.Repositories;

// State file must be under a trusted, access-controlled service directory.
// Exclusive sharing rejects concurrent writers; corrupt files fail closed.
public sealed class LocalRuleVersionRepository : IRuleVersionRepository
{
    private readonly string _stateFile;

    public LocalRuleVersionRepository(string stateFile)
    {
        _stateFile = Path.GetFullPath(stateFile);
    }

    public async Task AcceptAsync(
        long signedSequence,
        CancellationToken cancellationToken = default)
    {
        if (signedSequence <= 0)
            throw new InvalidDataException(TrustedRuleMessages.MalformedManifest);

        await using var stream = new FileStream(
            _stateFile,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None,
            TrustedRuleSettings.VersionStateLengthBytes,
            FileOptions.None);

        if (stream.Length != 0
            && stream.Length != TrustedRuleSettings.VersionStateLengthBytes)
            throw new InvalidDataException(TrustedRuleMessages.CorruptState);

        long highest = 0;
        if (stream.Length == TrustedRuleSettings.VersionStateLengthBytes)
        {
            var existing = new byte[TrustedRuleSettings.VersionStateLengthBytes];
            await stream.ReadExactlyAsync(existing, cancellationToken);
            highest = BinaryPrimitives.ReadInt64LittleEndian(existing);
            if (highest <= 0)
                throw new InvalidDataException(TrustedRuleMessages.CorruptState);
        }

        if (signedSequence < highest)
            throw new InvalidDataException(TrustedRuleMessages.DowngradeDenied);

        if (signedSequence == highest)
            return;

        var next = new byte[TrustedRuleSettings.VersionStateLengthBytes];
        BinaryPrimitives.WriteInt64LittleEndian(next, signedSequence);
        stream.Position = 0;
        await stream.WriteAsync(next, cancellationToken);
        stream.Flush(flushToDisk: true);
    }
}
