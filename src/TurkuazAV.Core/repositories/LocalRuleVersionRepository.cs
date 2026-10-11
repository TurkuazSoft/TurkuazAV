// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/repositories/LocalRuleVersionRepository.cs
// # 📌 Amac: Kalici en yuksek sequence ve ayni-surum manifest parmak izini saklamak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.4
// # Aciklama: Kalici en yuksek sequence ve ayni-surum manifest parmak izini saklamak
// # Bagimli Oldugu Katman: Repo | Config | Language

using System.Buffers.Binary;
using System.Security.Cryptography;
using TurkuazAV.Core.Config;
using TurkuazAV.Core.Language;

namespace TurkuazAV.Core.Repositories;

// Trusted, access-controlled service state directory is required.
// Exclusive open avoids concurrent writes, but privileged state deletion remains a risk.
// The v0.2.3 8-byte state cannot be silently migrated: fail closed.
public sealed class LocalRuleVersionRepository : IRuleVersionRepository
{
    private readonly string _stateFile;

    public LocalRuleVersionRepository(string stateFile)
    {
        _stateFile = Path.GetFullPath(stateFile);
    }

    public async Task AcceptAsync(
        long signedSequence,
        string signedManifestFingerprint,
        CancellationToken cancellationToken = default)
    {
        if (signedSequence <= 0)
            throw new InvalidDataException(TrustedRuleMessages.MalformedManifest);

        byte[] requestedFingerprint;
        try
        {
            requestedFingerprint = Convert.FromHexString(signedManifestFingerprint);
        }
        catch (FormatException error)
        {
            throw new InvalidDataException(TrustedRuleMessages.MalformedManifest, error);
        }

        if (requestedFingerprint.Length != TrustedRuleSettings.FingerprintLengthBytes)
            throw new InvalidDataException(TrustedRuleMessages.MalformedManifest);

        await using var stream = new FileStream(
            _stateFile,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None,
            TrustedRuleSettings.VersionStateLengthBytes,
            FileOptions.None);

        if (stream.Length != 0 && stream.Length != TrustedRuleSettings.VersionStateLengthBytes)
            throw new InvalidDataException(TrustedRuleMessages.CorruptState);

        if (stream.Length == TrustedRuleSettings.VersionStateLengthBytes)
        {
            var saved = new byte[TrustedRuleSettings.VersionStateLengthBytes];
            await stream.ReadExactlyAsync(saved, cancellationToken);
            var previousSequence = BinaryPrimitives.ReadInt64LittleEndian(
                saved.AsSpan(0, TrustedRuleSettings.SequenceLengthBytes));

            if (previousSequence <= 0)
                throw new InvalidDataException(TrustedRuleMessages.CorruptState);
            if (signedSequence < previousSequence)
                throw new InvalidDataException(TrustedRuleMessages.DowngradeDenied);

            if (signedSequence == previousSequence)
            {
                if (!CryptographicOperations.FixedTimeEquals(
                    requestedFingerprint,
                    saved.AsSpan(TrustedRuleSettings.SequenceLengthBytes)))
                    throw new InvalidDataException(TrustedRuleMessages.SequenceConflict);
                return;
            }
        }

        var next = new byte[TrustedRuleSettings.VersionStateLengthBytes];
        BinaryPrimitives.WriteInt64LittleEndian(
            next.AsSpan(0, TrustedRuleSettings.SequenceLengthBytes), signedSequence);
        requestedFingerprint.AsSpan().CopyTo(
            next.AsSpan(TrustedRuleSettings.SequenceLengthBytes));

        stream.Position = 0;
        await stream.WriteAsync(next, cancellationToken);
        stream.Flush(flushToDisk: true);
    }
}
