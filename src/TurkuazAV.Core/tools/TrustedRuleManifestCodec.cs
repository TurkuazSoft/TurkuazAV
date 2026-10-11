// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/tools/TrustedRuleManifestCodec.cs
// # 📌 Amac: Imzali manifesti katilikla ayrismak ve kanonik imza icerigi olusturmak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.3
// # Aciklama: Imzali manifesti katilikla ayrismak ve kanonik imza icerigi olusturmak
// # Bagimli Oldugu Katman: Tool | Config | Language

using System.Globalization;
using System.Text;
using System.Text.Json;
using TurkuazAV.Core.Config;
using TurkuazAV.Core.Language;
using TurkuazAV.Core.Models;

namespace TurkuazAV.Core.Tools;

public static class TrustedRuleManifestCodec
{
    public static TrustedRuleManifest Parse(ReadOnlySpan<byte> json)
    {
        if (json.Length == 0 || json.Length > TrustedRuleSettings.MaximumManifestBytes)
            throw new InvalidDataException(TrustedRuleMessages.MalformedManifest);

        try
        {
            using var document = JsonDocument.Parse(json.ToArray());
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || root.EnumerateObject().Count() != 4)
                throw new InvalidDataException(TrustedRuleMessages.MalformedManifest);

            var schema = root.GetProperty(TrustedRuleSettings.ManifestSchemaField).GetString();
            var version = root.GetProperty(TrustedRuleSettings.ManifestVersionField).GetInt64();
            var keyId = root.GetProperty(TrustedRuleSettings.ManifestKeyIdField).GetString();
            var digest = root.GetProperty(TrustedRuleSettings.ManifestHashField).GetString();

            if (schema != TrustedRuleSettings.Schema || version <= 0
                || !IsValidKeyId(keyId) || !IsValidHexDigest(digest))
                throw new InvalidDataException(TrustedRuleMessages.MalformedManifest);

            return new TrustedRuleManifest(schema!, version, keyId!, digest!);
        }
        catch (Exception exception) when (
            exception is JsonException or KeyNotFoundException or
            InvalidOperationException or FormatException or OverflowException)
        {
            throw new InvalidDataException(TrustedRuleMessages.MalformedManifest, exception);
        }
    }

    public static byte[] SignaturePayload(TrustedRuleManifest manifest)
    {
        if (manifest.Schema != TrustedRuleSettings.Schema || manifest.Sequence <= 0
            || !IsValidKeyId(manifest.KeyId) || !IsValidHexDigest(manifest.RulesSha256))
            throw new InvalidDataException(TrustedRuleMessages.MalformedManifest);

        var version = manifest.Sequence.ToString(CultureInfo.InvariantCulture);
        var canonical = string.Join('\n',
            TrustedRuleSettings.SignatureDomain, version,
            manifest.KeyId, manifest.RulesSha256, string.Empty);
        return Encoding.UTF8.GetBytes(canonical);
    }

    private static bool IsValidKeyId(string? value)
    {
        if (string.IsNullOrEmpty(value) ||
            value.Length > TrustedRuleSettings.MaximumKeyIdLength)
            return false;

        return value.All(character =>
            character is >= 'a' and <= 'z'
            or >= '0' and <= '9'
            or '-' or '_' or '.');
    }

    private static bool IsValidHexDigest(string? digest) =>
        digest?.Length == TrustedRuleSettings.Sha256HexLength
        && digest.All(character => character is >= '0' and <= '9'
            or >= 'a' and <= 'f');
}
