// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/tools/IRuleSignatureTool.cs
// # 📌 Amac: Imza kriptografisini Service katmanindan ayirmak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.0
// # Aciklama: Imza kriptografisini Service katmanindan ayirmak
// # Bagimli Oldugu Katman: Tool

namespace TurkuazAV.Core.Tools;
public interface IRuleSignatureTool
{
    bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, string publicKeyPem);
}
