// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/repositories/IFileRepository.cs
// # 📌 Amac: Dosya sistemi erisim sozlesmesini tanimlamak
// # 📌 Modul - FileType: Repository - CSharp
// # Version: 0.1.0
// # Aciklama: Dosya sistemi erisim sozlesmesini tanimlamak
// # Bagimli Oldugu Katman: Repo

namespace TurkuazAV.Core.Repositories;

public interface IFileRepository
{
    IEnumerable<string> EnumerateFiles(string path);
    FileAttributes GetAttributes(string path);
    long GetLength(string path);
    Stream OpenRead(string path);
}
