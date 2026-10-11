// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/repositories/LocalFileRepository.cs
// # 📌 Amac: Yerel dosyalari salt okunur olarak gezmek ve acmak
// # 📌 Modul - FileType: Repository - CSharp
// # Version: 0.1.0
// # Aciklama: Yerel dosyalari salt okunur olarak gezmek ve acmak
// # Bagimli Oldugu Katman: Repo | Config | Language

using TurkuazAV.Core.Config;
using TurkuazAV.Core.Language;

namespace TurkuazAV.Core.Repositories;

public sealed class LocalFileRepository : IFileRepository
{
    public IEnumerable<string> EnumerateFiles(string path)
    {
        var fullPath = Path.GetFullPath(path);

        if (File.Exists(fullPath))
        {
            return new[] { fullPath };
        }

        if (!Directory.Exists(fullPath))
        {
            throw new FileNotFoundException(CoreMessages.PathNotFound, fullPath);
        }

        if ((File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException(CoreMessages.RootSymlinkDenied);
        }

        return Directory.EnumerateFiles(
            fullPath,
            ScanDefaults.AllFilesPattern,
            new EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = false,
                AttributesToSkip = FileAttributes.ReparsePoint
            });
    }

    public FileAttributes GetAttributes(string path) => File.GetAttributes(path);

    public long GetLength(string path) => new FileInfo(path).Length;

    public Stream OpenRead(string path) => new FileStream(
        path,
        FileMode.Open,
        FileAccess.Read,
        FileShare.Read,
        ScanDefaults.StreamBufferSizeBytes,
        FileOptions.Asynchronous | FileOptions.SequentialScan);
}
