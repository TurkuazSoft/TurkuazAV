// # 📄 Dosya Yolu: /TurkuazAV/tests/TurkuazAV.SmokeTests/Program.cs
// # 📌 Amac: Hash ve dosya boyut limiti davranisini test etmek
// # 📌 Modul - FileType: Tests - CSharp
// # Version: 0.1.0
// # Aciklama: Hash ve dosya boyut limiti davranisini test etmek
// # Bagimli Oldugu Katman: Service | Repo | Tool | Config

using System.Security.Cryptography;
using System.Text;
using TurkuazAV.Core.Config;
using TurkuazAV.Core.Models;
using TurkuazAV.Core.Repositories;
using TurkuazAV.Core.Services;
using TurkuazAV.Core.Tools;
using TurkuazAV.SmokeTests.Config;

var root = Path.Combine(
    Path.GetTempPath(),
    TestSettings.TempDirectoryPrefix + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);

try
{
    var samplePath = Path.Combine(root, TestSettings.SampleFileName);
    var sample = Encoding.UTF8.GetBytes(TestSettings.TestText);
    await File.WriteAllBytesAsync(samplePath, sample);
    await File.WriteAllBytesAsync(
        Path.Combine(root, TestSettings.OversizedFileName),
        new byte[TestSettings.OversizedFileBytes]);

    var service = new ScanService(
        new LocalFileRepository(),
        new Sha256FileHashTool(),
        new ScanOptions(TestSettings.MaxFileSizeBytes));

    var results = new List<FileScanResult>();
    await foreach (var item in service.ScanAsync(root))
    {
        results.Add(item);
    }

    var expectedHash = Convert.ToHexString(SHA256.HashData(sample));
    var hashed = results.Single(item => item.Status == ScanStatus.Hashed);
    var skipped = results.Single(item => item.Status == ScanStatus.Skipped);

    if (results.Count != 2
        || hashed.Path != samplePath
        || hashed.Sha256 != expectedHash
        || skipped.SizeBytes != TestSettings.OversizedFileBytes)
    {
        throw new InvalidOperationException(TestSettings.Failed);
    }

    Console.WriteLine(TestSettings.Passed);
    return 0;
}
catch (Exception exception)
{
    Console.Error.WriteLine(exception);
    return 1;
}
finally
{
    Directory.Delete(root, recursive: true);
}
