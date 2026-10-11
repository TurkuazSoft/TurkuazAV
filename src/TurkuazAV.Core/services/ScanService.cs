// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/services/ScanService.cs
// # 📌 Amac: Dosya envanteri ve boyut politikalarini yonetmek
// # 📌 Modul - FileType: Service - CSharp
// # Version: 0.1.0
// # Aciklama: Dosya envanteri ve boyut politikalarini yonetmek
// # Bagimli Oldugu Katman: Service | Repo | Tool | Config

using System.Runtime.CompilerServices;
using TurkuazAV.Core.Config;
using TurkuazAV.Core.Language;
using TurkuazAV.Core.Models;
using TurkuazAV.Core.Repositories;
using TurkuazAV.Core.Tools;

namespace TurkuazAV.Core.Services;

public sealed class ScanService : IScanService
{
    private readonly IFileRepository _repository;
    private readonly IFileHashTool _hashTool;
    private readonly ScanOptions _options;

    public ScanService(IFileRepository repository, IFileHashTool hashTool, ScanOptions options)
    {
        ArgumentNullException.ThrowIfNull(repository);
        ArgumentNullException.ThrowIfNull(hashTool);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(options.MaxFileSizeBytes);

        _repository = repository;
        _hashTool = hashTool;
        _options = options;
    }

    public async IAsyncEnumerable<FileScanResult> ScanAsync(
        string path,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        foreach (var filePath in _repository.EnumerateFiles(path))
        {
            cancellationToken.ThrowIfCancellationRequested();
            FileScanResult result;

            try
            {
                if ((_repository.GetAttributes(filePath) & FileAttributes.ReparsePoint) != 0)
                {
                    result = new FileScanResult(
                        filePath, ScanStatus.Skipped, null, null, CoreMessages.SymbolicLinkSkipped);
                }
                else
                {
                    var length = _repository.GetLength(filePath);
                    if (length > _options.MaxFileSizeBytes)
                    {
                        result = new FileScanResult(
                            filePath, ScanStatus.Skipped, null, length, CoreMessages.FileTooLarge);
                    }
                    else
                    {
                        await using var input = _repository.OpenRead(filePath);
                        var sha256 = await _hashTool.ComputeSha256Async(input, cancellationToken);
                        result = new FileScanResult(
                            filePath, ScanStatus.Hashed, sha256, length, null);
                    }
                }
            }
            catch (IOException exception)
            {
                result = new FileScanResult(filePath, ScanStatus.Failed, null, null, exception.Message);
            }
            catch (UnauthorizedAccessException exception)
            {
                result = new FileScanResult(filePath, ScanStatus.Failed, null, null, exception.Message);
            }

            yield return result;
        }
    }
}
