// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Core/tools/YaraXCliTool.cs
// # 📌 Amac: YARA-X CLI motorunu shell kullanmadan sinirli sure ile calistirmak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.2
// # Aciklama: YARA-X CLI motorunu shell kullanmadan sinirli sure ile calistirmak
// # Bagimli Oldugu Katman: Tool | Config | Language

using System.Diagnostics;
using System.Text;
using TurkuazAV.Core.Config;
using TurkuazAV.Core.Language;
namespace TurkuazAV.Core.Tools;
public sealed class YaraXCliTool : IRuleEngineTool
{
    private readonly IEngineIntegrityTool _integrityTool;

    public YaraXCliTool() : this(new Sha256EngineIntegrityTool()) { }

    public YaraXCliTool(IEngineIntegrityTool integrityTool)
    {
        _integrityTool = integrityTool ?? throw new ArgumentNullException(nameof(integrityTool));
    }

    public async Task<IReadOnlyList<string>> ScanAsync(string executablePath,
        string verifiedRulePath, string targetPath,
        CancellationToken cancellationToken = default)
    {
        if (!Path.IsPathFullyQualified(executablePath) || !File.Exists(executablePath))
            throw new FileNotFoundException(RuleMessages.EngineNotFound, executablePath);
        await _integrityTool.VerifyAsync(executablePath, cancellationToken);
        var start = new ProcessStartInfo
        {
            FileName = executablePath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true
        };
        start.ArgumentList.Add(RuleSettings.YrScanVerb);
        start.ArgumentList.Add(RuleSettings.YrJsonOption);
        start.ArgumentList.Add(verifiedRulePath);
        start.ArgumentList.Add(targetPath);
        using var process = new Process { StartInfo = start };
        if (!process.Start()) throw new InvalidOperationException(RuleMessages.EngineFailure);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(RuleSettings.TimeoutSeconds));
        try
        {
            var stdout = ReadLimitedAsync(process.StandardOutput, timeout.Token);
            var stderr = ReadLimitedAsync(process.StandardError, timeout.Token);
            await Task.WhenAll(stdout, stderr, process.WaitForExitAsync(timeout.Token));
            if (process.ExitCode != 0)
                throw new InvalidDataException(RuleMessages.EngineFailure + " " + stderr.Result);
            return YaraXOutputParser.Parse(stdout.Result, targetPath);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(RuleMessages.EngineFailure);
        }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
    }
    private static async Task<string> ReadLimitedAsync(StreamReader input,
        CancellationToken cancellationToken)
    {
        var result = new StringBuilder();
        var buffer = new char[RuleSettings.ReadBuffer];
        int read;
        while ((read = await input.ReadAsync(buffer.AsMemory(), cancellationToken)) != 0)
        {
            if (result.Length + read > RuleSettings.MaxOutputChars)
                throw new InvalidDataException(RuleMessages.OutputLimit);
            result.Append(buffer, 0, read);
        }
        return result.ToString();
    }
}
