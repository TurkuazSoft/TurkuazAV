// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Cli/Program.cs
// # 📌 Amac: Hash ve imzali YARA-X komutlarini Service uzerine baglamak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.3
// # Aciklama: Hash ve imzali YARA-X komutlarini Service uzerine baglamak
// # Bagimli Oldugu Katman: Controller | Service | Repo | Tool | View | Language

using System.ComponentModel;
using System.Security.Cryptography;
using TurkuazAV.Cli.Config;
using TurkuazAV.Cli.Controllers;
using TurkuazAV.Cli.Views;
using TurkuazAV.Core.Config;
using TurkuazAV.Core.Repositories;
using TurkuazAV.Core.Services;
using TurkuazAV.Core.Tools;

var view = new ConsoleScanView();
try
{
    if (args.Length == CliSettings.ScanArgs && args[0] == CliSettings.ScanCommand)
    {
        var controller = new ScanController(new ScanService(
            new LocalFileRepository(), new Sha256FileHashTool(), ScanOptions.Default));
        return await view.WriteResultsAsync(controller.ScanAsync(args[1]));
    }

    if (args.Length == CliSettings.RuleArgs && args[0] == CliSettings.ScanRulesCommand)
    {
        var controller = new RuleScanController(new RuleScanService(
            new LocalRuleRepository(), new RsaPssRuleSignatureTool(), new YaraXCliTool()));
        var result = await controller.ScanAsync(args[1], args[2], args[3], args[4], args[5]);
        new ConsoleRuleScanView().Write(result);
        return ExitCodes.Success;
    }

    // BRK-AV-JSON-001: Machine-readable YARA-X *rule matches*, not a
    // guarantee of malware safety. The signer key is supplied by this CLI caller.
    if (args.Length == CliSettings.RuleArgs && args[0] == CliSettings.ScanRulesJsonCommand)
    {
        var target = Path.GetFullPath(args[1]);
        var attributes = File.GetAttributes(target);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new InvalidDataException("Target must be a regular file.");

        var before = await ComputeDigestAsync(target);
        var controller = new RuleScanController(new RuleScanService(
            new LocalRuleRepository(), new RsaPssRuleSignatureTool(), new YaraXCliTool()));
        var result = await controller.ScanAsync(target, args[2], args[3], args[4], args[5]);
        var after = await ComputeDigestAsync(target);
        if (!CryptographicOperations.FixedTimeEquals(before, after))
            throw new InvalidDataException("Target changed during scan.");

        new ConsoleRuleScanJsonView().Write(
            result, Convert.ToHexString(after).ToLowerInvariant());
        return ExitCodes.Success;
    }

    view.ShowUsage();
    return ExitCodes.InvalidArguments;
}
catch (Exception error) when (error is IOException or UnauthorizedAccessException
    or ArgumentException or CryptographicException or InvalidOperationException
    or TimeoutException or Win32Exception or InvalidDataException
    or PlatformNotSupportedException)
{
    view.ShowError(error.Message);
    return ExitCodes.ScanFailed;
}

static async Task<byte[]> ComputeDigestAsync(string target)
{
    await using var stream = new FileStream(
        target, FileMode.Open, FileAccess.Read, FileShare.Read,
        ScanDefaults.StreamBufferSizeBytes, FileOptions.Asynchronous | FileOptions.SequentialScan);
    if (stream.Length > ScanDefaults.MaxFileSizeBytes)
        throw new InvalidDataException("Target exceeds maximum scan size.");
    return await SHA256.HashDataAsync(stream);
}
