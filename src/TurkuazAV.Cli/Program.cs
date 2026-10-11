// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Cli/Program.cs
// # 📌 Amac: Hash ve imzali YARA-X komutlarini Service uzerine baglamak
// # 📌 Modul - FileType: CSharp
// # Version: 0.2.0
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

    view.ShowUsage();
    return ExitCodes.InvalidArguments;
}
catch (Exception error) when (error is IOException or UnauthorizedAccessException
    or ArgumentException or CryptographicException or InvalidOperationException
    or TimeoutException or Win32Exception)
{
    view.ShowError(error.Message);
    return ExitCodes.ScanFailed;
}
