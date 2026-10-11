// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Cli/Program.cs
// # 📌 Amac: Bagimliliklari olusturup konsol istegini yonlendirmek
// # 📌 Modul - FileType: Bootstrap - CSharp
// # Version: 0.1.0
// # Aciklama: Bagimliliklari olusturup konsol istegini yonlendirmek
// # Bagimli Oldugu Katman: Controller | Service | Repo | Tool | View | Language

using TurkuazAV.Cli.Config;
using TurkuazAV.Cli.Controllers;
using TurkuazAV.Cli.Views;
using TurkuazAV.Core.Config;
using TurkuazAV.Core.Repositories;
using TurkuazAV.Core.Services;
using TurkuazAV.Core.Tools;

var view = new ConsoleScanView();

if (args.Length != CliSettings.ScanArgumentsCount || args[0] != CliSettings.ScanCommand)
{
    view.ShowUsage();
    return ExitCodes.InvalidArguments;
}

var repository = new LocalFileRepository();
var hashTool = new Sha256FileHashTool();
var service = new ScanService(repository, hashTool, ScanOptions.Default);
var controller = new ScanController(service);

try
{
    return await view.WriteResultsAsync(controller.ScanAsync(args[1]));
}
catch (Exception exception) when (
    exception is IOException or UnauthorizedAccessException or ArgumentException)
{
    view.ShowError(exception.Message);
    return ExitCodes.ScanFailed;
}
