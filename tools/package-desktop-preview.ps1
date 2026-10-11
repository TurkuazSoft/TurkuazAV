# 📄 Dosya Yolu: /TurkuazAV/tools/package-desktop-preview.ps1
# 📌 Amac: Imzasiz Windows WinUI test paketini sadece dogrulanmis CI buildinden olusturmak
# 📌 Modul - FileType: Tool - PowerShell
# Version: 0.3.0
# Aciklama: Release build dosyalarini sandbox icin kopyalar ve SHA256 kaydi uretir
# Bagimli Oldugu Katman: Tool | Config

$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$source = Join-Path $root 'src/TurkuazAV.Desktop/bin/x64/Release/net10.0-windows10.0.26100.0/win-x64'
$target = Join-Path $root 'artifacts/TurkuazAV-0.3.0-UNSIGNED-LOCAL-TEST-win-x64'
$executable = Join-Path $source 'TurkuazAV.Desktop.exe'

if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw 'WinUI build exe was not found: cannot produce the test artifact.'
}

New-Item -Path $target -ItemType Directory -Force | Out-Null
Copy-Item -Path (Join-Path $source '*') -Destination $target -Recurse -Force

$readme = @(
    'TurkuazAV 0.3.0 - UNSIGNED LOCAL TEST BUILD',
    '',
    'This is an EXPERIMENTAL read-only SHA256 file analyzer.',
    'This is NOT a certified antivirus or realtime protection.',
    'No YARA-X detection or antivirus verdict is available from the GUI.',
    '',
    'Windows 10/11 x64 preview. Extract all files before launching.',
    'Run TurkuazAV.Desktop.exe from inside the extracted directory.',
    'Do not ignore antivirus warnings or create blanket AV exclusions.',
    'Test only with harmless files on a test device or isolated VM.',
    'Report startup/crash issues with Windows version and app logs.',
    '',
    'Source: https://github.com/TurkuazSoft/TurkuazAV'
)
$readme | Set-Content -LiteralPath (Join-Path $target 'README-LOCAL-TEST.txt') -Encoding UTF8

$hash = (Get-FileHash -LiteralPath (Join-Path $target 'TurkuazAV.Desktop.exe') -Algorithm SHA256).Hash
"TurkuazAV.Desktop.exe  SHA256: $hash" |
    Set-Content -LiteralPath (Join-Path $target 'SHA256.txt') -Encoding UTF8

Write-Host 'TURKUAZAV_UNSIGNED_PREVIEW_PACKAGE_OK'
