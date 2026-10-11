# 📄 Dosya Yolu: /TurkuazAV/tools/verify-desktop-preview.ps1
# 📌 Amac: Windows GUI test paketinin hash kaydini ve temel dosyalarini dogrulamak
# 📌 Modul - FileType: PowerShell
# Version: 0.3.1
# Aciklama: Windows GUI test paketinin hash kaydini ve temel dosyalarini dogrulamak
# Bagimli Oldugu Katman: Tool | Config

param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot
)

$ErrorActionPreference = 'Stop'
$folder = (Resolve-Path -LiteralPath $PackageRoot).Path

$requiredFiles = @(
    'TurkuazAV.Desktop.exe',
    'TurkuazAV.Desktop.dll',
    'TurkuazAV.Desktop.deps.json',
    'TurkuazAV.Desktop.runtimeconfig.json',
    'TurkuazAV.Core.dll',
    'README-LOCAL-TEST.txt',
    'SHA256.txt'
)

foreach ($item in $requiredFiles) {
    $fullPath = Join-Path $folder $item
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "Missing package file: $item"
    }
}

$hashFile = Join-Path $folder 'SHA256.txt'
$recorded = (Get-Content -LiteralPath $hashFile -Raw).Trim()
$pattern = '^TurkuazAV\.Desktop\.exe  SHA256: ([A-Fa-f0-9]{64})$'
if ($recorded -cnotmatch $pattern) {
    throw 'Malformed package SHA256 record'
}

$expected = $Matches[1].ToUpperInvariant()
$executable = Join-Path $folder 'TurkuazAV.Desktop.exe'
$actual = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToUpperInvariant()
if ($actual -cne $expected) {
    throw 'Package executable SHA256 mismatch'
}

$readme = Get-Content -LiteralPath (Join-Path $folder 'README-LOCAL-TEST.txt') -Raw
if ($readme -notmatch 'UNSIGNED LOCAL TEST BUILD'
    -or $readme -notmatch 'NOT a certified antivirus') {
    throw 'Missing experimental build disclosure'
}

Write-Host 'TURKUAZAV_DESKTOP_PACKAGE_VERIFIED'
