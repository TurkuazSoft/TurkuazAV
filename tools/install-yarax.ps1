# 📄 Dosya Yolu: /TurkuazAV/tools/install-yarax.ps1
# 📌 Amac: Resmi YARA-X paketini SHA256 dogrulayarak CI ortaminda kurmak
# 📌 Modul - FileType: Tool - PowerShell
# Version: 0.2.1
# Aciklama: Resmi YARA-X paketini SHA256 dogrulayarak CI ortaminda kurmak
# Bagimli Oldugu Katman: Tool | Config

$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$manifestPath = Join-Path $projectRoot 'config/yara-x-release.psd1'
$manifest = Import-PowerShellDataFile -Path $manifestPath

if ($IsWindows) {
    $platform = 'Windows'
} elseif ($IsLinux) {
    $platform = 'Linux'
} else {
    throw 'YARA-X installer currently supports only Windows and Linux.'
}

$package = $manifest[$platform]
$artifactRoot = Join-Path $projectRoot 'artifacts/yarax'
$packageRoot = Join-Path $artifactRoot $platform
$extractRoot = Join-Path $packageRoot 'extracted'
New-Item -ItemType Directory -Force -Path $extractRoot | Out-Null

$downloadUri = [Uri]$package.Url
$archiveName = [IO.Path]::GetFileName($downloadUri.AbsolutePath)
$archivePath = Join-Path $packageRoot $archiveName

Invoke-WebRequest -Uri $package.Url -OutFile $archivePath
$actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
$expectedHash = ([string]$package.Sha256).ToLowerInvariant()

if ($actualHash -cne $expectedHash) {
    Remove-Item -LiteralPath $archivePath -Force
    throw "YARA-X archive checksum mismatch for $platform"
}

if ($IsWindows) {
    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractRoot -Force
} else {
    & tar -xzf $archivePath -C $extractRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to unpack YARA-X archive for $platform"
    }
}

$binary = Get-ChildItem -Path $extractRoot -Recurse -File |
    Where-Object { $_.Name -ceq $package.Executable } |
    Select-Object -First 1

if ($null -eq $binary) {
    throw "YARA-X executable not found inside the verified archive for $platform"
}

if ($IsLinux) {
    & chmod +x $binary.FullName
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to set YARA-X executable permission.'
    }
}

& $binary.FullName --version
if ($LASTEXITCODE -ne 0) {
    throw 'YARA-X executable failed version check.'
}

if ($env:GITHUB_ENV) {
    Add-Content -LiteralPath $env:GITHUB_ENV -Value "TURKUAZ_YR_PATH=$($binary.FullName)" -Encoding utf8
}

Write-Host "YARA-X $($manifest.Version) archive SHA256 verified on $platform."
