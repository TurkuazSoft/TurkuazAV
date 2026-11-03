# Dosya Yolu: REPO_ROOT/tools/package-rust-preview.ps1
# Amac: Rust CLI/GUI test arshivini ve SHA256 kanitlarini olusturur
# Modul - FileType: Tool - PowerShell
# Version: 0.3.1
# Aciklama: Build artifact != signed production release; unpack and verify all files
# Bagimli Oldugu Katman: Tool | Config

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
if ($arch -ne [System.Runtime.InteropServices.Architecture]::X64) {
    throw 'Only x64 native preview packages are supported.'
}
if ($IsWindows) {
    $platform = 'win-x64'
    $extension = '.exe'
    $archiveExtension = '.zip'
} elseif ($IsLinux) {
    $platform = 'linux-x64'
    $extension = ''
    $archiveExtension = '.tar.gz'
} else {
    throw 'Native preview packaging currently supports Windows and Linux only.'
}
$metadata = (& cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect Cargo metadata.' }
$package = @($metadata.packages | Where-Object { $_.name -ceq 'turkuazav' })
if ($package.Count -ne 1) { throw 'TurkuazAV package metadata not found.' }
$version = [string]$package[0].version
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'Unexpected package version.' }

$name = "TurkuazAV-$version-RUST-UNSIGNED-LOCAL-TEST-$platform"
$output = Join-Path $root 'artifacts'
$stage = Join-Path $output $name
$archive = Join-Path $output "$name$archiveExtension"
$verify = Join-Path $output "_verify_$name"
New-Item -ItemType Directory -Path $output -Force | Out-Null
foreach ($dir in @($stage, $verify)) {
    if (Test-Path -LiteralPath $dir) {
        Remove-Item -LiteralPath $dir -Recurse -Force
    }
}
if (Test-Path -LiteralPath $archive) {
    Remove-Item -LiteralPath $archive -Force
}
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$payload = @("turkuazav$extension", "turkuazav-desktop$extension", 'README.md', 'SECURITY.md')
foreach ($filename in $payload) {
    $source = if ($filename -like "*$extension" -and $filename -match '^turkuazav') {
        Join-Path $root "target/release/$filename"
    } else {
        Join-Path $root $filename
    }
    if (!(Test-Path -LiteralPath $source -PathType Leaf)) { throw "Missing expected payload: $filename" }
    Copy-Item -LiteralPath $source -Destination (Join-Path $stage $filename)
}
$manifest = @(
    foreach ($filename in $payload) {
        $hash = (Get-FileHash -LiteralPath (Join-Path $stage $filename) -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $filename"
    }
)
[System.IO.File]::WriteAllLines((Join-Path $stage 'SHA256SUMS'), [string[]]$manifest, [System.Text.UTF8Encoding]::new($false))

try {
    if ($IsWindows) {
        Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -CompressionLevel Optimal
    } else {
        & tar -czf $archive -C $stage .
        if ($LASTEXITCODE -ne 0) { throw 'Could not create native Linux archive.' }
    }
    New-Item -ItemType Directory -Path $verify -Force | Out-Null
    if ($IsWindows) {
        Expand-Archive -LiteralPath $archive -DestinationPath $verify
    } else {
        & tar -xzf $archive -C $verify
        if ($LASTEXITCODE -ne 0) { throw 'Could not unpack native Linux archive.' }
    }

    $expected = @($payload) + 'SHA256SUMS'
    $actual = @(Get-ChildItem -LiteralPath $verify -Recurse -File | ForEach-Object {
        [System.IO.Path]::GetRelativePath($verify, $_.FullName)
    })
    if ($actual.Count -ne $expected.Count) { throw 'Archive contents count mismatch.' }
    foreach ($filename in $expected) {
        if ($actual -cnotcontains $filename) { throw "Missing archived file: $filename" }
    }
    $lines = @(Get-Content -LiteralPath (Join-Path $verify 'SHA256SUMS'))
    if ($lines.Count -ne $payload.Count) { throw 'Invalid manifest length.' }
    foreach ($line in $lines) {
        if ($line -cnotmatch '^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$') { throw 'Malformed manifest entry.' }
        $hash = $Matches[1]
        $filename = $Matches[2]
        if ($payload -cnotcontains $filename) { throw "Unexpected payload digest entry: $filename" }
        $actualHash = (Get-FileHash -LiteralPath (Join-Path $verify $filename) -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -cne $hash) { throw "Archive SHA256 mismatch: $filename" }
    }
    $archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    $digestFile = "$archive.sha256"
    [System.IO.File]::WriteAllText($digestFile, "$archiveHash  $(Split-Path $archive -Leaf)" + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
    Write-Host "RUST_NATIVE_PACKAGE_VERIFIED=$archive"
    Write-Host "RUST_NATIVE_PACKAGE_SHA256=$archiveHash"
} finally {
    if (Test-Path -LiteralPath $verify) { Remove-Item -LiteralPath $verify -Recurse -Force }
}
