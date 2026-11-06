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

$payload = @("turkuazav$extension", "turkuazav-desktop$extension", "turkuazav-service$extension", 'README.md', 'SECURITY.md', 'TEST_KILAVUZU_TR.md')
if ($IsWindows) { $payload += 'TurkuazAV-Preview-Setup.ps1' }
if ($IsLinux) { $payload += @('turkuazav-preview.service', 'preview.env.example') }
foreach ($filename in $payload) {
    $source = if ($filename -ceq 'turkuazav-preview.service') {
        Join-Path $root 'deploy/service/turkuazav-preview.service'
    } elseif ($filename -ceq 'preview.env.example') {
        Join-Path $root 'deploy/service/preview.env.example'
    } elseif ($filename -ceq 'TurkuazAV-Preview-Setup.ps1') {
        Join-Path $root 'tools/TurkuazAV-Preview-Setup.ps1'
    } elseif ($filename -like "*$extension" -and $filename -match '^turkuazav') {
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
    # Execute the unpacked CLI from an unrelated Unicode working directory.
    # A parseable archive alone does not prove the shipped executable works.
    $smokeDir = Join-Path $output ("_native_cli_smoke_" + [char]0x0130)
    New-Item -ItemType Directory -Path $smokeDir -Force | Out-Null
    try {
        $sample = Join-Path $smokeDir 'sample.txt'
        [System.IO.File]::WriteAllBytes($sample, [byte[]](0x61, 0x62, 0x63))
        $binary = Join-Path $verify "turkuazav$extension"
        Push-Location $smokeDir
        try {
            $outputText = (& $binary scan $sample 2>&1 | Out-String)
            if ($LASTEXITCODE -ne 0) { throw 'Unpacked CLI scan failed.' }
            if ($outputText -notmatch 'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD') {
                throw 'Unpacked CLI hash output differs from expected SHA-256.'
            }
            if ($outputText -notmatch 'Summary: hashed=1, skipped=0, failed=0') {
                throw 'Unpacked CLI summary contract failed.'
            }
        } finally {
            Pop-Location
        }
        Write-Host 'RUST_NATIVE_PACKAGE_CLI_SMOKE=PASS'
        # Run the shipped service host without SCM/systemd privileges.
        # A successful one-shot scan is not an OS service installation test.
        $serviceBinary = Join-Path $verify "turkuazav-service$extension"
        Push-Location $smokeDir
        try {
            $serviceText = (& $serviceBinary --once $smokeDir 1 2>&1 | Out-String)
            if ($LASTEXITCODE -ne 0) { throw 'Unpacked service host smoke failed.' }
            if ($serviceText -notmatch "SERVICE_ONCE=PASS version=$([regex]::Escape($version))") {
                throw 'Service host smoke contract failed.'
            }
        } finally {
            Pop-Location
        }
        Write-Host 'RUST_NATIVE_PACKAGE_SERVICE_SMOKE=PASS'

        # @dev-id TAV-DESKTOP-SMOKE-020
        # @purpose Exercise the exact archived GUI binary without a display.
        # @reason Compilation alone does not prove the delivered GUI binary
        # can launch its scan worker on the target OS and relocated directory.
        $desktopBinary = Join-Path $verify "turkuazav-desktop$extension"
        Push-Location $smokeDir
        try {
            $desktopText = (& $desktopBinary --headless-self-test 2>&1 | Out-String)
            if ($LASTEXITCODE -ne 0) { throw 'Unpacked desktop headless smoke failed.' }
            if ($desktopText -notmatch "RUST_DESKTOP_HEADLESS_SMOKE=PASS version=$([regex]::Escape($version))") {
                throw 'Unpacked desktop worker contract failed.'
            }
        } finally {
            Pop-Location
        }
        Write-Host 'RUST_NATIVE_PACKAGE_DESKTOP_HEADLESS_SMOKE=PASS'
    } finally {
        if (Test-Path -LiteralPath $smokeDir) {
            Remove-Item -LiteralPath $smokeDir -Recurse -Force
        }
    }
    $archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    $digestFile = "$archive.sha256"
    [System.IO.File]::WriteAllText($digestFile, "$archiveHash  $(Split-Path $archive -Leaf)" + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
    Write-Host "RUST_NATIVE_PACKAGE_VERIFIED=$archive"
    Write-Host "RUST_NATIVE_PACKAGE_SHA256=$archiveHash"
} finally {
    if (Test-Path -LiteralPath $verify) { Remove-Item -LiteralPath $verify -Recurse -Force }
}
