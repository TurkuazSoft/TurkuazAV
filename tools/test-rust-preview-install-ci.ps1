# Dosya Yolu: REPO_ROOT/tools/test-rust-preview-install-ci.ps1
# Amac: Windows Rust test paketinin kullanici kurulumu ve kaldirilmasini dogrula
# Modul - FileType: Tests - PowerShell
# Version: 0.3.1
# Aciklama: Yalnizca GitHub-hosted CI icinde gecici klasor kabul testi
# Bagimli Oldugu Katman: Tool | Config

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $IsWindows -or $env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Preview installer acceptance is restricted to GitHub-hosted Windows CI.'
}

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$archives = @(Get-ChildItem -LiteralPath (Join-Path $root 'artifacts') -File -Filter 'TurkuazAV-*-RUST-UNSIGNED-LOCAL-TEST-win-x64.zip')
if ($archives.Count -ne 1) {
    throw 'Exactly one verified Windows preview archive is required.'
}

$fixture = Join-Path $env:RUNNER_TEMP ('turkuazav-preview-install-' + [guid]::NewGuid().ToString('N'))
$extracted = Join-Path $fixture 'extracted'
$installed = Join-Path $fixture 'installed'
$tampered = Join-Path $fixture 'tampered'
$ciRecycle = Join-Path $fixture 'simulated-recycle'
$setupName = 'TurkuazAV-Preview-Setup.ps1'
try {
    $null = New-Item -ItemType Directory -Path $fixture
    Expand-Archive -LiteralPath $archives[0].FullName -DestinationPath $extracted

    $setup = Join-Path $extracted $setupName
    if (-not (Test-Path -LiteralPath $setup -PathType Leaf)) {
        throw 'Preview setup is missing from the verified archive.'
    }
    & $setup -Action Verify
    & $setup -Action Install -CiInstallRoot $installed -NoShortcuts

    foreach ($name in @('turkuazav.exe', 'turkuazav-desktop.exe', 'turkuazav-service.exe', $setupName)) {
        if (-not (Test-Path -LiteralPath (Join-Path $installed $name) -PathType Leaf)) {
            throw 'Installation did not copy the expected Rust payload.'
        }
    }
    $desktop = Join-Path $installed 'turkuazav-desktop.exe'
    $smoke = (& $desktop --headless-self-test 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or
        $smoke -notmatch 'RUST_DESKTOP_HEADLESS_SMOKE=PASS version=0\.3\.1') {
        throw 'Installed Rust desktop failed its worker self-test.'
    }
    Write-Host 'RUST_PREVIEW_INSTALLED_DESKTOP_SMOKE=PASS'

    $reinstallRejected = $false
    try {
        & $setup -Action Install -CiInstallRoot $installed -CiRecycleRoot $ciRecycle -NoShortcuts | Out-Null
    } catch {
        $reinstallRejected = $true
    }
    if (-not $reinstallRejected) {
        throw 'Installer unexpectedly overwrote the existing preview.'
    }
    Write-Host 'RUST_PREVIEW_REINSTALL_REJECTED=PASS'

    # Replacement approval recycles the complete previous folder before the
    # verified staging directory is renamed into place. CI intentionally
    # emulates the Recycle Bin in an isolated fixture rather than modifying
    # the hosted runner's actual Windows Recycle Bin.
    $oldEvidence = Join-Path $installed 'restore-me.txt'
    [IO.File]::WriteAllText($oldEvidence, 'previous user data')
    & $setup -Action Install -CiInstallRoot $installed -CiRecycleRoot $ciRecycle -CiApproveReplacement -NoShortcuts
    $recycled = @(Get-ChildItem -LiteralPath $ciRecycle -Directory)
    if ($recycled.Count -ne 1 -or
        -not (Test-Path -LiteralPath (Join-Path $recycled[0].FullName 'restore-me.txt')) -or
        (Test-Path -LiteralPath $oldEvidence) -or
        -not (Test-Path -LiteralPath (Join-Path $installed 'turkuazav-desktop.exe'))) {
        throw 'Approved reinstall did not retain prior data in the isolated recycle fixture.'
    }
    Write-Host 'RUST_PREVIEW_APPROVED_REPLACEMENT_RECOVERABLE=PASS'

    # An error AFTER the previous directory is recycled must preserve its
    # recoverable copy and refuse to present a partial installation as ready.
    $postFailureEvidence = Join-Path $installed 'post-failure-note.txt'
    [IO.File]::WriteAllText($postFailureEvidence, 'recover after failure')
    $failedAfterRecycle = $false
    try {
        & $setup -Action Install -CiInstallRoot $installed -CiRecycleRoot $ciRecycle -CiApproveReplacement -CiFailAfterRecycle -NoShortcuts | Out-Null
    } catch {
        $failedAfterRecycle = $true
    }
    $recycled = @(Get-ChildItem -LiteralPath $ciRecycle -Directory)
    $retainedEvidence = @($recycled | Where-Object {
        Test-Path -LiteralPath (Join-Path $_.FullName 'post-failure-note.txt')
    })
    if (-not $failedAfterRecycle -or $recycled.Count -ne 2 -or
        $retainedEvidence.Count -ne 1 -or
        (Test-Path -LiteralPath $installed)) {
        throw 'Post-recycle interruption did not preserve the previous directory.'
    }
    Write-Host 'RUST_PREVIEW_INTERRUPTED_REPLACEMENT_RECOVERABLE=PASS'

    # A clean installation is still possible after the interrupted attempt.
    & $setup -Action Install -CiInstallRoot $installed -NoShortcuts

    # The installer must not delete unrelated or user-owned files.
    $userFile = Join-Path $installed 'user-note.txt'
    [IO.File]::WriteAllText($userFile, 'keep this file')
    & (Join-Path $installed $setupName) -Action Uninstall -CiInstallRoot $installed -NoShortcuts
    if (-not (Test-Path -LiteralPath $userFile -PathType Leaf) -or
        (Test-Path -LiteralPath $desktop) -or
        (Test-Path -LiteralPath (Join-Path $installed '.turkuazav-preview-installed'))) {
        throw 'Uninstaller failed to preserve user data or remove owned files.'
    }
    Write-Host 'RUST_PREVIEW_UNINSTALL_USER_DATA_PRESERVED=PASS'

    $secondUninstallRejected = $false
    try {
        & $setup -Action Uninstall -CiInstallRoot $installed -NoShortcuts | Out-Null
    } catch {
        $secondUninstallRejected = $true
    }
    if (-not $secondUninstallRejected) {
        throw 'Uninstall without an owned marker must fail closed.'
    }
    Write-Host 'RUST_PREVIEW_UNOWNED_DELETE_REJECTED=PASS'

    # A byte change in a file named in SHA256SUMS must reject installation
    # before the destination is created.
    $null = New-Item -ItemType Directory -Path $tampered
    foreach ($file in @(Get-ChildItem -LiteralPath $extracted -File)) {
        Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $tampered $file.Name)
    }
    [IO.File]::AppendAllText((Join-Path $tampered 'README.md'), 'tampered')
    $tamperRejected = $false
    try {
        & (Join-Path $tampered $setupName) -Action Verify | Out-Null
    } catch {
        $tamperRejected = $true
    }
    if (-not $tamperRejected) {
        throw 'Tampered package was not rejected by SHA256SUMS.'
    }
    Write-Host 'RUST_PREVIEW_PACKAGE_TAMPER_REJECTED=PASS'
} finally {
    if (Test-Path -LiteralPath $fixture) {
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}