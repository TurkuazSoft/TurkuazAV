# Dosya Yolu: REPO_ROOT/tools/test-service-scm-ci.ps1
# Amac: GitHub-hosted Windows runner'inda gecici SCM servisini baslat/durdur
# Modul - FileType: Tests - PowerShell
# Version: 0.3.1
# Aciklama: LocalService, demand-only, kontrollu cleanup; production installer degil
# Bagimli Oldugu Katman: Tool | Service | Config

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $IsWindows -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Live SCM test is restricted to GitHub-hosted Windows CI.'
}

# This literal MUST match rust/src/bin/service_host.rs::scm::NAME.
$serviceName = 'TurkuazAVPreview'
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -ne $existing) { throw 'Refusing to modify pre-existing TurkuazAVPreview service.' }

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$source = Join-Path $repo 'target/release/turkuazav-service.exe'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'Release service binary not found.' }

$base = Join-Path $env:ProgramData ('TurkuazAV-CI-' + $env:GITHUB_RUN_ID + '-' + $env:GITHUB_RUN_ATTEMPT)
if (Test-Path -LiteralPath $base) { throw 'Refusing to overwrite existing CI service fixture.' }
$created = $false
try {
    $null = New-Item -ItemType Directory -Path $base
    $watch = Join-Path $base 'watched'
    $null = New-Item -ItemType Directory -Path $watch
    [System.IO.File]::WriteAllBytes((Join-Path $watch 'harmless.txt'), [byte[]](0x61, 0x62, 0x63))
    $binary = Join-Path $base 'turkuazav-service.exe'
    Copy-Item -LiteralPath $source -Destination $binary

    # LocalService SID S-1-5-19: read & execute only. No LocalSystem service.
    # The runner administrators and LocalSystem retain test cleanup access.
    $aclArgs = @(
        $base, '/inheritance:r', '/grant:r',
        '*S-1-5-19:(OI)(CI)RX',
        '*S-1-5-18:(OI)(CI)F',
        '*S-1-5-32-544:(OI)(CI)F'
    )
    & icacls.exe @aclArgs | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot restrict Windows CI service fixture ACL.' }

    $imagePath = ('"{0}" --scm "{1}" 1' -f $binary, $watch)
    & sc.exe create $serviceName 'type=' 'own' 'start=' 'demand' 'obj=' 'NT AUTHORITY\LocalService' 'binPath=' $imagePath
    if ($LASTEXITCODE -ne 0) { throw 'Cannot register ephemeral LocalService preview.' }
    $created = $true

    $info = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $info -or $info.StartMode -ne 'Manual' -or $info.StartName -notmatch 'LocalService') {
        throw 'SCM service account or start mode did not match the test contract.'
    }

    foreach ($cycle in 1..2) {
        $service = Get-Service -Name $serviceName
        $service.Start()
        $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(35))
        Start-Sleep -Milliseconds 800
        $service.Refresh()
        if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
            throw "Service exited unexpectedly on start cycle $cycle."
        }
        $service.Stop()
        $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(35))
        Write-Host "RUST_SCM_CYCLE_$($cycle)=PASS"
    }
    Write-Host 'RUST_SCM_LIVE_START_STOP=PASS'
} finally {
    if ($created) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($null -ne $service -and $service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                & sc.exe stop $serviceName | Out-Null
                $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(20))
            }
        } catch {
            Write-Warning "SCM cleanup stop: $($_.Exception.Message)"
        }
        & sc.exe delete $serviceName | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "SCM cleanup delete failed (code $LASTEXITCODE)."
        }
        for ($attempt = 0; $attempt -lt 40; $attempt++) {
            if ($null -eq (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { break }
            Start-Sleep -Milliseconds 250
        }
    }
    if (Test-Path -LiteralPath $base) {
        Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue
    }
}
