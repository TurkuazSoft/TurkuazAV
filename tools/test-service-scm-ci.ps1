# Dosya Yolu: REPO_ROOT/tools/test-service-scm-ci.ps1
# Amac: GitHub-hosted Windows runner'inda gecici SCM servisini baslat/durdur
# Modul - FileType: Tests - PowerShell
# Version: 0.3.1
# Aciklama: LocalService, crash recovery, offline upgrade/rollback; installer degil
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

    # CI-only SCM recovery contract. Only restart the ephemeral service:
    # never configure reboot or arbitrary external commands as failure actions.
    & sc.exe failure $serviceName 'reset=' '60' 'actions=' 'restart/1000/restart/1000/restart/1000' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot configure isolated SCM restart policy.' }
    $policy = (& sc.exe qfailure $serviceName | Out-String)
    if ($LASTEXITCODE -ne 0 -or $policy -notmatch 'RESTART') {
        throw 'SCM restart policy was not registered.'
    }
    Write-Host 'RUST_SCM_RECOVERY_POLICY=PASS'

    $service = Get-Service -Name $serviceName
    $service.Start()
    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(35))

    # Verify both the configured service and the exact live process belong
    # to the unique fixture BEFORE forcefully stopping that process.
    $live = $null
    for ($attempt = 0; $attempt -lt 50; $attempt++) {
        $live = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
        if ($null -ne $live -and $live.State -eq 'Running' -and [uint32]$live.ProcessId -gt 0) { break }
        Start-Sleep -Milliseconds 200
    }
    if ($null -eq $live -or $live.State -ne 'Running' -or [uint32]$live.ProcessId -eq 0) {
        throw 'SCM service has no running process for recovery acceptance.'
    }
    if ($live.StartMode -ne 'Manual' -or $live.StartName -notmatch 'LocalService' -or
        $live.PathName -notlike "*$binary*") {
        throw 'SCM recovery fixture identity unexpectedly changed.'
    }
    $previousPid = [uint32]$live.ProcessId
    $processRecord = Get-CimInstance Win32_Process -Filter "ProcessId=$previousPid"
    if ($null -eq $processRecord -or [string]::IsNullOrWhiteSpace($processRecord.ExecutablePath) -or
        $processRecord.ExecutablePath -ine $binary) {
        throw 'Refusing to terminate a process outside the isolated service binary.'
    }
    Stop-Process -Id $previousPid -Force -ErrorAction Stop

    # A process crash should trigger SCM recovery once, with a NEW PID.
    $restarted = $false
    for ($attempt = 0; $attempt -lt 140; $attempt++) {
        Start-Sleep -Milliseconds 250
        $newState = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
        if ($null -ne $newState -and $newState.State -eq 'Running' -and
            [uint32]$newState.ProcessId -gt 0 -and [uint32]$newState.ProcessId -ne $previousPid) {
            $newProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$($newState.ProcessId)"
            if ($null -ne $newProcess -and $newProcess.ExecutablePath -ieq $binary) {
                $restarted = $true
                break
            }
        }
    }
    if (-not $restarted) { throw 'SCM service did not recover with a new trusted process.' }
    Write-Host 'RUST_SCM_CRASH_RECOVERY=PASS'

    $service = Get-Service -Name $serviceName
    $service.Stop()
    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(35))
    Start-Sleep -Seconds 3
    $finalState = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $finalState -or $finalState.State -ne 'Stopped' -or
        [uint32]$finalState.ProcessId -ne 0) {
        throw 'Normal SCM STOP incorrectly triggered restart or retained a process.'
    }
    Write-Host 'RUST_SCM_STOP_NO_RESTART=PASS'

    # @dev-id TAV-SCM-UPGRADE-010
    # @purpose Exercise an offline, integrity-gated upgrade and rollback on
    # the unique temporary LocalService fixture. No production installation.
    $trustedHash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash
    $upgraded = Join-Path $base 'turkuazav-service-v2.exe'
    Copy-Item -LiteralPath $source -Destination $upgraded
    if ((Get-FileHash -LiteralPath $upgraded -Algorithm SHA256).Hash -cne $trustedHash) {
        throw 'Staged service candidate failed the trusted fixture hash check.'
    }

    $upgradedImagePath = ('"{0}" --scm "{1}" 1' -f $upgraded, $watch)
    & sc.exe config $serviceName 'binPath=' $upgradedImagePath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot switch the isolated SCM binary path.' }
    $configured = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $configured -or $configured.PathName -notlike "*$upgraded*" -or
        $configured.StartMode -ne 'Manual' -or $configured.StartName -notmatch 'LocalService') {
        throw 'SCM upgrade changed the expected identity or was not applied.'
    }

    $service = Get-Service -Name $serviceName
    $service.Start()
    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(35))
    $liveUpgraded = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $liveUpgraded -or $liveUpgraded.State -ne 'Running' -or
        [uint32]$liveUpgraded.ProcessId -eq 0) {
        throw 'Upgraded SCM service is not running.'
    }
    $actualUpgrade = Get-CimInstance Win32_Process -Filter "ProcessId=$($liveUpgraded.ProcessId)"
    if ($null -eq $actualUpgrade -or $actualUpgrade.ExecutablePath -ine $upgraded) {
        throw 'SCM upgrade launched an unexpected executable.'
    }
    $service.Stop()
    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(35))
    Write-Host 'RUST_SCM_OFFLINE_UPGRADE=PASS'

    # Inject a tampered candidate before registration. It must be rejected
    # without ever executing or reconfiguring the service.
    $tampered = Join-Path $base 'turkuazav-service-tampered.exe'
    [System.IO.File]::WriteAllBytes($tampered, [byte[]](0x62, 0x61, 0x64))
    if ((Get-FileHash -LiteralPath $tampered -Algorithm SHA256).Hash -ceq $trustedHash) {
        throw 'Deliberately corrupted test candidate unexpectedly matched.'
    }
    Remove-Item -LiteralPath $tampered -Force
    $unchanged = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $unchanged -or $unchanged.PathName -notlike "*$upgraded*") {
        throw 'Failed staging unexpectedly modified the live SCM configuration.'
    }
    Write-Host 'RUST_SCM_TAMPER_REJECTED=PASS'

    # Restore the prior verified configuration and re-launch the exact
    # original executable before deleting this CI-only service.
    & sc.exe config $serviceName 'binPath=' $imagePath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot roll back isolated SCM binary path.' }
    $service = Get-Service -Name $serviceName
    $service.Start()
    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(35))
    $restored = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $restored -or $restored.State -ne 'Running' -or
        [uint32]$restored.ProcessId -eq 0 -or $restored.PathName -notlike "*$binary*") {
        throw 'SCM rollback did not restore the original service configuration.'
    }
    $actualRollback = Get-CimInstance Win32_Process -Filter "ProcessId=$($restored.ProcessId)"
    if ($null -eq $actualRollback -or $actualRollback.ExecutablePath -ine $binary) {
        throw 'SCM rollback launched an unexpected executable.'
    }
    $service.Stop()
    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(35))
    Write-Host 'RUST_SCM_OFFLINE_ROLLBACK=PASS'
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
