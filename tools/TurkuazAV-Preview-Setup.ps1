# Dosya Yolu: REPO_ROOT/tools/TurkuazAV-Preview-Setup.ps1
# Amac: Rust test paketini tek kullanici icin kur/dogrula/kaldir
# Modul - FileType: Tool - PowerShell
# Version: 0.3.1
# Aciklama: Imzasiz preview; servis, surucu, registry veya yuksek yetki yok
# Bagimli Oldugu Katman: Tool | Config

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Verify', 'Install', 'Uninstall')]
    [string]$Action,
    [string]$CiInstallRoot,
    [switch]$NoShortcuts,
    [switch]$CiApproveReplacement,
    [string]$CiRecycleRoot,
    [switch]$CiFailAfterRecycle
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'The per-user preview setup supports Windows only.'
}

$markerName = '.turkuazav-preview-installed'
$markerValue = 'turkuazav.preview.install.v1'
$scriptName = 'TurkuazAV-Preview-Setup.ps1'
$payload = @(
    'turkuazav.exe', 'turkuazav-desktop.exe', 'turkuazav-service.exe',
    'README.md', 'SECURITY.md', 'TEST_KILAVUZU_TR.md', $scriptName
)
$expectedFiles = @($payload) + @('SHA256SUMS')
$sourceRoot = $PSScriptRoot
$local = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
if ([string]::IsNullOrWhiteSpace($local)) {
    throw 'LocalApplicationData cannot be resolved.'
}
$installRoot = Join-Path $local 'Programs\TurkuazAV-Preview'

if (-not [string]::IsNullOrWhiteSpace($CiInstallRoot)) {
    # An arbitrary target is never a user-facing installation option.
    if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
        throw 'CiInstallRoot is restricted to trusted GitHub-hosted CI.'
    }
    $installRoot = [IO.Path]::GetFullPath($CiInstallRoot)
    $NoShortcuts = $true
}

# CI-only injectable recycle destination: the user-facing code must always
# request an explicit approval and use the actual Windows Recycle Bin.
if ($CiApproveReplacement -or $CiFailAfterRecycle -or
    -not [string]::IsNullOrWhiteSpace($CiRecycleRoot)) {
    if ([string]::IsNullOrWhiteSpace($CiInstallRoot) -or
        $env:GITHUB_ACTIONS -cne 'true' -or
        $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
        [string]::IsNullOrWhiteSpace($CiRecycleRoot)) {
        throw 'Recycle test overrides are restricted to trusted hosted CI fixtures.'
    }
    $tempRoot = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
    $ciRecycle = [IO.Path]::GetFullPath($CiRecycleRoot)
    if (-not $ciRecycle.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $ciRecycle.Equals($installRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'CI recycle destination must be an isolated runner temporary path.'
    }
    $CiRecycleRoot = $ciRecycle
}

function Assert-NoReparse([string]$path) {
    $current = [IO.Path]::GetFullPath($path)
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction SilentlyContinue
        if ($null -ne $item -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'Reparse points and symbolic links are not accepted in preview setup paths.'
        }
        $parent = [IO.Directory]::GetParent($current)
        if ($null -eq $parent) { break }
        $current = $parent.FullName
    }
}

function Assert-Payload([string]$folder) {
    Assert-NoReparse $folder
    $items = @(Get-ChildItem -LiteralPath $folder -Force)
    if ($items.Count -ne ($expectedFiles.Count)) {
        throw 'Unexpected number of preview package files.'
    }
    foreach ($item in $items) {
        if ($item.PSIsContainer -or $expectedFiles -cnotcontains $item.Name) {
            throw 'Unexpected file or directory in the preview package.'
        }
    }
    $manifest = Join-Path $folder 'SHA256SUMS'
    Assert-NoReparse $manifest
    $lines = @(Get-Content -LiteralPath $manifest)
    if ($lines.Count -ne $payload.Count) {
        throw 'Invalid preview package manifest length.'
    }
    $seen = @{}
    foreach ($line in $lines) {
        if ($line -cnotmatch '^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$') {
            throw 'Invalid preview package digest entry.'
        }
        $digest = $Matches[1]
        $name = $Matches[2]
        if ($payload -cnotcontains $name -or $seen.ContainsKey($name)) {
            throw 'Unknown or duplicate preview package digest entry.'
        }
        $seen[$name] = $true
        $file = Join-Path $folder $name
        Assert-NoReparse $file
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            throw 'Missing preview package file.'
        }
        $actual = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -cne $digest) {
            throw 'Preview package SHA-256 mismatch. Installation refused.'
        }
    }
    if ($seen.Count -ne $payload.Count) {
        throw 'Incomplete preview package digest list.'
    }
}

function ShortcutPath {
    $programs = [Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)
    if ([string]::IsNullOrWhiteSpace($programs)) {
        throw 'Start Menu programs folder cannot be resolved.'
    }
    return (Join-Path $programs 'TurkuazAV Preview.lnk')
}

function Add-Shortcut([string]$destination) {
    $shortcut = ShortcutPath
    Assert-NoReparse $shortcut
    if ($null -ne (Get-Item -LiteralPath $shortcut -Force -ErrorAction SilentlyContinue)) {
        throw 'The TurkuazAV Preview Start Menu shortcut already exists.'
    }
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($shortcut)
    $link.TargetPath = (Join-Path $destination 'turkuazav-desktop.exe')
    $link.WorkingDirectory = $destination
    $link.Description = 'TurkuazAV Rust read-only test preview'
    $link.Save()
}

function Test-OwnedShortcut([string]$destination) {
    $shortcut = ShortcutPath
    Assert-NoReparse $shortcut
    if ($null -eq (Get-Item -LiteralPath $shortcut -Force -ErrorAction SilentlyContinue)) {
        return $false
    }
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($shortcut)
    if ($link.TargetPath -ine (Join-Path $destination 'turkuazav-desktop.exe')) {
        throw 'An unrelated Start Menu shortcut already uses this name.'
    }
    return $true
}

function Request-RecycleConsent([string]$destination) {
    if (-not [string]::IsNullOrWhiteSpace($CiRecycleRoot)) {
        if (-not $CiApproveReplacement) {
            throw 'An existing installation cannot be replaced without explicit approval.'
        }
        return
    }
    if (-not [Environment]::UserInteractive) {
        throw 'Replacing an existing folder requires an interactive user.'
    }
    Write-Warning "Klasor zaten var: $destination"
    Write-Warning 'Onay verirseniz MEVCUT klasor tum icerigiyle Windows Geri Donusum Kutusuna gonderilecek.'
    Write-Warning 'Bu islem geri alinabilir diye garanti verilmez: kutu devre disi, dolu veya bosaltilmis olabilir.'
    Write-Warning 'Onemli dosyalari ayrica yedekleyin ve uygulamayi once kapatin.'
    $answer = Read-Host 'Devam etmek ve mevcut klasoru Geri Donusum Kutusuna tasimak icin EVET yazin'
    if ($answer -cne 'EVET') {
        throw 'User declined existing-folder replacement; installation unchanged.'
    }
}

function Move-ExistingToRecycle([string]$destination) {
    Assert-NoReparse $destination
    if (-not [IO.Directory]::Exists($destination)) {
        throw 'The existing installation is no longer a normal directory.'
    }
    # Reject nested reparse points so unexpected linked directories cannot
    # extend the replacement scope.
    foreach ($child in @(Get-ChildItem -LiteralPath $destination -Force -Recurse -ErrorAction Stop)) {
        if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Existing installation contains a reparse point; replacement refused.'
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($CiRecycleRoot)) {
        # CI fixture emulates the recycle destination without operating on the
        # real user Recycle Bin; this does not prove shell recycle behavior.
        Assert-NoReparse $CiRecycleRoot
        $null = New-Item -ItemType Directory -Path $CiRecycleRoot -Force
        $archive = Join-Path $CiRecycleRoot ('TurkuazAV-Preview-' + [guid]::NewGuid().ToString('N'))
        [IO.Directory]::Move($destination, $archive)
        Write-Host 'RUST_PREVIEW_CI_RECYCLE_EMULATED=PASS'
    } else {
        [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory(
            $destination,
            [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs,
            [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin,
            [Microsoft.VisualBasic.FileIO.UICancelOption]::ThrowException
        )
    }
    if ($null -ne (Get-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue)) {
        throw 'Existing folder was not moved; new installation refused.'
    }
    Write-Host 'RUST_PREVIEW_EXISTING_FOLDER_MOVED=PASS'
}

function Remove-OwnedShortcut([string]$destination) {
    $shortcut = ShortcutPath
    Assert-NoReparse $shortcut
    if ($null -eq (Get-Item -LiteralPath $shortcut -Force -ErrorAction SilentlyContinue)) {
        return
    }
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($shortcut)
    if ($link.TargetPath -ieq (Join-Path $destination 'turkuazav-desktop.exe')) {
        Remove-Item -LiteralPath $shortcut -Force
    } else {
        Write-Warning 'A shortcut with the same name points elsewhere; leaving it unchanged.'
    }
}

switch ($Action) {
    'Verify' {
        Assert-Payload $sourceRoot
        Write-Host 'RUST_PREVIEW_SETUP_VERIFY=PASS'
    }
    'Install' {
        Assert-Payload $sourceRoot
        Assert-NoReparse $installRoot
        $sourcePath = [IO.Path]::GetFullPath($sourceRoot).TrimEnd('\')
        $targetPath = [IO.Path]::GetFullPath($installRoot).TrimEnd('\')
        if ($sourcePath.Equals($targetPath, [StringComparison]::OrdinalIgnoreCase) -or
            $sourcePath.StartsWith($targetPath + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Use setup from an extracted package outside the installation directory.'
        }
        $parent = Split-Path -Path $installRoot -Parent
        Assert-NoReparse $parent
        $null = New-Item -ItemType Directory -Path $parent -Force
        $shortcutOwned = $false
        if (-not $NoShortcuts) {
            $shortcutOwned = Test-OwnedShortcut $installRoot
        }
        $stage = Join-Path $parent ('.turkuazav-preview-stage-' + [guid]::NewGuid().ToString('N'))
        $committed = $false
        $recycledOld = $false
        try {
            $null = New-Item -ItemType Directory -Path $stage
            foreach ($name in $expectedFiles) {
                Copy-Item -LiteralPath (Join-Path $sourceRoot $name) -Destination (Join-Path $stage $name)
            }
            Assert-Payload $stage
            [IO.File]::WriteAllText(
                (Join-Path $stage $markerName),
                $markerValue,
                [Text.UTF8Encoding]::new($false)
            )
            # Reconcile the old directory only after the replacement payload
            # has been independently verified and fully staged.
            $existing = Get-Item -LiteralPath $installRoot -Force -ErrorAction SilentlyContinue
            if ($null -ne $existing) {
                if (-not $existing.PSIsContainer) {
                    throw 'An unrelated file occupies the installation path.'
                }
                Request-RecycleConsent $installRoot
                Move-ExistingToRecycle $installRoot
                $recycledOld = $true
            }
            if ($CiFailAfterRecycle -and $recycledOld) {
                throw 'CI injected post-recycle install interruption.'
            }
            # Same-parent directory rename refuses a concurrent destination
            # rather than overwriting its contents.
            [IO.Directory]::Move($stage, $installRoot)
            $committed = $true
        } catch {
            if ($recycledOld) {
                Write-Warning 'Yeni kurulum tamamlanamadi. Eski dosyalar icin Geri Donusum Kutusunu kontrol edin.'
            }
            throw
        } finally {
            if (-not $committed -and (Test-Path -LiteralPath $stage)) {
                Assert-NoReparse $stage
                Remove-Item -LiteralPath $stage -Recurse -Force
            }
        }
        if (-not $NoShortcuts -and -not $shortcutOwned) {
            try {
                Add-Shortcut $installRoot
            } catch {
                Write-Warning 'Preview files are installed, but Start Menu shortcut creation failed.'
            }
        }
        Write-Host 'RUST_PREVIEW_SETUP_INSTALL=PASS'
        Write-Host 'This is an unsigned per-user test preview, not a protected antivirus.'
    }
    'Uninstall' {
        Assert-NoReparse $installRoot
        $marker = Join-Path $installRoot $markerName
        Assert-NoReparse $marker
        if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
            throw 'Preview installation marker is absent; refusing to remove unrelated files.'
        }
        if ((Get-Content -LiteralPath $marker -Raw).Trim() -cne $markerValue) {
            throw 'Preview installation marker is invalid.'
        }
        foreach ($name in $expectedFiles) {
            Assert-NoReparse (Join-Path $installRoot $name)
        }
        if (-not $NoShortcuts) {
            Remove-OwnedShortcut $installRoot
        }
        foreach ($name in $expectedFiles) {
            $file = Join-Path $installRoot $name
            if (Test-Path -LiteralPath $file -PathType Leaf) {
                Remove-Item -LiteralPath $file -Force
            }
        }
        Remove-Item -LiteralPath $marker -Force
        $remaining = @(Get-ChildItem -LiteralPath $installRoot -Force)
        if ($remaining.Count -eq 0) {
            Remove-Item -LiteralPath $installRoot -Force
        } else {
            Write-Warning 'Unknown or user-owned files remain in the folder; they were preserved.'
        }
        Write-Host 'RUST_PREVIEW_SETUP_UNINSTALL=PASS'
    }
}