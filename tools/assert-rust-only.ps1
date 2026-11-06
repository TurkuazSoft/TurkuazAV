# Dosya Yolu: REPO_ROOT/tools/assert-rust-only.ps1
# Amac: Aktif Rust dalina eski teknoloji kaynaklarinin donmesini engelle
# Modul - FileType: Tool - PowerShell
# Version: 0.3.1
# Aciklama: CI icin salt okunur tracked-path sozlesmesi
# Bagimli Oldugu Katman: Tool | Config

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $repoRoot
try {
    # @dev-id TAV-RUST-ONLY-010
    # @purpose Keep the active tree focused on Rust without rewriting Git
    # history or deleting signed-state compatibility tests.
    $retiredPatterns = @(
        '*.cs', '*.csproj', '*.xaml', '*.sln', '*.slnx',
        'Directory.Build.props', '.github/workflows/ci.yml',
        'docs/rust-migration.md', 'src/*'
    )
    $retiredFiles = @(& git ls-files -- @retiredPatterns)
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to inspect Git tracked files.'
    }
    if ($retiredFiles.Count -gt 0) {
        throw "Retired sources found in the active Rust tree: $($retiredFiles -join ', ')"
    }
    Write-Host 'RUST_ONLY_ACTIVE_TREE=PASS'
} finally {
    Pop-Location
}
