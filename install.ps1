# mcp-hunter installer for Windows PowerShell
$ErrorActionPreference = 'Stop'

$Repo = "mcphunter/mcp-hunter"
$Version = "0.2.0"

Write-Host "==> Installing mcp-hunter v$Version for Windows..." -ForegroundColor Cyan

$Arch = if ([System.Environment]::Is64BitOperatingSystem) {
    if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
} else {
    Write-Error "Unsupported: 32-bit Windows is not supported."
    exit 1
}

$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\mcp-hunter"
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$TargetExe = Join-Path $InstallDir "mcp-hunter.exe"
$DownloadUrl = "https://github.com/$Repo/releases/download/v$Version/mcp-hunter_windows_$Arch.zip"
$ZipPath = Join-Path $env:TEMP "mcp-hunter.zip"

Write-Host "--> Downloading package from GitHub releases..." -ForegroundColor Gray
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath -UseBasicParsing
    Expand-Archive -Path $ZipPath -DestinationPath $InstallDir -Force
    Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
} catch {
    Write-Host "[!] Note: Release v$Version binary download failed. If building from source: 'go build -o mcp-hunter.exe .'" -ForegroundColor Yellow
}

# Update User PATH if needed
$UserPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    Write-Host "--> Adding $InstallDir to User PATH..." -ForegroundColor Gray
    [System.Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
    $env:Path += ";$InstallDir"
}

Write-Host "✔ Successfully configured mcp-hunter in $InstallDir" -ForegroundColor Green
Write-Host ""
Write-Host "Run zero-config audit:" -ForegroundColor White
Write-Host "  mcp-hunter" -ForegroundColor Cyan
