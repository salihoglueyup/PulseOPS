# PulseOps Standalone Binary Build Script for Windows
Write-Host "⚡ PulseOps Standalone Binary (.exe) Derleniyor..." -ForegroundColor Cyan

$repoRoot = Split-Path $PSScriptRoot -Parent
Set-Location $repoRoot
$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
$pyinstaller = Join-Path $repoRoot ".venv\Scripts\pyinstaller.exe"

if (-not (Test-Path $pyinstaller)) {
    Write-Host "📦 PyInstaller yukleniyor..." -ForegroundColor Yellow
    & $venvPython -m pip install pyinstaller
}

Write-Host "🔨 PyInstaller calistiriliyor..." -ForegroundColor Cyan
& $pyinstaller --noconfirm --clean --onefile --name pulseops --collect-all textual --add-data "pulseops/ui/styles.tcss;pulseops/ui" packaging/pyinstaller_entry.py

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✓ Derleme basariyla tamamlandi!" -ForegroundColor Green
    Write-Host "Dosya konumu: dist\pulseops.exe" -ForegroundColor Green
    
    # Optional copy to user PATH
    $targetDir = Join-Path $env:LOCALAPPDATA "Python\bin"
    $targetPath = Join-Path $targetDir "pulseops.exe"
    if (Test-Path $targetDir) {
        Copy-Item "dist\pulseops.exe" $targetPath -Force
        Write-Host "✓ Global PATH dizinine kopyalandi: $targetPath" -ForegroundColor Green
        Write-Host "Artik herhangi bir terminalde sadece 'pulseops' yazabilirsiniz!" -ForegroundColor Cyan
    }
} else {
    Write-Host "❌ Derleme basarisiz oldu!" -ForegroundColor Red
}
