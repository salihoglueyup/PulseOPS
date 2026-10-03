# PulseOps Standalone Binary Build Script for Windows
Write-Host "⚡ PulseOps Standalone Binary (.exe) Derleniyor..." -ForegroundColor Cyan

$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$pyinstaller = Join-Path $PSScriptRoot ".venv\Scripts\pyinstaller.exe"

if (-not (Test-Path $pyinstaller)) {
    Write-Host "📦 PyInstaller yukleniyor..." -ForegroundColor Yellow
    & $venvPython -m pip install pyinstaller
}

Write-Host "🔨 PyInstaller calistiriliyor..." -ForegroundColor Cyan
& $pyinstaller --noconfirm --clean --onefile --name pulseops --collect-all textual --add-data "ui/styles.tcss;ui" cli.py

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✓ Derleme basariyla tamamlandi!" -ForegroundColor Green
    Write-Host "Dosya konumu: dist\pulseops.exe" -ForegroundColor Green
    
    # Optional copy to user PATH
    $targetPath = "C:\Users\eyupz\AppData\Local\Python\bin\pulseops.exe"
    if (Test-Path "C:\Users\eyupz\AppData\Local\Python\bin") {
        Copy-Item "dist\pulseops.exe" $targetPath -Force
        Write-Host "✓ Global PATH dizinine kopyalandi: $targetPath" -ForegroundColor Green
        Write-Host "Artik herhangi bir terminalde sadece 'pulseops' yazabilirsiniz!" -ForegroundColor Cyan
    }
} else {
    Write-Host "❌ Derleme basarisiz oldu!" -ForegroundColor Red
}
