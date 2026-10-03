# PulseOps Windows One-line Installer
Write-Host "⚡ PulseOps Windows Otomatik Kurulumu Başlatılıyor..." -ForegroundColor Cyan

$installDir = Join-Path $HOME "AppData\Local\PulseOps"
$binDir = Join-Path $installDir "bin"
$venvDir = Join-Path $installDir "venv"

New-Item -ItemType Directory -Force -Path $binDir | Out-Null

$repoUrl = if ($env:PULSEOPS_REPO) { $env:PULSEOPS_REPO } else { "https://github.com/salihoglueyup/PulseOPS.git" }

if (Get-Command python -ErrorAction SilentlyContinue) {
    Write-Host "📦 Python bulundu, izole ortam hazırlanıyor..." -ForegroundColor Green
    python -m venv $venvDir
    & "$venvDir\Scripts\pip.exe" install --upgrade pip --quiet
    & "$venvDir\Scripts\pip.exe" install --upgrade "git+$repoUrl" --quiet
    Copy-Item "$venvDir\Scripts\pulseops.exe" "$binDir\pulseops.exe" -Force
} else {
    Write-Host "⬇️ Bağımsız PulseOps binary'si indiriliyor..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://github.com/salihoglueyup/PulseOPS/releases/latest/download/pulseops-windows-amd64.exe" -OutFile "$binDir\pulseops.exe"
}

# Add to User PATH if not present
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$binDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$binDir;$userPath", "User")
    Write-Host "✓ $binDir kullanıcı PATH ortam değişkenine eklendi." -ForegroundColor Green
}

Write-Host "`n🎉 PulseOps başarıyla kuruldu! Yeni bir terminal açıp 'pulseops' yazabilirsiniz." -ForegroundColor Cyan
