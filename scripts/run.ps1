param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScriptArgs
)
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"

$repoRoot = Split-Path $PSScriptRoot -Parent
$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"

if (Test-Path $venvPython) {
    Push-Location $repoRoot
    try { & $venvPython -m pulseops @ScriptArgs } finally { Pop-Location }
} else {
    Write-Error "[HATA] .venv ortami bulunamadi. Lutfen sanal ortami kontrol edin."
}
