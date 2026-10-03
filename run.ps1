param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScriptArgs
)
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"

$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$mainPy = Join-Path $PSScriptRoot "main.py"

if (Test-Path $venvPython) {
    & $venvPython $mainPy @ScriptArgs
} else {
    Write-Error "[HATA] .venv ortami bulunamadi. Lutfen sanal ortami kontrol edin."
}
