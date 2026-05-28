param(
    [string]$Port = '8765'
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonScript = Join-Path $scriptDir 'packet_tracer_backend.py'

$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $MyInvocation.MyCommand.Path,
        '-Port', $Port
    )
    exit
}

function Get-PythonCommand {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        return $python.Source
    }

    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        return $py.Source
    }

    throw 'Python was not found on PATH. Install Python or enable the Python launcher (py).'
}

Set-Location $scriptDir

Write-Host 'Starting packet tracer backend...' -ForegroundColor Cyan
Write-Host "Dashboard: http://127.0.0.1:$Port/" -ForegroundColor Cyan

try {
    $pythonCommand = Get-PythonCommand
    & $pythonCommand $pythonScript --interface any --port $Port
}
catch {
    Write-Host ''
    Write-Host 'Launcher error:' -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}