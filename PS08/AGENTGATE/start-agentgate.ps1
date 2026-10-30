$ErrorActionPreference = "Stop"

$projectRoot = $PSScriptRoot
$backendDir = Join-Path $projectRoot "agentgate_phase1"
$frontendDir = Join-Path $projectRoot "frontend"
$envFile = Join-Path $projectRoot ".env"

function New-RandomSecret {
    $bytes = New-Object byte[] 32
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    }
    finally {
        $generator.Dispose()
    }
    return [BitConverter]::ToString($bytes).Replace("-", "").ToLowerInvariant()
}

if (-not (Test-Path $envFile)) {
    $apiKey = New-RandomSecret
    $apiKeyMap = @{ $apiKey = @{ user_id = "admin-user"; session_id = "local-admin-session" } } | ConvertTo-Json -Compress
    @(
        "AGENTGATE_AUTH_KEY=$(New-RandomSecret)"
        "AGENTGATE_AUDIT_KEY=$(New-RandomSecret)"
        "AGENTGATE_API_KEYS=$apiKeyMap"
        "AGENTGATE_AUDIT_READERS=admin-user"
    ) | Set-Content -Path $envFile -Encoding ASCII
    Write-Host "Created local credentials in .env (ignored by Git)."
    Write-Host "Dashboard API key: $apiKey"
}

Get-Content $envFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith("#")) {
        $parts = $line -split "=", 2
        if ($parts.Length -eq 2) {
            [Environment]::SetEnvironmentVariable($parts[0], $parts[1], "Process")
        }
    }
}

$python = Join-Path $backendDir ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        throw "Python 3.10+ is required. Install Python and run this script again."
    }
    & $pythonCommand.Source -m venv (Join-Path $backendDir ".venv")
    if ($LASTEXITCODE -ne 0) { throw "Could not create the backend virtual environment." }
    $python = Join-Path $backendDir ".venv\Scripts\python.exe"
}

& $python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if ($LASTEXITCODE -ne 0) { throw "Python 3.10 or newer is required." }

& $python -c "import fastapi, uvicorn, pydantic" 2>$null
if ($LASTEXITCODE -ne 0) {
    & $python -m pip install -r (Join-Path $backendDir "requirements.txt")
    if ($LASTEXITCODE -ne 0) { throw "Backend dependency installation failed." }
}

$npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
if (-not $npm) {
    throw "Node.js 18+ and npm are required. Install Node.js and run this script again."
}
$node = Get-Command node.exe -ErrorAction SilentlyContinue
if (-not $node) {
    throw "Node.js 18+ is required. Install Node.js and run this script again."
}
$nodeVersion = (& $node.Source --version).TrimStart("v")
if ([version]$nodeVersion -lt [version]"18.0") {
    throw "Node.js 18 or newer is required."
}
if (-not (Test-Path (Join-Path $frontendDir "node_modules\vite\bin\vite.js"))) {
    Push-Location $frontendDir
    try {
        & $npm.Source ci
        if ($LASTEXITCODE -ne 0) { throw "Frontend dependency installation failed." }
    }
    finally {
        Pop-Location
    }
}

$backendProcess = Start-Process -FilePath $python `
    -ArgumentList @("-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", "8000") `
    -WorkingDirectory $backendDir -PassThru
$frontendProcess = Start-Process -FilePath $env:ComSpec `
    -ArgumentList @("/c", "npm run dev -- --host 127.0.0.1") `
    -WorkingDirectory $frontendDir -PassThru

Write-Host "Backend process: $($backendProcess.Id) (http://127.0.0.1:8000)"
Write-Host "Dashboard process: $($frontendProcess.Id) (http://127.0.0.1:5173)"
Write-Host "Close the two launched console windows to stop the services."

$backendReady = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    if ($backendProcess.HasExited) {
        throw "Backend exited during startup. Check its console for the configuration or port error."
    }
    try {
        $health = Invoke-RestMethod "http://127.0.0.1:8000/health" -TimeoutSec 2
        if ($health.status -eq "ok") {
            $backendReady = $true
            break
        }
    }
    catch {
        Start-Sleep -Seconds 1
    }
}
if (-not $backendReady) {
    Stop-Process -Id $backendProcess.Id -ErrorAction SilentlyContinue
    throw "Backend did not become ready at http://127.0.0.1:8000."
}

$frontendReady = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    if ($frontendProcess.HasExited) {
        Stop-Process -Id $backendProcess.Id -ErrorAction SilentlyContinue
        throw "Dashboard process exited during startup. Check its console for the error."
    }
    try {
        $response = Invoke-WebRequest "http://127.0.0.1:5173" -UseBasicParsing -TimeoutSec 2
        if ($response.StatusCode -eq 200) {
            $frontendReady = $true
            break
        }
    }
    catch {
        Start-Sleep -Seconds 1
    }
}
if (-not $frontendReady) {
    Stop-Process -Id $backendProcess.Id -ErrorAction SilentlyContinue
    throw "Dashboard did not become ready at http://127.0.0.1:5173."
}

Write-Host "Backend and dashboard are responding."
Start-Process "http://127.0.0.1:5173"
