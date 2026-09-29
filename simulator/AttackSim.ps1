param(
    [string]$LogPath = $(Join-Path (Split-Path -Parent $PSScriptRoot) "live_stream.log"),
    [string]$PidFilePath = $(Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) "runtime") "attack-sim.pid"),
    [string[]]$AttackTypes = @("Brute Force", "SQL Injection", "Port Scan", "Credential Stuffing"),
    [int]$IntervalMinSeconds = 1,
    [int]$IntervalMaxSeconds = 3
)

$supportedAttackTypes = @(
    "Brute Force",
    "SQL Injection",
    "Port Scan",
    "Credential Stuffing"
)

$invalidTypes = @($AttackTypes | Where-Object { $_ -notin $supportedAttackTypes })
if ($invalidTypes.Count -gt 0) {
    throw "Unsupported attack type selection: $($invalidTypes -join ', ')"
}

$attackTypes = @($AttackTypes | Select-Object -Unique)
if ($attackTypes.Count -eq 0) {
    throw "Select at least one attack type."
}

$logDirectory = Split-Path -Parent $LogPath
if (-not [string]::IsNullOrWhiteSpace($logDirectory) -and -not (Test-Path $logDirectory)) {
    New-Item -ItemType Directory -Path $logDirectory | Out-Null
}

$pidDirectory = Split-Path -Parent $PidFilePath
if (-not [string]::IsNullOrWhiteSpace($pidDirectory) -and -not (Test-Path $pidDirectory)) {
    New-Item -ItemType Directory -Path $pidDirectory | Out-Null
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$writer = $null

try {
    $writer = [System.IO.StreamWriter]::new($LogPath, $true, $utf8NoBom)
    [System.IO.File]::WriteAllText($PidFilePath, $PID.ToString(), $utf8NoBom)

    Write-Host "Starting Cyber Attack Simulation: $($attackTypes -join ', ')" -ForegroundColor Red
    Write-Host "Writing newline-delimited JSON to $LogPath" -ForegroundColor Cyan
    Write-Host "Simulator PID written to $PidFilePath" -ForegroundColor Cyan

    while ($true) {
        $randomAttack = $attackTypes | Get-Random
        $severity = Get-Random -Minimum 1 -Maximum 11

        $logEntry = [ordered]@{
            time = Get-Date -Format "HH:mm:ss"
            type = $randomAttack
            severity = $severity
            origin = "103.25.12.$(Get-Random -Minimum 1 -Maximum 255)"
        }

        $jsonLine = $logEntry | ConvertTo-Json -Compress
        $writer.WriteLine($jsonLine)
        $writer.Flush()

        Write-Host "Generated Threat: $randomAttack (Severity: $severity)" -ForegroundColor Yellow
        Start-Sleep -Seconds (Get-Random -Minimum $IntervalMinSeconds -Maximum ($IntervalMaxSeconds + 1))
    }
}
finally {
	if ($null -ne $writer) {
		$writer.Dispose()
	}

    if (Test-Path $PidFilePath) {
        try {
            $recordedPid = Get-Content -Path $PidFilePath -Raw -ErrorAction Stop
            if ($recordedPid.Trim() -eq $PID.ToString()) {
                Remove-Item -Path $PidFilePath -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            Remove-Item -Path $PidFilePath -Force -ErrorAction SilentlyContinue
        }
    }
}
