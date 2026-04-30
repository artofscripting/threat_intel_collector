param(
    [string]$EnvFile = ".env",
    [string]$TableName = "threat_intel_events",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function Get-EnvValue {
    param(
        [string]$FilePath,
        [string]$Key
    )

    if (-not (Test-Path $FilePath)) {
        throw "Env file not found: $FilePath"
    }

    $line = Get-Content $FilePath | Where-Object {
        $_ -match "^\s*$Key\s*="
    } | Select-Object -First 1

    if (-not $line) {
        return $null
    }

    $value = ($line -replace "^\s*$Key\s*=\s*", "").Trim()
    return $value.Trim('"').Trim("'")
}

if ($TableName -notmatch "^[a-zA-Z_][a-zA-Z0-9_]*$") {
    throw "Invalid table name: $TableName"
}

$password = Get-EnvValue -FilePath $EnvFile -Key "HONEY_POSTGRES_PASSWORD"
if (-not $password) {
    throw "HONEY_POSTGRES_PASSWORD was not found in $EnvFile"
}

$hostName = "switchyard.proxy.rlwy.net"
$port = "13718"
$user = "postgres"
$database = "railway"
$sql = "TRUNCATE TABLE $TableName RESTART IDENTITY;"

$dockerArgs = @(
    "run", "--rm",
    "-e", "PGPASSWORD=$password",
    "postgres:16-alpine",
    "psql",
    "-h", $hostName,
    "-p", $port,
    "-U", $user,
    "-d", $database,
    "-c", $sql
)

Write-Host "About to run: docker $($dockerArgs -join ' ')"

if ($DryRun) {
    Write-Host "Dry run enabled. No changes made."
    exit 0
}

& docker @dockerArgs
if ($LASTEXITCODE -ne 0) {
    throw "Failed to truncate table '$TableName'"
}

Write-Host "Successfully truncated table '$TableName'."
