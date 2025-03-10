# Set strict error handling
$ErrorActionPreference = 'Stop'

# Set directory cache paths relative to the current script
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$CACHE_DIR = Join-Path -Path $SCRIPT_DIR -ChildPath '.cache'
$TOKEN_FILE = Join-Path -Path $CACHE_DIR -ChildPath 'gffd_token.txt'
$EXP_FILE = Join-Path -Path $CACHE_DIR -ChildPath 'gffd_token_exp.txt'

# Create cache directory if it doesn't exist
if (-not (Test-Path $CACHE_DIR)) {
    New-Item -Path $CACHE_DIR -ItemType Directory | Out-Null
}

# Load environment variables from external script (.envrc or similar)
. "$SCRIPT_DIR\env.ps1"

# Verify necessary environment variables are set
foreach ($var in @('tenantid', 'clientid', 'secretid')) {
    if (-not (Get-Variable $var -ErrorAction SilentlyContinue)) {
        Write-Error "Missing required variable: $var"
        exit 1
    }
}

function Get-NewToken {
    Write-Host "🔄 Generating a new token..."
    
    # Call the getToken.ps1 script and capture token
    $GFFD_TOKEN = & "$SCRIPT_DIR\getToken.ps1" -tenant_id $tenantid -client_id $clientid -client_secret $secretid

    if (-not $GFFD_TOKEN) {
        throw "Token generation failed."
    }

    # Extract expiration timestamp from JWT payload
    $payload = $GFFD_TOKEN.Split('.')[1]

    # Add padding for base64 decoding if necessary
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
    }

    # Decode payload and get expiration time
    $decodedPayload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(($payload -replace '_','/' -replace '-','+')))
    $GFFD_TOKEN_EXP = (ConvertFrom-Json $decodedPayload).exp

    # Store token and expiration date in cache
    Set-Content -Path $TOKEN_FILE -Value $GFFD_TOKEN
    Set-Content -Path $EXP_FILE -Value $GFFD_TOKEN_EXP
}

# Attempt to recover token from cache
if ((Test-Path $TOKEN_FILE) -and (Test-Path $EXP_FILE)) {
    $GFFD_TOKEN = Get-Content -Path $TOKEN_FILE -Raw
    $GFFD_TOKEN_EXP = Get-Content -Path $EXP_FILE -Raw
}

# Validate token expiration
$currentTime = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
if ([string]::IsNullOrEmpty($GFFD_TOKEN) -or [string]::IsNullOrEmpty($GFFD_TOKEN_EXP) -or $currentTime -ge [int]$GFFD_TOKEN_EXP) {
    Get-NewToken
} else {
    Write-Host "Using cached token."
}

# Copy token to clipboard
$GFFD_TOKEN | Set-Clipboard
Write-Host "Token copied to clipboard."
