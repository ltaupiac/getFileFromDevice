param(
    [Parameter(Mandatory = $true)][string]$sourceBlobPath,
    [Parameter(Mandatory = $false)][string]$localDest,
    [switch]$Force
)

# Load environment variables from env.ps1
. "$PSScriptRoot\env.ps1"

# Constants
$tools = "$env:ProgramData\Nexthink\RemoteActions\bin\"
$azcopyExe = Join-Path -Path $tools -ChildPath "azcopy.exe"
$azcopyUrl = "https://aka.ms/downloadazcopy-v10-windows-32bit"

# Check required environment variables
foreach ($var in @("sas_download_token", "storage_account", "container")) {
    if (-not (Get-Variable -Name $var -ValueOnly -ErrorAction SilentlyContinue)) {
        Write-Host "Missing required environment variable: $var"
        exit 1
    }
}

# Ensure azcopy is available
if (-not (Test-Path -Path $azcopyExe)) {
    Write-Host "AzCopy not found. Downloading..."
    
    $tempZip = Join-Path -Path $env:TEMP -ChildPath "azcopy.zip"
    $extractPath = Join-Path -Path $env:TEMP -ChildPath "azcopy_extracted"

    # Download azcopy
    Invoke-WebRequest -Uri $azcopyUrl -OutFile $tempZip

    # Extract azcopy
    Expand-Archive -Path $tempZip -DestinationPath $extractPath -Force

    # Find azcopy.exe and copy
    $azcopyFound = Get-ChildItem -Path $extractPath -Filter "azcopy.exe" -Recurse | Select-Object -First 1
    if (-not $azcopyFound) {
        throw "Unable to find azcopy.exe after extraction."
    }

    # Ensure destination folder exists
    if (-not (Test-Path -Path $tools)) {
        New-Item -Path $tools -ItemType Directory | Out-Null
    }

    Copy-Item -Path $azcopyFound.FullName -Destination $tools -Force

    # Cleanup temporary files
    Remove-Item -Path $tempZip -Force
    Remove-Item -Path $extractPath -Recurse -Force

    Write-Host "AzCopy installation completed successfully."
}

$sourceBlobPath = $sourceBlobPath.TrimStart("/\")
# Build full source URL
$url = "https://$storage_account.blob.core.windows.net/$container/$sourceBlobPath`?$sas_download_token"

# If no destination is specified, use filename from blob path
if ([string]::IsNullOrEmpty($localDest)) {
    $localDest = Split-Path $sourceBlobPath -Leaf
}

# If local destination is a directory, append filename
if (Test-Path -Path $localDest -PathType Container) {
    $localDest = Join-Path $localDest (Split-Path $sourceBlobPath -Leaf)
}

# Check existence and handle overwrite option
if ((Test-Path -Path $localDest -PathType Leaf) -and -not $Force) {
    Write-Host "Target file '$localDest' already exists. Use -Force to overwrite."
    exit 1
}
elseif ((Test-Path -Path $localDest -PathType Leaf) -and $Force) {
    Write-Host "Existing file '$localDest' will be overwritten."
}

# AzCopy arguments
$azParams = @("--overwrite=true", "--check-length=false", "--skip-version-check", "--log-level=none", "--output-type=json")

# Download
Write-Host "Downloading from: $url"
$result = & $azcopyExe copy $url $localDest @azParams 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "AzCopy failed:`n$result"
    exit 1
}

# Validate transfer (JSON parsing)
$endJobJson = $result | ConvertFrom-Json | Where-Object { $_.MessageType -eq "EndOfJob" } | Select-Object -First 1
$messageContent = $endJobJson.MessageContent | ConvertFrom-Json

$transferredBytes = [int64]$messageContent.TotalBytesTransferred
$filesCompleted = [int]$messageContent.TransfersCompleted

# Verify file size
$fileSize = if (Test-Path -Path $localDest) {
    (Get-Item $localDest).Length
} else {
    0
}

Write-Host "Destination size:   $fileSize bytes"
Write-Host "Transferred bytes:  $transferredBytes"
Write-Host "Files completed:    $filesCompleted"

if ($filesCompleted -eq 1 -and $transferredBytes -eq $fileSize) {
    Write-Host "Download to '$localDest' completed successfully."
    exit 0
} else {
    Write-Host "Download verification failed."
    exit 1
}