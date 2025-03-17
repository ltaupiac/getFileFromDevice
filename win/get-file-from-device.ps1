<#
.SYNOPSIS
Get a file from a device and upload to Azure Blob Storage

.DESCRIPTION
Allows to securely retrieve a file from a device and upload it to an Azure Blob Storage container
using a SAS token with write permissions.

.FUNCTIONALITY
Data collection

.INPUTS
ID  Label                               Description
1   sas_upload_token                    SAS Token with write access to the container
2   storage_account                     Azure storage account name
3   container                           Azure blob container name
4   full_file_path                      The complete file path for the recovery target

.OUTPUTS
ID  Label                               Type            Description
1   file_uploaded                       boolean         True if file was found and uploaded
2   blob_path_file                      string          Blob path for downloading the file

.NOTES
NOTES
Context:            root
Version:            2.0.0.0 - Blob storage upload
Version:            1.0.0.0 - Initial release
Last Modified:      2025/03/14  21:40:49
Author              L. Taupiac
#>
#
# Input parameters definition
#
param(
    [Parameter(Mandatory = $true)][string]$sas_upload_token,
    [Parameter(Mandatory = $true)][string]$storage_account,
    [Parameter(Mandatory = $true)][string]$container,
    [Parameter(Mandatory = $true)][string]$full_file_path
)
# End of parameters definition

# Global trap of error
trap {
    $e=$Error[0]
    $host.ui.WriteErrorLine('Error :'+ $e.Exception.Message + ": [L"+$e.InvocationInfo.ScriptLineNumber + "/C" + $e.InvocationInfo.OffsetInLine + "]")
    exit 1
}

$env:Path = "$env:SystemRoot\system32;$env:SystemRoot;$env:SystemRoot\System32\Wbem;$env:SystemRoot\System32\WindowsPowerShell\v1.0\"

#
# Constants definition
#
$ERROR_EXCEPTION_TYPE = @{Environment = '[Environment error]'
    Input = '[Input error]'
    Internal = '[Internal error]'
}
Set-Variable -Name 'ERROR_EXCEPTION_TYPE' -Scope Script -Force

$LOCAL_SYSTEM_IDENTITY = 'S-1-5-18'
Set-Variable -Name 'LOCAL_SYSTEM_IDENTITY' -Scope Script -Force

$REMOTE_ACTION_DLL_PATH = "$env:NEXTHINK\RemoteActions\nxtremoteactions.dll"
Set-Variable -Name 'REMOTE_ACTION_DLL_PATH' -Scope Script -Force

$WINDOWS_VERSIONS = @{Windows7 = '6.1'
    Windows8 = '6.2'
    Windows81 = '6.3'
    Windows10 = '10.0'
    Windows11 = '10.0'
}
Set-Variable -Name 'WINDOWS_VERSIONS'  -Scope Script -Force

$LOG_REMOTE_ACTION_NAME = "Get-FileFromDevice"
Set-Variable -Name LOG_REMOTE_ACTION_NAME -Value $LOG_REMOTE_ACTION_NAME -Scope Global -Force

$ABSOLUTE_FILE_PATH_REGEX = '^[\/\\]([^\/\\]+[\/\\])*[^\/\\]+$'
$TOOLS="$env:ProgramData\Nexthink\RemoteActions\bin\"
$AZCOPY = "$TOOLS\azcopy.exe"
$AZ_URL = "https://aka.ms/downloadazcopy-v10-windows-32bit"


#
# Invoke Main
#
function Invoke-Main ([hashtable]$InputParameters) {
    Start-NxtLogging -RemoteActionName $LOG_REMOTE_ACTION_NAME

    $exitCode = 0
    $upload = Initialize-Outputs

    try {
        Add-NexthinkRemoteActionDLL
        # Test-RunningAsLocalSystem
        Test-MinimumSupportedOSVersion -WindowsVersion 'Windows10'
        Test-InputParameters -InputParameters $InputParameters
        Test-Proxy
        Test-Azcopy

        upload_file -output $upload
    } catch {
        Write-StatusMessage -Message $_
        $exitCode = 1
    } finally {
        Update-EngineOutputVariables -EventLogEntries $EventLogEntries
        Stop-NxtLogging -Result $exitCode
    }

    return $exitCode
}

function Test-Proxy {
    Write-NxtLog -Message "Checking proxy connectivity"

    if ($env:HTTP_PROXY) {
        try {
            $proxyUri = [uri]$env:HTTP_PROXY
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $tcpClient.Connect($proxyUri.Host, $proxyUri.Port)
            $tcpClient.Close()
            Write-NxtLog -Message "Proxy $($env:HTTP_PROXY) is reachable"
        } catch {
            throw "$($ERROR_EXCEPTION_TYPE.Environment) Proxy $($env:HTTP_PROXY) is not reachable or refused connection"
        }
    } else {
        Write-NxtLog -Message "No HTTP_PROXY variable defined, skipping proxy check"
    }
}

function Test-Azcopy {
    Write-NxtLog -Message "Ensuring azcopy is installed"
    if (-not (Test-Path -Path $AZCOPY)) {

        # Define the temp file and extraction paths
        $tempZip = Join-Path -Path $env:TEMP -ChildPath "azcopy.zip"
        $extractPath = Join-Path -Path $env:TEMP -ChildPath "azcopy_extracted"        

        $webClient = New-Object System.Net.WebClient

        if ($env:HTTP_PROXY) {
            $webProxy = New-Object System.Net.WebProxy($env:HTTP_PROXY, $true)
            $webClient.Proxy = $webProxy
            Write-NxtLog -Message "Using proxy $($env:HTTP_PROXY)"
        }
        Write-NxtLog -Message "Downloading AzCopy..."
        $webClient.DownloadFile($AZ_URL, $tempZip)

        # Extract azcopy
        Write-NxtLog -Message "Extracting azcopy archive..."
        Expand-Archive -Path $tempZip -DestinationPath $extractPath -Force

        # Locate azcopy.exe and copy to destination
        Write-NxtLog -Message "Copying azcopy to destination [$tools]..."
        $azcopyExe = Get-ChildItem -Path $extractPath -Filter "azcopy.exe" -Recurse | Select-Object -First 1

        if (-not $azcopyExe) {
            throw "Unable to find azcopy.exe after extraction."
        }

        # Ensure destination folder exists
        if (-not (Test-Path -Path $tools)) {
            New-Item -Path $tools -ItemType Directory | Out-Null
        }

        Copy-Item -Path $azcopyExe.FullName -Destination $tools -Force

        # Cleanup
        Remove-Item -Path $tempZip -Force
        Remove-Item -Path $extractPath -Recurse -Force

        Write-NxtLog -Message "Azcopy installation completed successfully."
    }
}

#
# Template functions
#
function Start-NxtLogging ([string]$RemoteActionName) {
    if (Test-PowerShellVersion -MinimumVersion 5) {
        $logFile = "$(Get-LogPath)$RemoteActionName.log"

        Start-NxtLogRotation -LogFile $logFile
        Start-Transcript -Path $logFile -Append | Out-Null
        Write-NxtLog -Message "Running Remote Action $RemoteActionName"
    }
}

function Initialize-Outputs {
    Write-NxtLog -Message "Calling function $($MyInvocation.MyCommand)"

    return @{
        file_uploaded = $false
        file_url = '-'
    }
}

function upload_file ([hashtable]$output) {
    Write-NxtLog -Message "Calling function $($MyInvocation.MyCommand)"
    $machine_name = $env:COMPUTERNAME
    if ([string]::IsNullOrEmpty($machine_name)) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Cannot get hostname"
    }
    $normalizedFilePath = $full_file_path -replace '[:]', '' -replace '\\', '/'
    $blob_path_file = "/$machine_name$normalizedFilePath"
    $output.blob_path_file = $blob_path_file
    
    $target = "https://${storage_account}.blob.core.windows.net/${container}${blob_path_file}?${sas_upload_token}"

    $params = @("copy", "`"$full_file_path`"", "`"$target`"", "--overwrite=true", "--output-level=essential",
                "--check-length=false", "--output-type=json", "--skip-version-check", "--from-to=LocalBlob")
 
    try {
        $result = & $AZCOPY @params | Out-String

        # Parsing result
        $json = Get-AzCopyResult -AzCopyOutput $result

        # Analyse du status
        if ($json.JobStatus -eq "Completed" -and $json.TotalBytesTransferred -gt 0) {
            $output.file_uploaded = $true
        } else {
            $reason = $json.FailedTransfers[0].ErrorCode
            throw "$($ERROR_EXCEPTION_TYPE.Upload) Upload failed: $reason"
        }
    } catch {
        throw "$($ERROR_EXCEPTION_TYPE.Upload) Error in azcopy upload: $_"
    }
}

function Get-AzCopyResult {
    param(
        [Parameter(Mandatory=$true)]
        [string]$AzCopyOutput
    )

    # Split the raw output into lines (multiple JSON objects possible)
    $lines = $AzCopyOutput -split "`n"

    foreach ($line in $lines) {
        try {
            $json = $line | ConvertFrom-Json -ErrorAction Stop

            if ($json.MessageType -eq 'EndOfJob') {
                # Second level of parsing: MessageContent is a JSON string → reparse it
                $innerJson = $json.MessageContent | ConvertFrom-Json -ErrorAction Stop
                return $innerJson
            }
        } catch {
            continue
        }
    }

    throw "[Internal error] Cannot extract EndOfJob result from azcopy output."
}

function Test-PowerShellVersion ([int]$MinimumVersion) {
    if ((Get-Host).Version.Major -ge $MinimumVersion) {
        return $true
    }
}

function Get-LogPath {
    if (Confirm-CurrentUserIsLocalSystem) {
        return "$env:ProgramData\Nexthink\RemoteActions\Logs\"
    }
    return "$env:LocalAppData\Nexthink\RemoteActions\Logs\"
}

function Confirm-CurrentUserIsLocalSystem {
    $currentIdentity = Get-CurrentIdentity
    return $currentIdentity -eq $LOCAL_SYSTEM_IDENTITY
}

function Get-CurrentIdentity {
    return [security.principal.windowsidentity]::GetCurrent().User.ToString()
}

function Start-NxtLogRotation ([string]$LogFile) {
    if (Test-Path -Path $LogFile) {
        $logSize = (Get-Item -Path $LogFile).Length
        if ($logSize -gt 1000000) {
            Remove-Item -Path "$($LogFile).001" -Force -ErrorAction SilentlyContinue
            Rename-Item -Path $LogFile -NewName "$($LogFile).001" -Force
        }
    }
}

function Write-NxtLog ([string]$Message, [object]$Object) {
    if (Test-PowerShellVersion -MinimumVersion 5) {
        $currentDate = Get-Date -Format 'yyyy/MM/dd hh:mm:ss'
        if ($Object) {
            $jsonObject = $Object | ConvertTo-Json -Compress -Depth 100
            Write-Information -MessageData "$currentDate - $Message $jsonObject"
        } else {
            Write-Information -MessageData "$currentDate - $Message"
        }
    }
}

function Add-NexthinkRemoteActionDLL {
    if (-not (Test-Path -Path $REMOTE_ACTION_DLL_PATH)) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Nexthink Remote Action DLL not found. "
    }
    Add-Type -Path $REMOTE_ACTION_DLL_PATH
}

function Test-RunningAsLocalSystem {
    if (-not (Confirm-CurrentUserIsLocalSystem)) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) This script must be run as LocalSystem. "
    }
}

function Test-MinimumSupportedOSVersion ([string]$WindowsVersion, [switch]$SupportedWindowsServer) {
    $currentOSInfo = Get-OSVersionType
    $OSVersion = $currentOSInfo.Version -as [version]

    $supportedWindows = $WINDOWS_VERSIONS.$WindowsVersion -as [version]

    if (-not ($currentOSInfo)) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) This script could not return OS version. "
    }

    if ( $SupportedWindowsServer -eq $false -and $currentOSInfo.ProductType -ne 1) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) This script is not compatible with Windows Servers. "
    }

    if ( $OSVersion -lt $supportedWindows) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) This script is compatible with $WindowsVersion and later only. "
    }
}

function Get-OSVersionType {
    return Get-WindowsManagementData -Class Win32_OperatingSystem | Select-Object -Property Version,ProductType
}

function Get-WindowsManagementData ([string]$Class, [string]$Namespace = 'root/cimv2') {
    try {
        $query = [wmisearcher] "Select * from $Class"
        $query.Scope.Path = "$Namespace"
        $query.Get()
    } catch {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Error getting CIM/WMI information. Verify WinMgmt service status and WMI repository consistency. "
    }
}

function Write-StatusMessage ([psobject]$Message) {
    $exceptionMessage = $Message.ToString()

    if ($Message.InvocationInfo.ScriptLineNumber) {
        $version = Get-ScriptVersion
        if (-not [string]::IsNullOrEmpty($version)) {
            $scriptVersion = "Version: $version. "
        }

        $errorMessageLine = $scriptVersion + "Line '$($Message.InvocationInfo.ScriptLineNumber)': "
    }

    $host.ui.WriteErrorLine($errorMessageLine + $exceptionMessage)
}

function Get-ScriptVersion {
    $scriptContent = Get-Content $MyInvocation.ScriptName | Out-String
    if ($scriptContent -notmatch '<#[\r\n]{2}.SYNOPSIS[^\#\>]*(.NOTES[^\#\>]*)\#>') { return }

    $helpBlock = $Matches[1].Split([environment]::NewLine)

    foreach ($line in $helpBlock) {
        if ($line -match 'Version:') {
            return $line.Split(':')[1].Split('-')[0].Trim()
        }
    }
}

function Stop-NxtLogging ([string]$Result) {
    if (Test-PowerShellVersion -MinimumVersion 5) {
        if ($Result -eq 0) {
            Write-NxtLog -Message 'Remote Action execution was successful'
        } else {
            Write-NxtLog -Message 'Remote Action execution failed'
        }
        Stop-Transcript | Out-Null
    }
}

function Format-StringValue ([string]$Value) {
    return $Value.Replace('"', '').Replace("'", '').Trim()
}

function Test-ParamIsInteger ([string]$ParamName, [string]$ParamValue) {
    $intValue = $ParamValue -as [int]
    if ([string]::IsNullOrEmpty($ParamValue) -or $null -eq $intValue) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Error in parameter '$ParamName'. '$ParamValue' is not an integer. "
    }
}

#
# Input parameter validation
#
function Test-InputParameters {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"
    Test-SASUploadToken $sas_upload_token
    Test-AbsoluteFilePath $full_file_path

    if ($storage_account -notmatch '^[a-z0-9]{3,24}$') {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Invalid storage account name: $storage_account"
    }
    if ($container -notmatch '^[a-z0-9\-]{3,63}$') {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Invalid container name: $container"
    }
}

function Test-AbsoluteFilePath {
    param([string]$path)
    Write-NxtLog -Message "Checking path format"

    if ($path -notmatch $ABSOLUTE_FILE_PATH_REGEX) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Invalid file path format: $path"
    }
    if (-not (Test-Path $path -PathType Leaf)) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) File '$path' not found or unreadable"
    }
}

function Test-SASUploadToken {
    param([string]$token)
    Write-NxtLog -Message "Checking SAS token"

    if ($token -notmatch "st=" -or $token -notmatch "se=") {
        throw "$($ERROR_EXCEPTION_TYPE.Input) SAS token missing 'st=' or 'se='."
    }

    $st = ($token -split '&') | Where-Object { $_ -like "st=*" } | ForEach-Object { ($_ -split '=')[1] }
    $se = ($token -split '&') | Where-Object { $_ -like "se=*" } | ForEach-Object { ($_ -split '=')[1] }

    try {
        $startDate = [datetime]::Parse($st).ToUniversalTime()
        $endDate = [datetime]::Parse($se).ToUniversalTime()
    } catch {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Invalid date format in SAS token"
    }

    $now = (Get-Date).ToUniversalTime()
    if ($now -lt $startDate) { throw "$($ERROR_EXCEPTION_TYPE.Input) SAS token not yet valid." }
    if ($now -gt $endDate) { throw "$($ERROR_EXCEPTION_TYPE.Input) SAS token expired." }
}

#
# Nexthink Output management
#
function Update-EngineOutputVariables ([hashtable]$EventLogEntries) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    [nxt]::WriteOutputBool("file_uploaded", $upload.file_uploaded)
    [nxt]::WriteOutputString("blob_path_file", $upload.blob_path_file)
}

#
# Main script flow
#
[environment]::Exit((Invoke-Main -InputParameters $MyInvocation.BoundParameters))








