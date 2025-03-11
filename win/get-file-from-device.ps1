<#
.SYNOPSIS
Get a file from a device

.DESCRIPTION
Allows to recover a file then a device. The file can then be downloaded from the URL returned by the RA 
It will also be available in the user's onedrive indicated in the RA parameters
For security reasons, the token must be generated outside the RA and provided in parameter
when using the RA
The getToken.sh script allows the generation of token

.FUNCTIONALITY
Data collection

.INPUTS
ID  Label                               Description
1   tenantid                            Directorty (Tenant) ID
2   token                               token got from the tenant with client_id/secret_id
3   user_upn                            OneDrive UPN owner (email)
4   full_file_path                      The complete file path for the recovery target
5   return_url                          Boolean: True if the RA should return an URL to download the file

.OUTPUTS
ID  Label                               Type            Description
1   file_uploaded                       boolean         True if file was found and uploaded
2   file_url                            string          URL for downloading the file

.FURTHER INFORMATION
- An application with API Permissions: Files.ReadWrite.All
- Directorty (Tenant) ID
- Application (client) ID
- Secret ID
- UPN (email) of OneDrive owner
- "_NexthinkRA_Bucket_" folder will be created at the root of the OneDrive account, 
and file will be uploaded into this folder.

.NOTES
NOTES
Context:            root
Version:            1.0.0.0 - Initial release
Last Modified:      2025/03/10  14:13:31
Author              L. Taupiac
#>
#
# Input parameters definition
#
param(
    [Parameter(Mandatory = $true)][string]$tenantid,
    [Parameter(Mandatory = $true)][string]$token,
    [Parameter(Mandatory = $true)][string]$user_upn,
    [Parameter(Mandatory = $true)][string]$full_file_path,
    [Parameter(Mandatory = $true)][string]$return_url
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
Set-Variable -Name 'ERROR_EXCEPTION_TYPE' -Option ReadOnly -Scope Script -Force

$LOCAL_SYSTEM_IDENTITY = 'S-1-5-18'
Set-Variable -Name 'LOCAL_SYSTEM_IDENTITY' -Option ReadOnly -Scope Script -Force

$REMOTE_ACTION_DLL_PATH = "$env:NEXTHINK\RemoteActions\nxtremoteactions.dll"
Set-Variable -Name 'REMOTE_ACTION_DLL_PATH' -Option ReadOnly -Scope Script -Force

$WINDOWS_VERSIONS = @{Windows7 = '6.1'
    Windows8 = '6.2'
    Windows81 = '6.3'
    Windows10 = '10.0'
    Windows11 = '10.0'
}
Set-Variable -Name 'WINDOWS_VERSIONS' -Option ReadOnly -Scope Script -Force


$LOG_REMOTE_ACTION_NAME = "Get-FileFromDevice"
Set-Variable -Name LOG_REMOTE_ACTION_NAME -Value $LOG_REMOTE_ACTION_NAME -Scope Global -Force

$TENANT_ID_REGEX = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
$UPN_REGEX = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
$ABSOLUTE_FILE_PATH_REGEX = '^[\/\\]([^\/\\]+[\/\\])*[^\/\\]+$'
$JWT_REGEX = '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
$BOOLEAN_REGEX = '^(0|1|true|false)$'

$ONEDRIVE_URL = 'https://graph.microsoft.com/v1.0/users/{0}/drive/root:{1}:/content'
$ONEDRIVE_BUCKET = "/_NexthinkRA_Bucket_"


#
# Invoke Main
#
function Invoke-Main ([hashtable]$InputParameters) {
    Start-NxtLogging -RemoteActionName $LOG_REMOTE_ACTION_NAME

    $exitCode = 0
    $upload = Initialize-Outputs

    try {
        Add-NexthinkRemoteActionDLL
        Test-RunningAsLocalSystem
        Test-MinimumSupportedOSVersion -WindowsVersion 'Windows10'
        Test-InputParameters -InputParameters $InputParameters
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

    # Obtient le nom d'hôte de la machine locale
    $machine_name = $env:COMPUTERNAME

    if ([string]::IsNullOrEmpty($machine_name)) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Impossible de récupérer le nom de la machine locale."
    }

    # Construit le chemin cible sur OneDrive
    $normalizedFilePath = $full_file_path -replace '[:]', '' -replace '\\', '/'
    $targetFile = "$ONEDRIVE_BUCKET/$machine_name/$normalizedFilePath"

    # URL finale formatée
    $url = [string]::Format($ONEDRIVE_URL, $user_upn, $targetFile)

    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type"  = "application/octet-stream"
    }

    if (-not (Test-Path -Path $full_file_path -PathType Leaf)) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) File '$full_file_path' does not exist or is not accessible."
    }

    try {
        # Use Invoke-WebRequest to access status code and headers
        $response = Invoke-WebRequest -Uri $url `
                                      -Headers $headers `
                                      -Method Put `
                                      -InFile $full_file_path `
                                      -UseBasicParsing `
                                      -ErrorAction Stop

        # Check the HTTP response status code
        if ($response.StatusCode -in 200, 201) {
            $output.file_uploaded = $true

            # Return download URL if requested
            if ($return_url -match '^(1|true)$') {
                $jsonResponse = $response.Content | ConvertFrom-Json
                $output.file_url = $jsonResponse.'@microsoft.graph.downloadUrl'
            }
        } else {
            $output.file_uploaded = $false
            throw "$($ERROR_EXCEPTION_TYPE.Internal) Upload failed with HTTP status $($response.StatusCode)."
        }
    }
    catch {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Error during file upload: $_"
    }
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

function Test-StringNullOrEmpty ([string]$ParamName, [string]$ParamValue) {
    if ([string]::IsNullOrEmpty((Format-StringValue -Value $ParamValue))) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) '$ParamName' cannot be empty nor null. "
    }
}

function Format-StringValue ([string]$Value) {
    return $Value.Replace('"', '').Replace("'", '').Trim()
}

function Test-ParamInAllowedRange ([string]$ParamName, [string]$ParamValue, [int]$LowerLimit, [int]$UpperLimit) {
    Test-ParamIsInteger -ParamName $ParamName -ParamValue $ParamValue
    $intValue = $ParamValue -as [int]
    if ($intValue -lt $LowerLimit -or $intValue -gt $UpperLimit) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Error in parameter '$ParamName'. It must be between [$LowerLimit, $UpperLimit]. "
    }
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

function Test-InputParameters ([hashtable]$InputParameters) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"
    if ($tenantid -notmatch $TENANT_ID_REGEX) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Invalid Tenant ID format."
    }
    if ($user_upn -notmatch $UPN_REGEX) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Invalid UPN (email) format."
    }
    if ($full_file_path -notmatch $ABSOLUTE_FILE_PATH_REGEX) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Invalid absolute file path."
    }
    if ($token -notmatch $JWT_REGEX) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Invalid JWT token format."
    }
    if ($return_url -notmatch $BOOLEAN_REGEX) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) return_url must be boolean."
    }
}

#
# Nexthink Output management
#
function Update-EngineOutputVariables ([hashtable]$EventLogEntries) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    [nxt]::WriteOutputBool("file_uploaded", $upload.file_uploaded)
    [nxt]::WriteOutputString("file_url", $upload.file_url)

}

#
# Main script flow
#
[environment]::Exit((Invoke-Main -InputParameters $MyInvocation.BoundParameters))








