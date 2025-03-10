<#
.SYNOPSIS
Obtain an authentication token (JWT) from Azure AD.

.DESCRIPTION
This script retrieves an OAuth2 JWT token from Azure Active Directory to access Microsoft Graph API.
The obtained token is copied to the Windows clipboard.

.PARAMETERS
- tenant_id: Azure AD Tenant ID
- client_id: Azure AD Application (Client) ID
- client_secret: Application Secret from Azure AD App Registration

.OUTPUTS
- JWT token (also copied to clipboard)
#>

param(
    [Parameter(Mandatory=$true)][string]$tenant_id,
    [Parameter(Mandatory=$true)][string]$client_id,
    [Parameter(Mandatory=$true)] [string]$client_secret
)

# OAuth2 Endpoint
$tokenUrl = "https://login.microsoftonline.com/$tenant_id/oauth2/v2.0/token"

# Request body
$body = @{
    client_id     = $client_id
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $client_secret
    grant_type    = "client_credentials"
}

# Send HTTP POST request to obtain the token
try {
    $response = Invoke-RestMethod -Uri $tokenUrl `
                                   -Method Post `
                                   -Body $body `
                                   -ContentType "application/x-www-form-urlencoded"

    if ($null -ne $response.access_token) {
        $token = $response.access_token

        # Copy token to clipboard
        Set-Clipboard -Value $token

        Write-Host "Token successfully obtained and copied to clipboard."
        Write-Output $token
    }
    else {
        throw "Error retrieving token: No token received."
    }
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
