#!/usr/bin/env zsh

SILENT_MODE=0

# Conditional log function
function log() {
    [[ $SILENT_MODE -eq 0 ]] && echo "$@"
}

# Parse long options
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --tenantid) TENANT_ID="$2"; shift 2 ;;
        --clientid) CLIENT_ID="$2"; shift 2  ;;
        --secretid) CLIENT_SECRET="$2"; shift 2 ;;
	-s|--silent) SILENT_MODE=1; shift ;;
        *) echo "Usage: $0 [-s] --tenantid TENANT_ID --clientid CLIENT_ID --secretid CLIENT_SECRET" >&2; exit 1 ;;
    esac
done

# Validate input parameters
if [[ -z "$TENANT_ID" || -z "$CLIENT_ID" || -z "$CLIENT_SECRET" ]]; then
    echo "All parameters (--tenantid, --clientid, --secretid) are required." >&2
    exit 1
fi

# Ensure `jq` is installed
if ! command -v jq &> /dev/null; then
    echo "Error: 'jq' is required but not installed. Install it with 'brew install jq'" >&2
    exit 1
fi

# OAuth2 token request URL
TOKEN_URL="https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token"

# Send request to obtain the access token
RESPONSE=$(curl -s -X POST "$TOKEN_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "client_id=$CLIENT_ID" \
    --data-urlencode "client_secret=$CLIENT_SECRET" \
    --data-urlencode "scope=https://graph.microsoft.com/.default" \
    --data-urlencode "grant_type=client_credentials")

# Extract the access token using jq
TOKEN=$(echo "$RESPONSE" | jq -r '.access_token')

# Validate the token response
if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
    echo "Error: Unable to retrieve the token. Please check your credentials." >&2
    echo "API response: $RESPONSE" >&2
    exit 1
fi

# Display the token
log "Access token retrieved:"
echo "$TOKEN"

# Copy the token to the clipboard
echo "$TOKEN" | pbcopy

log "Token copied to clipboard!"
