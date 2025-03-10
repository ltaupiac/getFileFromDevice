#!/usr/bin/env zsh
# shell check disable=SC1071

set -o nounset   # exit if an undefined var is used
set -o pipefail  # fail the entire command if any part of the pipe fails

: << SCRIPT_HEADER
SYNOPSIS
Get a file from a device
DESCRIPTION
Allows to recover a file then a device. The file can then be downloaded from the URL returned by the RA 
It will also be available in the user's onedrive indicated in the RA parameters
For security reasons, the token must be generated outside the RA and provided in parameter
when using the RA
The getToken.sh script allows the generation of token

PREREQUISITES
- An application with API Permissions: Files.ReadWrite.All
- Directorty (Tenant) ID
- Application (client) ID
- Secret ID
- UPN (email) of OneDrive owner

- The file will be uploaded to the following user_upn's OneDrive path:
/_NexthinkRA_Bucket_/{hostname where RA was run}/{full_file_path}

FUNCTIONALITY
Data collection

INPUTS
Name                                Description
------------------------------------------------------------------------------------------------------------------------
tenantid                            Directorty (Tenant) ID
token                               token got from the tenant with client_id/secret_id
user_upn                            OneDrive UPN owner (email)
full_file_path                      The complete file path for the recovery target
return_url                          Boolean: True if the RA should return an URL to download the file

OUTPUTS
Name                                Type               Description
------------------------------------------------------------------------------------------------------------------------
file_uploaded                      boolean True if file was found and uploaded
file_url                            string  URL for downloading the file

NOTES
Context:            root
Version:            1.0.0.1 - Add Hostname and full path for uploaded file
Version:            1.0.0.0 - Initial release
Last Modified:      2025/03/10  14:18:21
Author              L. Taupiac
SCRIPT_HEADER

# Check if script is ran in command line
if [[ ! -v NEXTHINK ]]
then
    Debug=1
    NEXTHINK="/Library/Application Support/Nexthink"
    # Will override output function in debug with just an echo
    function checkDebug() {
        echo "Debug Mode"
        nxt_write_output_string() { echo $* ;}  
        nxt_write_output_string_list() { echo $* ;}
        nxt_write_output_bool() { echo $* ;}
        nxt_write_output_uint32() { echo $* ;}
        nxt_write_output_float() { echo $* ;}
        nxt_write_output_error() { echo  $* ;}
        nxt_write_output_duration() { echo $* ;}
        nxt_write_output_date_time() { echo $* ;}
        nxt_write_output_size() { echo $* ;}
        nxt_write_output_bitrate() { echo $* ;}
        nxt_write_output_ratio() { echo $* ;}
        nxt_send_output_parameters() { echo -n "" ;}
    }
    # Trace argument
    if [[ $# -gt 0 && ( "$1" == "--trace" || "$1" == "-t" )]]
    then
        traceDebug=1 
        shift
    fi
    for i in {1..$#}; do
        echo "- \$$i: [${argv[i]}]"
    done
else
    checkDebug() { return ;}
    Debug=0
fi

. "${NEXTHINK}"/bash/nxt_ra_script_output.sh
# If in debug mode, override all output function
checkDebug
# If trace has been required
if [[ -v traceDebug ]]
then
    set -x
fi

# NXT_PARAMETERS_BEGIN
if [ $# -eq 0 ];then
    echo "Params required TenantID token userUPN full_file_path file_url"
    exit 1
fi
tenantid="$1"
token="$2"
user_upn="$3"
full_file_path="$4"
return_url="$5"
# NXT_PARAMETERS_END

# NXT_OUTPUTS_BEGIN
declare file_uploaded=0
declare file_url="-"
# NXT_OUTPUTS_END

# USER_CONFIGURABLE_CONSTANTS_BEGIN
readonly APP_NAME=${${0:t}%.sh}                 # Like basename($0) ".sh" without fork any process
readonly DATA_DIR="/private/var/tmp/NexthinkRA" # The location of logs and temporary data
readonly LOG_FILE="$DATA_DIR/$APP_NAME.log"
readonly ONEDRIVE_BUCKET="/_NexthinkRA_Bucket_"
readonly BINPATH='/Users/Shared/.Scripts/bin'
readonly PROXY_HOST="localhost"
readonly PROXY_PORT=9000
readonly PROXY="http://${PROXY_HOST}:${PROXY_PORT}"
# USER_CONFIGURABLE_CONSTANTS_END

# CONSTANTS_DEFINITION_BEGIN
readonly MINIMUM_MACOS_VERSION=(10 15)
readonly ROOT_USER_EUID=0
readonly INPUT_ERROR='[Input error]'
readonly ENVIRONMENT_ERROR='[Environment error]'
readonly UPLOAD_ERROR='[Upload error]'
readonly TENANT_ID_REGEX='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
readonly UPN_REGEX='^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
readonly ABSOLUTE_FILE_PATH_REGEX='^[\/\\]([^\/\\]+[\/\\])*[^\/\\]+$'
readonly JWT_REGEX='^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
readonly BOOLEAN_REGEX='^(0|1|[Tt][Rr][Uu][Ee]|[Ff][Aa][Ll][Ss][Ee])$'
readonly ONEDRIVE_URL='https://graph.microsoft.com/v1.0/users/${user_upn}/drive/root:${targetFile}:/content'
readonly PARAM_EMPTY_VALUE='-'

readonly JQ_ARM='https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-macos-arm64'
readonly JQ_AMD='https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-macos-amd64'

export PATH="$BINPATH:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin"
# CONSTANTS_DEFINITION_END

# 
# Start script
#
function main {
    startLog
    log "start main"
    test_macos_version
    test_running_as_root
    
    check_proxy
    ensure_jq
        
    # Check and filter input parameters
    test_input_parameters
    upload_file
    update_output_variables
    log "end"
}

function check_proxy {
    if ! zmodload zsh/net/tcp 2>/dev/null; then
        exit_with_error "Module zsh/net/tcp indisponible." 
    fi
    
    # Test proxy
    if ! ztcp $PROXY_HOST $PROXY_PORT 2>/dev/null; then
        exit_with_error "Proxy is not running"
    fi
    # Close the connection open by ztcp test
    ztcp -c         
}

function ensure_jq {
    # Create BINPATH if needed
    if [[ ! -d "$BINPATH" ]]; then
        mkdir -p "$BINPATH" || { nxt_write_output_error "Can't create folder $BINPATH"; }
    fi

    local jq_path="$BINPATH/jq"

    # Check if jq is already here
    if [[ -x "$jq_path" ]]; then
        return 0
    fi

    # Check arch
    local arch
    arch=$(uname -m)
    local url=""
    case "$arch" in
        arm64|aarch64)
            url="$JQ_ARM"
            ;;
        x86_64)
            url="$JQ_AMD"
            ;;
        *)
            exit_with_error "arch '$arch' not supported."
            ;;
    esac

    # Download jq
    log  "Download jq from $url..."
    if ! curl -sSL --proxy1.0 $PROXY "$url" -o "$jq_path"; then
        nxt_write_output_error "jq download failed" 
    fi
    chmod +x "$jq_path" || { nxt_write_output_error "can't make jq executable."; }    
    log "jq installed to $jq_path"
    return 0
}

function test_input_parameters {
    log "start"

    # Log input params
    log "tenantid=[$tenantid]"
    log "token=[${token:0:30}...]"
    log "user_upn=[$user_upn]"
    log "full_file_path=[$full_file_path]"
    log "return_url=[$return_url]"

    test_tenant_id "$tenantid"
    validate_jwt_token "$token"
    test_user_upn "$user_upn"
    test_absolute_file_path "$full_file_path"
    test_return_url "$return_url"

    log "end"
}

function exit_with_error {
    # function parameters
    local error_type="$1"
    local error_message="${2:-}"

    local line_number="${LINENO:-unknown}"
    local caller_func=${funcstack[2]}
    local caller_fileline=${funcfiletrace[2]}
    
    # Separate file and line number
    local caller_file=${caller_fileline%%:*}
    local caller_line=${caller_fileline#*:}
    
    # Build the error message
    local msg="${caller_func}[#${caller_line}]: $error_type"
    [[ -n "$error_message" ]] && msg+=" $error_message"
    
    log "$msg"
    nxt_write_output_error "$msg"

    exit 1
}

function createMetaDirectory() {
    if [[ ! -d "$DATA_DIR" ]]; then
        ## Creating Metadirectory
        log "Creating [$DATA_DIR] to store logs and temporary data"
        mkdir -p "$DATA_DIR"
    fi
}

function startLog() {
    createMetaDirectory
    exec > >(tee -a "$LOG_FILE") 2>&1
}

function log() {
    local caller_line caller_func stacksize indent

    # Get the line number and the calling function
    caller_line=${funcfiletrace[1]##*:}   # Extract the call line number
    caller_func=${funcstack[2]:-main}     # Calling function

    stacksize=$(( ${#funcstack[@]} - 2 ))
    f=$(printf "%-30s" "${caller_func}[$caller_line]")

    indent=$( (( stacksize > 0 )) && printf ' >>%.0s' {1..$stacksize} || echo "")

    print -P "%F{green}$(date)%f | $f | $indent %F{cyan}$* %f"
}

function test_macos_version {
    log "start"
    local current_version
    current_version="$(get_macos_version)"

    local major_version minor_version

    if [[ "$current_version" =~ ^([0-9]{2})\.([0-9]{1,2}) ]]; then
        major_version="$match[1]"
        minor_version="$match[2]"

        if (( major_version < MINIMUM_MACOS_VERSION[1] || 
            (major_version == MINIMUM_MACOS_VERSION[1] && minor_version < MINIMUM_MACOS_VERSION[2]) )); then
            exit_with_error "Unsupported macOS version: ${current_version}"
        fi
    else
        exit_with_error "$ENVIRONMENT_ERROR" "The macOS version format is invalid: ${current_version}"
    fi
    log "end"
}

function get_macos_version {
    /usr/bin/sw_vers -productVersion
}

function trim_string_value {
    local value
    value="$1";
    value="${value#"${value%%[![:space:]]*}"}";
    value="${value%"${value##*[![:space:]]}"}";
    echo "$value"
}

function test_running_as_root {
    log "start"
    [[ $(get_current_user_uid) == $ROOT_USER_EUID ]] || exit_with_error "$ENVIRONMENT_ERROR" 'This remote action can only be run as root'
    log "end"
}

function get_current_user_uid {
    echo "$EUID"
}

# Validate the ID tenant format
function test_tenant_id() {
    local tenant_id="$1"
    log "start"

    if [[ ! "$tenant_id" =~ $TENANT_ID_REGEX ]];then
       log "$INPUT_ERROR: Invalid tenant ID [$tenant_id]"     
       exit_with_error "$INPUT_ERROR: Invalid tenant ID [$tenant_id]"     
    fi
    log "end"
    return 0
}

# Validate upn format (email expected)
function test_user_upn() {
    local user_upn="$1"
    log "start"

    if [[ ! $user_upn =~ $UPN_REGEX ]]; then
        log "$INPUT_ERROR: Invalid UPN user [$user_upn]"
        exit_with_error "$INPUT_ERROR: Invalid UPN user [$user_upn]"
    fi
    log "end"
    return 0
}

# Validate path and file existance
function test_absolute_file_path() {
    local file_path="$1"
    log "start"

    # Check path format
    if [[ ! $file_path =~ $ABSOLUTE_FILE_PATH_REGEX ]]; then
        log "$INPUT_ERROR: Invalid file path [$full_file_path]"
        exit_with_error "$INPUT_ERROR: Invalid file path [$full_file_path]"
    fi

    # Check file existance
    if [[ ! -r "$file_path" ]]; then
        log "$INPUT_ERROR: file is not readable [$full_file_path]"
        exit_with_error "$INPUT_ERROR: file is not readable [$full_file_path]"
    fi

    log "end"
    return 0
}

# JWT Token validation
function validate_jwt_token() {
    local token="$1"
    log "start"

    # Global format (3 alphanum sections separated by dot)
    if [[ ! $token =~ $JWT_REGEX ]]; then
        log "$INPUT_ERROR: Not valid Token format: [$token]" 
        exit_with_error "$INPUT_ERROR: Not valid token format [A-Za-z0-9_-]"
    fi

    # Reads the 3 sections
    IFS='.' read -r header payload signature <<< "$token"

    # Check if there is 3 sections
    if [[ -z "$header" || -z "$payload" || -z "$signature" ]]; then
        log "Token section is missing"
        log "header: [$header]"
        log "payload: [$payload]"
        log "signature: [$signature]"
        exit_with_error "$INPUT_ERROR: The token should have 3 sections xxx.xxx.xxx"
    fi

    # Padd with == to avoid error on the base64
    header="$header=="
    payload="$payload=="

    local decoded_header decoded_payload
    decoded_header=$(echo "$header" | tr '_-' '/+' | base64 --decode 2>/dev/null)
    decoded_payload=$(echo "$payload" | tr '_-' '/+' | base64 --decode 2>/dev/null)

    # Check JSON
    if ! echo "$decoded_header" | jq empty >/dev/null 2>&1 ; then
        exit_with_error "$INPUT_ERROR: Json header invalide [$decoded_header]"
    fi
    if ! echo "$decoded_payload" | jq empty >/dev/null 2>&1; then
        exit_with_error "$INPUT_ERROR: Json payload invalide [$decoded_payload]"
    fi
    log "end"
    return 0
}

# Boolean check
function test_return_url() {
    local value="$1"
    log "start"

    if [[ ! $value =~ $BOOLEAN_REGEX ]]; then
        log "$INPUT_ERROR: Boolean expected [$return_url]"
        exit_with_error "$INPUT_ERROR: Boolean expected [$return_url]"
    fi
    log "end"
    return 0
}

function upload_file {
    log "start"

    # Get local hostname
    local machine_name
    machine_name=$(hostname -s)
    [[ -z "$machine_name" ]] && exit_with_error "$UPLOAD_ERROR" "Can't get localhostname."

    local targetFile="$ONEDRIVE_BUCKET/$machine_name$full_file_path"
    local url=${(e)ONEDRIVE_URL}
    local authent="Authorization: Bearer $token"
    local header="Content-Type: text/plain"

    res=$(curl --location -s -o - -w '%{http_code}' -X PUT $url -H "$authent" --header "$header" --data-binary @"$full_file_path")  

    http_code="${res:(-3)}"  # Get HTTP code
    json_response="${res:0:(-3)}"  # Get JSON

    error_message=$(echo "$json_response" | jq -r '.error.message // empty')
    file_uploaded=$([[ "$http_code" == "200" || "$http_code" == "201" ]] && [[ -z "$error_message" ]] && echo 1 || echo 0)
    
    log "http_code=[$http_code]"
    log "json_response=[$json_response]"

    if [[ $file_uploaded -eq 0 ]];then 
        exit_with_error "$UPLOAD_ERROR: $error_message"
    fi
    
    if [[ $return_url -eq 1 ]]; then
        file_url=$(echo $json_response | jq -r '."@microsoft.graph.downloadUrl"')
        log "FileUrl=[$file_url]"
    fi
        
    log "end"
}
# COMMON_FUNCTIONS_END

function update_output_variables {
    log "start"
    nxt_write_output_bool 'file_uploaded' "$file_uploaded"
    nxt_write_output_string 'file_url' "$file_url"
    log "end"
}

main >&2; exit $?
