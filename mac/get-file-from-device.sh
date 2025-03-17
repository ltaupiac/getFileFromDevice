#!/usr/bin/env zsh
# shell check disable=SC1071

set -o nounset   # exit if an undefined var is used
set -o pipefail  # fail the entire command if any part of the pipe fails

: << SCRIPT_HEADER
SYNOPSIS
Get a file from a device

DESCRIPTION
This Remote Action allows secure retreiving of a file from a device and uploads it 
to an Azure Blob Storage container using a write only SAS token.

The uploaded file will be stored in the following path within the container:
  /{hostname}/{full_file_path}

The SAS token upload must be generated outside the Remote Action and provided as a parameter. 
It grants write-only, time-limited access to the target container.

The uploaded file can be download with downloadFromBlob.sh script or from Storage Browser 
on https://portal.azure.com

This script ensures:
- Secure upload using `azcopy`
- Dynamic verification of SAS token validity and expiration
- Preservation of the original file path and hostname as part of blob path
- Return of the blob path for download purposes

PREREQUISITES
- Azure Blob storage
- SAS Upload Token with following permissions: write-only,create blob objects

FUNCTIONALITY
Data collection

INPUTS
Name                                Description
------------------------------------------------------------------------------------------------------------------------
sas_upload_token                    SAS token for uploading
storage_account                     Azure storage account name
container                           Azure blob container name
full_file_path                      Absolute file path for the target file to upload

OUTPUTS
Name                                Type               Description
------------------------------------------------------------------------------------------------------------------------
file_uploaded                       boolean True if file was found and uploaded
blob_path_file                      string  Path of file in container

NOTES
Context:            root
Version:            2.0.0.0 - Blob storage usage 
Version:            1.0.0.1 - Add Hostname and full path for uploaded file
Version:            1.0.0.0 - Initial release
Last Modified:      2025/03/14  09:35:54
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
    echo "Params required sas_upload_token storage_account container full_file_path"
    exit 1
fi
sas_upload_token="$1"
storage_account="$2"
container="$3"
full_file_path="$4"
# NXT_PARAMETERS_END

# NXT_OUTPUTS_BEGIN
declare file_uploaded=0
declare blob_path_file="-"
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
readonly ABSOLUTE_FILE_PATH_REGEX='^[\/\\]([^\/\\]+[\/\\])*[^\/\\]+$'
readonly JWT_REGEX='^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
readonly BOOLEAN_REGEX='^(0|1|[Tt][Rr][Uu][Ee]|[Ff][Aa][Ll][Ss][Ee])$'
readonly ONEDRIVE_URL='https://graph.microsoft.com/v1.0/users/${user_upn}/drive/root:${targetFile}:/content'
readonly PARAM_EMPTY_VALUE='-'

readonly JQ_ARM='https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-macos-arm64'
readonly JQ_AMD='https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-macos-amd64'

readonly AZCOPY_ARM='https://aka.ms/downloadazcopy-v10-mac-arm64'
readonly AZCOPY_X86='https://aka.ms/downloadazcopy-v10-mac'

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
    ensure_azcopy
        
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
        chmod 755 "$BINPATH" || { nxt_write_output_error "Can't change rights on folder $BINPATH"; }
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
        arm64|aarch64) url="$JQ_ARM" ;;
        x86_64)        url="$JQ_AMD" ;;
        *) exit_with_error "Unsupported arch: $arch" ;;
    esac

    # Download jq
    log  "Downloading jq from $url..."
    curl -sSL --proxy1.0 $PROXY "$url" -o "$jq_path" || nxt_write_output_error "jq download failed" 
    chmod 755 "$jq_path" || nxt_write_output_error "can't make jq executable."
    log "jq installed to $jq_path"
    return 0
}

function ensure_azcopy {
    if [[ ! -d "$BINPATH" ]]; then
        mkdir -p "$BINPATH" || { nxt_write_output_error "Can't create folder $BINPATH"; }
        chmod 755 "$BINPATH" || { nxt_write_output_error "Can't change rights on folder $BINPATH"; }
    fi

    if  [[ -x "$BINPATH/azcopy" ]]; then 
        return 0; 
    fi

    local arch url zipfile tmpdir
    arch=$(uname -m)
    tmpdir=$(mktemp -d)
    case "$arch" in
        arm64|aarch64) url="$AZCOPY_ARM" ;;
        x86_64)        url="$AZCOPY_X86" ;;
        *) exit_with_error "Unsupported arch: $arch" ;;
    esac

    log "Downloading azcopy from $url"
    curl -sSL --proxy1.0 "$PROXY" -o "$tmpdir/azcopy.zip" "$url" || exit_with_error "Azcopy download failed"
    unzip -q "$tmpdir/azcopy.zip" -d "$tmpdir" || exit_with_error "Unzip failed"
    local azcopy_bin
    azcopy_bin=$(find "$tmpdir" -type f -name azcopy -perm +111)
    if [[ -z "$azcopy_bin" || ! -x "$azcopy_bin" ]]; then
        exit_with_error "Cannot locate azcopy binary after extraction"
    fi
    cp "$azcopy_bin" "$BINPATH/azcopy" || exit_with_error "Cannot install azcopy"
    chmod 755 "$BINPATH/azcopy" || nxt_write_output_error "can't make az_copy executable."
    log "azcopy installed to $BINPATH/azcopy"
}

function test_input_parameters {
    log "start"
    log "sas_upload_token=[${sas_upload_token:0:30}...]"
    log "storage_account=[$storage_account]"
    log "container=[$container]"
    log "full_file_path=[$full_file_path]"

    test_sas_upload_token "$sas_upload_token"

    if [[ ! "$storage_account" =~ ^[a-z0-9]{3,24}$ ]]; then
        exit_with_error "$INPUT_ERROR: Invalid storage account name [$storage_account]"
    fi

    if [[ ! "$container" =~ ^[a-z0-9\-]{3,63}$ ]]; then
        exit_with_error "$INPUT_ERROR: Invalid container name [$container]"
    fi

    test_absolute_file_path "$full_file_path"
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

# Validate format and validity of a SAS upload token
function test_sas_upload_token {
    local token="$1"
    log "start"

    # Check required SAS token keys
    for key in se st; do
        if [[ "$token" != *"$key="* ]]; then
            exit_with_error "$INPUT_ERROR: SAS token is missing required key '$key='"
        fi
    done

    # Extract start and expiry dates
    local st_param se_param
    st_param=$(echo "$token" | grep -o 'st=[^&]*' | cut -d= -f2)
    se_param=$(echo "$token" | grep -o 'se=[^&]*' | cut -d= -f2)

    if [[ -z "$st_param" || -z "$se_param" ]]; then
        exit_with_error "$INPUT_ERROR: SAS token is missing 'st' or 'se' date."
    fi

    # Convert to epoch
    local st_epoch se_epoch now_epoch
    st_epoch=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$st_param" "+%s" 2>/dev/null)
    se_epoch=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$se_param" "+%s" 2>/dev/null)
    now_epoch=$(date "+%s")

    if [[ -z "$st_epoch" || -z "$se_epoch" ]]; then
        exit_with_error "$INPUT_ERROR: Invalid date format in SAS token."
    fi

    if (( now_epoch < st_epoch )); then
        exit_with_error "$INPUT_ERROR: SAS token is not yet valid (start date in future)."
    fi

    if (( now_epoch > se_epoch )); then
        exit_with_error "$INPUT_ERROR: SAS token has expired."
    fi

    log "end"
}

function upload_file {
    log "start"
    local machine_name target_blob_url result_file="$DATA_DIR/azcopy_result.json"

    machine_name=$(hostname -s)
    [[ -z "$machine_name" ]] && exit_with_error "$UPLOAD_ERROR" "Can't get local hostname"

    blob_path_file="${machine_name}${full_file_path}"
    target_blob_url="https://${storage_account}.blob.core.windows.net/${container}/${blob_path_file}?${sas_upload_token}"

    log "Uploading to: $target_blob_url"

    azparams=(--overwrite=true --check-length=false --skip-version-check --from-to=LocalBlob)
    azparams+=(--output-level=essential --log-level=none --output-type json)
    
    res=$("$BINPATH/azcopy" copy "$full_file_path" "$target_blob_url" "${azparams[@]}" ) 2>/dev/null

    local job_status
    job_status=$(echo $res | jq -r 'select(.MessageType == "EndOfJob") | .MessageContent | fromjson | .JobStatus')

    if [[ "$job_status" == "Completed" ]]; then
        local bytes
        bytes=$(echo $res | jq -r 'select(.MessageType == "EndOfJob") | .MessageContent | fromjson | .TotalBytesTransferred' )
        file_uploaded=$([[ "$bytes" -gt 0 ]] && echo 1 || echo 0)
        log "status=[$job_status], bytes=[$bytes]"
    else
        local upload_error_reason
        upload_error_reason=$(echo $res | jq -r 'select(.MessageType == "EndOfJob") | .MessageContent | fromjson | .FailedTransfers[0].ErrorCode // "unknown-error"')
        exit_with_error "$UPLOAD_ERROR" "azcopy upload failed: $upload_error_reason"
    fi

    log "end"
}

function update_output_variables {
    log "start"
    nxt_write_output_bool 'file_uploaded' "$file_uploaded"
    nxt_write_output_string 'blob_path_file' "$blob_path_file"
    log "end"
}

main >&2; exit $?
