#!/usr/bin/env zsh

# Download a file from Azure Storage Blob using azcopy.
# Uses the following environment variables:
# - sas_download_token
# - storage_account
# - container
# Argument 1: source blob path (e.g., M71879/Library/Preferences/SystemConfiguration/com.apple.smb.server.plist)
# Argument 2 (optional): local destination (directory or file)
# Option -f: overwrite the destination file if it exists

source .envrc

# Initialization
force=false
red="%F{red}"
green="%F{green}"
rst=" %f"

# Handle -f option
while getopts "f" opt; do
  case $opt in
    f) force=true ;;
    *) print -P "${red}Invalid option${rst}"; exit 1 ;;
  esac
done
shift $((OPTIND-1))

# Check arguments
if [[ $# -lt 1 ]]; then
  print -P "${green}Usage: $0 [-f] <source_blob_path> [<local_dest_path|dir>]$rst"
  exit 1
fi

source_blob_path="$1"
local_dest="$2"

# Check required environment variables
for var in sas_download_token storage_account container; do
  if [[ -z ${(P)var} ]]; then
    print -P "${red}Missing required environment variable: $var$rst"
    exit 1
  fi
done

# Build the full source URL
url="https://${storage_account}.blob.core.windows.net/${container}/${source_blob_path}?${sas_download_token}"

# If no destination is specified, use the filename from the blob path
if [[ -z "$local_dest" ]]; then
  local_dest="$(basename "$source_blob_path")"
fi

# If the destination is a directory, append the filename to it
if [[ -d "$local_dest" ]]; then
  local_dest="$local_dest/$(basename "$source_blob_path")"
fi

# Check if the destination file exists
if [[ -f "$local_dest" && "$force" != true ]]; then
  print -P "${red}Target file '$local_dest' already exists. Use -f to overwrite.$rst"
  exit 1
elif [[ -f "$local_dest" && "$force" == true ]]; then
  echo "⚠️  Existing file '$local_dest' will be overwritten."
fi

# Download
azparams=(--overwrite=true --check-length=false --skip-version-check --log-level=none --output-type json)

echo "⬇️  Downloading from: $url"
if ! json=$(azcopy copy "$url" "$local_dest" $azparams 2>&1); then
  print -P "${red}AzCopy failed:$rst"
  echo "$json" 
  exit 1
fi

# Integrity check
transferred_bytes=$(echo "$json" | jq -r 'select(.MessageType=="EndOfJob") | .MessageContent | fromjson | .TotalBytesTransferred')
files_completed=$(echo "$json" | jq -r 'select(.MessageType=="EndOfJob") | .MessageContent | fromjson | .TransfersCompleted')

# Actual size of the local file
if [[ -f "$local_dest" ]]; then
  file_size=$(stat -f "%z" "$local_dest")
else
  file_size=0
fi

echo "➡️  Destination size:    $file_size bytes"
echo "➡️  Transferred bytes:   $transferred_bytes"
echo "➡️  Files completed:     $files_completed"

if [[ $files_completed -eq 1 && $transferred_bytes -eq $file_size ]]; then
  print -P "${green}Download to '$local_dest' completed successfully.$rst"
  exit 0
else
  print -P "${red}Download verification failed.$rst"
  exit 1
fi
