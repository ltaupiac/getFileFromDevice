#!/usr/bin/env zsh

set -o nounset   # exit if an undefined var is used
set -o pipefail  # fail the entire command if any part of the pipe fails

# init required var
source .envrc

# Check root
[[ $EUID -ne 0 ]] && echo "Must be root." && exit 1

# Check required var
for var in sas_upload_token storage_account container target_file; 
    do [[ -z ${(P)var} ]] && echo "❌ $var is not defined." && exit 1
done

# Set Cache directory
SCRIPT_DIR="${0:A:h}"
FULL_FILE_PATH=$target_file

echo ""
echo get-file-from-device.sh  $FULL_FILE_PATH 
echo ""
$SCRIPT_DIR/get-file-from-device.sh $sas_upload_token $storage_account $container $FULL_FILE_PATH 1
