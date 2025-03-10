#!/usr/bin/env zsh

set -o nounset   # exit if an undefined var is used
set -o pipefail  # fail the entire command if any part of the pipe fails

source .envrc

# Set directory cache
SCRIPT_DIR="${0:A:h}"
CACHE_DIR="$SCRIPT_DIR/.cache"
TOKEN_FILE="$CACHE_DIR/gffd_token"
EXP_FILE="$CACHE_DIR/gffd_token_exp"

# Create directory cache if required
mkdir -p "$CACHE_DIR"

# get and store a new token
get_new_token() {
  echo "🔄 Génération d’un nouveau token..."
  GFFD_TOKEN=$($SCRIPT_DIR/getToken.sh -s --tenantid $tenantid --clientid $clientid --secretid $secretid) 

  # Extract payload from the token
  IFS='.' read -r _ PAYLOAD _ <<< "$GFFD_TOKEN"

  # Add padding to avoid base64 decode error
  PAYLOAD="${PAYLOAD}=="

  # decode and get expiration date
  GFFD_TOKEN_EXP=$(echo "$PAYLOAD" | tr '_-' '/+' | base64 -d | jq -r '.exp')

  # store token and expiration date in cache
  echo "$GFFD_TOKEN" > "$TOKEN_FILE"
  echo "$GFFD_TOKEN_EXP" > "$EXP_FILE"

  export GFFD_TOKEN
  export GFFD_TOKEN_EXP
}

# Recover token from cache if possible
if [[ -f "$TOKEN_FILE" && -f "$EXP_FILE" ]]; then
  GFFD_TOKEN=$(cat "$TOKEN_FILE")
  GFFD_TOKEN_EXP=$(cat "$EXP_FILE")
fi

# check token validity
NOW=$(date +%s)
if [[ -z "$GFFD_TOKEN" || -z "$GFFD_TOKEN_EXP" || $NOW -ge $GFFD_TOKEN_EXP ]]; then
  get_new_token
else
  echo "✅ Using cache token."
fi
token=$GFFD_TOKEN
echo "Token copied to clipboard"
echo $token | pbcopy

