# 📘 Remote Action - Usage Guide

## 🧩 Purpose

This document describes how to use the associated utility scripts for the Remote Action `get-file-from-device` to:
- Prepare configuration
- Download file from blob
- Run and test the RA locally (mac only)

---

## 🖥️ 1. MacOS – Usage

### 🧪 `run.sh`
Allows you to **run and test the Remote Action locally** using the token and required parameters.

---

### 📤 `downloadFromBlob.sh`
This script allows downloading a file from Azure Storage Blob using a read-only SAS token.

```bash
Usage: ./downloadFromBlob.sh <blob_path_file> [output_path] [-f]
```

- `<blob_path_file>`: Required path returned by the Remote Action, e.g., `M12345/etc/hosts`
- `[output_path]`: Optional local file or directory path. If not provided, the filename from the blob will be used.
- `-f`: Force overwrite if the target file already exists.

Example:
```bash
./downloadFromBlob.sh M12345/etc/hosts ./output/ -f
```

## 🪪 Configuration – `.envrc`

Create a `.envrc` file at the root of the project:

```bash
export sas_upload_token="<upload SAS token>"
export sas_download_token="<download SAS token>"
export storage_account="<storage account name>"
export container="<container name>"
export target_file="<absolute path of test file used by run.sh>"
```

> `direnv` will auto-load these variables if configured (`direnv allow`).

---

## 🪵 Logs

- Log location (macOS):  
  `/private/var/tmp/NexthinkRA/get-file-from-device.log`

---

## 📥 File Upload Path

Files will be uploaded to the specidied container in the following path:

```
/<hostname>/<absolute_path_to_file>
```

> Example: `/private/etc/passwd` on host `macbook123` →  
`/macbook123/private/etc/passwd`

---

## 🖥️ 2. Windows – Usage

### 📤 `downloadFromBlob.ps1`
PowerShell version of the download script for Azure Storage Blob.

- Usage and parameters will be similar to the MacOS version.

---

## 🪪 Configuration – `env.ps1`

Create a PowerShell config file:

```powershell
$sas_upload_token = "<upload SAS token>"
$sas_download_token = "<download SAS token>"
$storage_account = "<storage account name>"
$container = "<container name>"
```

---

## 📂 Notes

- The RA script will automatically **download `jq` and `azcopy`** on MacOS if missing, into:
  ```
  /Users/Shared/.Scripts/bin
  ```
