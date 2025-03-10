# 📘 Remote Action - Usage Guide

## 🧩 Purpose

This document describes how to use the associated utility scripts for the Remote Action `get-file-from-device` to:
- Generate authentication tokens
- Prepare configuration
- Run and test the RA locally

---

## 🖥️ 1. MacOS – Usage

### 🔐 `getToken.sh`
Generates an OAuth2 token for Microsoft Graph API access.

```bash
Usage: ./getToken.sh [-s] --tenantid TENANT_ID --clientid CLIENT_ID --secretid CLIENT_SECRET
```

- ✅ Token is **cached** in a `.cache` directory.
- ✅ A **new token is generated only if the previous one is expired**.
- ✅ The token is automatically copied to the **clipboard**.

### ⚙ `runGetToken.sh`
Helper script that:
- Loads environment configuration from `.envrc`
- Calls `getToken.sh`
- Puts the token in the clipboard

#### Example:
```bash
./runGetToken.sh
```

### 🧪 `run.sh`
Allows you to **run and test the Remote Action locally** using the token and required parameters.

---

## 🪪 Configuration – `.envrc`

Create a `.envrc` file at the root of the project:

```bash
# Token generation
export tenantid="<your-tenant-id>"
export clientid="<your-client-id>"
export secretid="<your-client-secret>"

# Remote Action test
export user_upn="<user@domain.com>"
export target_file="/absolute/path/to/target/file"
```

> `direnv` will auto-load these variables if configured (`direnv allow`).

---

## 🪵 Logs

- Log location (macOS):  
  `/private/var/tmp/NexthinkRA/get-file-from-device.log`

---

## 📥 File Upload Path

Files will be uploaded to the user's OneDrive in the following path:

```
/_NexthinkRA_Bucket_/<hostname>/<absolute_path_to_file>
```

> Example: `/private/etc/passwd` on host `macbook123` →  
`/_NexthinkRA_Bucket_/macbook123/private/etc/passwd`

---

## 🖥️ 2. Windows – Usage

### 🔐 `getToken.ps1`
PowerShell version of the token generator.

- Reads parameters from `env.ps1`
- Caches the token in `.cache`
- Automatically puts token in **clipboard**

### ⚙ `runGetToken.ps1`
Helper to:
- Load configuration
- Call `getToken.ps1`
- Copy the token to clipboard

#### Example:
```powershell
.
unGetToken.ps1
```

---

## 🪪 Configuration – `env.ps1`

Create a PowerShell config file:

```powershell
# Token generation
$tenantid = "<your-tenant-id>"
$clientid = "<your-client-id>"
$secretid = "<your-client-secret>"

# Remote Action test
$user_upn = "<user@domain.com>"
$target_file = "C:\absolute\path\to\file"
```

---

## 📂 Notes

- The RA script will automatically **download `jq`** on MacOS if missing, into:
  ```
  /Users/Shared/.Scripts/bin
  ```

- The token must be passed as parameter to the RA.
