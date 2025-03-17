# 📘 Remote Action — Get File From Device

This document explains the usage, parameters, and output structure of the `get-file-from-device.sh` Remote Action.  
It describes how the file is uploaded to an Azure Blob Storage using a SAS token, and how to retrieve the uploaded file.

---

## 🎯 Purpose

The goal of this Remote Action is to retrieve a specific file from a device and upload it securely to Azure Blob Storage.  
It replaces the previous approach based on OneDrive with a more secure and scoped method using a SAS upload token.

---

## 🔐 Input Parameters

| Parameter            | Description                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| `sas_upload_token`   | SAS token with write access for the blob container                         |
| `storage_account`    | Azure Storage Account name                                                  |
| `container`          | Name of the blob container                                                  |
| `full_file_path`     | Absolute path of the file to retrieve from the local device                |

---

## 📤 Output Variables

| Output Variable       | Description                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| `file_uploaded`        | Boolean – `1` if the file upload succeeded, `0` otherwise                  |
| `blob_path_file`       | Relative path of the uploaded file in the container: `<hostname>/<full_path>` |

---

## 📂 Blob Storage Upload Path Structure

Files are uploaded to Azure Blob Storage in the following structure:

```
<container>/<hostname>/<full_file_path>
```

- `<hostname>` is the local hostname of the machine where the Remote Action is executed.
- `<full_file_path>` is the full absolute path of the file retrieved from the system, normalized with forward slashes (`/`).

> 📌 Example:  
> If the file is `/private/etc/passwd` on a machine named `bingo`,  
> it will be uploaded to the blob container as:  
> `bingo/private/etc/passwd`

---

## 🔗 Associated Documentation

- [🔗 Azure Blob Storage Configuration Guide](BLOB_STORAGE.md) — Step-by-step instructions to configure the Azure Storage Account and generate SAS tokens.
- [🔗 Tools and Usage Guide](TOOLS.md) — Explanation of `downloadFromBlob.sh` and helper `run.sh`.

---

## 📌 Notes

- For security reasons, it is recommended to use two separate SAS tokens:
  - One SAS token for **upload operations**, with `Write` and `Add` permissions.
  - One SAS token for **download operations**, with `Read` permission only.
- The download SAS token is only required when using the `downloadFromBlob.sh` tool to retrieve files.
- If the container is accessed through the Azure portal or Storage Explorer, the download SAS token is not needed.
- The script auto-downloads `azcopy` if it is not present.
- Path normalization is handled automatically to ensure compatibility across systems (macOS, Windows).
