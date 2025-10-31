# HKCU_reg_file_use_ps
---

# Apply-RegToUser.ps1

A PowerShell script that allows an administrator to safely apply a **.reg** file to the **HKEY_CURRENT_USER** hive of **another user** on the same system.
The script automatically resolves the user SID, loads the target user’s `NTUSER.DAT` hive if needed, rewrites the registry paths inside the `.reg` file to map `HKCU` → `HKEY_USERS\<SID>`, and imports the modified file.

---

## ✅ Features

* Applies any `.reg` file to **another user’s** HKCU hive
* Automatically detects the interactive user if `-TargetUser` is not provided
* Automatically resolves user SID
* Loads & unloads the user's registry hive when necessary
* Safely rewrites all `HKCU` / `HKEY_CURRENT_USER` paths
* Requires administrative privileges

---

## 🔧 Requirements

* Windows
* PowerShell 5+
* Administrator privileges
* The target user must have a profile on the system (`NTUSER.DAT` available)

---

## 📌 Parameters

### **`-RegFile`** (required)

Path to the `.reg` file that will be transformed and imported.
All `HKCU` paths inside the file will be replaced with `HKEY_USERS\<SID>` of the target user.

### **`-TargetUser`** (optional)

User account to apply the registry file to.
Formats accepted:

* `DOMAIN\User`
* `User`

If omitted, the script attempts to detect the active interactive user by checking the owner of `explorer.exe`.

---

## 🚀 Usage Examples

Apply `ready_policy.reg` to the user **ivan**:

```powershell
.\Apply-RegToUser.ps1 -RegFile "C:\tmp\ready_policy.reg" -TargetUser "ivan"
```

Automatically detect the interactive user and apply the `.reg` file:

```powershell
.\Apply-RegToUser.ps1 -RegFile "C:\tmp\ready_policy.reg"
```

---

## 📝 How It Works

0. Log Off from other Users. Else the registry may apply to another user.
1. Verifies that the script is running as Administrator
2. Resolves the target user’s SID
3. Locates the user's profile directory and `NTUSER.DAT`
4. Loads the user hive into `HKEY_USERS\<SID>` if it’s not already loaded
5. Creates a temporary converted `.reg` file where

   * `HKCU` → `HKEY_USERS\<SID>`
6. Imports the converted file using `reg.exe`
7. Unloads the hive if it was loaded by the script
8. Cleans up temporary files

---

## ⚠️ Notes

* Be careful when applying registry settings to other users—incorrect modifications may affect login, UI behavior, or policies.
* If the target user has never logged in, their profile (and NTUSER.DAT) may not exist.
* Log Off from other Users. Else the registry may apply to another user.

---

## ✅ Status

**Stable and ready for administrative automation.**

---
