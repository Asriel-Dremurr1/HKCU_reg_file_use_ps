<#
.SYNOPSIS
  Apply a .reg file to the HKCU hive of a specified user (run as Administrator).

.PARAMETER RegFile
  **Path to the .reg file to be applied and transformed.**
  This file will be read, its HKCU/HKEY_CURRENT_USER paths replaced with the
  target user's HKEY_USERS\<SID>, and then imported.

.PARAMETER TargetUser
  (Optional) Name of the target user. Format: "DOMAIN\User" or "User".
  If omitted, the script attempts to detect the interactive user via explorer.exe.

.EXAMPLE
  .\Apply-RegToUser.ps1 -RegFile "C:\tmp\ready_policy.reg" -TargetUser "ivan"
  .\Apply-RegToUser.ps1 -RegFile "C:\tmp\ready_policy.reg"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$RegFile,   # <--- CLEARLY IDENTIFIED FILE NAME TO MODIFY

    [Parameter(Mandatory = $false)]
    [string]$TargetUser
)

function Throw-IfNotAdmin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] `
               [Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

    if (-not $isAdmin) {
        Write-Error "This script must be run with administrative privileges."
        exit 1
    }
}

function Get-InteractiveUser {
    try {
        $expl = Get-Process -Name explorer -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($expl) {
            $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$($expl.Id)"
            $owner = $proc | Invoke-CimMethod -MethodName GetOwner
            if ($owner.User) {
                if ($owner.Domain) { return "$($owner.Domain)\$($owner.User)" }
                return $owner.User
            }
        }
    } catch {}

    return $env:USERNAME
}

function Get-SIDFromName([string]$name) {
    try {
        if ($name -match "\\") {
            $nt = New-Object System.Security.Principal.NTAccount($name)
        } else {
            $nt = New-Object System.Security.Principal.NTAccount("$env:COMPUTERNAME\$name")
        }

        return $nt.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        throw "Failed to resolve SID for user '$name'. Check the username."
    }
}

function Get-ProfilePathBySID([string]$sid) {
    try {
        $profile = Get-CimInstance Win32_UserProfile -Filter "SID = '$sid'" -ErrorAction SilentlyContinue
        if ($profile -and $profile.LocalPath) { return $profile.LocalPath }
    } catch {}

    $userName = (New-Object System.Security.Principal.SecurityIdentifier($sid)) `
                .Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]

    return Join-Path -Path $env:SystemDrive -ChildPath "Users\$userName"
}

# --- main ---
Throw-IfNotAdmin

if (-not (Test-Path -Path $RegFile -PathType Leaf)) {
    Write-Error ".reg file not found: $RegFile"
    exit 1
}

if (-not $TargetUser) {
    $TargetUser = Get-InteractiveUser
    Write-Host "TargetUser not provided. Using detected interactive user: $TargetUser"
}

try {
    $sid = Get-SIDFromName -name $TargetUser
    Write-Host "Target user SID: $sid"
} catch {
    Write-Error $_.Exception.Message
    exit 1
}

$profilePath = Get-ProfilePathBySID -sid $sid
$ntUserDat = Join-Path $profilePath "NTUSER.DAT"

if (-not (Test-Path $ntUserDat -PathType Leaf)) {
    Write-Error "NTUSER.DAT not found at: $ntUserDat"
    Write-Host "Verify that profile exists. It might be remote or have a different path."
    exit 1
}

$regPath = "Registry::HKEY_USERS\$sid"
$weLoadedHive = $false

if (-not (Test-Path $regPath)) {
    Write-Host "Hive not loaded — attempting load from: $ntUserDat"
    $args = "load","HKU\$sid","`"$ntUserDat`""
    $p = Start-Process reg.exe -ArgumentList $args -NoNewWindow -Wait -PassThru

    if ($p.ExitCode -ne 0) {
        Write-Error "reg.exe load failed. Exit code $($p.ExitCode)"
        exit 1
    }

    $weLoadedHive = $true
    Write-Host "Hive loaded as HKEY_USERS\$sid"
} else {
    Write-Host "Hive already loaded: HKEY_USERS\$sid"
}

# Create converted .reg with HKCU replaced by HKU\<SID>
try {
    $content = Get-Content -Raw -LiteralPath $RegFile

    $content = $content -replace "(?i)\[HKEY_CURRENT_USER", "[HKEY_USERS\$sid"
    $content = $content -replace "(?i)\[HKCU", "[HKEY_USERS\$sid"

    $tmpReg = Join-Path $env:TEMP ("converted_{0}.reg" -f ($sid -replace '[\\/:*?"<>|]','_'))
    $content | Out-File -FilePath $tmpReg -Encoding Unicode -Force

    Write-Host "Temporary .reg created: $tmpReg"
} catch {
    Write-Error "Error creating temporary .reg: $_"
    if ($weLoadedHive) { Start-Process reg.exe -ArgumentList "unload","HKU\$sid" -Wait }
    exit 1
}

# Import
try {
    Write-Host "Importing .reg into HKEY_USERS\$sid ..."
    $p = Start-Process reg.exe -ArgumentList "import","`"$tmpReg`"" -NoNewWindow -Wait -PassThru
    if ($p.ExitCode -ne 0) {
        Write-Error "reg.exe import failed. Exit code $($p.ExitCode)"
        throw "Import failed"
    }
    Write-Host "Import completed successfully."
} catch {
    Write-Error "Failed to import .reg: $_"
    if ($weLoadedHive) {
        Write-Host "Unloading hive..."
        Start-Process reg.exe -ArgumentList "unload","HKU\$sid" -Wait
    }
    exit 1
}

if ($weLoadedHive) {
    Write-Host "Unloading hive HKEY_USERS\$sid ..."
    Start-Process reg.exe -ArgumentList "unload","HKU\$sid" -NoNewWindow -Wait
    Write-Host "Hive unloaded."
} else {
    Write-Host "Hive was not loaded by this script — nothing to unload."
}

Write-Host "Done. Check the registry of user $TargetUser (SID: $sid)."
