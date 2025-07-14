# AppLocker requires admin privileges to run, so this checks to makes sure the script is run with admin privileges
If (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run with Administrator privileges. Please re-run."
    Break
}
# Do initial checks

# Checks if the current user is admin
function isAdmin {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($user)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # write-host "Current user: $($user.Name)"
    # write-host "Is Admin: $isAdmin"

    return $isAdmin
}

function isChromeInstalled {
    $chromeInstalled = $false

    # Checks program files for machine-wide installations
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" # For 32-bit Chrome on 64-bit OS
    )

    foreach ($path in $uninstallPaths) {
        try {
            $chrome = Get-ItemProperty -Path $path | Where-Object { $_.DisplayName -like "Google Chrome*" }
            if ($chrome) {
                $chromeInstalled = $true
                break
            }
        }
        catch {
            # Ignore errors
        }
    }

    # Looks for user-specific installations
    if (-not $chromeInstalled) {
        $userUninstallPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        try {
            $chrome = Get-ItemProperty -Path $userUninstallPath | Where-Object { $_.DisplayName -like "Google Chrome*" }
            if ($chrome) {
                $chromeInstalled = $true
            }
        }
        catch {
            # Ignore errors
        }
    }

    if (-not $chromeInstalled) {
Host "Google Chrome is not installed."
    }

    return $chromeInstalled
}

# Check to make sure the script is being run from a non-admin account and that Chrome is installed
$admin = isAdmin
$chromeInstalled = isChromeInstalled

# if (-not $admin -and $chromeInstalled) {
#     write-host "Initial check success. Proceeding."
# }
# else {
#     write-host "This script must be run from a non-admin account and Google Chrome must be installed."
#     write-host "Please switch to a non-admin account and ensure Google Chrome is installed before running this script."
#     exit
# }

# Write a few lines of text on the screen explaining briefly what the
# script does and double check with the user (have them enter the exact string "I AGREE" or st) before proceeding.

write-host "This is a PowerShell script that hardens Windows. Features like Command Prompt, USB Access, and Program Files access will be restricted."
write-host "Please type 'I AGREE' to continue."
$response = read-host
if ($response -ne "I AGREE") {
    write-host "You did not agree to the terms. Exiting script."
    exit
}

# Read inputs:
# A list of email addresses, which will be allowed to be signed into chrome

write-host "Please enter email addresses that will be allowed to sign into Chrome. Type 'done' when finished."
$allowedEmails = @()
while ($true) {
    $input = Read-Host -Prompt "Enter an email (type 'done' when finished):"
    if ($input -eq "done") {
        break
    }
    # Validate email format (basic check)
    if ($input -match "^[^@\s]+@[^@\s]+\.[^@\s]+$") {
        $allowedEmails += $input
    } else {
        Write-Warning "Invalid email format. Please try again."
    }
}


# Protect the OS Internals

# Disable access to PowerShell, Command Prompt, Registry Editor


# Disable access to Powershell
# Define output path for the AppLocker policy XML
$policyXmlPath = "$env:TEMP\PowerShell_Disable_AppLocker_Policy.xml"

Write-Host "Creating AppLocker rules to deny PowerShell..."

# Create publisher rules to deny powershell.exe and powershell_ise.exe
$denyPowershellRule = New-AppLockerRule -RuleType Publisher -User Everyone -Action Deny -PublisherName "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" -ProductName "Microsoft® Windows® Operating System" -FileVersion "*" -Filepath "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Description "Deny PowerShell.exe"
$denyPowershellISERule = New-AppLockerRule -RuleType Publisher -User Everyone -Action Deny -PublisherName "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" -ProductName "Microsoft® Windows® Operating System" -FileVersion "*" -Filepath "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe" -Description "Deny PowerShell_ISE.exe"

# Note: These PowerShell rules will be merged into the main AppLocker policy later in Set-AppLockerWhitelist.
# This initial setting is redundant if Set-AppLockerWhitelist always runs and merges all rules.
# For simplicity, I'm removing the immediate application here to rely on the unified AppLocker policy application.
# $appLockerPolicy = New-AppLockerPolicy -Rule $denyPowershellRule, $denyPowershellISERule -Service EnforcementMode -RuleType Exe, Dll
# Set-AppLockerPolicy -PolicyObject $appLockerPolicy -RuleCollectionType Exe -EnforcementMode AuditOnly
# Set-AppLockerPolicy -PolicyObject $appLockerPolicy -RuleCollectionType Dll -EnforcementMode AuditOnly
# write-host "AppLocker policy set to deny PowerShell and PowerShell ISE."

# Enable and Start AppLocker service, required for PowerShell restriction to work
try {
    write-host "Ensuring 'Application Identity' service is running and set to Automatic..."
    Get-Service -Name "AppIDSvc" | Set-Service -StartupType Automatic -PassThru | Start-Service -ErrorAction Stop
}
catch {
    write-error "Failed to start Application Identity service: $($_.Exception.Message)"
    exit
}

# Disable access to the Command Prompt
$regPathCMD = "HKCU:\Software\Policies\Microsoft\Windows\System"

write-host "Blocking Command Prompt..."

try {
    # Ensure the registry path exists
    if (-not (Test-Path $regPathCMD)) {
        New-Item -Path $regPathCMD -Force | Out-Null
    }
    # -Value 0: Enable Command Prompt
    # -Value 1: Command Prompt disabled for scripts
    # -Value 2: Command Prompt disabled for all users
    Set-ItemProperty -Path $regPathCMD -Name "DisableCMD" -Value 2 -Force

    write-host "Command Prompt has been blocked. User needs to log off and log back on for changes to apply."
}
catch {
    write-error "Failed to block Command Prompt. Error: $($_.Exception.Message)"
    write-host "Ensure the script is run with appropriate permissions."
    exit
}

# Disable access to the Registry Editor
$regPathRegedit = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"

write-host "Blocking Registry Editor..."

try {
    if (-not (Test-Path $regPathRegedit)) {
        New-Item -Path $regPathRegedit -Force | Out-Null
    }
    # -Value 0: Registry Editor enabled
    # -Value 1: Registry Editor disabled
    Set-ItemProperty -Path $regPathRegedit -Name "DisableRegistryTools" -Value 1 -Force
    write-host "Registry Editor has been blocked. User needs to log off and log back on for changes to apply."
}
catch {
    write-error "Failed to block Registry Editor. Error: $($_.Exception.Message)"
    write-host "Ensure the script is run with appropriate permissions."
    exit
}

# Disable USB storage access, NICs

# Value 4 prevents USB storage devices from being used
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor" -Name "Start" -Value 4
write-host "USB storage devices have been disabled."

# Pipes all values from Get-NetAdapter to Disable-NetAdapter, -Confirm:$false suppresses confirmation prompts
# On a VM, this will terminate the network connection to the VM
# Get-NetAdapter | Disable-NetAdapter -Confirm:$false
# write-host "Network adapters have been disabled."

# Disable Cortana, Microsoft store

# Create the Windows Search key if it doesn't exist
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'Windows Search' -ErrorAction SilentlyContinue
# Set the AllowCortana DWORD value to 0 to disable Cortana
New-ItemProperty -Path 'HKLM:\SOFTWARE:\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -PropertyType DWORD -Value 0 -Force

write-host "Cortana has been disabled."

# Create the WindowsStore key if it doesn't exist
New-Item -Path 'HKLM:\SOFTWARE:\Policies\Microsoft\WindowsStore' -ErrorAction SilentlyContinue
# Set the RemoveWindowsStore DWORD value to 1 to disable the Store
Set-ItemProperty -Path 'HKLM:\SOFTWARE:\Policies\Microsoft\WindowsStore' -Name 'RemoveWindowsStore' -PropertyType DWORD -Value 1 -Force
write-host "Microsoft Store has been disabled."


# 1. Enable SmartScreen for applications and files (Shell)
Set-MpPreference -SmartScreenForExplorer Enabled
write-host "SmartScreen for applications and files (Shell) has been enabled."

# 2. Configure SmartScreen for Microsoft Edge (Strict Settings via Registry)
write-host "Configuring Microsoft Edge SmartScreen..."
# Create the 'Edge' registry key if it doesn't exist
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -ErrorAction SilentlyContinue | Out-Null

# Enable SmartScreen for Microsoft Edge browser itself
Set-ItemProperty -Path "HKLM:\SOFTWARE:\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -PropertyType DWORD -Value 1 -Force
write-host "Microsoft Edge SmartScreen enabled."

# Prevent bypassing SmartScreen prompts for potentially malicious sites
Set-ItemProperty -Path "HKLM:\SOFTWARE:\Policies\Microsoft\Edge" -Name "SmartScreenBlockMaliciousURLs" -PropertyType DWORD -Value 1 -Force
write-host "Preventing bypass of SmartScreen prompts for malicious sites in Edge."

# Prevent bypassing SmartScreen warnings about unverified (potentially malicious) downloads
Set-ItemProperty -Path "HKLM:\SOFTWARE:\Policies\Microsoft\Edge" -Name "SmartScreenBlockDownloads" -PropertyType DWORD -Value 1 -Force
write-host "Preventing bypass of SmartScreen warnings about downloads in Edge."

write-host "SmartScreen Configuration Complete"

# Enable BitLocker
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XTSAES256 -UsedSpaceOnly -TpmProtector
Write-Host "BitLocker encryption initiated for C: drive with TPM protector. Please wait for the process to complete."
Write-Host "Remember to save your recovery key!"

# Block the ability to install any new apps
# .exe files will be blocked later via AppLocker

# Create the Installer key if it doesn't exist
New-Item -Path 'HKLM:\SOFTWARE:\Policies\Microsoft\Windows\Installer' -ErrorAction SilentlyContinue | Out-Null

# Set DisableMSI DWORD value to 2 to block all MSI installations
Set-ItemProperty -Path 'HKLM:\SOFTWARE:\Policies\Microsoft\Windows\Installer' -Name 'DisableMSI' -PropertyType DWORD -Value 2 -Force
Write-Host "Blocking all MSI package installations."

# Disable system restore to prevent rollback of changes
Disable-ComputerRestore -Drive "C:\", "D:\"
write-host "System restore has been disabled for C: and D: drives."

# Use NTFS permissions to restrict access to:
#     C:\Windows\System32
#     C:\Program Files
#     C:\Users\<OtherUsers>

function Set-NTFSAccess {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [string]$Identity,
        [Parameter(Mandatory=$true)]
        [System.Security.AccessControl.FileSystemRights]$FileSystemRights,
        [Parameter(Mandatory=$true)]
        [System.Security.AccessControl.AccessControlType]$AccessControlType,
        [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'None',
        [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = 'None',
        [switch]$RemoveExistingIdentityEntry
    )

    Write-Host "Configuring permissions for $Path..."

    try {
        $acl = Get-Acl $Path

        if ($RemoveExistingIdentityEntry) {
            $existingRules = $acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) | Where-Object {$_.IdentityReference.Value -eq (New-Object System.Security.Principal.NTAccount $Identity).Translate([System.Security.Principal.SecurityIdentifier]).Value}

            if ($existingRules) {
                foreach ($rule in $existingRules) {
                    $acl.RemoveAccessRule($rule)
                    Write-Host "  - Removed existing rule for '$Identity' on '$Path'."
                }
            }
        }

        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $Identity,
            $FileSystemRights,
            $InheritanceFlags,
            $PropagationFlags,
            $AccessControlType
        )

        $acl.AddAccessRule($rule)
        Set-Acl -Path $Path -AclObject $acl
        Write-Host "  - Successfully set '$AccessControlType' '$FileSystemRights' for '$Identity' on '$Path'."
    }
    catch {
        Write-Error "Failed to set permissions on $Path. Error: $($_.Exception.Message)"
        Write-Host "This could be due to insufficient permissions or the path not existing."
    }
}

# Restrict C:\Windows\System32
Write-Host "Restricting C:\Windows\System32"
$pathSystem32 = "C:\Windows\System32"
$identityUsers = "BUILTIN\Users"

# Deny Write, Delete, Change Permissions, Take Ownership to Users group
Set-NTFSAccess -Path $pathSystem32 -Identity $identityUsers -FileSystemRights Write, Delete, ChangePermissions, TakeOwnership -AccessControlType Deny -InheritanceFlags ContainerInherit, ObjectInherit -PropagationFlags None -RemoveExistingIdentityEntry
Write-Host "Users group restricted from writing/modifying in $pathSystem32."

Write-Host "Restricting C:\Program Files"
$pathProgramFiles = "C:\Program Files"

# Deny Write, Delete, Change Permissions, Take Ownership to Users group
Set-NTFSAccess -Path $pathProgramFiles -Identity $identityUsers -FileSystemRights Write, Delete, ChangePermissions, TakeOwnership -AccessControlType Deny -InheritanceFlags ContainerInherit, ObjectInherit -PropagationFlags None -RemoveExistingIdentityEntry
Write-Host "Users group restricted from writing/modifying in $pathProgramFiles."

Write-Host "Restricting C:\Users\<OtherUsers> Profiles"

# Get all local user accounts

$allLocalUsers = Get-LocalUser

# Get the SID of the current user running the script, to avoid locking them out of their own profile
$currentUserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# Define accounts to explicitly exclude from profile restriction
$excludedUsernames = @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount", "HomeGroupUser$")

# Filter out built-in accounts and the current user's account
$usersToRestrict = $allLocalUsers | Where-Object {
    $_.SID -ne $currentUserSID -and # Not the current user
    $_.Enabled -eq $true -and       # Only active accounts
    -not ($excludedUsernames -contains $_.Name) -and # Not in the excluded list
    (Test-Path "C:\Users\$($_.Name)") # Ensure the profile folder actually exists
}

if ($usersToRestrict.Count -eq 0) {
    Write-Warning "No other user profiles found to restrict after filtering."
} else {
    Write-Host "Found $($usersToRestrict.Count) user profile(s) to restrict: $($usersToRestrict.Name -join ', ')"
}

foreach ($user in $usersToRestrict) {
    $otherUserPath = "C:\Users\$($user.Name)"
    Write-Host "`nProcessing profile for user: $($user.Name) ($otherUserPath)"

    # Get necessary SIDs for the current user's profile we are restricting
    try {
        $owner = (Get-ACL $otherUserPath).Owner
        $systemSid = (New-Object System.Security.Principal.NTAccount "SYSTEM").Translate([System.Security.Principal.SecurityIdentifier])
        $administratorsSid = (New-Object System.Security.Principal.NTAccount "BUILTIN\Administrators").Translate([System.Security.Principal.SecurityIdentifier])
        $authenticatedUsersSid = (New-Object System.Security.Principal.NTAccount "Authenticated Users").Translate([System.Security.Principal.SecurityIdentifier])
    }
    catch {
        Write-Error "Failed to get SIDs for $($user.Name). Ensure the user exists and the path is accessible. Error: $($_.Exception.Message)"
        continue
    }

    # Remove ALL inherited permissions on the target user's profile folder
    try {
        $acl = Get-Acl $otherUserPath
        $acl.SetAccessRuleProtection($true, $false) # Disable inheritance and copy existing inherited rules as explicit
        Set-Acl -Path $otherUserPath -AclObject $acl
        Write-Host "  - Disabled inheritance from '$otherUserPath' and copied existing rules."

        # Remove "Authenticated Users" if it was copied and now exists as an explicit rule
        $acl = Get-Acl $otherUserPath
        $existingAuthUsersRule = $acl.Access | Where-Object {$_.IdentityReference.Value -eq $authenticatedUsersSid.Value}
        if ($existingAuthUsersRule) {
            $acl.RemoveAccessRule($existingAuthUsersRule)
            Set-Acl -Path $otherUserPath -AclObject $acl
            Write-Host "  - Removed explicit 'Authenticated Users' rule (if present)."
        }
    }
    catch {
        Write-Error "Failed initial ACL cleanup for $otherUserPath. Error: $($_.Exception.Message)"
        continue
    }

    # Grant explicit FullControl to the Owner of the profile
    Set-NTFSAccess -Path $otherUserPath -Identity $owner.Value -FileSystemRights FullControl -AccessControlType Allow -InheritanceFlags ContainerInherit, ObjectInherit -PropagationFlags None -RemoveExistingIdentityEntry

    # Grant explicit FullControl to SYSTEM
    Set-NTFSAccess -Path $otherUserPath -Identity $systemSid.Value -FileSystemRights FullControl -AccessControlType Allow -InheritanceFlags ContainerInherit, ObjectIntrusive -PropagationFlags None -RemoveExistingIdentityEntry

    # Grant explicit FullControl to Administrators (for management/recovery)
    Set-NTFSAccess -Path $otherUserPath -Identity $administratorsSid.Value -FileSystemRights FullControl -AccessControlType Allow -InheritanceFlags ContainerInherit, ObjectInherit -PropagationFlags None -RemoveExistingIdentityEntry

    # Explicitly DENY ListDirectory/ReadData/ReadAttributes for "Users" group for the target profile folder
    Set-NTFSAccess -Path $otherUserPath -Identity "BUILTIN\Users" -FileSystemRights ReadData, ListDirectory, ReadAttributes -AccessControlType Deny -InheritanceFlags None -PropagationFlags None -RemoveExistingIdentityEntry

    Write-Host "Access to '$otherUserPath' successfully restricted for other standard users."
}

# Create a whitelist-only environment for apps, allow only specific apps.
function Set-AppLockerWhitelist {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$false)]
        # define paths for apps to be whitelisted
        [string[]]$AllowedExecutablePaths = @(),

        [Parameter(Mandatory=$false)]
        [string[]]$AllowedChromePaths = @(
            "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe",
            "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
        ),

        [Parameter(Mandatory=$false)]
        [switch]$AuditOnlyMode = $false 
    )

    Write-Host "Starting AppLocker Whitelist Configuration..." -ForegroundColor Green

    # Enable the Application Identity Service
    Write-Host "1. Ensuring 'Application Identity' service is running and set to Automatic..."
    try {
        Set-Service -Name "AppIDSvc" -StartupType Automatic -ErrorAction Stop
        Start-Service -Name "AppIDSvc" -ErrorAction Stop
        Write-Host "   'Application Identity' service configured and started successfully." -ForegroundColor Green
    }
    catch {
        Write-Warning "   Failed to configure or start 'Application Identity' service: $($_.Exception.Message). AppLocker may not function correctly."
        return
    }

    # Get the current AppLocker policy or create a new empty one
    Write-Host "2. Retrieving current AppLocker policy or creating an empty one..."
    try {
        $AppLockerPolicy = Get-AppLockerPolicy -Local -ErrorAction SilentlyContinue
        if (-not $AppLockerPolicy) {
            # Create an empty policy if no local policy exists
            $AppLockerPolicy = New-Object -TypeName Microsoft.Security.ApplicationId.PolicyManagement.AppLockerPolicy
            Write-Host "   No existing local AppLocker policy found. Creating a new empty policy." -ForegroundColor Yellow
        } else {
            Write-Host "   Existing local AppLocker policy retrieved." -ForegroundColor Green
        }
    }
    catch {
        Write-Error "   Failed to retrieve or create AppLocker policy: $($_.Exception.Message)"
        return
    }

    # Create Default Rules (Crucial for system stability)
    # These rules allow Windows and Program Files executables, installers, and scripts.
    Write-Host "3. Creating AppLocker default rules for system stability..."
    try {
        $DefaultRules = New-AppLockerPolicy -AllowWindows -RuleType Executable, Script, Msi, AppX -ErrorAction Stop
        # Merge default rules into the existing policy
        $AppLockerPolicy = $AppLockerPolicy | Merge-AppLockerPolicy -Policy $DefaultRules -ErrorAction Stop
        Write-Host "   Default AppLocker rules created and merged." -ForegroundColor Green
    }
    catch {
        Write-Warning "   Failed to create or merge default AppLocker rules: $($_.Exception.Message). This may cause system instability if not handled manually."
    }

    Write-Host "Adding AppLocker rules to deny executables, scripts, and installers from Downloads, AppData, and Desktop..."
    $DenyRules = @()

    # Paths to restrict
    $UserWritableFolders = @(
        "$env:UserProfile\Downloads",
        "$env:LocalAppData",
        "$env:AppData",
        "$env:UserProfile\Desktop"
    )

    # Deny EXEs from user-writable locations
    foreach ($folder in $UserWritableFolders) {
        $path = Join-Path $folder "*.exe"
        # For AppData, use ** to cover subdirectories
        if ($folder -like "*AppData*") { $path = Join-Path $folder "**\*.exe" }
        try {
            $DenyRules += New-AppLockerRule -RuleType Path -User Everyone -Action Deny -Path $path -Description "Deny EXE from $folder" -ErrorAction Stop
            Write-Host "   Deny rule for EXE '$path' created." -ForegroundColor Cyan
        } catch { Write-Warning "   Failed to create deny rule for EXE path '$path': $($_.Exception.Message)" }
    }

    $ScriptExtensions = @("*.ps1", "*.bat", "*.cmd", "*.vbs", "*.js")
    foreach ($folder in $UserWritableFolders) {
        foreach ($ext in $ScriptExtensions) {
            $path = Join-Path $folder $ext
            if ($folder -like "*AppData*") { $path = Join-Path $folder "**\$ext" }
            try {
                $DenyRules += New-AppLockerRule -RuleType Path -User Everyone -Action Deny -Path $path -Description "Deny $ext from $folder" -ErrorAction Stop
                Write-Host "   Deny rule for Script '$path' created." -ForegroundColor Cyan
            } catch { Write-Warning "   Failed to create deny rule for Script path '$path': $($_.Exception.Message)" }
        }
    }

    $MsiExtensions = @("*.msi", "*.msp")
    foreach ($folder in @("$env:UserProfile\Downloads", "$env:UserProfile\Desktop")) { 
        foreach ($ext in $MsiExtensions) {
            $path = Join-Path $folder $ext
            try {
                $DenyRules += New-AppLockerRule -RuleType Path -User Everyone -Action Deny -Path $path -Description "Deny $ext from $folder" -ErrorAction Stop
                Write-Host "   Deny rule for MSI/MSP '$path' created." -ForegroundColor Cyan
            } catch { Write-Warning "   Failed to create deny rule for MSI/MSP path '$path': $($_.Exception.Message)" }
        }
    }

    Write-Host "New: Adding AppLocker rule to deny all Appx packages..."
    try {
        $DenyRules += New-AppLockerRule -RuleType PackagedApp -User Everyone -Action Deny -PackageName "*" -Description "Deny All Appx Packages" -ErrorAction Stop
        Write-Host "   Deny rule for ALL Appx Packages created." -ForegroundColor Cyan
    } catch {
        Write-Warning "   Failed to create deny rule for all Appx packages: $($_.Exception.Message)"
    }

    Write-Host "New: Adding AppLocker rule to block Microsoft Edge..."
    $edgePaths = @(
        "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    )
    foreach ($edgePath in $edgePaths) {
        if (Test-Path $edgePath) {
            try {
                $edgeFileInfo = Get-AppLockerFileInformation -Path $edgePath -ErrorAction Stop
                $DenyRules += New-AppLockerRule -RuleType Publisher -User Everyone -Action Deny -FileInformation $edgeFileInfo -Description "Deny Microsoft Edge" -ErrorAction Stop
                Write-Host "   Deny rule for Microsoft Edge '$edgePath' created." -ForegroundColor Cyan
            } catch {
                Write-Warning "   Failed to create deny rule for Microsoft Edge '$edgePath': $($_.Exception.Message)"
            }
        } else {
            Write-Warning "   Microsoft Edge executable not found at '$edgePath'. Skipping AppLocker rule for this path."
        }
    }

    if ($DenyRules.Count -gt 0) {
        $DenyPolicy = New-AppLockerPolicy -Rule $DenyRules -PolicyType Executable, Script, Msi, AppX
        $AppLockerPolicy = $AppLockerPolicy | Merge-AppLockerPolicy -Policy $DenyPolicy -ErrorAction Stop
        Write-Host "   All new deny rules for user-writeable paths, scripts, MSI/MSP, Appx, and Edge merged into policy." -ForegroundColor Green
    } else {
        Write-Warning "   No new deny rules were successfully created."
    }
    if ($AllowedChromePaths) {
        Write-Host "4. Adding AppLocker rule for Google Chrome..."
        foreach ($chromePath in $AllowedChromePaths) {
            if (Test-Path $chromePath) {
                try {
                    $chromeFileInfo = Get-AppLockerFileInformation -Path $chromePath -ErrorAction Stop
                    $ChromeRule = New-AppLockerPolicy -FileInformation $chromeFileInfo -RuleType Publisher -User Everyone -PolicyType Exe -ErrorAction Stop

                    if ($ChromeRule.RuleCollections.Exe.PolicyRules.Count -gt 0) {
                        $currentRule = $ChromeRule.RuleCollections.Exe.PolicyRules[0]
                        $currentRule.Conditions[0].BinaryName = "*"
                        $AppLockerPolicy = $AppLockerPolicy | Merge-AppLockerPolicy -Policy $ChromeRule -ErrorAction Stop
                        Write-Host "   Publisher rule for $($chromePath) added." -ForegroundColor Green
                    } else {
                        Write-Warning "   Could not generate a publisher rule for $($chromePath). Check the path or file signature."
                    }
                }
                catch {
                    Write-Warning "   Failed to add AppLocker rule for $($chromePath): $($_.Exception.Message)"
                }
            } else {
                Write-Warning "   Chrome executable not found at $($chromePath). Skipping rule creation for this path."
            }
        }
    }

    if ($AllowedExecutablePaths) {
        Write-Host "5. Adding AppLocker rules for specified custom applications..."
        foreach ($appPath in $AllowedExecutablePaths) {
            if (Test-Path $appPath) {
                try {
                    $appFileInfo = Get-AppLockerFileInformation -Path $appPath -ErrorAction Stop
                    $appRules = New-AppLockerPolicy -FileInformation $appFileInfo -RuleType Publisher, Hash -User Everyone -PolicyType Exe -ErrorAction Stop

                    if ($appRules.RuleCollections.Exe.PolicyRules.Count -gt 0) {
                        $AppLockerPolicy = $AppLockerPolicy | Merge-AppLockerPolicy -Policy $appRules -ErrorAction Stop
                        Write-Host "   Rule for $($appPath) added (Publisher preferred, Hash fallback)." -ForegroundColor Green
                    } else {
                        Write-Warning "   Could not generate a rule for $($appPath). Check the path or file signature."
                    }
                }
                catch {
                    Write-Warning "   Failed to add AppLocker rule for $($appPath): $($_.Exception.Message)"
                }
            } else {
                Write-Warning "   Custom application not found at $($appPath). Skipping rule creation for this path."
            }
        }
    }

    Write-Host "6. Setting AppLocker enforcement mode..."
    $EnforcementMode = if ($AuditOnlyMode) { "AuditOnly" } else { "Enabled" }

    $RuleCollections = $AppLockerPolicy.RuleCollections
    foreach ($collection in $RuleCollections) {
        # Set enforcement for all relevant rule types (Exe, Script, Msi, AppX)
        if ($collection.PolicyType -ne "Dll") {
            Write-Host "   Setting enforcement for $($collection.PolicyType) to '$EnforcementMode'..."
            $collection.EnforcementMode = $EnforcementMode
        }
    }

    Write-Host "7. Applying the AppLocker policy..."
    try {
        Set-AppLockerPolicy -PolicyObject $AppLockerPolicy -Local -ErrorAction Stop
        Write-Host "   AppLocker policy applied successfully. Enforcement mode: '$EnforcementMode'." -ForegroundColor Green
        if ($AuditOnlyMode) {
            Write-Host "   *** IMPORTANT: AppLocker is in AUDIT-ONLY mode. No applications will be blocked, but events will be logged. ***" -ForegroundColor Yellow
            Write-Host "   Review Event Viewer (Applications and Services Logs/Microsoft/Windows/AppLocker) for blocked events before switching to 'Enforce'." -ForegroundColor Yellow
        } else {
            Write-Host "   *** IMPORTANT: AppLocker is in ENFORCE mode. Only whitelisted applications will run. ***" -ForegroundColor Red
        }
    }
    catch {
        Write-Error "   Failed to apply AppLocker policy: $($_.Exception.Message)"
        return
    }

    Write-Host "AppLocker Whitelist Configuration Complete." -ForegroundColor Green
}

function Configure-BrowserHardening {
    param (
        [Parameter(Mandatory=$true)]
        [string[]]$AllowedEmails
    )

    Write-Host "`n--- Configuring Browser Hardening ---" -ForegroundColor Green

    # Base path for Chrome policies (machine-wide)
    $chromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
    Write-Host "Configuring Google Chrome policies..."

    try {
        if (-not (Test-Path $chromePolicyPath)) {
            New-Item -Path $chromePolicyPath -Force | Out-Null
        }

        # Disable Incognito Mode
        # IncognitoModeAvailability: 1 = Disabled
        Set-ItemProperty -Path $chromePolicyPath -Name "IncognitoModeAvailability" -PropertyType DWORD -Value 1 -Force
        Write-Host "  - Incognito Mode disabled in Chrome."

        # Disable Password Manager
        # PasswordManagerEnabled: 0 = Disabled
        Set-ItemProperty -Path $chromePolicyPath -Name "PasswordManagerEnabled" -PropertyType DWORD -Value 0 -Force
        Write-Host "  - Password Manager disabled in Chrome."
        # Disable Developer Tools
        # DeveloperToolsAvailability: 2 = Disabled
        Set-ItemProperty -Path $chromePolicyPath -Name "DeveloperToolsAvailability" -PropertyType DWORD -Value 2 -Force
        Write-Host "  - Developer Tools disabled in Chrome."
        # Set Extensions Block and Allow list
        Set-ItemProperty -Path $chromePolicyPath -Name "ExtensionInstallBlocklist" -PropertyType MultiString -Value "*" -Force
        Write-Host "  - Extensions installation blocked by default."
        $allowedExtensions = @(
            "eimadpbcbfnmbkopoojfekhnkhdbieeh", 
            "cmedhionkhpnakcndndgjdbohmhepckk", 
            "cjpalhdlnbpafiamejdnhcphjbkeiagm", 
            "ddkjiahejlhfcafbddmgiahcphecmpfh", 
            "mnjggcdmjocbbbhaepdhchncahnbgone"  
        )
        Set-ItemProperty -Path $chromePolicyPath -Name "ExtensionInstallAllowlist" -PropertyType MultiString -Value $allowedExtensions -Force
        Write-Host "  - Whitelisted extensions: $($allowedExtensions -join ', ')."
        $allowedDomains = $AllowedEmails | ForEach-Object { ($_.Split('@'))[1] } | Select-Object -Unique
        # If no emails were provided, this policy cannot be applied meaningfully.
        if ($allowedDomains.Count -gt 0) {
            Set-ItemProperty -Path $chromePolicyPath -Name "RestrictSigninToPattern" -PropertyType String -Value ".*@($(($allowedDomains | ForEach-Object { [regex]::Escape($_) }) -join '|'))" -Force
            Write-Host "  - Chrome sign-in restricted to domains: $($allowedDomains -join ', ')."
        } else {
            Write-Warning "  - No allowed email addresses provided. Chrome sign-in restriction policy will not be applied."
        }
        Write-Host "Google Chrome policies configured." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to configure Google Chrome policies: $($_.Exception.Message)"
    }
    Write-Host "Browser Hardening Configuration Complete." -ForegroundColor Green
}
# --- Main Script Execution Flow ---
# Call the AppLocker hardening function first
Set-AppLockerWhitelist -AuditOnlyMode $true -AllowedExecutablePaths @(
    # Add any other essential apps here that are NOT in Program Files/Windows
)
# Then call the browser hardening function
# Make sure $allowedEmails contains the input from the user at the start
Configure-BrowserHardening -AllowedEmails $allowedEmails
write-host "All changes have been made to harden Windows. A system restart is required for all changes to take effect."
write-host "Type 'Y' to restart the computer now or 'N' to exit without restarting."
$response = read-host "Restart now? (Y/N)"
if ($response -eq "Y" -or $response) {
    write-host "Restarting the computer..."
    Restart-Computer -Force
} else {
    write-host "Exiting without restarting. Please restart your computer later to apply changes."
    exit
}