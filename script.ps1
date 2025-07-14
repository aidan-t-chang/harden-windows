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
        Write-Host "Google Chrome is not installed."
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

function getUserInputToArray {
    param(
        [string]$Prompt = "Enter an email (type 'done' when finished):"
    )

    $inputArray = @()
    while ($true) {
        $input = Read-Host -Prompt $Prompt
        if ($input -eq "done") { 
            break 
        }
        $inputArray += $input 
    }
     
    return $inputArray
}

write-host "Please enter email addresses that will be allows to sign into Chrome. Type 'done' when finished."
$allowedEmails = getUserInputToArray

# Protect the OS Internals

# Disable access to PowerShell, Command Prompt, Registry Editor


# Disable access to Powershell
# Define output path for the AppLocker policy XML
$policyXmlPath = "$env:TEMP\PowerShell_Disable_AppLocker_Policy.xml"

Write-Host "Creating AppLocker rules to deny PowerShell..."

# Create publisher rules to deny powershell.exe and powershell_ise.exe
$denyPowershellRule = New-AppLockerRule -RuleType Publisher -User Everyone -Action Deny -PublisherName "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" -ProductName "Microsoft® Windows® Operating System" -FileVersion "*" -Filepath "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Description "Deny PowerShell.exe"
$denyPowershellISERule = New-AppLockerRule -RuleType Publisher -User Everyone -Action Deny -PublisherName "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" -ProductName "Microsoft® Windows® Operating System" -FileVersion "*" -Filepath "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe" -Description "Deny PowerShell_ISE.exe"

$appLockerPolicy = New-AppLockerPolicy -Rule $denyPowershellRule, $denyPowershellISERule -Service EnforcementMode -RuleType Exe, Dll

# 'AuditOnly' for testing: Set-AppLockerPolicy -PolicyObject $appLockerPolicy -RuleCollectionType Exe -EnforcementMode AuditOnly
Set-AppLockerPolicy -PolicyObject $appLockerPolicy -RuleCollectionType Exe -EnforcementMode AuditOnly 
Set-AppLockerPolicy -PolicyObject $appLockerPolicy -RuleCollectionType Dll -EnforcementMode AuditOnly 

write-host "AppLocker policy set to deny PowerShell and PowerShell ISE."

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
Get-NetAdapter | Disable-NetAdapter -Confirm:$false
write-host "Network adapters have been disabled."

# Disable Cortana, Microsoft store

# Create the Windows Search key if it doesn't exist
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'Windows Search' -ErrorAction SilentlyContinue
# Set the AllowCortana DWORD value to 0 to disable Cortana
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -PropertyType DWORD -Value 0 -Force

write-host "Cortana has been disabled."

# Create the WindowsStore key if it doesn't exist
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -ErrorAction SilentlyContinue
# Set the RemoveWindowsStore DWORD value to 1 to disable the Store
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name 'RemoveWindowsStore' -PropertyType DWORD -Value 1 -Force
write-host "Microsoft Store has been disabled."


# 1. Enable SmartScreen for applications and files (Shell)
Set-MpPreference -SmartScreenForExplorer Enabled
write-host "SmartScreen for applications and files (Shell) has been enabled."

# 2. Configure SmartScreen for Microsoft Edge (Strict Settings via Registry)
write-host "Configuring Microsoft Edge SmartScreen..."
# Create the 'Edge' registry key if it doesn't exist
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -ErrorAction SilentlyContinue | Out-Null

# Enable SmartScreen for Microsoft Edge browser itself
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -PropertyType DWORD -Value 1 -Force
write-host "Microsoft Edge SmartScreen enabled."

# Prevent bypassing SmartScreen prompts for potentially malicious sites
Set-ItemProperty -Path "HKLM:\SOFTWARE:\Policies\Microsoft\Edge" -Name "SmartScreenBlockMaliciousURLs" -PropertyType DWORD -Value 1 -Force
write-host "Preventing bypass of SmartScreen prompts for malicious sites in Edge."

# Prevent bypassing SmartScreen warnings about unverified (potentially malicious) downloads
Set-ItemProperty -Path "HKLM:\SOFTWARE:\Policies\Microsoft\Edge" -Name "SmartScreenBlockDownloads" -PropertyType DWORD -Value 1 -Force
write-host "Preventing bypass of SmartScreen warnings about downloads in Edge."

write-host "SmartScreen Configuration Complete"

# Enable BitLocker
# Replace 'C:' with the drive letter you want to encrypt
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XTSAES256 -UsedSpaceOnly -TpmProtector
Write-Host "BitLocker encryption initiated for C: drive with TPM protector. Please wait for the process to complete."
Write-Host "Remember to save your recovery key!"

# Block the ability to install any new apps
# There is no direct PowerShell command to block app installations, so instead .msi and .exe files will be blocked via AppLocker (Microsoft Store apps were already blocked)

# Create the Installer key if it doesn't exist
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -ErrorAction SilentlyContinue | Out-Null

# Set DisableMSI DWORD value to 2 to block all MSI installations
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'DisableMSI' -PropertyType DWORD -Value 2 -Force
Write-Host "Blocking all MSI package installations."

# Still need to disable .exe files via AppLocker

# Disable system restore to prevent rollback of changes
Disable-ComputerRestore -Drive "C:\", "D:\"
write-host "System restore has been disabled for C: and D: drives."

# Use NTFS permissions to restrict access to:
#     C:\Windows\System32
#     C:\Program Files
#     C:\Users\<OtherUsers>

# Helper function definition
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

# --- Step 3: Restrict C:\Program Files ---
Write-Host "Restricting C:\Program Files"
$pathProgramFiles = "C:\Program Files"

# Deny Write, Delete, Change Permissions, Take Ownership to Users group
Set-NTFSAccess -Path $pathProgramFiles -Identity $identityUsers -FileSystemRights Write, Delete, ChangePermissions, TakeOwnership -AccessControlType Deny -InheritanceFlags ContainerInherit, ObjectInherit -PropagationFlags None -RemoveExistingIdentityEntry
Write-Host "Users group restricted from writing/modifying in $pathProgramFiles."

# --- Step 4: Restrict C:\Users\<OtherUsers> Profiles Dynamically ---
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

    # 1. Remove ALL inherited permissions on the target user's profile folder
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

    # 2. Grant explicit FullControl to the Owner of the profile
    Set-NTFSAccess -Path $otherUserPath -Identity $owner.Value -FileSystemRights FullControl -AccessControlType Allow -InheritanceFlags ContainerInherit, ObjectInherit -PropagationFlags None -RemoveExistingIdentityEntry

    # 3. Grant explicit FullControl to SYSTEM
    Set-NTFSAccess -Path $otherUserPath -Identity $systemSid.Value -FileSystemRights FullControl -AccessControlType Allow -InheritanceFlags ContainerInherit, ObjectInherit -PropagationFlags None -RemoveExistingIdentityEntry

    # 4. Grant explicit FullControl to Administrators (for management/recovery)
    Set-NTFSAccess -Path $otherUserPath -Identity $administratorsSid.Value -FileSystemRights FullControl -AccessControlType Allow -InheritanceFlags ContainerInherit, ObjectInherit -PropagationFlags None -RemoveExistingIdentityEntry

    # 5. Explicitly DENY ListDirectory/ReadData/ReadAttributes for "Users" group for the target profile folder
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
        [switch]$AuditOnlyMode = $false # Set to $true to start in Audit-Only mode, recommended for testing
    )

    Write-Host "Starting AppLocker Whitelist Configuration..." -ForegroundColor Green

    # 1. Enable the Application Identity Service
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

    # 2. Get the current AppLocker policy or create a new empty one
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

    # 3. Create Default Rules (Crucial for system stability)
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

    # 4. Add Rules for Chrome (Publisher Rule)
    if ($AllowedChromePaths) {
        Write-Host "4. Adding AppLocker rule for Google Chrome..."
        foreach ($chromePath in $AllowedChromePaths) {
            if (Test-Path $chromePath) {
                try {
                    $chromeFileInfo = Get-AppLockerFileInformation -Path $chromePath -ErrorAction Stop
                    $ChromeRule = New-AppLockerPolicy -FileInformation $chromeFileInfo -RuleType Publisher -User Everyone -PolicyType Exe -ErrorAction Stop

                    # Publisher rule for Chrome should be broad enough to cover updates.
                    # Adjust the publisher level if needed. For Google Chrome, typically 'Publisher' or 'Product Name' is good.
                    # This example tries to get the most specific publisher info and then generalizes it slightly.
                    if ($ChromeRule.RuleCollections.Exe.PolicyRules.Count -gt 0) {
                        $currentRule = $ChromeRule.RuleCollections.Exe.PolicyRules[0]
                        # Set the BinaryName to '*' to allow all binaries from Google Chrome product
                        $currentRule.Conditions[0].BinaryName = "*"
                        # Set the ProductName to '*' to allow all products from Google LLC
                        # $currentRule.Conditions[0].ProductName = "*" # Uncomment if you want to allow all products from Google LLC
                        
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

    # 5. Add Rules for Other Specified Executables (Publisher or Hash Rule fallback)
    if ($AllowedExecutablePaths) {
        Write-Host "5. Adding AppLocker rules for specified custom applications..."
        foreach ($appPath in $AllowedExecutablePaths) {
            if (Test-Path $appPath) {
                try {
                    $appFileInfo = Get-AppLockerFileInformation -Path $appPath -ErrorAction Stop
                    $appRules = New-AppLockerPolicy -FileInformation $appFileInfo -RuleType Publisher, Hash -User Everyone -PolicyType Exe -ErrorAction Stop
                    
                    if ($appRules.RuleCollections.Exe.PolicyRules.Count -gt 0) {
                        # Prioritize publisher rule if available, otherwise use hash
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

    # 6. Set Enforcement Mode (for all rule collections)
    Write-Host "6. Setting AppLocker enforcement mode..."
    $EnforcementMode = if ($AuditOnlyMode) { "AuditOnly" } else { "Enabled" }

    # Iterate through all rule collections and set their enforcement mode
    $RuleCollections = $AppLockerPolicy.RuleCollections
    foreach ($collection in $RuleCollections) {
        if ($collection.PolicyType -ne "Dll" -and $collection.PolicyType -ne "Msi") { # Dll can be tricky, Msi often has its own default allow rules.
            # Only set for relevant types initially for simplicity and safety.
            # You might need to adjust for MSI and Script rules based on your specific needs.
            Write-Host "   Setting enforcement for $($collection.PolicyType) to '$EnforcementMode'..."
            $collection.EnforcementMode = $EnforcementMode
        }
    }

    # 7. Apply the policy
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

# Prevent running .exe files from Downloads, AppData, Desktop
    Write-Host "New: Adding AppLocker rules to deny executables from Downloads, AppData, and Desktop..."
    $UserRestrictedPaths = @(
        "$env:UserProfile\Downloads\*",
        "$env:LocalAppData\*\*", # This covers all subfolders within AppData\Local
        "$env:AppData\*\*",     # This covers all subfolders within AppData\Roaming
        "$env:UserProfile\Desktop\*"
    )

    $DenyRules = @()
    foreach ($path in $UserRestrictedPaths) {
        try {
            $DenyRule = New-AppLockerRule -RuleType Path -User Everyone -Action Deny -Path $path -Description "Deny EXE from $path" -ErrorAction Stop
            $DenyRules += $DenyRule
            Write-Host "   Deny rule for '$path' created." -ForegroundColor Cyan
        }
        catch {
            Write-Warning "   Failed to create deny rule for path '$path': $($_.Exception.Message)"
        }
    }
    if ($DenyRules.Count -gt 0) {
        # Create a new policy object containing only the deny rules for merging
        $DenyPolicy = New-AppLockerPolicy -Rule $DenyRules -PolicyType Exe
        $AppLockerPolicy = $AppLockerPolicy | Merge-AppLockerPolicy -Policy $DenyPolicy -ErrorAction Stop
        Write-Host "   Deny rules for Downloads, AppData, and Desktop merged into policy." -ForegroundColor Green
    } else {
        Write-Warning "   No deny rules were successfully created for user-writeable paths."
    }

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

# SIG # Begin signature block
# MIIFkQYJKoZIhvcNAQcCoIIFgjCCBX4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUGee10SStooBc2Z4b1x8sXU09
# NligggMgMIIDHDCCAgSgAwIBAgIQNS6VGhmLeppLxXfcEQ+GEjANBgkqhkiG9w0B
# AQsFADAmMSQwIgYDVQQDDBtQb3dlcnNoZWxsU2NyaXB0Q2VydGlmaWNhdGUwHhcN
# MjUwNjMwMDIzOTQwWhcNMjYwNjMwMDI1OTQwWjAmMSQwIgYDVQQDDBtQb3dlcnNo
# ZWxsU2NyaXB0Q2VydGlmaWNhdGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
# AoIBAQCoYRjT/FrhYTSrvOLmH4CGoQRqieTqEyVqcahfozAAXhh75iovhvwCOiLB
# 2sPqG7WWTzlPbTcOD22gqSwKyCG6rXwN0xBAOsm0WTuY9GGKHAj/zDldJjlQvFMH
# WxPbwxI++c5WpA07HIdp8Ad1hHOvQTsMQrNVWTnyNYTpk4fX3OlzFhqibDP9v9x1
# xFMwokzi7FP9O2ctBab0pMa7pBTwTntJ4jOP76Ma3pKKgVDlWvl24uLVXZQLgGM0
# jdbNIKoDqUQNKJeL4uV9DQRrBRe7TU7VIMcm+oJkmxr9H1BtyfHBFFGP7qFrqRLa
# CvnSMM3/97V6hLBMrPV8iSCIrGzRAgMBAAGjRjBEMA4GA1UdDwEB/wQEAwIHgDAT
# BgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUqERASzOI1PU37onPrp3t/XwG
# GqIwDQYJKoZIhvcNAQELBQADggEBAFsf4chWaS3iFdUTnSP+HoG8TLTpi6S0z2p0
# LDA5KiX2Vu8fi2aprFIMH4hj2cSNHVh56fdbmHG8vMuQwuT+JYruY4mTTXWvwx6p
# z4IZMJG3DORHF27ByqSc6lD80uvQf9tktBFEDge2JCvhwDMAOetUwpgbgC+yhFAd
# sRphPaWVErPnVNsO/TBv8w6w5HHK664yFogGG6L/VctOTeR52OTRTLUmlSY+rcsa
# +x0sJCikklIlnY4Tr6iEr8JvSjmrYyUQrQP8vA3vHH9dl7YByXpePxwJfJRk1hHM
# fhB1XpZLY0OiSAka/OssguJovpg5M/C/o4QPUv0v3r+XE1PKe+kxggHbMIIB1wIB
# ATA6MCYxJDAiBgNVBAMMG1Bvd2Vyc2hlbGxTY3JpcHRDZXJ0aWZpY2F0ZQIQNS6V
# GhmLeppLxXfcEQ+GEjAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAA
# oQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU9Xk79W3tNS9E06AnWeYTByIn
# g9YwDQYJKoZIhvcNAQEBBQAEggEADmRx9FHpkMpBjoxVHyr9bab62Z5AtrKoddkM
# VgfNrQqk4EwFtWaSyG8zFITVX8+ybwgqIugo08ZfJBV4qGFikl+rOSSW/UoVU789
# qvAkU/QNsAgVU1iFaIMoNd7hFvhzwz8YE+LFLOp0c3LPIti6MHHjnhPkybd/UgfF
# iaConquTLVE2vEnHhrmJIHM/RfvnAynbkOAyJKkLu4cFU391rl4EzVbzEYAYblKe
# 2w7gMYmTP+SwT4Vcx5himNFSqzIPqYs+3x6xjMO2intmOAittL4eQXuGP7xWsvmQ
# v6uN/wUCmpe7UhBa6foRgcFKrVVcES4UaeFQF6poHLg3Se90XA==
# SIG # End signature block
