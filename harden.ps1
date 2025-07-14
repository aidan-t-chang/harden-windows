# Written by Aidan Chang - achang1@imsa.edu
# This is a script that is designed to harden Windows by restricting access to many features and applications. 
# For example, PowerShell will not be able to be accessed and any .exe files will be blocked from running. Only Chrome with certain email addresses will be allowed to run.
# !!!!! ONCE RUN, IT IS VERY HARD TO UNDO THIS SCRIPT !!!!!

# If the script does not run for you, try running the command "Set-ExecutionPolicy -ExecutionPolicy Bypass" in PowerShell first.

# ----  1. Check to make sure the script is being run from a non-admin account and that Chrome is installed  ----

# Checks if the current user is admin
function isAdmin {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($user)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # write-host "Current user: $($user.Name)"
    # write-host "Is Admin: $isAdmin"

    return $isAdmin
}

# Certain applications like AppLocker require admin privileges to run, so check if user has admin rights
if (-not (isAdmin)) {
    write-host "This script must be run with Administrator privileges. Please re-run as an administrator."
    exit
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
        write-host "Google Chrome is not installed. Please install Google Chrome before running this script."
    }

    return $chromeInstalled
}

$chromeInstalled = isChromeInstalled

if (-not $chromeInstalled) {
    write-host "Exiting script because Google Chrome is not installed."
    exit
}

# --------------------

# ---------     2. Write a few lines of text on the screen explaining briefly what the
# script does and double check with the user (have them enter the exact string "I AGREE" or st) before proceeding.    ---------
write-host "Make sure that Zoom is installed as well as PyCharm and Microsoft Visual Studio. This script will restrict installations."
$test2 = read-host -Prompt "Input anything to continue"

write-host "Please create the Chrome profiles for the above emails right now. The script will restrict Chrome to only these profiles."
$test = read-host -Prompt "Input anything to continue"
write-host "This is a PowerShell script that hardens Windows. Features like Command Prompt, USB Access, and Program Files access will be restricted. ONCE YOU RUN THIS SCRIPT, IT IS VERY HARD TO UNDO THE CHANGES."
write-host "Please type 'I AGREE' to continue."
$response = read-host
if ($response -ne "I AGREE") {
    write-host "You did not agree to the terms. Exiting script."
    exit
}
# ---------

# -------------    3. Read inputs:
# A list of email addresses, which will be allowed to be signed into chrome   -------------------

write-host "Please enter email addresses that will be allowed to sign into Chrome. Type 'done' when finished."
$allowedEmails = @()
while ($true) {
    $ninput = Read-Host -Prompt "Enter an email (type 'done' when finished):"
    if ($ninput -eq "done") {
        break
    }
    # Validate email format (basic check)
    if ($ninput -match "^[^@\s]+@[^@\s]+\.[^@\s]+$") {
        $allowedEmails += $ninput
    } else {
        Write-Warning "Invalid email format. Please try again."
    }
}


# -----------------


#  ------       4. PROTECT THE OS INTERNALS       ------

# PowerShell will be denied later on using AppLocker

# Enable and Start AppLocker service, required for PowerShell restriction to work
# try {
#     write-host "Ensuring 'Application Identity' service is running and set to Automatic..."
#     Get-Service -Name "AppIDSvc" | Set-Service -StartupType Automatic -PassThru | Start-Service -ErrorAction Stop
# }
# catch {
#     write-error "Failed to start Application Identity service: $($_.Exception.Message)"
#     exit
# }

# 4.1 Disable access to the Command Prompt
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

# 4.2 Disable access to the Registry Editor
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

# 4.3 Disable access to USB storage devices

# Value 4 prevents USB storage devices from being used
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor" -Name "Start" -Value 4
write-host "USB storage devices have been disabled."

# Pipes all values from Get-NetAdapter to Disable-NetAdapter, -Confirm:$false suppresses confirmation prompts
# On a VM, this will terminate the network connection to the VM
# Get-NetAdapter | Disable-NetAdapter -Confirm:$false
# write-host "Network adapters have been disabled."

# 4.4 Disable Cortana 
# Create the Windows Search key if it doesn't exist
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'Windows Search' -ErrorAction SilentlyContinue
# Set the AllowCortana DWORD value to 0 to disable Cortana
$isWin11 = (Get-ComputerInfo | Select-Object -expand OsName) -match 11
if ($isWin11) {
    write-host "Cortana is not available on Windows 11, skipping Cortana disable step."
}
else {
    New-ItemProperty -Path 'HKLM:\SOFTWARE:\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -Value 0 -Force
    write-host "Cortana has been disabled."
}

# 4.5 Disable Microsoft Store
# Create the WindowsStore key if it doesn't exist
if (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Force | Out-Null
}

# Set the RemoveWindowsStore DWORD value to 1 to disable the Store
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Value 1 -Force 
write-host "Microsoft Store has been disabled."

# 4.6 Enable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false
# No need to enable SmartScreen for Edge/Explorer if it is going to be disabled 

# 4.8 Block the ability to install any new apps
# .exe files will be blocked later via AppLocker

# Create the Installer key if it doesn't exist
if (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer')) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Force | Out-Null
}

# Set DisableMSI DWORD value to 2 to block all MSI installations
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'DisableMSI' -Value 2 -Force
Write-Host "Blocking all MSI package installations."

# 4.9 Disable system restore to prevent rollback of changes
write-host "Disabling system restore for all drives."

Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -ne "" -and $_.Free -ne $null } | ForEach-Object {
    $driveLetter = $_.Name
    $drivePath = "$($driveLetter):\"
    write-host "Attempting to disable system restore on drive $($drivePath)"
    try {
        Disable-ComputerRestore -Drive $drivePath -Confirm:$false -ErrorAction Stop
        write-host "Successfully disabled system restore on drive $($drivePath)" -ForegroundColor Green
    }
    catch {
        write-warning "Failed to disable system restore on drive $($drivePath)"
    }
}

# 4.10 Use NTFS permissions to restrict access to:
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
        Write-Host "  - Successfully set '$AccessControlType' '$FileSystemRights' for '$Identity' on '$Path'." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to set permissions on $Path. Error: $($_.Exception.Message)"
        Write-Host "This could be due to insufficient permissions or the path not existing."
    }
}

# Disabling System32 means disabling access to AppLocker, which is required for the rest of the script to work.
# Therefore, System32 cannot be blocked.
# Set-NTFSAccess -Path $pathSystem32 -Identity $identityUsers -FileSystemRights Write, Delete, ChangePermissions, TakeOwnership -AccessControlType Deny -InheritanceFlags ContainerInherit, ObjectInherit -PropagationFlags None -RemoveExistingIdentityEntry

$identityUsers = "BUILTIN\Users"
Write-Host "Restricting C:\Program Files"
$pathProgramFiles = "C:\Program Files"

# In order for Chrome to be able to run, the NTFS access to Program Files must allow the Chrome executable to run. Therefore, blockiung access to Program Files is not possible.
# Deny Write, Delete, Change Permissions, Take Ownership to Users group
# Set-NTFSAccess -Path $pathProgramFiles -Identity $identityUsers -FileSystemRights Write, Delete, ChangePermissions, TakeOwnership -AccessControlType Deny -InheritanceFlags ContainerInherit, ObjectInherit -PropagationFlags None -RemoveExistingIdentityEntry
# Write-Host "Users group restricted from writing/modifying in $pathProgramFiles."

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
    Write-Host "No other user profiles found to restrict after filtering."
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

# 4.11 Create a whitelist-only environment for apps, allow only specific apps.

$whitelistXml = @"
<AppLockerPolicy Version="1">
    <RuleCollection Type="Exe" EnforcementMode="NotConfigured">
        <FilePublisherRule Id="46652a30-5fad-467d-9950-b73c36c60327" Name="Signed by O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
            <Conditions>
                <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="*" BinaryName="*">
                    <BinaryVersionRange LowSection="*" HighSection="*"/>
                </FilePublisherCondition>
            </Conditions>
        </FilePublisherRule>
        <FilePublisherRule Id="9282367e-14d8-4c73-a842-5b4bbe7d866d" Name="PYCHARM, from O=JETBRAINS S.R.O., L=PRAHA, C=CZ" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
            <Conditions>
                <FilePublisherCondition PublisherName="O=JETBRAINS S.R.O., L=PRAHA, C=CZ" ProductName="PYCHARM" BinaryName="*">
                    <BinaryVersionRange LowSection="*" HighSection="*"/>
                </FilePublisherCondition>
            </Conditions>
        </FilePublisherRule>
        <FilePublisherRule Id="b9d12183-5569-4aff-a8ab-df7367aa531c" Name="MICROSOFT® VISUAL STUDIO®, from O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
            <Conditions>
                <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® VISUAL STUDIO®" BinaryName="*">
                    <BinaryVersionRange LowSection="*" HighSection="*"/>
                </FilePublisherCondition>
            </Conditions>
        </FilePublisherRule>
        <FilePublisherRule Id="5ec10056-6d2f-438d-81dd-80e7e7f2fcdf" Name="Signed by O=ZOOM VIDEO COMMUNICATIONS, INC., L=SAN JOSE, S=CALIFORNIA, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
            <Conditions>
                <FilePublisherCondition PublisherName="O=ZOOM VIDEO COMMUNICATIONS, INC., L=SAN JOSE, S=CALIFORNIA, C=US" ProductName="*" BinaryName="*">
                    <BinaryVersionRange LowSection="*" HighSection="*"/>
        </FilePublisherCondition>
            </Conditions>
        </FilePublisherRule>
        <FilePublisherRule Id="6206f54d-9c04-4edf-9c11-0b316f8a3d08" Name="MICROSOFT® WINDOWS® OPERATING SYSTEM, from O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
            <Conditions>
                <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="*">
                    <BinaryVersionRange LowSection="*" HighSection="*"/>
                </FilePublisherCondition>
            </Conditions>
        </FilePublisherRule>
        <FilePathRule Id="8ce8c67f-cc8a-4c9b-9a97-9a1003d523c0" Name="%SYSTEM32%\*" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
            <Conditions>
                <FilePathCondition Path="%SYSTEM32%\*"/>
            </Conditions>
        </FilePathRule>
        <FilePathRule Id="ad051e01-8fed-4125-83a1-b34d805ccdc9" Name="%WINDIR%\*" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
            <Conditions>
                <FilePathCondition Path="%WINDIR%\*"/>
            </Conditions>
        </FilePathRule>
        <FilePathRule Id="c0dc9913-0ece-468d-930f-e17350f370c7" Name="%PROGRAMFILES%\Google\*" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
            <Conditions>
                <FilePathCondition Path="%PROGRAMFILES%\Google\*"/>
            </Conditions>
        </FilePathRule>
        <FilePathRule Id="c2a197c1-e462-4071-920b-cdb8001be0f9" Name="%PROGRAMFILES%\Microsoft\Edge\*" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
            <Conditions>
                <FilePathCondition Path="%PROGRAMFILES%\Microsoft\Edge\*"/>
            </Conditions>
        </FilePathRule>
    </RuleCollection>
    <RuleCollection Type="Msi" EnforcementMode="NotConfigured">
        <FilePathRule Id="b9af7461-1b0e-41b1-bce5-42b50efeeb23" Name="*" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
            <Conditions>
                <FilePathCondition Path="*"/>
            </Conditions>
        </FilePathRule>
    </RuleCollection>
    <RuleCollection Type="Script" EnforcementMode="NotConfigured"/>
    <RuleCollection Type="Dll" EnforcementMode="NotConfigured"/>
    <RuleCollection Type="Appx" EnforcementMode="NotConfigured">
        <FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba" Name="(Default Rule) All signed packaged apps" Description="Allows members of the Everyone group to run packaged apps that are signed." UserOrGroupSid="S-1-1-0" Action="Allow">
            <Conditions>
                <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
                    <BinaryVersionRange LowSection="0.0.0.0" HighSection="*"/>
                </FilePublisherCondition>
            </Conditions>
        </FilePublisherRule>
    </RuleCollection>
</AppLockerPolicy>
"@

function Create-AppLockerWhitelist {
    Write-Host "Adding AppLocker rule to whitelist..."
    $whitelistXml | Out-File -FilePath "C:\Windows\Temp\whitelist_policy.xml" -Encoding UTF8
    Set-AppLockerPolicy -XmlPolicy "C:\Windows\Temp\whitelist_policy.xml"
    write-host "AppLocker whitelist implemented."

}
# ------------------

# -------------------- 5. HARDEN THE BROWSER --------------------
function Configure-BrowserHardening {
    param (
        [Parameter(Mandatory=$true)]
        [string[]]$AllowedEmails
    )

    write-host "Hardening Google Chrome..."
    # Base path for Chrome policies (machine-wide)
    $chromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
    Write-Host "Configuring Google Chrome policies..."

    try {
        if (-not (Test-Path $chromePolicyPath)) {
            New-Item -Path $chromePolicyPath -Force | Out-Null
        }

        # 5.1 Disable Incognito Mode
        # IncognitoModeAvailability: 1 = Disabled
        Set-ItemProperty -Path $chromePolicyPath -Name "IncognitoModeAvailability" -Value 1 -Force
        Write-Host "  - Incognito Mode disabled in Chrome."

        # 5.2 Disable Password Manager
        # PasswordManagerEnabled: 0 = Disabled
        Set-ItemProperty -Path $chromePolicyPath -Name "PasswordManagerEnabled" -Value 0 -Force
        Write-Host "  - Password Manager disabled in Chrome."

        # 5.3 Disable Developer Tools
        # DeveloperToolsAvailability: 2 = Disabled
        Set-ItemProperty -Path $chromePolicyPath -Name "DeveloperToolsAvailability" -Value 2 -Force
        Write-Host "  - Developer Tools disabled in Chrome."

        # 5.4 Disable Guest Profile Login 
        Set-ItemProperty -Path $chromePolicyPath -Name "BrowserGuestModeEnabled" -Value 0 -Force
        Write-Host "  - Guest profile login disabled in Chrome."

        # $allowedExtensions contains the IDs of extensions that are allowed to be installed. These are available in the url of the extension in the Chrome Web Store.
        # 5.5 Whitelist specific extensions (dark reader, adblock for youtube, Ublock origin, ublock origin lite, sponsorblock for youtube)
        $darkReaderId = "eimadpbcbfnmbkopoojfekhnkhdbieeh" # Dark Reader
        $adblockForYoutubeId = "cmedhionkhpnakcndndgjdbohmhepckk" # Adblock for YouTube
        $ublockOriginId = "cjpalhdlnbpafiamejdnhcphjbkeiagm" # uBlock Origin
        $ublockOriginLiteId = "ddkjiahejlhfcafbddmgiahcphecmpfh" # uBlock Origin Lite
        $sponsorBlockId = "mnjggcdmjocbbbhaepdhchncahnbgone" # SponsorBlock for YouTube
        
        $allowedExtensions = @(
            $darkReaderId,
            $adblockForYoutubeId,
            $ublockOriginId,
            $ublockOriginLiteId,
            $sponsorBlockId
        )

        # 5.5a. Download and "inject" Chrome ADM template into Group Policy
        write-host "Downloading and injecting Chrome ADM template into Group Policy..."
        # The drive link is a link to the ADM template for Google Chrome policies to avoid having to download the entire policy templates zip file.
        New-Item -Path "C:\Windows\System32\GroupPolicy\Adm" -ItemType Directory -Force
        
        # Downloads the Chrome ADM into the Group Policy ADM directory
        Invoke-WebRequest -Uri "https://drive.google.com/uc?id=1nbi5erG7i8bKgUmkq9GukaW1F8sGJXbT" -OutFile "C:\Windows\System32\GroupPolicy\Adm\chrome.adm" -ErrorAction Stop

        write-host "Chrome ADM template has been injected into Group Policy."

        # 5.5b. Create the extensions blocklist and allowlist
        write-host "Creating the extensions blocklist and allowing specific extensions..."

        # Add the registry keys to turn on the blocklist and allow the certain extensions
        New-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist" -Force
        New-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallAllowlist" -Force

        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist" -Name "1" -Value "*" -Force
        $arrayLen = $allowedExtensions.Count
        # Create a registry entry for each allowed extension
        for ($i = 0; $i -lt $arrayLen; $i++) {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallAllowlist" -Name ($i + 1) -Value $allowedExtensions[$i] -Force
            write-host "Extension ID $($allowedExtensions[$i]) has been added to the extensions allowlist." -ForegroundColor Green
        }


        # Restrict sign-in to specific email addresses
        # Users will be able to sign in to Chrome under allowed email address profiles, there is nothing to control that
        # However, users will only be able to turn on sync and create profiles of allowed email addresses

        # Force the user to sign in to Chrome (prevents them from using Chrome without signing in)
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "BrowserSignin" -Value 2 -Force

        # Disable the ability to add new people (profiles) in Chrome
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "BrowserAddPersonEnabled" -Value 0 -Force

        $newString = ""
        foreach ($email in $AllowedEmails) {
            $newString += "($email)|"
        }
        $newString = $newString.TrimEnd('|') # Remove the trailing pipe character

        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "RestrictSigninToPattern" -Value $newString -Force

        Write-Host "Google Chrome policies configured." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to configure Google Chrome policies: $($_.Exception.Message)"
    }

    Write-Host "Browser Hardening Configuration Complete." -ForegroundColor Green
}

# -----------------

# --------- 6. DISABLE WIDGETS ----------------

write-host "`n--- Disabling Widgets and Unwanted Apps ---" 
# 6.1 Disable the News and Interests widget on the taskbar
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0 -Force 

# 6.2 Disable Xbox Game Bar UI for all users
if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR")) {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR' -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Force 

# 6.3 Disable the Game Bar entirely 
if (!(Test-Path "HKCU:\System\GameConfigStore")) {
    New-Item -Path 'HKCU:\System\GameConfigStore' -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Force 
write-host "Game Bar and Widgets have been disabled."

# 6.4 Disable Xbox App, Groove Music, Movies & TV, Weather, Clipchamp, and other apps using AppLocker

# Microsoft Edge
$edgeXml = @"
<AppLockerPolicy Version="1">
    <RuleCollection Type="Appx" EnforcementMode="NotConfigured"/>
    <RuleCollection Type="Dll" EnforcementMode="NotConfigured"/>
    <RuleCollection Type="Exe" EnforcementMode="NotConfigured">
        <FilePublisherRule Id="43065e5f-4025-43db-a021-a31867446c92" Name="MICROSOFT EDGE, from O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
            <Conditions>
                <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT EDGE" BinaryName="MSEDGE.EXE">
                    <BinaryVersionRange LowSection="*" HighSection="*"/>
                </FilePublisherCondition>
            </Conditions>
        </FilePublisherRule>
    </RuleCollection>
    <RuleCollection Type="Msi" EnforcementMode="NotConfigured"/>
    <RuleCollection Type="Script" EnforcementMode="NotConfigured"/>
</AppLockerPolicy>
"@

Write-Host "Adding AppLocker rule to block Microsoft Edge..."
$edgeXml | Out-File -FilePath "C:\Windows\Temp\msedge_policy.xml" -Encoding UTF8
Set-AppLockerPolicy -XmlPolicy "C:\Windows\Temp\msedge_policy.xml"
write-host "Microsoft Edge AppLocker rule created." 

# Xbox App (and related components)
$xBoxXML = @"
<AppLockerPolicy Version="1">
    <RuleCollection Type="Appx" EnforcementMode="NotConfigured">
        <FilePublisherRule Id="0b499a1c-d2db-4ea7-90b1-c19f34199a02" Name="Microsoft.GamingApp, from Microsoft Corporation" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
            <Conditions>
                <FilePublisherCondition PublisherName="CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" ProductName="Microsoft.GamingApp" BinaryName="*">
                    <BinaryVersionRange LowSection="*" HighSection="*"/>
                </FilePublisherCondition>
            </Conditions>
        </FilePublisherRule>
    </RuleCollection>
    <RuleCollection Type="Dll" EnforcementMode="NotConfigured"/>
    <RuleCollection Type="Exe" EnforcementMode="NotConfigured"/>
    <RuleCollection Type="Msi" EnforcementMode="NotConfigured"/>
    <RuleCollection Type="Script" EnforcementMode="NotConfigured"/>
</AppLockerPolicy>
"@

$xBoxXML | Out-File -FilePath "C:\Windows\Temp\xbox_policy.xml" -Encoding UTF8
Set-AppLockerPolicy -XmlPolicy "C:\Windows\Temp\xbox_policy.xml"

write-host "AppLocker policies to block Xbox App and related components have been created."

# Groove Music (or Media Player)
$grooveMusic = @"
<AppLockerPolicy Version="1">
    <RuleCollection Type="Appx" EnforcementMode="NotConfigured">
        <FilePublisherRule Id="1698cc4c-d3a1-4336-ac40-2a068c402306" Name="Microsoft.ZuneMusic, from Microsoft Corporation" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
            <Conditions>
                <FilePublisherCondition PublisherName="CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" ProductName="Microsoft.ZuneMusic" BinaryName="*">
                    <BinaryVersionRange LowSection="*" HighSection="*"/>
                </FilePublisherCondition>
            </Conditions>
        </FilePublisherRule>
    </RuleCollection>
    <RuleCollection Type="Dll" EnforcementMode="NotConfigured"/>
    <RuleCollection Type="Exe" EnforcementMode="NotConfigured"/>
    <RuleCollection Type="Msi" EnforcementMode="NotConfigured"/>
    <RuleCollection Type="Script" EnforcementMode="NotConfigured"/>
</AppLockerPolicy>
"@

$grooveMusic | Out-File -FilePath "C:\Windows\Temp\groove_policy.xml" -Encoding UTF8
Set-AppLockerPolicy -XmlPolicy "C:\Windows\Temp\groove_policy.xml"

write-host "AppLocker policies to block Media Player (in control of Groove Music and Movies & TV)have been created."

# Weather
$weatherXml = @"
<AppLockerPolicy Version="1">
    <RuleCollection Type="Appx" EnforcementMode="NotConfigured">
        <FilePublisherRule Id="75f88950-141b-4483-a3f4-0662223464d1" Name="Microsoft.BingWeather, from Microsoft Corporation" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
            <Conditions>
                <FilePublisherCondition PublisherName="CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" ProductName="Microsoft.BingWeather" BinaryName="*">
                    <BinaryVersionRange LowSection="*" HighSection="*"/>
                </FilePublisherCondition>
            </Conditions>
        </FilePublisherRule>
    </RuleCollection>
    <RuleCollection Type="Dll" EnforcementMode="NotConfigured"/>
    <RuleCollection Type="Exe" EnforcementMode="NotConfigured"/>
    <RuleCollection Type="Msi" EnforcementMode="NotConfigured"/>
    <RuleCollection Type="Script" EnforcementMode="NotConfigured"/>
</AppLockerPolicy>
"@

$weatherXml| Out-File -FilePath "C:\Windows\Temp\weather_policy.xml" -Encoding UTF8
Set-AppLockerPolicy -XmlPolicy "C:\Windows\Temp\weather_policy.xml"
write-host "AppLocker policy to block Weather has been created."

# Clipchamp
$clipchampXml = @"
<AppLockerPolicy Version="1">
    <RuleCollection Type="Appx" EnforcementMode="NotConfigured">
        <FilePublisherRule Id="c1f0c456-0403-4af5-8398-71b20b0c064f" Name="Clipchamp.Clipchamp, from Microsoft Corp." Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
            <Conditions>
                <FilePublisherCondition PublisherName="CN=33F0F141-36F3-4EC2-A77D-51B53D0BA0E4" ProductName="Clipchamp.Clipchamp" BinaryName="*">
                    <BinaryVersionRange LowSection="*" HighSection="*"/>
                </FilePublisherCondition>
            </Conditions>
        </FilePublisherRule>
    </RuleCollection>
    <RuleCollection Type="Dll" EnforcementMode="NotConfigured"/>
    <RuleCollection Type="Exe" EnforcementMode="NotConfigured"/>
    <RuleCollection Type="Msi" EnforcementMode="NotConfigured"/>
    <RuleCollection Type="Script" EnforcementMode="NotConfigured"/>
</AppLockerPolicy>
"@
$clipchampXml | Out-File -FilePath "C:\Windows\Temp\clipchamp_policy.xml" -Encoding UTF8
Set-AppLockerPolicy -XmlPolicy "C:\Windows\Temp\clipchamp_policy.xml"

write-host "AppLocker policy to block Clipchamp has been created."

# --------------------

# Disable Search Highlights
write-host "Disabling search highlights.."
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force
New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "EnableDynamicContentInWSB" -Value 0
write-host "Search highlights have been disabled."

# Disable the Mobile Hotspot feature
write-host "Disabling the Mobile Hotspot feature..."
$ServiceName = "icssvc"

if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
    # Stop the service if it's running
    Stop-Service $ServiceName

    # Set the service to disabled startup type
    Set-Service $ServiceName -StartupType Disabled

    Write-Host "The Windows Mobile Hotspot Service ($ServiceName) has been disabled."
} else {
    Write-Host "The Windows Mobile Hotspot Service ($ServiceName) is not installed or found."
}

# --- Set AppLocker Policy Enforcement ---
# This ensures that AppLocker rules are actively enforced.
# This part is critical. If not set, rules are just defined but not active.

# --- Main Script Execution Flow ---

# Call the browser hardening function
# Make sure $allowedEmails contains the input from the user at the start
Configure-BrowserHardening -AllowedEmails $allowedEmails

$bitLockerStatus = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
Enable-BitLockerAutoUnlock -MountPoint "C:" -ErrorAction SilentlyContinue
if ($bitLockerStatus -ne $null) {
    if ($bitLockerStatus.VolumeStatus -eq "FullyEncrypted" -or
        $bitLockerStatus.VolumeStatus -eq "EncryptionInProgress" -or
        $bitLockerStatus.VolumeStatus -eq "PartiallyEncrypted") {

        Write-Host "BitLocker is already enabled or encryption is in progress on C: drive. Current status: $($bitLockerStatus.VolumeStatus)"
        Write-Host "Remember to save your recovery key!"
        $recoveryKey = ((Get-BitLockerVolume -MountPoint C).KeyProtector).RecoveryPassword
        $ask = read-host "Do you want to display the recovery key? (Y/N)"
        if ($ask -eq "Y") {
            Write-Host "Recovery Key: $recoveryKey" -ForegroundColor Yellow
        } else {
            Write-Host "Recovery key will not be displayed. Please ensure you have saved it securely."
        }
    }
    else {
        Enable-BitLocker -MountPoint "C:" -EncryptionMethod XTSAES256 -UsedSpaceOnly -RecoveryPasswordProtector *>$null
        Write-Host "BitLocker encryption initiated for C: drive with Recovery Key Protector. Please wait for the process to complete."
        $recoveryKey2 = ((Get-BitLockerVolume -MountPoint C).KeyProtector).RecoveryPassword
        $ask = read-host "Do you want to display the recovery key? (Y/N)"
        if ($ask -eq "Y") {
            Write-Host "Recovery Key: $recoveryKey2" -ForegroundColor Yellow
        } else {
            Write-Host "Recovery key will not be displayed. Please ensure you have saved it securely."
        }
    }
}

# Call the AppLocker whitelist function
Create-AppLockerWhitelist

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force
write-host "All changes have been made to harden Windows. A system restart is required for all changes to take effect."
write-host "Type 'Y' to restart the computer now or 'N' to exit without restarting."
$response = read-host "Restart now? (Y/N)"
if ($response -eq "Y") {
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
