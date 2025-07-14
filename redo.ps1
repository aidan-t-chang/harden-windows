<#
.SYNOPSIS
    Resets (re-enables) access to Command Prompt, Registry Editor, and PowerShell.

.DESCRIPTION
    This script reverses the common hardening steps for disabling Command Prompt,
    Registry Editor, and PowerShell.

    - Re-enables Command Prompt by removing the 'DisableCMD' registry value.
    - Re-enables Registry Editor by removing the 'DisableRegistryTools' registry value.
    - Re-enables PowerShell by removing specific AppLocker Publisher rules for
      powershell.exe and powershell_ise.exe (assuming they were created with
      descriptions like "Deny PowerShell.exe via Hardening Script").

.NOTES
    - Must be run with Administrator privileges.
    - The affected user(s) must log off and log back on for changes to take effect.
    - AppLocker changes are machine-wide.
    - Command Prompt and Registry Editor changes apply to HKCU (current user
      or the user under which context the script is run if not targeting specific hives).
#>
param(
    [switch]$Force # Optional switch to suppress some confirmation prompts if any were added later
)

function Test-IsAdmin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- 1. Check for Administrative Privileges ---
If (-not (Test-IsAdmin)) {
    Write-Warning "This script must be run with Administrator privileges. Please re-run."
    Exit 1 # Exit with an error code
}

Write-Host "Starting reset process for Command Prompt, Registry Editor, and PowerShell..."
Write-Host "------------------------------------------------------------------------"

# --- 2. Re-enable Command Prompt ---
Write-Host "`n-- Re-enabling Command Prompt --"
$regPathCMD = "HKCU:\Software\Policies\Microsoft\Windows\System"
try {
    if (Test-Path -Path $regPathCMD) {
        Remove-ItemProperty -Path $regPathCMD -Name "DisableCMD" -ErrorAction SilentlyContinue
        Write-Host "Command Prompt 'DisableCMD' registry value removed."
    } else {
        Write-Host "Command Prompt policy path '$regPathCMD' does not exist. No action needed."
    }
}
catch {
    Write-Error "Failed to re-enable Command Prompt. Error: $($_.Exception.Message)"
}

# --- 3. Re-enable Registry Editor ---
Write-Host "`n-- Re-enabling Registry Editor --"
$regPathRegedit = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
try {
    if (Test-Path -Path $regPathRegedit) {
        Remove-ItemProperty -Path $regPathRegedit -Name "DisableRegistryTools" -ErrorAction SilentlyContinue
        Write-Host "Registry Editor 'DisableRegistryTools' registry value removed."
    } else {
        Write-Host "Registry Editor policy path '$regPathRegedit' does not exist. No action needed."
    }
}
catch {
    Write-Error "Failed to re-enable Registry Editor. Error: $($_.Exception.Message)"
}

# --- 4. Re-enable PowerShell (via AppLocker) ---
Write-Host "`n-- Re-enabling PowerShell via AppLocker --"

# Ensure the Application Identity service is running
try {
    Write-Host "Ensuring 'Application Identity' service is running and set to Automatic..."
    Get-Service -Name "AppIDSvc" | Set-Service -StartupType Automatic -PassThru | Start-Service -ErrorAction Stop
}
catch {
    Write-Error "Failed to start Application Identity service, AppLocker changes might not apply. Error: $($_.Exception.Message)"
}

try {
    # Get the current AppLocker policy for Executable and DLL rules
    $currentPolicy = Get-AppLockerPolicy -Scope Effective -RuleCollectionType Exe, Dll -ErrorAction Stop

    Write-Host "Checking for existing PowerShell deny rules..."

    # Define common descriptions used by the previous hardening script
    $powershellDenyDescriptions = @(
        "Deny PowerShell.exe via Hardening Script",
        "Deny PowerShell_ISE.exe via Hardening Script",
        "Deny PowerShell.exe", # General description if you used simpler ones
        "Deny PowerShell_ISE.exe"
    )

    # Filter out the PowerShell deny rules based on description
    $updatedRules = $currentPolicy.PolicyRules | Where-Object {
        ($_.RuleCollectionName -eq 'AppLocker\EXE') -and `
        ($_.Action -eq 'Deny') -and `
        ($_.Description -in $powershellDenyDescriptions)
    }

    if ($updatedRules.Count -gt 0) {
        Write-Host "Found $($updatedRules.Count) PowerShell deny rules to remove."
        # Create a new policy object with all *other* rules
        $rulesToKeep = $currentPolicy.PolicyRules | Where-Object {
            ($_.Description -notin $powershellDenyDescriptions) -or `
            ($_.RuleCollectionName -ne 'AppLocker\EXE') -or `
            ($_.Action -ne 'Deny')
        }

        # It's crucial to explicitly specify RuleCollectionType when creating a new policy,
        # and ensure you are passing all desired rules (including default ones)
        # to avoid accidentally clearing other unrelated rules.
        # This approach builds a new policy from the rules to keep.
        $newPolicyObject = New-AppLockerPolicy -Rule $rulesToKeep -Service EnforcementMode -RuleCollectionType Exe, Dll

        # Set the updated policy
        Set-AppLockerPolicy -PolicyObject $newPolicyObject -RuleCollectionType Exe -EnforcementMode Enforced -ErrorAction Stop
        Set-AppLockerPolicy -PolicyObject $newPolicyObject -RuleCollectionType Dll -EnforcementMode Enforced -ErrorAction Stop

        Write-Host "Specific AppLocker rules for PowerShell removed."
    } else {
        Write-Host "No PowerShell deny rules (with expected descriptions) found in AppLocker policy. No action needed."
    }
}
catch {
    Write-Error "Failed to modify AppLocker policy for PowerShell. Error: $($_.Exception.Message)"
    Write-Host "AppLocker might not be configured, or there's an issue with the service/permissions."
}

Get-NetAdapter | Enable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor" -Name "Start" -Value 3

# Option 1: Delete the AllowCortana registry value
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -ErrorAction SilentlyContinue

# Option 2: Change the AllowCortana value to 1 (if the key still exists)
# New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -PropertyType DWORD -Value 1 -Force
Write-Host "`n------------------------------------------------------------------------"
Write-Host "Reset process completed."
Write-Host "!!! IMPORTANT: The user must LOG OFF and LOG BACK ON for all changes to take effect !!!"

Restart-Computer -Force