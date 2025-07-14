# Invoke-WebRequest -Uri "https://dl.google.com/dl/edgedl/chrome/policy/policy_templates.zip" -OutFile "C:\Windows\Temp\policy_templates.zip" 
# Expand-Archive -Path "C:\Windows\Temp\policy_templates.zip" -DestinationPath "C:\Windows\Temp\policy_templates" -Force
$admPath = "Z:\policy_templates\windows\adm\en-US\chrome.adm"
$chromePolicyPath = "HKLM:\Software\Policies\Google\Chrome"
Set-ItemProperty -Path $chromePolicyPath -Name "ExtensionInstallBlocklist" -Value "*" -Force
