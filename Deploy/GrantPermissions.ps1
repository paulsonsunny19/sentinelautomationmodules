<#
STAT v2 post-deployment permissions helper.
Based on briandelmsft/SentinelAutomationModules.
Run the upstream-maintained permission script from Azure Cloud Shell after deployment:
  Invoke-WebRequest -Uri https://aka.ms/mstatgrantscript -OutFile GrantPermissions.ps1
  .\GrantPermissions.ps1

The upstream script grants Microsoft Sentinel Responder plus the Microsoft Graph / Defender application permissions required by STAT.
#>
param()
Write-Host "Download and run the current Microsoft STAT permissions script:" -ForegroundColor Cyan
Write-Host "Invoke-WebRequest -Uri https://aka.ms/mstatgrantscript -OutFile GrantPermissions.ps1"
Write-Host ".\GrantPermissions.ps1"
