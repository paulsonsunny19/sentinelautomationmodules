# STAT permission setup
# This compatibility branch preserves the upstream STAT deployment architecture.
# Run the official upstream permission script after deployment:
# https://github.com/briandelmsft/SentinelAutomationModules/blob/main/Deploy/GrantPermissions.ps1
#
# The script is intentionally referenced rather than modified so Entra ID and Azure
# permission behavior remains aligned with the upstream STAT release.
Write-Host 'Use the official STAT GrantPermissions.ps1 from briandelmsft/SentinelAutomationModules main branch.'
Write-Host 'https://github.com/briandelmsft/SentinelAutomationModules/blob/main/Deploy/GrantPermissions.ps1'
