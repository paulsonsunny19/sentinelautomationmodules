# STAT Next - tenant API permissions for the Function App managed identity
# Run as a tenant administrator after the core deployment creates the Function identity.
# Requires Microsoft Graph PowerShell or Azure CLI with permission to create app-role assignments.
#
# This intentionally grants only permissions used by the current implementation:
#   Microsoft Graph: IdentityRiskyUser.Read.All
#   WindowsDefenderATP: AdvancedQuery.Read.All, Machine.Read.All
#
# Usage:
#   ./grant-api-permissions.ps1 -FunctionPrincipalId '<managed-identity-object-id>'

[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(Mandatory=$true)]
  [ValidatePattern('^[0-9a-fA-F-]{36}$')]
  [string]$FunctionPrincipalId
)

$ErrorActionPreference = 'Stop'

function Get-ServicePrincipalByAppId([string]$appId) {
  $sp = az ad sp list --filter "appId eq '$appId'" --query '[0]' -o json | ConvertFrom-Json
  if (-not $sp -or -not $sp.id) { throw "Service principal for appId $appId was not found in this tenant." }
  return $sp
}

function Grant-AppRole([string]$resourceAppId, [string]$roleValue) {
  $resource = Get-ServicePrincipalByAppId $resourceAppId
  $role = @($resource.appRoles | Where-Object { $_.value -eq $roleValue -and $_.allowedMemberTypes -contains 'Application' })[0]
  if (-not $role) { throw "Application role '$roleValue' was not exposed by resource $resourceAppId." }

  $existing = az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/$FunctionPrincipalId/appRoleAssignments" -o json | ConvertFrom-Json
  $match = @($existing.value | Where-Object { $_.resourceId -eq $resource.id -and $_.appRoleId -eq $role.id })
  if ($match.Count -gt 0) {
    Write-Host "Already granted: $roleValue"
    return
  }

  if ($PSCmdlet.ShouldProcess($FunctionPrincipalId, "Grant $roleValue on $($resource.displayName)")) {
    $body = @{ principalId=$FunctionPrincipalId; resourceId=$resource.id; appRoleId=$role.id } | ConvertTo-Json -Compress
    az rest --method POST --url "https://graph.microsoft.com/v1.0/servicePrincipals/$FunctionPrincipalId/appRoleAssignments" --headers 'Content-Type=application/json' --body $body --output none
    Write-Host "Granted: $roleValue"
  }
}

# Microsoft Graph
Grant-AppRole '00000003-0000-0000-c000-000000000000' 'IdentityRiskyUser.Read.All'

# Microsoft Defender for Endpoint / WindowsDefenderATP
$defender = az ad sp list --filter "displayName eq 'WindowsDefenderATP'" --query '[0]' -o json | ConvertFrom-Json
if (-not $defender -or -not $defender.appId) { throw 'WindowsDefenderATP enterprise application was not found in this tenant.' }
Grant-AppRole $defender.appId 'AdvancedQuery.Read.All'
Grant-AppRole $defender.appId 'Machine.Read.All'

Write-Host 'STAT Next Function API permissions are configured.'
