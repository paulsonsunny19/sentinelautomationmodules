# STAT Next - tenant API permissions for the Function App managed identity
# Run as a tenant administrator after the core deployment creates the Function identity.
# Requires Azure CLI with permission to create Microsoft Graph app-role assignments.
#
# Microsoft Graph application permissions used by modules/aad_risks.py / modules/oof.py:
#   User.Read.All                 - user profile lookup
#   IdentityRiskyUser.Read.All    - riskyUsers
#   IdentityRiskEvent.Read.All    - riskDetections
#   AuditLog.Read.All             - authenticationMethods userRegistrationDetails
#   RoleManagement.Read.Directory - directory role assignments/definitions
#   MailboxSettings.Read          - automatic-replies / OOF status (optional OOFModule)
#
# Additional optional service permissions:
#   WindowsDefenderATP: AdvancedQuery.Read.All, Machine.Read.All
#   Microsoft Cloud App Security: Investigation.Read
#
# All permissions granted here are read-only. No client secret is created: the Azure
# Function uses its system-assigned managed identity to obtain OAuth tokens.
#
# Usage:
#   ./grant-api-permissions.ps1 -FunctionPrincipalId '<managed-identity-object-id>'

[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(Mandatory=$true)]
  [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
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
  $role = @($resource.appRoles | Where-Object { $_.value -ieq $roleValue -and $_.allowedMemberTypes -contains 'Application' })[0]
  if (-not $role) { throw "Application role '$roleValue' was not exposed by resource $resourceAppId ($($resource.displayName))." }

  $existing = az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/$FunctionPrincipalId/appRoleAssignments" -o json | ConvertFrom-Json
  $match = @($existing.value | Where-Object { $_.resourceId -eq $resource.id -and $_.appRoleId -eq $role.id })
  if ($match.Count -gt 0) {
    Write-Host "Already granted: $roleValue on $($resource.displayName)"
    return
  }

  if ($PSCmdlet.ShouldProcess($FunctionPrincipalId, "Grant $roleValue on $($resource.displayName)")) {
    $body = @{ principalId=$FunctionPrincipalId; resourceId=$resource.id; appRoleId=$role.id } | ConvertTo-Json -Compress
    az rest --method POST --url "https://graph.microsoft.com/v1.0/servicePrincipals/$FunctionPrincipalId/appRoleAssignments" --headers 'Content-Type=application/json' --body $body --output none
    Write-Host "Granted: $roleValue on $($resource.displayName)"
  }
}

$graphAppId = '00000003-0000-0000-c000-000000000000'

# Microsoft Graph / Entra identity and optional OOF enrichment. These are the
# least-privileged application permissions documented for the Graph endpoints
# STAT Next calls.
Grant-AppRole $graphAppId 'User.Read.All'
Grant-AppRole $graphAppId 'IdentityRiskyUser.Read.All'
Grant-AppRole $graphAppId 'IdentityRiskEvent.Read.All'
Grant-AppRole $graphAppId 'AuditLog.Read.All'
Grant-AppRole $graphAppId 'RoleManagement.Read.Directory'
Grant-AppRole $graphAppId 'MailboxSettings.Read'

# Microsoft Defender for Endpoint / WindowsDefenderATP
$defender = az ad sp list --filter "displayName eq 'WindowsDefenderATP'" --query '[0]' -o json | ConvertFrom-Json
if (-not $defender -or -not $defender.appId) { throw 'WindowsDefenderATP enterprise application was not found in this tenant.' }
Grant-AppRole $defender.appId 'AdvancedQuery.Read.All'
Grant-AppRole $defender.appId 'Machine.Read.All'

# Microsoft Defender for Cloud Apps. Investigation.Read is sufficient for the
# read-only entities/investigation operations used by the STAT MCAS module.
Grant-AppRole '05a65629-4c1b-48c1-a78b-804c4abdd4af' 'Investigation.Read'

Write-Host 'STAT Next Function API permissions are configured.'
