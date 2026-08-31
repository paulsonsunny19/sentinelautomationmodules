[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$SubscriptionId,
  [Parameter(Mandatory=$true)][string]$ResourceGroup,
  [Parameter(Mandatory=$true)][string]$FunctionAppName,
  [Parameter(Mandatory=$true)][string]$LogicAppName
)
$ErrorActionPreference = 'Stop'
az account set --subscription $SubscriptionId
$tenantId = az account show --query tenantId -o tsv
$logicPrincipalId = az resource show --resource-group $ResourceGroup --resource-type Microsoft.Logic/workflows --name $LogicAppName --query identity.principalId -o tsv
if (-not $logicPrincipalId) { throw 'Logic App system-assigned managed identity was not found.' }

$displayName = "STAT Next API - $FunctionAppName"
$app = az ad app list --display-name $displayName --query '[0]' -o json | ConvertFrom-Json
if (-not $app) {
  $app = az ad app create --display-name $displayName --sign-in-audience AzureADMyOrg -o json | ConvertFrom-Json
}
$appId = $app.appId
$appObjectId = $app.id
$identifierUri = "api://$appId"
az ad app update --id $appObjectId --identifier-uris $identifierUri | Out-Null

$apiRoleId = [guid]::NewGuid().Guid
$roleBody = @{
  appRoles = @(@{
    allowedMemberTypes = @('Application')
    description = 'Invoke the STAT Next protected API.'
    displayName = 'Invoke STAT Next API'
    id = $apiRoleId
    isEnabled = $true
    value = 'STAT.Invoke'
  })
} | ConvertTo-Json -Depth 8 -Compress
az rest --method PATCH --url "https://graph.microsoft.com/v1.0/applications/$appObjectId" --headers 'Content-Type=application/json' --body $roleBody --output none

$apiSp = az ad sp list --filter "appId eq '$appId'" --query '[0]' -o json | ConvertFrom-Json
if (-not $apiSp) { $apiSp = az ad sp create --id $appId -o json | ConvertFrom-Json }
$apiSpId = $apiSp.id
$existing = az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/$logicPrincipalId/appRoleAssignments" -o json | ConvertFrom-Json
$match = @($existing.value | Where-Object { $_.resourceId -eq $apiSpId -and $_.appRoleId -eq $apiRoleId })
if ($match.Count -eq 0) {
  $assignment = @{ principalId=$logicPrincipalId; resourceId=$apiSpId; appRoleId=$apiRoleId } | ConvertTo-Json -Compress
  az rest --method POST --url "https://graph.microsoft.com/v1.0/servicePrincipals/$logicPrincipalId/appRoleAssignments" --headers 'Content-Type=application/json' --body $assignment --output none
}

$auth = @{
  properties = @{
    platform = @{ enabled=$true; runtimeVersion='~1' }
    globalValidation = @{ requireAuthentication=$true; unauthenticatedClientAction='Return401' }
    identityProviders = @{
      azureActiveDirectory = @{
        enabled = $true
        registration = @{ openIdIssuer="https://sts.windows.net/$tenantId/v2.0"; clientId=$appId }
        validation = @{ allowedAudiences=@($identifierUri); defaultAuthorizationPolicy=@{ allowedApplications=@($logicPrincipalId) } }
      }
    }
    login = @{ tokenStore=@{ enabled=$false } }
  }
} | ConvertTo-Json -Depth 12 -Compress
$authUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Web/sites/$FunctionAppName/config/authsettingsV2?api-version=2022-03-01"
az rest --method PUT --url $authUrl --headers 'Content-Type=application/json' --body $auth --output none

Write-Host "STAT Function authentication configured."
Write-Host "STAT API audience: $identifierUri"
Write-Host "Logic App principal: $logicPrincipalId"
Write-Host "Next: deploy/update the playbook using this audience."
