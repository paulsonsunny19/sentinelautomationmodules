targetScope = 'resourceGroup'

@description('Use the same Name Prefix as the STAT Next core deployment.')
@minLength(5)
param namePrefix string
param location string = resourceGroup().location
@description('Subscription containing the Sentinel workspace.')
param sentinelSubscriptionId string = subscription().subscriptionId
@description('Resource group containing the Sentinel workspace.')
param sentinelResourceGroup string
@description('Log Analytics workspace used by Microsoft Sentinel.')
param sentinelWorkspaceName string

var functionName = '${namePrefix}-api'
var playbookName = '${namePrefix}-incident-triage'

resource functionApp 'Microsoft.Web/sites@2022-09-01' existing = {
  name: functionName
}

// Stage 2: create the Logic App separately from STAT Next core.  The workflow
// remains disabled during creation so its managed identity can be granted the
// Sentinel Responder role before an analyst enables/registers the webhook.
module playbook 'playbook.bicep' = {
  name: 'statNextIncidentPlaybook'
  params: {
    name: playbookName
    location: location
    functionAppName: functionApp.name
  }
}

module playbookRbac 'workspace-rbac.bicep' = {
  name: 'statNextPlaybookRbac'
  scope: resourceGroup(sentinelSubscriptionId, sentinelResourceGroup)
  params: {
    workspaceName: sentinelWorkspaceName
    functionPrincipalId: functionApp.identity.principalId
    playbookPrincipalId: playbook.outputs.principalId
  }
}

output playbookName string = playbook.outputs.playbookName
output playbookPrincipalId string = playbook.outputs.principalId
output playbookState string = playbook.outputs.bootstrapState
output nextStep string = 'After deployment succeeds and RBAC propagates, enable the Logic App in Azure Portal to register the Sentinel incident webhook.'
