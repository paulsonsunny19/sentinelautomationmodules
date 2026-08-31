targetScope = 'resourceGroup'

@description('System Assigned Managed Identity object ID for the STAT Next Function App.')
param functionPrincipalId string

var sentinelPlaybookOperatorRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '51d6186e-6489-4900-b93f-92e23144cca5')

resource playbookOperator 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, functionPrincipalId, 'stat-run-playbook-operator')
  properties: {
    roleDefinitionId: sentinelPlaybookOperatorRole
    principalId: functionPrincipalId
    principalType: 'ServicePrincipal'
  }
}
