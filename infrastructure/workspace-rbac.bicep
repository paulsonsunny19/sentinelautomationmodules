targetScope = 'resourceGroup'

param workspaceName string
param functionPrincipalId string
param playbookPrincipalId string = ''

var logAnalyticsReaderRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions','73c42c96-874c-492b-b04d-ab87d138a893')
var sentinelReaderRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions','8d289c81-5878-46d4-8554-54e1e3d8b5cb')
var sentinelResponderRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions','3e150937-b8fe-4cfb-8069-0eaf05ecd056')

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource logReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(workspace.id, functionPrincipalId, 'log-reader')
  scope: workspace
  properties: {
    roleDefinitionId: logAnalyticsReaderRole
    principalId: functionPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource sentinelReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(workspace.id, functionPrincipalId, 'sentinel-reader')
  scope: workspace
  properties: {
    roleDefinitionId: sentinelReaderRole
    principalId: functionPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource playbookResponder 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(playbookPrincipalId)) {
  name: guid(workspace.id, playbookPrincipalId, 'sentinel-responder')
  scope: workspace
  properties: {
    roleDefinitionId: sentinelResponderRole
    principalId: playbookPrincipalId
    principalType: 'ServicePrincipal'
  }
}
