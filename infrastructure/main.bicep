targetScope = 'resourceGroup'

@description('Globally unique base name for STAT Next resources.')
@minLength(5)
param namePrefix string = 'statnext${uniqueString(resourceGroup().id)}'
param location string = resourceGroup().location
@description('Resource ID of the Log Analytics workspace used by Microsoft Sentinel.')
param sentinelWorkspaceResourceId string

var storageName = take(replace(toLower(namePrefix), '-', ''), 24)
var planName = '${namePrefix}-plan'
var functionName = '${namePrefix}-api'
var insightsName = '${namePrefix}-appi'
var storageBlobDataOwnerRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions','b7e6dc6d-f1e8-4753-8033-0f276bb0955b')
var logAnalyticsReaderRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions','73c42c96-874c-492b-b04d-ab87d138a893')
var sentinelReaderRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions','8d289c81-5878-46d4-8554-54e1e3d8b5cb')

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    allowCrossTenantReplication: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    defaultToOAuthAuthentication: true
    publicNetworkAccess: 'Enabled'
  }
}

resource insights 'Microsoft.Insights/components@2020-02-02' = {
  name: insightsName
  location: location
  kind: 'web'
  properties: { Application_Type: 'web' }
}

resource plan 'Microsoft.Web/serverfarms@2022-09-01' = {
  name: planName
  location: location
  sku: { name: 'Y1', tier: 'Dynamic' }
  kind: 'linux'
  properties: { reserved: true }
}

resource functionApp 'Microsoft.Web/sites@2022-09-01' = {
  name: functionName
  location: location
  kind: 'functionapp,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    clientAffinityEnabled: false
    siteConfig: {
      linuxFxVersion: 'PYTHON|3.12'
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      http20Enabled: true
      appSettings: [
        { name: 'FUNCTIONS_EXTENSION_VERSION', value: '~4' }
        { name: 'FUNCTIONS_WORKER_RUNTIME', value: 'python' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: insights.properties.ConnectionString }
        { name: 'AzureWebJobsStorage__accountName', value: storage.name }
        { name: 'AzureWebJobsStorage__credential', value: 'managedidentity' }
        { name: 'AzureWebJobsStorage__blobServiceUri', value: storage.properties.primaryEndpoints.blob }
        { name: 'AzureWebJobsStorage__queueServiceUri', value: storage.properties.primaryEndpoints.queue }
        { name: 'AzureWebJobsStorage__tableServiceUri', value: storage.properties.primaryEndpoints.table }
      ]
    }
  }
}

resource hostStorageRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, functionApp.id, 'host-storage')
  scope: storage
  properties: {
    roleDefinitionId: storageBlobDataOwnerRole
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  scope: resourceGroup(split(sentinelWorkspaceResourceId, '/')[4], split(sentinelWorkspaceResourceId, '/')[8])
  name: split(sentinelWorkspaceResourceId, '/')[8]
}

resource logReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(sentinelWorkspaceResourceId, functionApp.id, 'log-reader')
  scope: workspace
  properties: { roleDefinitionId: logAnalyticsReaderRole, principalId: functionApp.identity.principalId, principalType: 'ServicePrincipal' }
}

resource sentinelReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(sentinelWorkspaceResourceId, functionApp.id, 'sentinel-reader')
  scope: workspace
  properties: { roleDefinitionId: sentinelReaderRole, principalId: functionApp.identity.principalId, principalType: 'ServicePrincipal' }
}

resource ftpPolicy 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2022-09-01' = { parent: functionApp, name: 'ftp', properties: { allow: false } }
resource scmPolicy 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2022-09-01' = { parent: functionApp, name: 'scm', properties: { allow: false } }

output functionName string = functionApp.name
output functionPrincipalId string = functionApp.identity.principalId
output storageAccountName string = storage.name
