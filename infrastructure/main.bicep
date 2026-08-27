targetScope = 'resourceGroup'

@description('Globally unique base name for STAT Next resources.')
@minLength(5)
param namePrefix string = 'statnext${uniqueString(resourceGroup().id)}'
param location string = resourceGroup().location
@description('Subscription containing the Sentinel workspace.')
param sentinelSubscriptionId string = subscription().subscriptionId
@description('Resource group containing the Sentinel workspace.')
param sentinelResourceGroup string
@description('Log Analytics workspace used by Microsoft Sentinel.')
param sentinelWorkspaceName string
@description('Public source URL used only to stage the validated package into private Azure Blob Storage.')
param packageUri string
@description('Optional tenant-specific Defender for Cloud Apps API/portal URL from Defender portal > Settings > Cloud Apps > System > About. Leave empty to deploy MDCA in ConfigurationRequired mode.')
param defenderCloudAppsApiUrl string = ''

var storageName = take(replace(toLower(namePrefix), '-', ''), 24)
var planName = '${namePrefix}-plan'
var functionName = '${namePrefix}-api'
var insightsName = '${namePrefix}-appi'
var workbookName = guid(resourceGroup().id, namePrefix, 'status-workbook')
var packageContainerName = 'statnext-package'
var packageBlobName = 'stat-next.zip'
var privatePackageUri = '${storage.properties.primaryEndpoints.blob}${packageContainerName}/${packageBlobName}'
var stagingIdentityName = '${take(namePrefix, 40)}-stage'
var storageBlobDataOwnerRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions','b7e6dc6d-f1e8-4753-8033-0f276bb0955b')
var storageBlobDataReaderRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions','2a2b9908-6ea1-4ae2-8e65-a410df84e7d1')
var storageBlobDataContributorRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions','ba92f5b4-2d11-453d-a403-e96b0029c9fe')

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: { allowBlobPublicAccess: false, allowCrossTenantReplication: false, minimumTlsVersion: 'TLS1_2', supportsHttpsTrafficOnly: true, defaultToOAuthAuthentication: true, publicNetworkAccess: 'Enabled' }
}
resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = { parent: storage, name: 'default' }
resource packageContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = { parent: blobService, name: packageContainerName, properties: { publicAccess: 'None' } }
resource stagingIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = { name: stagingIdentityName, location: location }
resource stagingWriter 'Microsoft.Authorization/roleAssignments@2022-04-01' = { name: guid(storage.id, stagingIdentity.id, 'package-stage-writer'), scope: storage, properties: { roleDefinitionId: storageBlobDataContributorRole, principalId: stagingIdentity.properties.principalId, principalType: 'ServicePrincipal' } }
resource stagePackage 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: 'StageSTATNextPackage'
  location: location
  kind: 'AzureCLI'
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${stagingIdentity.id}': {} } }
  properties: {
    azCliVersion: '2.67.0'
    timeout: 'PT15M'
    cleanupPreference: 'OnSuccess'
    retentionInterval: 'P1D'
    forceUpdateTag: packageUri
    environmentVariables: [ { name: 'SOURCE_URI', value: packageUri }, { name: 'STORAGE_ACCOUNT', value: storage.name }, { name: 'CONTAINER', value: packageContainerName }, { name: 'BLOB_NAME', value: packageBlobName } ]
    scriptContent: '''
      set -euo pipefail
      az storage blob copy start --account-name "$STORAGE_ACCOUNT" --destination-container "$CONTAINER" --destination-blob "$BLOB_NAME" --source-uri "$SOURCE_URI" --auth-mode login --only-show-errors
      for i in $(seq 1 60); do
        status=$(az storage blob show --account-name "$STORAGE_ACCOUNT" --container-name "$CONTAINER" --name "$BLOB_NAME" --auth-mode login --query properties.copy.status -o tsv 2>/dev/null || true)
        if [ "$status" = "success" ]; then exit 0; fi
        if [ "$status" = "failed" ] || [ "$status" = "aborted" ]; then echo "Package staging failed: $status" >&2; exit 1; fi
        sleep 5
      done
      echo "Timed out waiting for package staging" >&2
      exit 1
    '''
  }
  dependsOn: [packageContainer, stagingWriter]
}
resource insights 'Microsoft.Insights/components@2020-02-02' = { name: insightsName, location: location, kind: 'web', properties: { Application_Type: 'web' } }
resource plan 'Microsoft.Web/serverfarms@2022-09-01' = { name: planName, location: location, sku: { name: 'Y1', tier: 'Dynamic' }, kind: 'linux', properties: { reserved: true } }
resource functionApp 'Microsoft.Web/sites@2022-09-01' = { name: functionName, location: location, kind: 'functionapp,linux', identity: { type: 'SystemAssigned' }, properties: { serverFarmId: plan.id, httpsOnly: true, clientAffinityEnabled: false, siteConfig: { linuxFxVersion: 'PYTHON|3.12', minTlsVersion: '1.2', ftpsState: 'Disabled', http20Enabled: true } }, dependsOn: [stagePackage] }
resource hostStorageRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = { name: guid(storage.id, functionApp.id, 'host-storage'), scope: storage, properties: { roleDefinitionId: storageBlobDataOwnerRole, principalId: functionApp.identity.principalId, principalType: 'ServicePrincipal' } }
resource packageReaderRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = { name: guid(storage.id, functionApp.id, 'package-reader'), scope: storage, properties: { roleDefinitionId: storageBlobDataReaderRole, principalId: functionApp.identity.principalId, principalType: 'ServicePrincipal' } }

// Core deployment intentionally excludes the Sentinel Logic App connector.
// The playbook is installed separately after the Function identity and core
// Sentinel RBAC are healthy, so a transient Logic Apps connector outage cannot
// fail the STAT Next platform deployment.
module workspaceRbac 'workspace-rbac.bicep' = { name: 'statNextWorkspaceRbac', scope: resourceGroup(sentinelSubscriptionId, sentinelResourceGroup), params: { workspaceName: sentinelWorkspaceName, functionPrincipalId: functionApp.identity.principalId } }

resource appSettings 'Microsoft.Web/sites/config@2022-09-01' = {
  parent: functionApp
  name: 'appsettings'
  properties: union({ FUNCTIONS_EXTENSION_VERSION: '~4', FUNCTIONS_WORKER_RUNTIME: 'python', APPLICATIONINSIGHTS_CONNECTION_STRING: insights.properties.ConnectionString, AzureWebJobsStorage__accountName: storage.name, AzureWebJobsStorage__credential: 'managedidentity', AzureWebJobsStorage__blobServiceUri: storage.properties.primaryEndpoints.blob, AzureWebJobsStorage__queueServiceUri: storage.properties.primaryEndpoints.queue, AzureWebJobsStorage__tableServiceUri: storage.properties.primaryEndpoints.table, WEBSITE_RUN_FROM_PACKAGE: privatePackageUri, WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID: 'SystemAssigned' }, empty(defenderCloudAppsApiUrl) ? {} : { STAT_MCAS_PORTAL_URL: defenderCloudAppsApiUrl })
  dependsOn: [hostStorageRole, packageReaderRole, workspaceRbac]
}
resource ftpPolicy 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2022-09-01' = { parent: functionApp, name: 'ftp', properties: { allow: false } }
resource scmPolicy 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2022-09-01' = { parent: functionApp, name: 'scm', properties: { allow: false } }
resource workbook 'Microsoft.Insights/workbooks@2023-06-01' = { name: workbookName, location: location, kind: 'shared', properties: { displayName: 'Sentinel Triage AssistanT Next - Status', serializedData: loadTextContent('../workbook/stat-next.workbook.json'), version: '1.0', sourceId: insights.id, category: 'workbook', description: 'STAT Next sample operational workbook based on the original STAT Status workbook.' }, dependsOn: [functionApp, insights, workspaceRbac] }

output functionName string = functionApp.name
output functionPrincipalId string = functionApp.identity.principalId
output storageAccountName string = storage.name
output packageBlobUri string = privatePackageUri
output workbookName string = workbook.name
output defenderCloudAppsConfigured bool = !empty(defenderCloudAppsApiUrl)
output playbookDeployment string = 'Deploy infrastructure/playbook-main.json after the core deployment succeeds.'
