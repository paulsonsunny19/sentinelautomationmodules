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
@description('Deployment nonce used to force a fresh package download. Leave the default for a new deployment; change it for an intentional package refresh.')
param packageDeploymentId string = utcNow('yyyyMMddHHmmss')
@description('Optional tenant-specific Defender for Cloud Apps API/portal URL from Defender portal > Settings > Cloud Apps > System > About. Leave empty to deploy MDCA in ConfigurationRequired mode.')
param defenderCloudAppsApiUrl string = ''

var storageName = take(replace(toLower(namePrefix), '-', ''), 24)
var planName = '${namePrefix}-plan'
var functionName = '${namePrefix}-api'
var insightsName = '${namePrefix}-appi'
var workbookName = guid(resourceGroup().id, namePrefix, 'status-workbook')
var packageContainerName = 'statnext-package'
var packageBlobName = 'stat-next-${packageDeploymentId}.zip'
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
    forceUpdateTag: packageDeploymentId
    environmentVariables: [ { name: 'SOURCE_URI', value: packageUri }, { name: 'STORAGE_ACCOUNT', value: storage.name }, { name: 'CONTAINER', value: packageContainerName }, { name: 'BLOB_NAME', value: packageBlobName } ]
    scriptContent: '''
      set -euo pipefail
      tmp=/tmp/stat-next.zip
      curl --fail --location --retry 3 --output "$tmp" "$SOURCE_URI"
      test -s "$tmp"
      python3 - <<'PY'
import zipfile
p='/tmp/stat-next.zip'
with zipfile.ZipFile(p) as z:
    names=set(z.namelist())
    if 'function_app.py' not in names:
        raise SystemExit('Invalid STAT package: function_app.py missing from ZIP root')
    data=z.read('function_app.py').decode('utf-8')
    required=['stat_base','stat_aad_risks','stat_related_alerts','stat_threat_intel','stat_watchlist','stat_kql','stat_mde','stat_ueba','stat_file','stat_mcas','stat_scoring']
    missing=[x for x in required if x not in data]
    if missing:
        raise SystemExit('Invalid/incomplete STAT package; missing routes: '+','.join(missing))
print('STAT package validation passed')
PY
      az storage blob upload --account-name "$STORAGE_ACCOUNT" --container-name "$CONTAINER" --name "$BLOB_NAME" --file "$tmp" --overwrite true --auth-mode login --only-show-errors
      az storage blob show --account-name "$STORAGE_ACCOUNT" --container-name "$CONTAINER" --name "$BLOB_NAME" --auth-mode login --query '{name:name,size:properties.contentLength}' -o json
    '''
  }
  dependsOn: [packageContainer, stagingWriter]
}
resource insights 'Microsoft.Insights/components@2020-02-02' = { name: insightsName, location: location, kind: 'web', properties: { Application_Type: 'web' } }
resource plan 'Microsoft.Web/serverfarms@2022-09-01' = { name: planName, location: location, sku: { name: 'Y1', tier: 'Dynamic' }, kind: 'linux', properties: { reserved: true } }
resource functionApp 'Microsoft.Web/sites@2022-09-01' = { name: functionName, location: location, kind: 'functionapp,linux', identity: { type: 'SystemAssigned' }, properties: { serverFarmId: plan.id, httpsOnly: true, clientAffinityEnabled: false, siteConfig: { linuxFxVersion: 'PYTHON|3.12', minTlsVersion: '1.2', ftpsState: 'Disabled', http20Enabled: true } }, dependsOn: [stagePackage] }
resource hostStorageRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = { name: guid(storage.id, functionApp.id, 'host-storage'), scope: storage, properties: { roleDefinitionId: storageBlobDataOwnerRole, principalId: functionApp.identity.principalId, principalType: 'ServicePrincipal' } }
resource packageReaderRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = { name: guid(storage.id, functionApp.id, 'package-reader'), scope: storage, properties: { roleDefinitionId: storageBlobDataReaderRole, principalId: functionApp.identity.principalId, principalType: 'ServicePrincipal' } }
module workspaceRbac 'workspace-rbac.bicep' = { name: 'statNextWorkspaceRbac', scope: resourceGroup(sentinelSubscriptionId, sentinelResourceGroup), params: { workspaceName: sentinelWorkspaceName, functionPrincipalId: functionApp.identity.principalId } }
resource appSettings 'Microsoft.Web/sites/config@2022-09-01' = {
  parent: functionApp
  name: 'appsettings'
  properties: union({ FUNCTIONS_EXTENSION_VERSION: '~4', FUNCTIONS_WORKER_RUNTIME: 'python', APPLICATIONINSIGHTS_CONNECTION_STRING: insights.properties.ConnectionString, AzureWebJobsStorage__accountName: storage.name, AzureWebJobsStorage__credential: 'managedidentity', AzureWebJobsStorage__blobServiceUri: storage.properties.primaryEndpoints.blob, AzureWebJobsStorage__queueServiceUri: storage.properties.primaryEndpoints.queue, AzureWebJobsStorage__tableServiceUri: storage.properties.primaryEndpoints.table, WEBSITE_RUN_FROM_PACKAGE: privatePackageUri, WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID: 'SystemAssigned' }, empty(defenderCloudAppsApiUrl) ? {} : { STAT_MCAS_PORTAL_URL: defenderCloudAppsApiUrl })
  dependsOn: [hostStorageRole, packageReaderRole, workspaceRbac]
}
resource ftpPolicy 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2022-09-01' = { parent: functionApp, name: 'ftp', properties: { allow: false } }
resource scmPolicy 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2022-09-01' = { parent: functionApp, name: 'scm', properties: { allow: false } }
resource workbook 'Microsoft.Insights/workbooks@2023-06-01' = { name: workbookName, location: location, kind: 'shared', properties: { displayName: 'Sentinel Triage AssistanT Next - Status', serializedData: loadTextContent('../workbook/stat-next.workbook.json'), version: '1.0', sourceId: insights.id, category: 'workbook', description: 'STAT Next operational workbook based on the original STAT Status workbook.' }, dependsOn: [functionApp, insights, workspaceRbac] }
output functionName string = functionApp.name
output functionPrincipalId string = functionApp.identity.principalId
output storageAccountName string = storage.name
output packageBlobUri string = privatePackageUri
output packageDeploymentId string = packageDeploymentId
output workbookName string = workbook.name
output defenderCloudAppsConfigured bool = !empty(defenderCloudAppsApiUrl)
output playbookDeployment string = 'Deploy infrastructure/playbook-activate.json only after the complete Function set is healthy.'
