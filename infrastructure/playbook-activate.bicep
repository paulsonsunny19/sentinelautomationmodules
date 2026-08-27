targetScope = 'resourceGroup'

@description('Use the same Name Prefix as the STAT Next core and playbook bootstrap deployments.')
@minLength(5)
param namePrefix string
param location string = resourceGroup().location
@description('Subscription containing the Microsoft Sentinel workspace.')
param sentinelSubscriptionId string = subscription().subscriptionId
@description('Resource group containing the Microsoft Sentinel workspace.')
param sentinelResourceGroup string
@description('Log Analytics workspace used by Microsoft Sentinel.')
param sentinelWorkspaceName string

var functionName = '${namePrefix}-api'
var playbookName = '${namePrefix}-incident-triage'
var sentinelConnectionName = '${playbookName}-sentinel'
var sentinelManagedApiId = subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
var incidentContextUri = 'https://${functionApp.properties.defaultHostName}/api/incident_context'

resource functionApp 'Microsoft.Web/sites@2022-09-01' existing = {
  name: functionName
}

resource bootstrapPlaybook 'Microsoft.Logic/workflows@2019-05-01' existing = {
  name: playbookName
}

resource sentinelConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: sentinelConnectionName
  location: location
  kind: 'V1'
  properties: {
    displayName: sentinelConnectionName
    customParameterValues: {}
    parameterValueType: 'Alternative'
    api: {
      id: sentinelManagedApiId
    }
  }
}

resource activatedPlaybook 'Microsoft.Logic/workflows@2019-05-01' = {
  name: playbookName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        '$connections': {
          type: 'Object'
          defaultValue: {}
        }
        ProjectName: {
          type: 'String'
          defaultValue: 'STATNext'
        }
        PlaybookVersion: {
          type: 'String'
          defaultValue: '1.1.2'
        }
      }
      triggers: {
        When_Microsoft_Sentinel_incident_was_created: {
          type: 'ApiConnectionWebhook'
          inputs: {
            body: {
              callback_url: '@{listCallbackUrl()}'
            }
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
              }
            }
            path: '/incident-creation'
          }
        }
      }
      actions: {
        Get_STAT_Next_incident_context: {
          type: 'Http'
          runAfter: {}
          inputs: {
            method: 'POST'
            uri: incidentContextUri
            headers: {
              'Content-Type': 'application/json'
            }
            body: {
              subscriptionId: sentinelSubscriptionId
              resourceGroup: sentinelResourceGroup
              workspaceName: sentinelWorkspaceName
              incidentId: '@{last(split(triggerBody()?[\'object\']?[\'id\'], \'/\'))}'
            }
            authentication: {
              type: 'ManagedServiceIdentity'
              audience: 'https://management.azure.com/'
            }
          }
        }
        Add_STAT_Next_comment_to_incident: {
          type: 'ApiConnection'
          runAfter: {
            Get_STAT_Next_incident_context: [
              'Succeeded'
            ]
          }
          inputs: {
            body: {
              incidentArmId: '@triggerBody()?[\'object\']?[\'id\']'
              message: '@{concat(\'STAT Next triage completed. Correlation ID: \', body(\'Get_STAT_Next_incident_context\')?[\'correlationId\'])}'
            }
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/Incidents/Comment'
          }
        }
      }
      outputs: {}
    }
    parameters: {
      '$connections': {
        value: {
          azuresentinel: {
            connectionId: sentinelConnection.id
            connectionName: sentinelConnection.name
            id: sentinelManagedApiId
            connectionProperties: {
              authentication: {
                type: 'ManagedServiceIdentity'
              }
            }
          }
        }
      }
    }
  }
  dependsOn: [
    sentinelConnection
    bootstrapPlaybook
  ]
}

output playbookName string = activatedPlaybook.name
output playbookState string = 'Enabled'
output sentinelConnectionName string = sentinelConnection.name
output sentinelWorkspace string = sentinelWorkspaceName
