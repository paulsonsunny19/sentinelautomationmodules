param name string
param location string
param functionAppName string

var sentinelConnectionName = '${name}-sentinel'
var sentinelManagedApiId = subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')

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

resource playbook 'Microsoft.Logic/workflows@2019-05-01' = {
  name: name
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
          defaultValue: '1.0.0'
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
          type: 'Function'
          runAfter: {}
          inputs: {
            body: {
              subscriptionId: '@{triggerBody()?[\'object\']?[\'id\']?[1]}'
              resourceGroup: '@{triggerBody()?[\'workspaceInfo\']?[\'ResourceGroupName\']}'
              workspaceName: '@{triggerBody()?[\'workspaceInfo\']?[\'WorkspaceName\']}'
              incidentId: '@{last(split(triggerBody()?[\'object\']?[\'id\'], \'/\'))}'
            }
            function: {
              id: resourceId('Microsoft.Web/sites/functions', functionAppName, 'incident_context')
            }
            method: 'POST'
          }
        }
        Add_STAT_Next_comment_to_incident: {
          type: 'ApiConnection'
          runAfter: {
            Get_STAT_Next_incident_context: [ 'Succeeded' ]
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
  dependsOn: [sentinelConnection]
}

output principalId string = playbook.identity.principalId
output resourceId string = playbook.id
output playbookName string = playbook.name
