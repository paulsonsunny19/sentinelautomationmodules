targetScope = 'resourceGroup'

@minLength(5)
param namePrefix string
param location string = resourceGroup().location
param sentinelSubscriptionId string = subscription().subscriptionId
param sentinelResourceGroup string
param sentinelWorkspaceName string
param sentinelWorkspaceId string
param enrichmentKql string = ''
param watchlistAlias string = ''
param watchlistKey string = 'SearchKey'
@allowed([
  'upn'
  'ip'
  'cidr'
  'fqdn'
])
param watchlistKeyDataType string = 'upn'
param mcasScoreThreshold int = 0
param lowScoreThreshold int = 10
param mediumScoreThreshold int = 30
param highScoreThreshold int = 60
param relatedAlertsLookbackDays int = 14
param relatedAlertsKqlFilter string = ''

var functionName = '${namePrefix}-api'
var playbookName = '${namePrefix}-incident-triage'
var sentinelConnectionName = '${playbookName}-sentinel'
var sentinelManagedApiId = subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
var functionBaseUri = 'https://${functionApp.properties.defaultHostName}/api'

resource functionApp 'Microsoft.Web/sites@2022-09-01' existing = {
  name: functionName
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
      contentVersion: '2.1.0.0'
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
          defaultValue: '2.1.0-full'
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
                name: '@parameters(''$connections'')[''azuresentinel''][''connectionId'']'
              }
            }
            path: '/incident-creation'
          }
        }
      }
      actions: {
        Get_incident_context: {
          type: 'Http'
          runAfter: {}
          inputs: {
            method: 'POST'
            uri: '${functionBaseUri}/incident_context'
            headers: {
              'Content-Type': 'application/json'
            }
            body: {
              subscriptionId: sentinelSubscriptionId
              resourceGroup: sentinelResourceGroup
              workspaceName: sentinelWorkspaceName
              incidentId: '@{last(split(triggerBody()?[''object'']?[''id''], ''/''))}'
            }
            authentication: {
              type: 'ManagedServiceIdentity'
              audience: environment().resourceManager
            }
          }
        }
        Build_STAT_Base: {
          type: 'Http'
          runAfter: {
            Get_incident_context: [
              'Succeeded'
            ]
          }
          inputs: {
            method: 'POST'
            uri: '${functionBaseUri}/stat_base'
            body: {
              entities: '@body(''Get_incident_context'')?[''entities'']'
              incidentArmId: '@triggerBody()?[''object'']?[''id'']'
              workspaceId: sentinelWorkspaceId
              tenantId: '@body(''Get_incident_context'')?[''tenantId'']'
            }
            authentication: {
              type: 'ManagedServiceIdentity'
              audience: environment().resourceManager
            }
          }
        }
        AAD_Risks: {
          type: 'Http'
          runAfter: {
            Build_STAT_Base: [
              'Succeeded'
            ]
          }
          inputs: {
            method: 'POST'
            uri: '${functionBaseUri}/stat_aad_risks'
            body: {
              workspaceId: sentinelWorkspaceId
              base: '@body(''Build_STAT_Base'')'
              lookbackDays: 14
            }
            authentication: {
              type: 'ManagedServiceIdentity'
              audience: environment().resourceManager
            }
          }
        }
        Related_Alerts: {
          type: 'Http'
          runAfter: {
            Build_STAT_Base: [
              'Succeeded'
            ]
          }
          inputs: {
            method: 'POST'
            uri: '${functionBaseUri}/stat_related_alerts'
            body: {
              workspaceId: sentinelWorkspaceId
              base: '@body(''Build_STAT_Base'')'
              lookbackDays: relatedAlertsLookbackDays
              alertKqlFilter: relatedAlertsKqlFilter
              checkAccounts: true
              checkHosts: true
              checkIPs: true
            }
            authentication: {
              type: 'ManagedServiceIdentity'
              audience: environment().resourceManager
            }
          }
        }
        Threat_Intelligence: {
          type: 'Http'
          runAfter: {
            Build_STAT_Base: [
              'Succeeded'
            ]
          }
          inputs: {
            method: 'POST'
            uri: '${functionBaseUri}/stat_threat_intel'
            body: {
              workspaceId: sentinelWorkspaceId
              base: '@body(''Build_STAT_Base'')'
              lookbackDays: 14
            }
            authentication: {
              type: 'ManagedServiceIdentity'
              audience: environment().resourceManager
            }
          }
        }
        MDE: {
          type: 'Http'
          runAfter: {
            Build_STAT_Base: [
              'Succeeded'
            ]
          }
          inputs: {
            method: 'POST'
            uri: '${functionBaseUri}/stat_mde'
            body: {
              base: '@body(''Build_STAT_Base'')'
              lookbackDays: 14
            }
            authentication: {
              type: 'ManagedServiceIdentity'
              audience: environment().resourceManager
            }
          }
        }
        UEBA: {
          type: 'Http'
          runAfter: {
            Build_STAT_Base: [
              'Succeeded'
            ]
          }
          inputs: {
            method: 'POST'
            uri: '${functionBaseUri}/stat_ueba'
            body: {
              workspaceId: sentinelWorkspaceId
              base: '@body(''Build_STAT_Base'')'
              lookbackDays: 14
              minimumInvestigationPriority: 1
            }
            authentication: {
              type: 'ManagedServiceIdentity'
              audience: environment().resourceManager
            }
          }
        }
        File_Insights: {
          type: 'Http'
          runAfter: {
            Build_STAT_Base: [
              'Succeeded'
            ]
          }
          inputs: {
            method: 'POST'
            uri: '${functionBaseUri}/stat_file'
            body: {
              base: '@body(''Build_STAT_Base'')'
            }
            authentication: {
              type: 'ManagedServiceIdentity'
              audience: environment().resourceManager
            }
          }
        }
        Defender_for_Cloud_Apps: {
          type: 'Http'
          runAfter: {
            Build_STAT_Base: [
              'Succeeded'
            ]
          }
          inputs: {
            method: 'POST'
            uri: '${functionBaseUri}/stat_mcas'
            body: {
              base: '@body(''Build_STAT_Base'')'
              scoreThreshold: mcasScoreThreshold
            }
            authentication: {
              type: 'ManagedServiceIdentity'
              audience: environment().resourceManager
            }
          }
        }
        Optional_KQL: {
          type: 'If'
          expression: '@not(empty(''${replace(enrichmentKql, '''', '''''')}''))'
          runAfter: {
            Build_STAT_Base: [
              'Succeeded'
            ]
          }
          actions: {
            Run_KQL: {
              type: 'Http'
              inputs: {
                method: 'POST'
                uri: '${functionBaseUri}/stat_kql'
                body: {
                  workspaceId: sentinelWorkspaceId
                  base: '@body(''Build_STAT_Base'')'
                  query: enrichmentKql
                  lookbackDays: 14
                }
                authentication: {
                  type: 'ManagedServiceIdentity'
                  audience: environment().resourceManager
                }
              }
            }
          }
          else: {
            actions: {
              KQL_Skipped: {
                type: 'Compose'
                inputs: {
                  ModuleName: 'KQLModule'
                  ResultsCount: 0
                  ResultsFound: false
                }
              }
            }
          }
        }
        Optional_Watchlist: {
          type: 'If'
          expression: '@not(empty(''${replace(watchlistAlias, '''', '''''')}''))'
          runAfter: {
            Build_STAT_Base: [
              'Succeeded'
            ]
          }
          actions: {
            Run_Watchlist: {
              type: 'Http'
              inputs: {
                method: 'POST'
                uri: '${functionBaseUri}/stat_watchlist'
                body: {
                  workspaceId: sentinelWorkspaceId
                  base: '@body(''Build_STAT_Base'')'
                  watchlistAlias: watchlistAlias
                  watchlistKey: watchlistKey
                  watchlistKeyDataType: watchlistKeyDataType
                }
                authentication: {
                  type: 'ManagedServiceIdentity'
                  audience: environment().resourceManager
                }
              }
            }
          }
          else: {
            actions: {
              Watchlist_Skipped: {
                type: 'Compose'
                inputs: {
                  ModuleName: 'WatchlistModule'
                  WatchlistMatchCount: 0
                }
              }
            }
          }
        }
        Score_STAT: {
          type: 'Http'
          runAfter: {
            AAD_Risks: [
              'Succeeded'
              'Failed'
            ]
            Related_Alerts: [
              'Succeeded'
              'Failed'
            ]
            Threat_Intelligence: [
              'Succeeded'
              'Failed'
            ]
            MDE: [
              'Succeeded'
              'Failed'
            ]
            UEBA: [
              'Succeeded'
              'Failed'
            ]
            File_Insights: [
              'Succeeded'
              'Failed'
            ]
            Defender_for_Cloud_Apps: [
              'Succeeded'
              'Failed'
            ]
            Optional_KQL: [
              'Succeeded'
              'Failed'
            ]
            Optional_Watchlist: [
              'Succeeded'
              'Failed'
            ]
          }
          inputs: {
            method: 'POST'
            uri: '${functionBaseUri}/stat_scoring'
            body: {
              inputs: [
                {
                  module: '@body(''AAD_Risks'')'
                }
                {
                  module: '@body(''Related_Alerts'')'
                }
                {
                  module: '@body(''Threat_Intelligence'')'
                }
                {
                  module: '@body(''MDE'')'
                }
                {
                  module: '@body(''UEBA'')'
                }
                {
                  module: '@body(''File_Insights'')'
                }
                {
                  module: '@body(''Defender_for_Cloud_Apps'')'
                }
              ]
            }
            authentication: {
              type: 'ManagedServiceIdentity'
              audience: environment().resourceManager
            }
          }
        }
        Determine_STAT_Severity: {
          type: 'Compose'
          runAfter: {
            Score_STAT: [
              'Succeeded'
            ]
          }
          inputs: '@{if(greaterOrEquals(body(''Score_STAT'')?[''TotalScore''], ${highScoreThreshold}), ''High'', if(greaterOrEquals(body(''Score_STAT'')?[''TotalScore''], ${mediumScoreThreshold}), ''Medium'', if(greaterOrEquals(body(''Score_STAT'')?[''TotalScore''], ${lowScoreThreshold}), ''Low'', ''Informational'')))}'
        }
        Add_STAT_comment: {
          type: 'ApiConnection'
          runAfter: {
            Determine_STAT_Severity: [
              'Succeeded'
            ]
          }
          inputs: {
            body: {
              incidentArmId: '@triggerBody()?[''object'']?[''id'']'
              message: '@{concat(''STAT Next full triage completed. Score: '', string(body(''Score_STAT'')?[''TotalScore'']), ''. STAT severity: '', outputs(''Determine_STAT_Severity''), ''. Related alerts: '', string(body(''Related_Alerts'')?[''RelatedAlertsCount'']), ''; highest related severity: '', string(body(''Related_Alerts'')?[''HighestSeverityAlert'']), ''. TI matches: '', string(body(''Threat_Intelligence'')?[''MatchedTIItemCount'']), ''. UEBA anomalies: '', string(body(''UEBA'')?[''AnomalyCount'']), ''. File threats: '', string(body(''File_Insights'')?[''HashesLinkedToThreatCount'']), ''.'')}'
            }
            host: {
              connection: {
                name: '@parameters(''$connections'')[''azuresentinel''][''connectionId'']'
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
  ]
}

output playbookName string = activatedPlaybook.name
output playbookState string = 'Enabled'
output sentinelConnectionName string = sentinelConnection.name
output sentinelWorkspace string = sentinelWorkspaceName
