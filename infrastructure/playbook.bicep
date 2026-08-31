param name string
param location string
param functionAppName string

// Bootstrap only: create a disabled Logic App shell with a system-assigned
// identity. Do not create or reference the Microsoft Sentinel managed API
// connection here. This keeps initial provisioning independent of the Logic
// Apps connector host and allows Sentinel RBAC to be assigned first.
resource playbook 'Microsoft.Logic/workflows@2019-05-01' = {
  name: name
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Disabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        ProjectName: {
          type: 'String'
          defaultValue: 'STATNext'
        }
        PlaybookVersion: {
          type: 'String'
          defaultValue: '1.1.0-bootstrap'
        }
        FunctionAppName: {
          type: 'String'
          defaultValue: functionAppName
        }
      }
      triggers: {
        manual: {
          type: 'Request'
          kind: 'Http'
          inputs: {
            schema: {
              type: 'object'
              properties: {}
            }
          }
        }
      }
      actions: {
        Bootstrap_ready: {
          type: 'Compose'
          inputs: {
            status: 'STAT Next Sentinel playbook identity created. Sentinel connector activation is the next stage.'
            functionAppName: functionAppName
          }
          runAfter: {}
        }
      }
      outputs: {}
    }
    parameters: {}
  }
}

output principalId string = playbook.identity.principalId
output resourceId string = playbook.id
output playbookName string = playbook.name
output bootstrapState string = 'Disabled'
