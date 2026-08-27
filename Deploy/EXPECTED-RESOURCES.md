# Expected Azure resources

Core deployment:
- `Microsoft.Storage/storageAccounts`: STAT storage
- `Microsoft.Web/sites`: STAT Linux Function App
- `Microsoft.Web/customApis`: SentinelTriageAssistantv2 / STAT v2 connector
- connector connection resources created by the upstream connector template

Optional sample:
- `Microsoft.Logic/workflows`: Sample-STAT-Triage
- Azure Sentinel managed API connection used by the sample
