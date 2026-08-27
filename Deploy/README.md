# STAT Deployment

This deployment restores the upstream STAT chain for System Assigned Managed Identity:

1. STAT storage account
2. Linux Consumption STAT Function App
3. STAT v2 Logic Apps custom connector
4. Optional Sample-STAT-Triage playbook

The Function App resource is created before the nested connector deployment. The compatibility change is limited to requiring a direct Azure Blob SAS URL for `FunctionPackage`.

See ../DEPLOY-STAT.md.
