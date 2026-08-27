# Sentinel Automation Modules — Linux Consumption deployment fix

Deployable STAT package based on `briandelmsft/SentinelAutomationModules`, updated for Azure's Linux Consumption restriction on redirected `WEBSITE_RUN_FROM_PACKAGE` URLs.

The original deployment uses a GitHub Releases URL for `stat.zip`; this fork requires `FunctionPackage` to be a direct Azure Blob Storage URL, normally a read-only Blob SAS URL:

```
https://<account>.blob.core.windows.net/<container>/stat.zip?<SAS>
```

The template creates the storage account and Function App, then deploys the upstream STAT custom Logic Apps connector and optionally the upstream basic sample.

## Deploy

See [DEPLOY-AZURE.md](DEPLOY-AZURE.md) for Azure Portal instructions.

Main template: `Deploy/statdeploy.json`

Recommended identity: `system`.

Upstream: https://github.com/briandelmsft/SentinelAutomationModules
