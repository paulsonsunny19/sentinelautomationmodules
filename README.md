# Sentinel Automation Modules — Linux Consumption deployment fix

Deployable STAT package based on `briandelmsft/SentinelAutomationModules`, updated for Azure's Linux Consumption restriction on redirected `WEBSITE_RUN_FROM_PACKAGE` URLs.

The original deployment uses a GitHub Releases URL for `stat.zip`; this fork requires `FunctionPackage` to be a direct Azure Blob Storage URL, normally a read-only Blob SAS URL.

## Deploy

**Azure Portal:** https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fpaulsonsunny19%2Fsentinelautomationmodules%2Ffix%2Flinux-consumption-package%2FDeploy%2Fstatdeploy.json

Read [DEPLOY-AZURE.md](DEPLOY-AZURE.md) first. You must upload `stat.zip` to Azure Blob Storage and provide its direct read-only SAS URL during deployment.

The template creates the storage account and Function App, then deploys the upstream STAT custom Logic Apps connector and optionally the upstream basic sample. Recommended identity: `system`.

Upstream: https://github.com/briandelmsft/SentinelAutomationModules
