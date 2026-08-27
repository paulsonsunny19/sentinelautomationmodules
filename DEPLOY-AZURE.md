# Deploy STAT from Azure Portal

This branch fixes the Linux Consumption `WEBSITE_RUN_FROM_PACKAGE` redirect failure.

## 1. Prepare stat.zip

Download `stat.zip` from https://github.com/briandelmsft/STAT-Function/releases/tag/v2.3.0 and do not unzip it. Do not use the GitHub release URL as `FunctionPackage` because it redirects.

## 2. Put stat.zip in Azure Blob Storage

In Azure Portal, open a Storage account > Data storage > Containers, create/open a private container, upload `stat.zip`, then open the blob > Generate SAS. Grant Read only, set a suitable expiry, and copy the Blob SAS URL. It must begin directly with your `*.blob.core.windows.net` endpoint.

## 3. Deploy

Deploy to Azure:

https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fpaulsonsunny19%2Fsentinelautomationmodules%2Ffix%2Flinux-consumption-package%2FDeploy%2Fstatdeploy.json

Enter `STATFunctionName`, `STATStorageName`, and your direct Blob SAS URL as `FunctionPackage`. Use `identityType=system` unless you specifically require another identity. Connector names can remain at their defaults. `DeployBasicSample` is optional.

The template creates the storage account, Linux Function App, and STAT custom Logic Apps connector. Connector/sample definitions are sourced from the upstream STAT repository; the Function deployment uses the corrected templates in this fork.

## 4. Permissions

Run the upstream STAT GrantPermissions script after deployment:
https://github.com/briandelmsft/SentinelAutomationModules/blob/main/Deploy/GrantPermissions.ps1

For a system-assigned identity, `STATIdentityName` is your Function App name. Allow time for permissions to propagate.

## 5. Validate

In Function App > Configuration / Environment variables, verify `WEBSITE_RUN_FROM_PACKAGE` is your direct Azure Blob SAS URL, not a GitHub URL.

If Related Alerts returns Log Analytics HTTP 403, verify the STAT identity also has query access to the Sentinel Log Analytics workspace (for example Log Analytics Reader where appropriate).
