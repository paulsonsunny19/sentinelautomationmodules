# Deploy STAT from Azure Portal

This branch fixes the Linux Consumption `WEBSITE_RUN_FROM_PACKAGE` redirect failure.

## 1. Prepare stat.zip

Download `stat.zip` from the STAT Function v2.3.0 release:
https://github.com/briandelmsft/STAT-Function/releases/tag/v2.3.0

Do not use the GitHub release URL as `FunctionPackage` because it redirects.

## 2. Put stat.zip in Azure Blob Storage

In Azure Portal:
1. Open a Storage account.
2. Data storage > Containers > create/open a private container (for example `stat`).
3. Upload `stat.zip`.
4. Open the blob > Generate SAS.
5. Grant Read only and set a suitable expiry.
6. Copy the Blob SAS URL. It must begin directly with your `*.blob.core.windows.net` endpoint.

## 3. Deploy the ARM template

Open Azure Portal > Deploy a custom template > Build your own template in the editor.

Use this template URL/source:
https://raw.githubusercontent.com/paulsonsunny19/sentinelautomationmodules/fix/linux-consumption-package/Deploy/statdeploy.json

Enter:
- `STATFunctionName`: globally unique Function App name
- `STATStorageName`: globally unique lowercase storage account name
- `FunctionPackage`: direct Blob SAS URL from step 2
- `identityType`: `system` (recommended), `user`, or `sp`
- Connector names can normally remain at their defaults
- `DeployBasicSample`: optional

Review + create, then Create.

The template creates the storage account, Linux Function App, and STAT custom Logic Apps connector. The connector and optional basic sample are sourced from the upstream Microsoft STAT repository while the Function deployment uses the corrected templates in this fork.

## 4. Grant STAT permissions

After deployment run `Deploy/GrantPermissions.ps1`. For system-assigned identity, `STATIdentityName` is the Function App name.

The account running the script needs the Entra and Azure permissions described in the script header. Allow time for role/permission propagation.

## 5. Validate

Check Function App > Configuration / Environment variables and verify `WEBSITE_RUN_FROM_PACKAGE` is the direct Azure Blob SAS URL, not a GitHub URL.

If Related Alerts returns Log Analytics HTTP 403 after deployment, verify the STAT identity has the required Sentinel/Log Analytics access to the Sentinel workspace/resource group and that the permission script completed successfully.
