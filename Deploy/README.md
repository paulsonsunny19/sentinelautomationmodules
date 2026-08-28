# STAT Azure deployment — Linux Consumption package fix

This deployment variant fixes Azure error **51024**: Linux Consumption Function Apps cannot be created with `WEBSITE_RUN_FROM_PACKAGE` pointing at a URL that redirects.

## Prepare the Function package

1. Download the STAT v2.3.0 `stat.zip` package from the upstream STAT-Function release.
2. Upload `stat.zip` to a private Azure Blob Storage container.
3. Generate a read-only Blob SAS URL with sufficient lifetime for deployment.
4. Supply that **direct `https://<account>.blob.core.windows.net/.../stat.zip?...` URL** as `FunctionPackage`.

Do not use the GitHub Releases download URL as `FunctionPackage`; it redirects.

## Templates

`statdeploy.json` is the entry template. It creates the storage account and selects the system-assigned, user-assigned, or service-principal Function template.

After deployment, run `Deploy/GrantPermissions.ps1` / the current upstream STAT permissions script. Permission propagation can take several minutes.

## Upstream

Based on briandelmsft/SentinelAutomationModules and STAT-Function v2.3.0.
