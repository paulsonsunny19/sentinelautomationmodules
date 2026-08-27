# STAT Next portal deployment

STAT Next deploys from Azure Portal in the same general user experience as legacy STAT. GitHub Actions validate and publish the versioned application artifact; they do not deploy into the customer's Azure subscription.

## User inputs

- Target resource group / Azure region (Azure deployment basics)
- STAT Next name prefix
- Microsoft Sentinel resource group
- Microsoft Sentinel Log Analytics workspace name

The deployment creates the Function infrastructure, System Assigned Managed Identity, monitoring, secure host storage configuration, and workspace-scoped RBAC.

## Application payload

Linux Consumption requires `WEBSITE_RUN_FROM_PACKAGE` to reference a URL. STAT Next does not point the Function App at GitHub and does not use a long-lived SAS.

During the ARM deployment, a short-lived Azure Deployment Script uses a User Assigned Managed Identity to perform a server-side copy of the validated `stat-next.zip` from the publication source into a **private container in the STAT Next storage account**. The script uses Azure CLI storage copy operations and does not depend on `curl`.

The Function App's System Assigned Managed Identity receives Storage Blob Data Reader access and `WEBSITE_RUN_FROM_PACKAGE` is set to the direct private Azure Blob URL. `WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID=SystemAssigned` makes package access identity-based. The staging identity has only the temporary storage write permission needed to place the package.

The published ZIP is ready-to-run and includes Python dependencies under `.python_packages/lib/site-packages`, so no OneDeploy/remote build operation is required at deployment time.

## Security

- Package container is private.
- No package SAS token is stored in Function settings.
- Function package access uses the Function's System Assigned Managed Identity.
- GitHub is only the publication source used during staging; the running Function reads its package from Azure Storage.
- No Graph, Exchange, Entra Risk, or Defender application permissions are requested unless optional modules explicitly require them in a future release.
