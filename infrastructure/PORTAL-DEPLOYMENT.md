# STAT Next portal deployment

STAT Next deploys from Azure Portal in the same general user experience as legacy STAT. GitHub Actions validate and publish the application artifact; they do not deploy into the customer's Azure subscription.

## User inputs

The template asks for the Azure deployment target plus the Microsoft Sentinel workspace information required to scope the playbook and Function correctly. Typical inputs include:

- Target subscription, resource group, and Azure region
- STAT Next name prefix
- Microsoft Sentinel subscription/resource group
- Microsoft Sentinel Log Analytics workspace name and workspace ID
- Published STAT Next package URI when the template exposes the staging-source parameter
- Optional module configuration values such as Defender for Cloud Apps settings

The deployment creates the Function infrastructure, System Assigned Managed Identity, monitoring, secure host storage configuration, Logic App/Sentinel connection, and workspace-scoped Azure RBAC.

## Application payload

Linux Consumption requires `WEBSITE_RUN_FROM_PACKAGE` to reference a package URL. STAT Next does not leave the running Function pointed at GitHub and does not use a long-lived package SAS.

During the ARM deployment, a short-lived Azure Deployment Script uses a User Assigned Managed Identity to perform a server-side copy of the validated `stat-next.zip` from the publication source into a **private container in the STAT Next storage account**. The script uses Azure CLI storage copy operations and does not depend on `curl`.

The Function App's System Assigned Managed Identity receives Storage Blob Data Reader access and `WEBSITE_RUN_FROM_PACKAGE` is set to the private Azure Blob URL. `WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID=SystemAssigned` makes package access identity-based. The staging identity has only the storage write permission required to place the package.

The published ZIP is ready-to-run and includes Python dependencies under `.python_packages/lib/site-packages`, so no OneDeploy/remote build operation is required at deployment time.

## Sentinel incident wiring

The native activation playbook sends the full Microsoft Sentinel incident trigger to `stat_base` and also passes the incident's full ARM resource ID explicitly as `incidentArmId`. This ARM ID is required for first-party Sentinel GeoData enrichment because it identifies the Sentinel subscription, resource group, and workspace. `stat_base` now rejects a request that does not provide resolvable incident ARM scope instead of silently returning blank GeoData.

## Azure RBAC versus tenant API permissions

The ARM/Bicep deployment creates Azure resource RBAC such as workspace Log Analytics Reader, Microsoft Sentinel Reader/Responder, and package-storage access. It does **not** silently grant tenant-wide Microsoft Graph or Defender application roles.

STAT Next currently contains optional Graph/Defender-backed enrichment modules. If those modules are required, a tenant administrator should review and run `infrastructure/grant-api-permissions.ps1` using the Function App managed-identity object ID. The script grants the read-only roles currently used by the code:

- Microsoft Graph: `User.Read.All`, `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`, `AuditLog.Read.All`, `RoleManagement.Read.Directory`
- WindowsDefenderATP: `AdvancedQuery.Read.All`, `Machine.Read.All`
- Microsoft Defender for Cloud Apps: `Investigation.Read`

If a tenant API permission is not granted, STAT Next is designed to preserve the rest of the triage result and surface an enrichment warning where possible rather than hiding the missing integration.

## Security

- Package container is private.
- No package SAS token is stored in Function settings.
- Function package access uses the Function's System Assigned Managed Identity.
- GitHub is only the publication source used during staging; the running Function reads its package from Azure Storage.
- Tenant-wide Graph/Defender roles are administrator-reviewed and separate from the ARM deployment.
- Function Log Analytics/Sentinel permissions are read-only and workspace-scoped; Sentinel incident updates/comments are performed by the Logic App identity.
