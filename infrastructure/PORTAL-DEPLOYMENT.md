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
- Optional `runPlaybookAllowedResourceIds`, `runPlaybookSubscriptionId`, and `runPlaybookResourceGroup` values when privileged RunPlaybook compatibility is intentionally enabled

The deployment creates the Function infrastructure, System Assigned Managed Identity, monitoring, secure host storage configuration, Logic App/Sentinel connection, and workspace-scoped Azure RBAC.

## Application payload

Linux Consumption requires `WEBSITE_RUN_FROM_PACKAGE` to reference a package URL. STAT Next does not leave the running Function pointed at GitHub and does not use a long-lived package SAS.

During the ARM deployment, a short-lived Azure Deployment Script downloads the already validated `stat-next.zip`, validates the expected Function routes, and uploads the package into a **private container in the STAT Next storage account**. GitHub/public package access is therefore limited to deployment-time staging; the running Function reads only from private Azure Storage.

The Function App's System Assigned Managed Identity receives Storage Blob Data Reader access and `WEBSITE_RUN_FROM_PACKAGE` is set to the private Azure Blob URL. `WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID=SystemAssigned` makes package access identity-based. The staging identity has only the storage write permission required to place the package.

The published ZIP is ready-to-run and includes Python dependencies under `.python_packages/lib/site-packages`, so no OneDeploy/remote build operation is required at deployment time.

## Sentinel incident wiring

The native activation playbook sends the full Microsoft Sentinel incident trigger to `stat_base` and also passes the incident's full ARM resource ID explicitly as `incidentArmId`. This ARM ID is required for first-party Sentinel GeoData enrichment because it identifies the Sentinel subscription, resource group, and workspace. `stat_base` rejects a request that does not provide resolvable incident ARM scope instead of silently returning blank GeoData.

## Optional RunPlaybook compatibility

RunPlaybook is disabled when `runPlaybookAllowedResourceIds` is empty, which is the default.

When enabling it:

1. Put only the exact Consumption Logic App resource IDs that STAT Next is allowed to trigger into the comma-separated `runPlaybookAllowedResourceIds` parameter.
2. Set `runPlaybookSubscriptionId` and `runPlaybookResourceGroup` to the single resource group containing those allow-listed workflows.
3. The deployment conditionally grants the Function managed identity Microsoft Sentinel Playbook Operator on that resource group.
4. Each target workflow must expose a Request/manual trigger named `manual` that accepts an `IncidentARMId` JSON property.

The Function does not receive Logic App Contributor. It uses Playbook Operator to call the Azure Resource Manager `listCallbackUrl` action for the allow-listed workflow, validates the returned HTTPS Logic Apps callback host, then posts the current incident ARM ID. The signed callback URL is not returned by the API.

If you use native Microsoft Sentinel incident/alert/entity triggers or automation rules instead of this Request/manual compatibility mode, configure the Microsoft Sentinel service account permissions described by Microsoft for those playbook execution paths.

## Azure RBAC versus tenant API permissions

The ARM/Bicep deployment creates Azure resource RBAC such as workspace Log Analytics Reader, Microsoft Sentinel Reader/Responder, package-storage access, and the optional scoped Playbook Operator assignment. It does **not** silently grant tenant-wide Microsoft Graph or Defender application roles.

STAT Next currently contains optional Graph/Defender-backed enrichment modules. If those modules are required, a tenant administrator should review and run `infrastructure/grant-api-permissions.ps1` using the Function App managed-identity object ID. The script grants the read-only roles currently used by the code:

- Microsoft Graph: `User.Read.All`, `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`, `AuditLog.Read.All`, `RoleManagement.Read.Directory`, `MailboxSettings.Read`
- WindowsDefenderATP: `AdvancedQuery.Read.All`, `Machine.Read.All`
- Microsoft Defender for Cloud Apps: `Investigation.Read`

`MailboxSettings.Read` is used only by the optional `stat_oof` automatic-replies enrichment endpoint. The native triage playbook does not invoke that endpoint by default.

If a tenant API permission is not granted, STAT Next is designed to preserve the rest of the triage result and surface an enrichment warning where possible rather than hiding the missing integration.

## Security

- Package container is private.
- No package SAS token is stored in Function settings.
- Function package access uses the Function's System Assigned Managed Identity.
- GitHub is only a deployment-time publication source; the running Function reads its package from Azure Storage.
- Tenant-wide Graph/Defender roles are administrator-reviewed and separate from the ARM deployment.
- Function Log Analytics/Sentinel permissions are read-only and workspace-scoped.
- RunPlaybook is disabled by default and uses exact target allow-listing plus a separate scoped Playbook Operator role.
- Sentinel incident updates/comments are performed by the Logic App identity.
