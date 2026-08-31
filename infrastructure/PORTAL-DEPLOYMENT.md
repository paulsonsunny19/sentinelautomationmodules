# STAT Next portal deployment

STAT Next uses a staged Azure Portal deployment so identities and least-privilege RBAC exist before the Microsoft Sentinel incident workflow is enabled.

## Recommended deployment sequence

### Stage 1 - Core Function and security boundary

Deploy `infrastructure/azuredeploy.json` into the resource group where you want the STAT Next application resources.

Portal link:

`https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fpaulsonsunny19%2Fsentinelautomationmodules%2Fstat-next%2Finfrastructure%2Fazuredeploy.json`

Required inputs:

- Target Azure subscription, resource group, and region
- `namePrefix` - the wrapper adds a deterministic uniqueness suffix
- `sentinelSubscriptionId`
- `sentinelResourceGroup`
- `sentinelWorkspaceName`

The wrapper pins the package source to the validated `stat-next` branch artifact and deploys the published core `main.json` template.

After deployment, open **Deployment > Outputs** and copy `effectiveNamePrefix`. Use that exact value for stages 2 and 3. The wrapper also outputs the Function name and the dedicated API-caller managed-identity name.

Stage 1 creates the Function App, private package storage, Application Insights, the Function system-assigned managed identity, a dedicated user-assigned API-caller identity, workspace-scoped read RBAC, and App Service Authentication / Easy Auth.

The Function routes deliberately remain `anonymous` at the Functions host layer because Easy Auth is the authentication boundary. Easy Auth requires authentication, returns HTTP 401 to unauthenticated callers, requires HTTPS, and restricts accepted tokens to the dedicated API-caller managed identity. A browser request to `/api/health` returning 401 after Stage 1 is therefore expected, not a deployment failure.

### Stage 2 - Bootstrap the Sentinel playbook identity and RBAC

Deploy `infrastructure/playbook-main.json` into the **same resource group** as Stage 1.

Portal link:

`https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fpaulsonsunny19%2Fsentinelautomationmodules%2Fstat-next%2Finfrastructure%2Fplaybook-main.json`

Use:

- `namePrefix` = the exact Stage 1 `effectiveNamePrefix`
- the same Sentinel subscription, resource group, and workspace name

This stage creates the Logic App in a disabled bootstrap state, gives it a system-assigned managed identity, and grants that identity Microsoft Sentinel Responder on the target workspace before the real Sentinel webhook is enabled.

Wait for the deployment and role assignment to complete before Stage 3. This avoids enabling the incident workflow before its identity can update incident severity, tags, and comments.

### Stage 3 - Activate native Microsoft Sentinel triage

Deploy `infrastructure/playbook-activate.json` into the **same resource group**.

Portal link:

`https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fpaulsonsunny19%2Fsentinelautomationmodules%2Fstat-next%2Finfrastructure%2Fplaybook-activate.json`

Use:

- `namePrefix` = the exact Stage 1 `effectiveNamePrefix`
- the same Sentinel subscription/resource group/workspace name
- `sentinelWorkspaceId` = the Log Analytics Workspace ID (customer ID / GUID), not the ARM resource ID
- `tenantId` = the Microsoft Entra tenant ID
- optional lookback and scoring thresholds as required

Stage 3 upgrades the bootstrap Logic App to the enabled native Sentinel incident workflow, attaches the dedicated Stage 1 user-assigned API-caller identity, creates the Sentinel managed API connection, and configures every HTTP call to the STAT Function to authenticate with that identity.

The system-assigned Logic App identity remains the identity used for Sentinel connector operations; the user-assigned identity is used only for protected Function API calls.

## Application payload

Linux Consumption requires `WEBSITE_RUN_FROM_PACKAGE` to reference a package URL. STAT Next does not leave the running Function pointed at GitHub and does not use a long-lived package SAS.

During Stage 1, a short-lived Azure Deployment Script downloads the already validated `stat-next.zip`, validates the expected Function routes, and uploads the package into a private container in the STAT Next storage account. GitHub/public package access is limited to deployment-time staging; the running Function reads from private Azure Storage with its system-assigned managed identity.

The published ZIP is ready-to-run and includes Python dependencies under `.python_packages/lib/site-packages`, so no OneDeploy or remote-build operation is required.

## Post-deployment validation

After Stage 3:

1. Open the Logic App named `<effectiveNamePrefix>-incident-triage` and confirm it is **Enabled**.
2. Under **Identity**, confirm both System assigned and the `<effectiveNamePrefix>-api-caller` user-assigned identity are present.
3. Open the Function App Authentication blade and confirm Microsoft Entra authentication is enabled. An unauthenticated browser request to a Function route should return 401.
4. Create or select a safe test Microsoft Sentinel incident and run the playbook manually, or trigger it through an automation rule.
5. In **Logic App > Run history**, verify `Build_STAT_Base`, enrichment actions, `Score_STAT`, and `Build_STAT_Comment` complete. The HTTP enrichment actions should authenticate through the user-assigned identity.
6. Confirm the incident receives the STAT Next tag/severity update and rich analyst comment.
7. Review Application Insights and any `EnrichmentWarnings` if optional Graph/Defender integrations are not yet granted.

## Tenant API permissions

The ARM/Bicep deployment creates Azure resource RBAC. It does **not** silently grant tenant-wide Microsoft Graph or Defender application roles.

If those enrichment modules are required, a tenant administrator should review and run `infrastructure/grant-api-permissions.ps1` using the Function App system-assigned managed-identity object ID. The current optional read-only roles are:

- Microsoft Graph: `User.Read.All`, `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`, `AuditLog.Read.All`, `RoleManagement.Read.Directory`, `MailboxSettings.Read`
- WindowsDefenderATP: `AdvancedQuery.Read.All`, `Machine.Read.All`
- Microsoft Defender for Cloud Apps: `Investigation.Read`

`MailboxSettings.Read` is used only by optional `stat_oof`; the default native triage playbook does not invoke that endpoint.

Missing optional tenant permissions should degrade the affected enrichment and surface warnings rather than block the core Sentinel-native triage path.

## Optional RunPlaybook compatibility

RunPlaybook is disabled when `runPlaybookAllowedResourceIds` is empty, which is the secure default.

When intentionally enabling it through the core `main.json` template:

1. Put only exact Consumption Logic App resource IDs into the comma-separated `runPlaybookAllowedResourceIds` parameter.
2. Set `runPlaybookSubscriptionId` and `runPlaybookResourceGroup` to the single resource group containing those workflows.
3. The deployment conditionally grants the Function managed identity Microsoft Sentinel Playbook Operator on that resource group.
4. Each target workflow must expose a Request/manual trigger named `manual` that accepts an `IncidentARMId` JSON property.

The Function does not receive Logic App Contributor. RunPlaybook validates the exact target allow-list and does not return the signed Logic Apps callback URL.

## Security checkpoints

- Package container is private.
- No package SAS token is stored in Function settings.
- Function package access uses the Function system-assigned managed identity.
- Function HTTP endpoints are protected by Easy Auth and restricted to the dedicated API-caller user-assigned identity.
- The playbook uses its system-assigned identity for Sentinel operations and the user-assigned identity for Function calls.
- Function Log Analytics/Sentinel permissions are read-only and workspace-scoped.
- Tenant-wide Graph/Defender roles are administrator-reviewed and separate from ARM deployment.
- RunPlaybook is disabled by default and, when enabled, uses exact target allow-listing plus separate scoped Playbook Operator RBAC.
