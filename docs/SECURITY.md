# STAT Next security, identity, and permissions

This document is the security reference for deploying and operating STAT Next. It describes every runtime identity, Azure RBAC assignment, Microsoft Entra enterprise application involved, tenant API permission, and optional privilege boundary used by the current `stat-next` branch.

## Security design summary

STAT Next is designed to be secretless at runtime. Azure Functions and Logic Apps authenticate with managed identities rather than client secrets. Tenant-wide API permissions are application permissions assigned directly to the Function App system-assigned managed identity service principal. Azure resource access is granted with narrowly scoped Azure RBAC.

The important distinction is:

- **Function system-assigned managed identity** = enrichment identity. It reads Sentinel/Log Analytics, Microsoft Graph, MDE, and optional Defender for Cloud Apps data.
- **Logic App system-assigned managed identity** = Sentinel incident-response identity. It updates incidents, tags, severity, and comments.
- **`*-api-caller` user-assigned managed identity** = caller identity used by the Logic App when calling the Function App through App Service Authentication / Easy Auth. It is not the enrichment identity and should not receive Graph or Defender data permissions.
- **`*-stage` user-assigned managed identity** = deployment-only package staging identity. It writes the deployment ZIP to the private package container.

No normal runtime component requires a client secret.

## Microsoft Entra enterprise applications

Managed identities are represented in Microsoft Entra ID by **service principals**, and service principals are visible under **Entra ID > Enterprise applications**. A managed identity does not require a separate App Registration/application object. Do not create a client secret or a duplicate App Registration for the Function managed identity.

A typical STAT Next deployment therefore has the following tenant-visible enterprise applications / managed identities.

| Enterprise application / identity | Type | Purpose | Required permissions |
|---|---|---|---|
| `<effective-prefix>-api` | System-assigned managed identity attached to the Function App | Main enrichment identity | Azure workspace/storage RBAC plus the tenant API application roles described below |
| `<effective-prefix>-incident-triage` | System-assigned managed identity attached to the Logic App | Microsoft Sentinel incident updates/comments | Microsoft Sentinel Responder on the target Sentinel workspace |
| `<effective-prefix>-api-caller` | User-assigned managed identity | Authenticates Logic App HTTP calls to the Function App | No Microsoft Graph/MDE/MDCA application roles; only used as the authenticated caller accepted by Function Easy Auth |
| `<effective-prefix>-stage` | User-assigned managed identity | Stages the Function deployment package into private Azure Storage | Storage Blob Data Contributor on the STAT package storage account during deployment |

For the current deployment prefix used during development, these names follow the same pattern, for example `statnext<suffix>-api`, `statnext<suffix>-incident-triage`, `statnext<suffix>-api-caller`, and `statnext<suffix>-stage`.

### How to find the Function enterprise application

In Microsoft Entra admin center:

1. Open **Identity > Applications > Enterprise applications > All applications**.
2. Filter **Application type = Managed Identities**.
3. Search for the Function App resource name ending in `-api`.
4. Confirm its **Object ID** matches the Function App **Identity > System assigned > Object (principal) ID** in Azure Portal.
5. This Object ID is the value passed to `infrastructure/grant-api-permissions.ps1 -FunctionPrincipalId`.

Do not confuse the Function system identity with the `-api-caller` user-assigned identity. The Function identity receives data-access permissions; `-api-caller` only authenticates the Logic App-to-Function request.

## Resource enterprise applications used by STAT Next

The Function managed identity obtains tokens for Microsoft APIs. The corresponding Microsoft-owned enterprise applications/service principals must exist in the tenant.

| Resource enterprise application | App ID / identification | STAT Next use |
|---|---|---|
| Microsoft Graph | `00000003-0000-0000-c000-000000000000` | Entra user/risk/authentication/role enrichment and OOF automatic-reply reads |
| WindowsDefenderATP | Resolved by service-principal display name by the permission script | MDE advanced hunting and machine/device enrichment |
| Microsoft Defender for Cloud Apps | `05a65629-4c1b-48c1-a78b-804c4abdd4af` | Optional read-only investigation/entity enrichment |
| Azure Resource Manager | Token audience `https://management.azure.com/` | Logic App managed-identity token used when calling the Easy-Auth-protected Function and ARM operations used by optional RunPlaybook |

These Microsoft resource service principals are not STAT-owned app registrations. Do not create replacement applications with these names.

## Azure RBAC required by the Function system identity

The core deployment assigns the Function App system-assigned managed identity the following Azure roles.

| Scope | Built-in role | Role definition ID | Why required |
|---|---|---|---|
| Target Log Analytics / Sentinel workspace | Log Analytics Reader | `73c42c96-874c-492b-b04d-ab87d138a893` | Related alerts, TI queries, UEBA, IP network baseline, Sentinel-first identity data, optional KQL/watchlists |
| Target Sentinel workspace | Microsoft Sentinel Reader | `8d289c81-5878-46d4-8554-54e1e3d8b5cb` | Read-only Sentinel enrichment and incident/Sentinel context |
| STAT package storage account | Storage Blob Data Owner | `b7e6dc6d-f1e8-4753-8033-0f276bb0955b` | Azure Functions host storage access using managed identity |
| STAT package storage account | Storage Blob Data Reader | `2a2b9908-6ea1-4ae2-8e65-a410df84e7d1` | Read the private `WEBSITE_RUN_FROM_PACKAGE` ZIP |

The workspace roles are scoped to the target workspace rather than the subscription.

### IP GeoData permission note

The standalone IP GeoData module can call Microsoft Sentinel enrichment operations such as `Microsoft.SecurityInsights/enrichment/listGeodataByIp/action`. A normal Microsoft Sentinel Reader assignment may not authorize those enrichment actions in every environment/API version. The native STAT Next incident workflow no longer calls or renders the standalone IP GeoData module, so this permission is **not required for the normal native triage workflow**. Do not broaden the Function role solely to suppress that optional module's 403 unless the separate IP-enrichment feature is intentionally enabled and reviewed.

IP network prevalence is separate and continues to use workspace telemetry such as `DeviceNetworkEvents` under the read-only query model.

## Logic App Sentinel permissions

The native incident-triage Logic App uses its **system-assigned managed identity** for the Microsoft Sentinel connector.

| Scope | Built-in role | Role definition ID | Purpose |
|---|---|---|---|
| Target Sentinel workspace | Microsoft Sentinel Responder | `3e150937-b8fe-4cfb-8069-0eaf05ecd056` | Update incident severity/tags and add the STAT analyst comment |

The Logic App should not receive the Function's Microsoft Graph or Defender application permissions.

If an existing Sentinel Responder role assignment already exists for the same Logic App principal at the same workspace scope, keep it. Do not delete a valid assignment merely because an ARM deployment reports `RoleAssignmentExists` for a differently named role-assignment resource.

## Function API authentication / `-api-caller` enterprise application

The Function routes use Functions `ANONYMOUS` auth level intentionally because authentication is enforced in front of the runtime by **App Service Authentication (Easy Auth)**.

The deployment configures:

- Easy Auth enabled.
- Authentication required.
- Unauthenticated requests return HTTP 401.
- HTTPS required.
- Token store disabled.
- Accepted token audience: `https://management.azure.com/`.
- Allowed application: the `-api-caller` managed identity client/application ID.
- Allowed principal: the `-api-caller` managed identity object/principal ID.

The Logic App's Function HTTP actions request an Azure Resource Manager audience token using the `-api-caller` user-assigned managed identity. Easy Auth then restricts the caller to that exact managed identity. The ARM audience is the **token resource**, while `-api-caller` is the **caller identity**; the managed identity client ID must not itself be used as the MSI audience.

The `-api-caller` identity does **not** need `User.Read.All`, Defender permissions, Sentinel Reader, or other enrichment privileges.

## Microsoft Graph application permissions on the Function enterprise application

When Graph-backed enrichment and OOF are enabled, the Function system-assigned managed identity receives the following **application permissions / app roles** directly on its enterprise-application service principal.

| Microsoft Graph application permission | Required by | Access |
|---|---|---|
| `User.Read.All` | User profile enrichment | Read user directory profiles |
| `IdentityRiskyUser.Read.All` | Entra risky-user enrichment | Read `identityProtection/riskyUsers` |
| `IdentityRiskEvent.Read.All` | Entra risk-event enrichment | Read `identityProtection/riskDetections` |
| `AuditLog.Read.All` | Authentication/MFA registration enrichment | Read authentication-method registration/reporting information used by STAT |
| `RoleManagement.Read.Directory` | Directory role context | Read directory role assignments and role definitions |
| `MailboxSettings.Read` | OOF / automatic replies | Read `users/{user}/mailboxSettings/automaticRepliesSetting`; no mailbox writes and no mail send permission |

These are **application** permissions because the Function runs unattended as its managed identity. They are not delegated user permissions.

The native workflow currently invokes OOF, so `MailboxSettings.Read` is required if OOF results are expected. If it is not granted, the OOF module is designed to degrade with an enrichment warning rather than gaining write access or failing the entire triage workflow.

STAT Next does not require `Mail.Read`, `Mail.ReadWrite`, `Mail.Send`, `Directory.ReadWrite.All`, `User.ReadWrite.All`, or `RoleManagement.ReadWrite.Directory` for these features.

## Microsoft Defender for Endpoint application permissions

For MDE enrichment, grant these application roles to the **Function system-assigned managed identity** on the WindowsDefenderATP resource service principal:

| Application permission | Purpose |
|---|---|
| `AdvancedQuery.Read.All` | Read-only Defender advanced-hunting/enrichment queries |
| `Machine.Read.All` | Read MDE machine/device context |

These are data-read permissions only. STAT Next does not require machine isolation, remediation, alert write, or other Defender response permissions for the MDE enrichment module.

## Microsoft Defender for Cloud Apps permission

Defender for Cloud Apps is optional. If configured, the Function managed identity uses:

| Resource | Application permission | Purpose |
|---|---|---|
| Microsoft Defender for Cloud Apps | `Investigation.Read` | Read-only investigation/entity enrichment |

The tenant-specific Defender for Cloud Apps API/portal URL must also be configured. If the module is not needed, do not grant this role.

## Granting the tenant API permissions

Tenant API application roles are intentionally not embedded in the normal ARM/Bicep deployment. They require explicit tenant-administrator review.

The repository provides:

`infrastructure/grant-api-permissions.ps1`

Run it **after** the Function App exists, using the Function system-assigned managed identity Object ID:

```powershell
./infrastructure/grant-api-permissions.ps1 -FunctionPrincipalId '<FUNCTION-SYSTEM-MANAGED-IDENTITY-OBJECT-ID>'
```

The current script grants the complete reviewed Graph + MDE + Defender for Cloud Apps read-only bundle listed above. It is idempotent: an existing matching app-role assignment is detected and retained.

The administrator running the grant must have sufficient Microsoft Entra authority to create app-role assignments. This is a tenant-level administrative operation and is separate from Azure subscription/resource-group RBAC.

### Verification in Enterprise applications

After running the script:

1. Open **Microsoft Entra ID > Enterprise applications**.
2. Filter to **Managed Identities**.
3. Open `<effective-prefix>-api` — the Function system identity, not `-api-caller`.
4. Open **Permissions**.
5. Verify the expected Microsoft Graph application permissions.
6. Verify MDE/WindowsDefenderATP and optional Defender for Cloud Apps app-role assignments using the enterprise-application permissions view or Microsoft Graph/CLI.
7. Confirm there are no unexpected write application roles.

The permissions can also be enumerated from the Function managed identity service principal's `appRoleAssignments` collection.

## Optional RunPlaybook permissions

`stat_run_playbook` is privileged orchestration and is disabled by default. It becomes available only when `runPlaybookAllowedResourceIds` / `RUN_PLAYBOOK_ALLOWED_RESOURCE_IDS` contains exact Consumption Logic App ARM resource IDs.

When enabled, the deployment grants the Function system identity:

| Scope | Role | Role definition ID |
|---|---|---|
| Configured playbook resource group | Microsoft Sentinel Playbook Operator | `51d6186e-6489-4900-b93f-92e23144cca5` |

Security restrictions include:

- Exact Logic App ARM resource IDs only; no wildcard or prefix allow-list.
- Consumption Logic Apps only.
- Target must expose a Request/manual trigger named `manual`.
- STAT obtains the signed callback through ARM rather than granting Logic App Contributor.
- Callback must be HTTPS on an expected Azure Logic Apps host.
- Signed callback URLs are not returned to the caller.
- Only the current incident ARM ID is posted to the target playbook.

Do not grant Logic App Contributor just to enable this compatibility path.

## Deployment identities and storage

The core deployment also creates a `-stage` user-assigned managed identity. It receives **Storage Blob Data Contributor** (`ba92f5b4-2d11-453d-a403-e96b0029c9fe`) on the STAT storage account so the deployment script can place the validated Function ZIP in the private package container.

The storage account is configured with public blob access disabled, HTTPS-only access, TLS 1.2 minimum, cross-tenant replication disabled, and OAuth as the default authentication model. The Function reads the private package using managed identity rather than a package SAS secret.

## Deployment operator permissions

The human/service principal performing the deployment needs enough Azure access to create the STAT resources and create the required role assignments at the relevant scopes. Because the Sentinel workspace can be in a different resource group from STAT Next, the deployment operator also needs role-assignment authority at the Sentinel workspace/resource-group scope where the workspace RBAC modules execute.

Tenant API grants are separate: the administrator who runs `grant-api-permissions.ps1` must be authorized in Microsoft Entra to create application-role assignments. Azure `Owner` on a subscription does not automatically imply Microsoft Entra tenant administrative permission.

## What should exist after a complete deployment

For a normal native deployment with Graph/MDE/OOF enrichment, expect:

1. Function App with system-assigned managed identity `<prefix>-api`.
2. Logic App with system-assigned managed identity `<prefix>-incident-triage`.
3. User-assigned managed identity `<prefix>-api-caller` attached to the Logic App for Function HTTP authentication.
4. User-assigned staging identity `<prefix>-stage` used by package deployment.
5. Microsoft Graph resource enterprise application already supplied by Microsoft.
6. WindowsDefenderATP resource enterprise application for MDE, if MDE is used.
7. Microsoft Defender for Cloud Apps resource enterprise application, if MDCA enrichment is used.
8. No STAT client secret.
9. No separate custom STAT App Registration required for the managed-identity runtime design.

## Minimum permission profiles by feature

| Feature | Function Azure RBAC | Function tenant API app roles | Logic App RBAC |
|---|---|---|---|
| Base entity normalization | None beyond runtime/storage | None | Sentinel trigger access handled by connector identity |
| Related Alerts / TI / UEBA / IP baseline / Sentinel-first identity | Log Analytics Reader + Sentinel Reader on workspace | None when workspace data is sufficient | None |
| Entra Graph fallback/details | Workspace roles remain | `User.Read.All`, `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`, `AuditLog.Read.All`, `RoleManagement.Read.Directory` | None |
| OOF | None additional Azure RBAC | `MailboxSettings.Read` | None |
| MDE | None additional Azure RBAC | WindowsDefenderATP `AdvancedQuery.Read.All`, `Machine.Read.All` | None |
| Defender for Cloud Apps | None additional Azure RBAC | `Investigation.Read` | None |
| Incident severity/tags/comments | None | None | Microsoft Sentinel Responder on workspace |
| Function HTTP calls | None on Function enrichment identity | None | `-api-caller` UAMI authenticated by Easy Auth |
| Optional RunPlaybook | Microsoft Sentinel Playbook Operator on configured playbook RG | None | Target playbook keeps its own permissions |

## Permissions STAT Next should not need

Do not grant the following merely to make normal STAT Next enrichment work:

- Global Administrator to any runtime identity.
- Owner or Contributor at subscription scope to the Function or Logic App.
- `Directory.ReadWrite.All`.
- `User.ReadWrite.All`.
- `RoleManagement.ReadWrite.Directory`.
- `Mail.ReadWrite` or `Mail.Send` for OOF.
- Logic App Contributor for RunPlaybook.
- Defender remediation/isolation/write permissions for read-only MDE enrichment.
- A client secret for the Function, Logic App, or API caller identity.

If a module reports 401/403, identify the exact resource, action, identity object ID, and scope before adding permissions. Do not solve a narrow authorization error by assigning a broad subscription or directory role.

## Runtime hardening

The deployment additionally enforces or uses:

- HTTPS only.
- TLS 1.2 minimum.
- FTP/FTPS disabled.
- FTP and SCM basic publishing credentials disabled.
- App Service Authentication required for Function HTTP routes.
- Unauthenticated Function requests return 401.
- Easy Auth caller allow-list restricted to the API-caller managed identity.
- No Easy Auth token store.
- Anonymous Azure Blob access disabled.
- Application Insights for operational telemetry.
- Managed-identity package access.
- KQL safety guards plus read-only workspace RBAC as the primary query boundary.
- Attacker-shapeable enrichment cannot reduce incident risk/severity.
- Privileged workflow execution is opt-in and exact-allow-listed.

## Security review checklist

Before production approval, verify:

- Function system managed identity Object ID is known and documented.
- `-api-caller` Object ID/client ID are different from the Function system identity and are not accidentally granted Graph/Defender permissions.
- Logic App system identity has Sentinel Responder only at the intended workspace scope.
- Function system identity has Log Analytics Reader and Sentinel Reader only at the intended workspace scope.
- Microsoft Graph permissions match the enabled modules.
- `MailboxSettings.Read` is present when native OOF enrichment is expected.
- MDE permissions are present only if MDE enrichment is required.
- Defender for Cloud Apps permission is present only if that module is configured.
- No unexpected write application roles exist on the Function enterprise application.
- No client secrets or certificates were introduced for runtime authentication.
- Function `/api/health` is not anonymously accessible; an unauthenticated browser request should receive 401.
- RunPlaybook remains disabled unless explicitly required, and its allow-list contains exact reviewed Logic App ARM resource IDs.
- Storage package container is private.
- Role assignments are workspace/resource scoped wherever possible.

## Principle

STAT Next separates **authentication identity**, **data-reading identity**, and **incident-writing identity**. The API-caller managed identity proves which Logic App is calling the Function; the Function system identity reads enrichment sources; the Logic App system identity performs Sentinel incident updates. Keep those boundaries separate and grant only the permissions required by the enabled modules.