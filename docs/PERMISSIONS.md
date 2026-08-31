# Permission model

STAT Next uses separate permission profiles rather than one all-powerful identity permission bundle. Runtime code uses managed identities and read-only APIs wherever possible; tenant-wide application roles are granted only after explicit administrator review.

## Azure RBAC created by the deployment

| Identity | Scope | Access | Used by |
|---|---|---|---|
| Function System Assigned Managed Identity | Target Log Analytics workspace | Log Analytics Reader | Related Alerts, TI queries, UEBA, IP baseline, Sentinel-first identity tables, optional KQL/watchlists |
| Function System Assigned Managed Identity | Target Sentinel workspace | Microsoft Sentinel Reader | Incident/Sentinel enrichment including first-party GeoData |
| Logic App System Assigned Managed Identity | Target Sentinel workspace | Microsoft Sentinel Responder | Incident severity/tag updates and analyst comments |
| Function System Assigned Managed Identity | Private package container/blob | Storage Blob Data Reader | `WEBSITE_RUN_FROM_PACKAGE` |

The deployment keeps these assignments at the narrow resource/workspace scope rather than subscription-wide whenever the Azure resource model permits it.

## Microsoft Graph / Entra profile

`modules/aad_risks.py` prefers current Microsoft Sentinel/Log Analytics identity-risk tables first, then uses Microsoft Graph for enrichment that is not present or available in the workspace.

The administrator-reviewed Graph application roles used by the module are:

| Application role | Purpose |
|---|---|
| `User.Read.All` | Read the incident user's directory profile |
| `IdentityRiskyUser.Read.All` | Read `identityProtection/riskyUsers` |
| `IdentityRiskEvent.Read.All` | Read `identityProtection/riskDetections` |
| `AuditLog.Read.All` | Read authentication-method registration details |
| `RoleManagement.Read.Directory` | Read directory role assignments and definitions |

These are read-only application permissions. They are **not** granted automatically by the main ARM/Bicep deployment. A tenant administrator should review and run `infrastructure/grant-api-permissions.ps1` against the Function managed-identity object ID when Graph-backed identity enrichment is required.

If these tenant permissions are absent, the affected Graph lookups degrade with explicit enrichment warnings; Sentinel-native identity enrichment can still succeed where the corresponding workspace tables are present.

## Defender profiles

The same administrator-reviewed permission script currently supports the read-only Defender integrations used by STAT Next:

| Resource | Application role | Purpose |
|---|---|---|
| WindowsDefenderATP | `AdvancedQuery.Read.All` | Defender advanced hunting/enrichment queries |
| WindowsDefenderATP | `Machine.Read.All` | MDE device context |
| Microsoft Defender for Cloud Apps | `Investigation.Read` | Read-only investigation/entity enrichment |

Do not grant these roles if the corresponding module is not needed.

## KQL/query boundary

Log Analytics modules run under the Function identity's workspace-scoped Log Analytics Reader role. `stat_kql` intentionally supports caller-supplied KQL for compatibility and controlled custom enrichment. Input guards reject management commands and obvious outbound/code-execution primitives, but least-privilege workspace RBAC remains the primary security boundary.

Related-alert custom filters and watchlist identifiers have narrower validation before any KQL is issued.

## Permission principles

- Prefer Sentinel/Log Analytics data over tenant-wide API permissions when equivalent data exists.
- Keep runtime identities secretless.
- Keep all enrichment API roles read-only.
- Do not silently grant permissions for unrelated modules.
- Do not grant broad write roles such as `Directory.ReadWrite.All`, `User.ReadWrite.All`, or `RoleManagement.ReadWrite.Directory` to STAT Next.
- Sentinel incident write operations remain in the Logic App / Sentinel connector rather than the Function enrichment modules.
