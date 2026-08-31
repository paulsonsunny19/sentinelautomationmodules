# Permission model

STAT Next uses separate permission profiles rather than one all-powerful identity permission bundle. Runtime code uses managed identities and read-only APIs wherever possible; tenant-wide application roles are granted only after explicit administrator review.

## Azure RBAC created by the deployment

| Identity | Scope | Access | Used by |
|---|---|---|---|
| Function System Assigned Managed Identity | Target Log Analytics workspace | Log Analytics Reader | Related Alerts, TI queries, UEBA, IP baseline, Sentinel-first identity tables, optional KQL/watchlists |
| Function System Assigned Managed Identity | Target Sentinel workspace | Microsoft Sentinel Reader | Incident/Sentinel enrichment including first-party GeoData |
| Logic App System Assigned Managed Identity | Target Sentinel workspace | Microsoft Sentinel Responder | Incident severity/tag updates and analyst comments |
| Function System Assigned Managed Identity | Private package container/blob | Storage Blob Data Reader | `WEBSITE_RUN_FROM_PACKAGE` |
| Function System Assigned Managed Identity | Configured playbook resource group, only when RunPlaybook is enabled | Microsoft Sentinel Playbook Operator | Obtain callback URL for exact-allow-listed Consumption Logic App `manual` triggers |

The deployment keeps these assignments at the narrow resource/workspace scope rather than subscription-wide whenever the Azure resource model permits it. The RunPlaybook role assignment is conditional: leaving `runPlaybookAllowedResourceIds` empty creates no Playbook Operator assignment and leaves the route default-denied.

## Microsoft Graph / Entra profile

`modules/aad_risks.py` prefers current Microsoft Sentinel/Log Analytics identity-risk tables first, then uses Microsoft Graph for enrichment that is not present or available in the workspace.

The administrator-reviewed Graph application roles used by current identity/OOF enrichment are:

| Application role | Purpose |
|---|---|
| `User.Read.All` | Read the incident user's directory profile |
| `IdentityRiskyUser.Read.All` | Read `identityProtection/riskyUsers` |
| `IdentityRiskEvent.Read.All` | Read `identityProtection/riskDetections` |
| `AuditLog.Read.All` | Read authentication-method registration details |
| `RoleManagement.Read.Directory` | Read directory role assignments and definitions |
| `MailboxSettings.Read` | Optional `stat_oof` read of `mailboxSettings/automaticRepliesSetting` |

These are read-only application permissions. They are **not** granted automatically by the main ARM/Bicep deployment. A tenant administrator should review and run `infrastructure/grant-api-permissions.ps1` against the Function managed-identity object ID when Graph-backed enrichment is required.

`stat_oof` is not enabled in the default native triage playbook, specifically so deployments that do not need mailbox automatic-replies context do not depend on `MailboxSettings.Read` at runtime.

If tenant permissions are absent, affected Graph lookups degrade with explicit enrichment warnings; Sentinel-native identity enrichment can still succeed where the corresponding workspace tables are present.

## RunPlaybook profile

`stat_run_playbook` is the exceptional privileged module. It starts another compatible Consumption Logic App and therefore does not inherit the read-only permission model used by enrichment modules.

The module is disabled unless `RUN_PLAYBOOK_ALLOWED_RESOURCE_IDS` contains one or more **exact** Logic App ARM resource IDs. `infrastructure/main.bicep` exposes the corresponding `runPlaybookAllowedResourceIds` parameter and, only when non-empty, deploys `infrastructure/run-playbook-rbac.bicep` into the configured playbook resource group.

That RBAC module grants the Function managed identity the built-in **Microsoft Sentinel Playbook Operator** role (`51d6186e-6489-4900-b93f-92e23144cca5`). The role permits reading the workflow and listing trigger callback URLs; STAT Next deliberately uses that callback flow instead of granting Logic App Contributor or invoking the broader workflow trigger `run` ARM action.

Current compatibility scope is intentionally narrow:

- Consumption Logic Apps only (`Microsoft.Logic/workflows`).
- The target workflow must expose a Request/manual trigger named `manual`.
- The callback is obtained from Azure Resource Manager and must be HTTPS on a recognized Azure Logic Apps callback host.
- The callback receives only `{ "IncidentARMId": "<current incident ARM ID>" }`.
- The signed callback URL is never returned to the caller.
- Prefix allow-lists and an unrestricted fallback mode are not supported.

The target playbook itself remains responsible for its own Sentinel connector permissions and any response actions it performs. If you instead use native Microsoft Sentinel incident/alert/entity triggers or automation rules, follow Microsoft's documented Microsoft Sentinel Automation Contributor requirements for the Azure Security Insights service account on the playbook resource group.

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
- Keep enrichment API roles read-only.
- Keep privileged orchestration features opt-in, exact-allow-listed, and separately scoped.
- Do not silently grant permissions for unrelated modules.
- Do not grant broad write roles such as `Directory.ReadWrite.All`, `User.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, or Logic App Contributor to STAT Next for RunPlaybook compatibility.
- Sentinel incident write operations remain in the Logic App / Sentinel connector rather than the Function enrichment modules.
