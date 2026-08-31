# STAT Next architecture

STAT Next separates infrastructure deployment, application packaging, runtime enrichment, and privileged orchestration.

```text
Microsoft Sentinel incident trigger
              |
              v
      Logic App / Playbook
              |
              v
        STAT Next API
       Azure Functions v4
    System Assigned Identity
              |
   +----------+----------------------+-------------------+------------------+
   |                                 |                   |                  |
Sentinel ARM / GeoData         Log Analytics       Optional APIs     Optional RunPlaybook
incident context, TI           related alerts,     Microsoft Graph,  exact allow-list only
IP enrichment                  UEBA, baseline      MDE, Defender     Logic App callback
```

The native activation playbook keeps Sentinel incident writes in the playbook connector. Function enrichment modules return structured data; `stat_comment` renders the analyst comment, which the Logic App posts to the incident. `stat_run_playbook` is intentionally separate because it is the one Function route that initiates another workflow and therefore has its own opt-in RBAC and exact target allow-list.

## Runtime flow

1. The Sentinel incident webhook fires the native activation playbook.
2. `stat_base` receives the full trigger payload and an explicit `incidentArmId`.
3. Base entity normalization extracts accounts, IPs, hosts, files, hashes, domains and URLs.
4. Public IPs are enriched with Microsoft Sentinel GeoData. The incident ARM ID supplies the subscription/resource-group/workspace scope needed by the API.
5. Enrichment modules execute independently: identity risk, related alerts, TI, IP network baseline, MDE, UEBA, file insights and optional Defender for Cloud Apps / OOF context.
6. `stat_scoring` consumes module results, including safe module-provided `ScoringData`.
7. `stat_comment` builds the rich incident summary and the Logic App posts it through the Sentinel connector.
8. Custom deployments may separately call `stat_run_playbook`. That route derives the incident ARM ID from the normalized `base`, requires an exact allow-listed Consumption Logic App resource ID, obtains that workflow's `manual` trigger callback URL through Azure Resource Manager, and posts only the current `IncidentARMId` to the signed callback.

The default native triage playbook does not call either OOF or RunPlaybook, so mailbox permissions and privileged playbook-execution RBAC are not required for the standard path.

## Security boundaries

- Managed identity is the default runtime identity; no client secret is required.
- Workspace RBAC grants the Function Log Analytics Reader and Microsoft Sentinel Reader at the target workspace.
- Tenant API permissions are separate and explicitly granted with `infrastructure/grant-api-permissions.ps1` after administrator review.
- Most endpoints accept structured parameters.
- `stat_kql` is the deliberate exception: it accepts caller-supplied KQL for upstream compatibility. Obvious management/outbound primitives are rejected, but the real boundary is the Function identity's read-only, workspace-scoped Log Analytics access.
- Related-alert filter fragments accept only `| where` statements and reject statement separators/dangerous constructs.
- Watchlist aliases and column references are shape-validated before being embedded in KQL.
- IP baseline absence is not scored as malicious because telemetry coverage cannot be assumed. Established estate prevalence is context-only and never lowers severity.
- `stat_run_playbook` is default-deny. An empty `RUN_PLAYBOOK_ALLOWED_RESOURCE_IDS` setting disables it; targets require exact resource-ID membership rather than prefix or wildcard matching.
- Enabling RunPlaybook conditionally grants only Microsoft Sentinel Playbook Operator on one configured playbook resource group. It does not grant Logic App Contributor.
- RunPlaybook accepts incident scope from `base.IncidentARMId`, not from a separate caller-controlled top-level incident identifier.
- The signed Logic Apps callback URL obtained through ARM is validated as HTTPS on a recognized Azure Logic Apps host and is never returned to the caller or included in the module result.

## Deployment artifact flow

CI validates Python, Bicep/ARM, the RunPlaybook RBAC module, and the ready-to-run Linux Consumption package. Only push-triggered validation publishes stable Portal artifacts, preventing duplicate push/PR publishers. The package ZIP is built with normalized entry ordering/timestamps so identical source and dependencies produce identical package bytes.

The ARM deployment stages the validated package into private Azure Storage. The running Function reads that package with its System Assigned Managed Identity rather than a long-lived SAS or direct GitHub URL.
