# STAT Next security model

## Defaults

- System Assigned Managed Identity for the Function runtime.
- HTTPS only and TLS 1.2 minimum.
- FTP/FTPS disabled.
- FTP and SCM basic publishing credentials disabled.
- Anonymous Blob access disabled.
- Cross-tenant storage replication disabled.
- Application Insights enabled for operational auditability.
- No application/client secret in the runtime design.
- No package SAS bootstrap architecture.
- Private package staging in Azure Storage with managed-identity package access.
- Samples and privileged write integrations are not enabled implicitly.

## KQL safety

`stat_kql` intentionally accepts free-form KQL. It is not treated as a sandbox: input guards reject KQL management commands and obvious outbound/code-execution primitives, while the primary boundary is the Function managed identity's **Log Analytics Reader** permission scoped to the intended workspace.

Other KQL-building modules use narrower contracts:

- Related Alerts accepts only `| where` filter lines, limits their length, and rejects statement separators/dangerous constructs.
- Watchlist alias and key values are validated as identifiers/column references before interpolation.
- Entity values used by the free-form KQL prefix are escaped into generated datatables.

## Permission profiles

### Core Sentinel

The Function receives Microsoft Sentinel Reader and Log Analytics Reader at the target workspace. The playbook identity receives the Sentinel responder permissions required for incident updates/comments.

### Entra / Microsoft Graph identity enrichment

`modules/aad_risks.py` uses Microsoft Graph only for read operations that are not already available from Sentinel workspace tables. The reviewed application roles are:

- `User.Read.All`
- `IdentityRiskyUser.Read.All`
- `IdentityRiskEvent.Read.All`
- `AuditLog.Read.All`
- `RoleManagement.Read.Directory`

These roles are not silently embedded as tenant-wide ARM grants. A tenant administrator reviews and runs `infrastructure/grant-api-permissions.ps1` for the Function managed identity.

### Defender

Defender for Endpoint and Defender for Cloud Apps permissions are independent read-only API profiles in the same administrator-reviewed permission script.

## IP enrichment policy

Public IP GeoData uses Microsoft Sentinel first-party enrichment. Failure is surfaced in `EnrichmentWarnings` and in the analyst comment rather than rendered silently as unexplained blank fields. The native playbook explicitly supplies the full incident ARM resource ID, and `stat_base` rejects requests where that scope is missing.

IP network prevalence uses `DeviceNetworkEvents`. An isolated peer can add a small positive score; a well-established peer is context-only and never subtracts risk. A target not observed in telemetry receives no score because endpoint/network coverage is not assumed.

## Principle

Enabling one enrichment path must not silently grant unrelated write permissions. Attacker-shapeable or coverage-dependent enrichment must not reduce incident severity.
