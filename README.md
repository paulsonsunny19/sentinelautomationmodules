# STAT Next

A secure-by-default modernization of the Microsoft Sentinel Triage AssistanT concept.

STAT Next is a new implementation rather than a deployment wrapper around the legacy STAT Function package.

## Design goals

- System Assigned Managed Identity for runtime authentication.
- No application client secrets.
- No GitHub-release `WEBSITE_RUN_FROM_PACKAGE` bootstrap chain at runtime.
- Least-privilege, module-specific permissions.
- Native Microsoft Sentinel and Log Analytics enrichment first.
- Microsoft Graph / Entra / Defender integrations remain explicit permission profiles.
- HTTPS only, TLS 1.2+, basic publishing disabled.
- Infrastructure as code using Bicep/ARM.
- Ready-to-run Function package validated and published by CI.
- Structured JSON responses with correlation IDs and auditable module execution.

## Current API surface

| Route | Purpose |
|---|---|
| `health` | Service/module health |
| `incident_context` | Microsoft Sentinel incident, alert and entity context |
| `stat_base` | Normalize incident entities and enrich public IPs with Sentinel GeoData |
| `stat_aad_risks` | Sentinel/Entra identity risk, registration, role and MFA context |
| `stat_related_alerts` | Related-alert correlation with exact structured IP matching |
| `stat_threat_intel` | Sentinel threat-intelligence correlation |
| `stat_ip_baseline` | `DeviceNetworkEvents` IP prevalence/baseline context |
| `stat_watchlist` | Sentinel watchlist correlation |
| `stat_kql` | Explicit free-form KQL enrichment endpoint with safety guards |
| `stat_mde` | Microsoft Defender for Endpoint context |
| `stat_ueba` | Sentinel UEBA / anomaly context |
| `stat_file` | File/hash enrichment |
| `stat_mcas` | Defender for Cloud Apps compatibility enrichment |
| `stat_scoring` | Aggregate module scoring |
| `stat_comment` | Build the rich analyst-facing Sentinel incident comment |

The native activation playbook passes the complete Sentinel trigger plus an explicit `incidentArmId` into `stat_base`. Missing incident ARM scope is rejected instead of silently skipping GeoIP enrichment.

## Deployment notes

The Function package is staged into private Azure Storage during deployment and loaded with managed identity. Tenant-wide API permissions are **not** created silently by the ARM deployment. When Graph/Defender enrichment is required, a tenant administrator should review and run `infrastructure/grant-api-permissions.ps1` for the Function managed identity.

See `docs/ARCHITECTURE.md`, `docs/PERMISSIONS.md`, `docs/SECURITY.md`, and `infrastructure/PORTAL-DEPLOYMENT.md`.
