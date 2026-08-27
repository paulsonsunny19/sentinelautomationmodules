# STAT Next security model

## Defaults

- System Assigned Managed Identity.
- HTTPS only and TLS 1.2 minimum.
- FTP/FTPS disabled.
- FTP and SCM basic publishing credentials disabled.
- Anonymous Blob access disabled.
- Cross-tenant storage replication disabled.
- Application Insights enabled for operational auditability.
- No application/client secret in the runtime design.
- No package SAS bootstrap architecture.
- No arbitrary KQL API endpoint.
- Samples and high-privilege integrations are opt-in.

## Permission profiles

### Core Sentinel
Required for incident/alert retrieval and approved Sentinel operations. Scope RBAC to the target Sentinel workspace/resource group rather than subscription scope.

### Related Alerts
Grant only Log Analytics query/read access required for the target workspace. Do not grant Microsoft Graph permissions for this module.

### Entra / Graph enrichment
Optional. Grant only the Graph application permissions required by enabled enrichment operations.

### Defender
Optional and separate from Graph/Entra permissions.

## Principle

Enabling one STAT Next module must not silently grant permissions needed by unrelated modules.

## Remaining infrastructure work

The initial Bicep skeleton intentionally does not embed storage keys. Before production deployment, host storage and code deployment will be finalized using an Azure-supported identity-based configuration for the selected Functions hosting plan, and CI/CD will use federated GitHub OIDC rather than stored Azure credentials.
