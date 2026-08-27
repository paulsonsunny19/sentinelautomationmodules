# STAT secure-by-default hardening

This branch retains upstream STAT functionality while reducing deployment exposure.

## Applied

- STAT runtime uses System Assigned Managed Identity; no application client secret is introduced.
- Function is HTTPS-only, TLS 1.2 minimum, HTTP/2 enabled, client affinity disabled.
- FTP/FTPS is disabled and both FTP and SCM basic publishing credentials are disabled.
- Function package ARM parameter is `secureString`, preventing normal parameter disclosure.
- Package source is pinned to STAT-Function v2.3.0 and SHA-256 `c07e9031d2ba7c0ca0ee2e14c2b520560c705a80cfce88aece57bdbf9a803b34` is verified before upload.
- Package download requires HTTPS/TLS 1.2.
- Package Blob container is private and storage disables public Blob access.
- Storage enforces HTTPS and TLS 1.2 and disables cross-tenant object replication.
- Package SAS is read-only and reduced from 365 days to 7 days.
- Deployment-script resources use `cleanupPreference: Always` with one-hour retention.
- Optional sample remains disabled by default.

## Compatibility exceptions

### Shared-key Function storage

The upstream Linux Consumption STAT Function uses `AzureWebJobsStorage` and `WEBSITE_CONTENTAZUREFILECONNECTIONSTRING` connection strings. This branch currently retains storage shared-key support to avoid breaking Azure Files/content-share startup behavior. `allowSharedKeyAccess` therefore remains enabled. Migrating the runtime to identity-based host storage should be tested separately before disabling shared keys.

### Package SAS

The current Linux Consumption compatibility path uses a direct Blob SAS URL for `WEBSITE_RUN_FROM_PACKAGE`. The SAS is treated as a secret and is short-lived. A future validated path should use managed-identity package access and eliminate SAS entirely.

### Storage network ACL

The storage account currently allows public network routing because Linux Consumption package/content access and the Azure deployment-script staging path must remain functional. Public Blob *anonymous access* is disabled. Private endpoints/VNet integration require a different hosting/network design and should not be enabled blindly on Consumption.

## Permissions

Do not automatically grant every upstream STAT Graph/Defender permission unless the corresponding modules are required. The upstream grant script includes broad application permissions such as Directory.Read.All, AuditLog.Read.All, RoleManagement.Read.Directory, mailbox, identity-risk, Defender and threat-intelligence permissions. Use the smallest permission set required by the STAT modules actually enabled in your environment.

The STAT managed identity should receive Microsoft Sentinel RBAC only at the Sentinel workspace/resource-group scope required for operation, never subscription scope by default.
