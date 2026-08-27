# Deploy actual STAT to Azure

This branch preserves the upstream STAT deployment chain for the recommended System Assigned Managed Identity deployment:

Storage Account -> STAT Linux Function App -> STAT v2 Custom Connector -> optional Sample-STAT-Triage playbook.

The only deployment compatibility change is that `FunctionPackage` must be a direct Azure Blob Storage URL (normally a read-only SAS URL) to `stat.zip`. GitHub Release redirect URLs are not accepted by Azure Linux Consumption creation.

## Portal

1. Download `stat.zip` from the upstream STAT-Function v2.3.0 release.
2. Upload it to a private Azure Blob container.
3. Generate a read-only SAS URL for the blob.
4. Deploy `Deploy/statdeploy.json` from this branch using Azure Portal custom template.
5. Use `NamingType=default` unless you require custom globally unique names.
6. Set `FunctionPackage` to the direct `https://<account>.blob.core.windows.net/<container>/stat.zip?...` URL.
7. Leave `identityType=system`.
8. After deployment, run the upstream `Deploy/GrantPermissions.ps1` permission procedure.

The Function template explicitly creates Microsoft.Web/sites before the nested LogicAppConnector deployment, matching the upstream STAT architecture.
