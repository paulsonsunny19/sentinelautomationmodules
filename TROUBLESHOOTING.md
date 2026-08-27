# Troubleshooting

## `WEBSITE_RUN_FROM_PACKAGE ... URL with redirects`
Use a direct Azure Blob SAS URL for `FunctionPackage`.

## `Microsoft.Web/sites/<name> was not found`
Use the `stat-upstream-azure-fix` deployment. Its Function identity template creates `Microsoft.Web/sites` before the nested `LogicAppConnector` deployment using ARM `dependsOn`.

## Related Alerts returns Log Analytics 403
Complete the official STAT `GrantPermissions.ps1` process and verify the Function's managed identity has the required Sentinel/Log Analytics workspace access. Allow for Azure RBAC propagation.
