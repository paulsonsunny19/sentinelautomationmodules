# STAT Function deployment

`SystemIdentity.json` preserves the upstream STAT Function + nested custom connector deployment topology. The Function App is created before `LogicAppConnector` via an explicit ARM `dependsOn`.

`WEBSITE_RUN_FROM_PACKAGE` receives the `FunctionPackage` parameter. For Linux Consumption this fork requires that parameter to be a direct Azure Blob Storage URL rather than a redirecting GitHub Release URL.
