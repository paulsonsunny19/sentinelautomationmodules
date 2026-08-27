# Sentinel Automation Modules

Azure deployment-compatible fork of briandelmsft/SentinelAutomationModules.

This fork addresses the Linux Consumption Function App restriction that prevents `WEBSITE_RUN_FROM_PACKAGE` from using redirecting GitHub Release URLs.

## Deployment package fix

Use a direct Azure Blob Storage URL (normally a read-only Blob SAS URL) for `FunctionPackage`, for example:

```
https://<account>.blob.core.windows.net/<container>/stat.zip?<SAS>
```

Source: https://github.com/briandelmsft/SentinelAutomationModules
