# Function package requirement

`FunctionPackage` must resolve directly to the STAT `stat.zip` bytes without an HTTP redirect. For Azure Portal deployments, upload upstream STAT-Function v2.3.0 `stat.zip` to a private Azure Blob container and use a read-only Blob SAS URL.

Do not use `https://github.com/.../releases/download/.../stat.zip` as `WEBSITE_RUN_FROM_PACKAGE` on Linux Consumption because GitHub redirects release asset downloads.
