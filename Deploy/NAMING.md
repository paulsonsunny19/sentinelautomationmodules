# Resource naming

With `NamingType=default`, the template uses the same upstream STAT convention:

- Function: `stat-<uniqueString(resourceGroup().id)>`
- Storage: `stat<uniqueString(resourceGroup().id)>`

This avoids relying on a manually supplied name such as `stat-Abp` and keeps the Function and connector references derived from the same ARM variable.
