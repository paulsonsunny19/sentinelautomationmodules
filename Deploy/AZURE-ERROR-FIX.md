# Fix for the reported Azure errors

### Redirect error
Fixed by supplying `FunctionPackage` as a direct Azure Blob SAS URL.

### `Microsoft.Web/sites/stat-Abp was not found`
The rebuilt SystemIdentity template creates the Function App as an ARM resource and makes `LogicAppConnector` depend explicitly on that exact Function resource. Default naming derives the Function name once in the parent template and passes the same value into all child references.
