# Recommended first test

Target: a fresh resource group.

Parameters:
- NamingType: default
- FunctionPackage: direct Blob SAS URL
- identityType: system
- DeployBasicSample: false

Expected sequence in Deployment operations:
1. storage account succeeds
2. nested `STATFunctionSystemId` starts
3. `Microsoft.Web/sites` Function succeeds
4. nested `LogicAppConnector` starts
5. `Microsoft.Web/customApis` STAT connector succeeds
