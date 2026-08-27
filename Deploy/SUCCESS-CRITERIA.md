# Success criteria

A successful core deployment must show both the Function App and `STAT v2` connector in the resource group. The Function's Overview page should be reachable, its System Assigned identity should have an object/principal ID, and its `WEBSITE_RUN_FROM_PACKAGE` setting should contain the Azure Blob package URL. Only after these checks should the permissions script and module tests be performed.
