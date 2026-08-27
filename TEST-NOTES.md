# Test notes

Use a new/empty resource group for the first validation deployment. Default naming derives stable globally unique Function and Storage names from the resource-group ID. Supply the direct Blob SAS URL to `stat.zip`, leave `identityType` as `system`, and initially leave the optional sample disabled. Once the core Function and STAT v2 connector deploy successfully, enable/test the sample separately if desired.
