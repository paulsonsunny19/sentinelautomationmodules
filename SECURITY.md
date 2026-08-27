# Security notes

Use a private Blob container for `stat.zip`. When using a SAS URL, grant only Blob Read permission and choose an appropriate expiry. Treat the SAS URL as a secret because anyone possessing a valid SAS can read the deployment package until it expires.
