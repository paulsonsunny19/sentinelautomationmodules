# Azure Portal steps

- Create/open a private Blob container and upload `stat.zip`.
- Generate a read-only SAS URL for the blob.
- Open `DEPLOY-URL.txt`.
- Choose your subscription, resource group, and region.
- Paste the complete Blob SAS URL into the Function Package parameter.
- Keep System Assigned identity and initially disable the sample.
- Select Review + create, then Create.
