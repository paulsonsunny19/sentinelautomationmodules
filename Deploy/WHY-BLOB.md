# Why Azure Blob Storage is required

Azure currently rejects creation of Linux Consumption Function Apps when `WEBSITE_RUN_FROM_PACKAGE` is a URL that responds with a redirect. GitHub Release asset links redirect to another host. A direct Azure Blob URL avoids that redirect while leaving STAT's run-from-package architecture unchanged.
