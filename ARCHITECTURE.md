# STAT deployment architecture

```text
Resource Group
  |-- Storage Account (stat...)
  `-- STAT Function App (stat-...; Linux; System Assigned MI)
        |
        `-- nested LogicAppConnector deployment
              |-- STAT v2 custom API / connector
              `-- optional Sample-STAT-Triage
```

The Function App's `WEBSITE_RUN_FROM_PACKAGE` points directly at the user-supplied Azure Blob SAS URL for upstream STAT-Function v2.3.0 `stat.zip`.
