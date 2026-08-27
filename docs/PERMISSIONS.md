# Permission model

STAT Next uses permission profiles rather than one all-powerful identity permission bundle.

| Profile | Intended access |
|---|---|
| Core Sentinel | Sentinel incident and alert read/approved response operations at target workspace scope |
| Related Alerts | Log Analytics query access to target workspace |
| Entra Basic | Optional directory/user enrichment only |
| Entra Risk | Optional identity-risk enrichment |
| Defender XDR | Optional Defender XDR enrichment |
| Defender Endpoint | Optional MDE enrichment |
| Threat Intelligence | Optional TI enrichment |

The deployment must not grant optional profiles unless explicitly enabled.

For the first milestone, only Core Sentinel and Related Alerts will be implemented. This avoids reproducing the broad legacy STAT Graph/Defender permission footprint before those integrations are needed.
