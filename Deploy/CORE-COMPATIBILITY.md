# Core compatibility

The local System Assigned Function template retains the upstream settings that were missing from the earlier simplified attempt, including `WEBSITE_CONTENTAZUREFILECONNECTIONSTRING`, `WEBSITE_CONTENTSHARE`, `clientAffinityEnabled`, the full STAT API endpoint environment variables, and the nested connector deployment with an explicit dependency on the Function App.
