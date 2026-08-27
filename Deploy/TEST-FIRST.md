# First deployment recommendation

Deploy into a new test resource group with `DeployBasicSample=false`. This validates the three core stages independently: storage creation, STAT Function creation/package mount, and STAT v2 connector creation. Once those succeed, redeploy with the sample enabled if required.
