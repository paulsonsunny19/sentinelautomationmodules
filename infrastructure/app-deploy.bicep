param functionName string
@description('Direct HTTPS URL to a deterministic STAT Next application ZIP. Redirecting URLs are not supported.')
param packageUri string

resource functionApp 'Microsoft.Web/sites@2022-09-01' existing = {
  name: functionName
}

// Deploy the application through the App Service OneDeploy ARM extension instead of
// WEBSITE_RUN_FROM_PACKAGE. This keeps deployment Portal/ARM-driven and avoids
// persisting a package URL or SAS token in Function application settings.
resource oneDeploy 'Microsoft.Web/sites/extensions@2022-09-01' = {
  parent: functionApp
  name: 'onedeploy'
  properties: {
    packageUri: packageUri
    remoteBuild: true
  }
}
