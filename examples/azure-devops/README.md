# Azure DevOps example

Use the repository's reusable template from an Azure pipeline:

```yaml
steps:
  - checkout: self
  - template: /.azuredevops/sanctifier.yml
    parameters:
      scanPath: contracts/my-contract
      artifactName: sanctifier-sarif
```

This scans the checked-in `contracts/my-contract` example and publishes the SARIF artifact before enforcing the Sanctifier exit status.
