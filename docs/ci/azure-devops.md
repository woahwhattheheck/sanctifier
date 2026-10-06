# Azure DevOps CI integration

Sanctifier can run as an Azure DevOps quality gate and publish a SARIF report as a pipeline artifact. See `.azuredevops/sanctifier.yml` for the reusable task steps and `examples/azure-devops/azure-pipelines.yml` for a minimal repository pipeline.

The task runs `sanctifier ci <path> --format sarif`, publishes `sanctifier.sarif`, and only then reapplies Sanctifier's original exit status so findings fail the gate without hiding the report.

The focused CLI smoke test parses SARIF as JSON and checks the template/example wiring. It does not claim an Azure-hosted run; an Azure pipeline remains the platform-level integration gate.
