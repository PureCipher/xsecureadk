# SecureADK Quickstart

This sample shows the config-driven SecureADK runtime in the smallest possible
agent:

- `secureadk.yaml` is autodiscovered from the agent folder.
- model responses are signed and written to the SecureADK ledger
- tool calls are checked against runtime policy before execution
- the same app can be inspected with `adk secure ...` audit commands

## Run locally

From the repository root:

```bash
adk run contributing/samples/secureadk_quickstart
```

To use the web UI:

```bash
adk web contributing/samples
```

Try prompts like:

- `What does this sample do?`
- `Record this evidence: camera 3 saw the blue sedan at 9:14 PM.`

The second prompt should trigger the `record_evidence` tool, which is allowed by
`secureadk.yaml`.

## Override the config explicitly

You can override autodiscovery with `--secure_config`:

```bash
adk run \
  --secure_config contributing/samples/secureadk_quickstart/secureadk.yaml \
  contributing/samples/secureadk_quickstart
```

The same flag is supported by:

- `adk eval`
- `adk web`
- `adk api_server`
- `adk deploy cloud_run`
- `adk deploy gke`
- `adk deploy agent_engine`

## Inspect and verify

After you run the sample, you can inspect the SecureADK artifacts directly:

```bash
adk secure replay-ledger contributing/samples/secureadk_quickstart --show_entries
adk secure dashboard contributing/samples/secureadk_quickstart
adk secure trust-report contributing/samples/secureadk_quickstart
```

You can also export and verify evidence bundles:

```bash
adk secure export-invocation-bundle \
  contributing/samples/secureadk_quickstart \
  INVOCATION_ID \
  --output_path /tmp/secureadk-bundle.json

adk secure verify-bundle \
  contributing/samples/secureadk_quickstart \
  /tmp/secureadk-bundle.json
```

If you extend the config with `deployment_attestation.enabled: true`, deploy
packaging will also emit `.secureadk.attestation.json`, which you can verify
with:

```bash
adk secure verify-attestation contributing/samples/secureadk_quickstart
```

## Deploy

Cloud Run:

```bash
adk deploy cloud_run \
  --project=YOUR_PROJECT \
  --region=us-central1 \
  --service_name=secureadk-quickstart \
  --secure_config contributing/samples/secureadk_quickstart/secureadk.yaml \
  contributing/samples/secureadk_quickstart
```

GKE:

```bash
adk deploy gke \
  --project=YOUR_PROJECT \
  --region=us-central1 \
  --cluster_name=YOUR_CLUSTER \
  --service_name=secureadk-quickstart \
  --secure_config contributing/samples/secureadk_quickstart/secureadk.yaml \
  contributing/samples/secureadk_quickstart
```

Agent Engine:

```bash
adk deploy agent_engine \
  --project=YOUR_PROJECT \
  --region=us-central1 \
  --secure_config contributing/samples/secureadk_quickstart/secureadk.yaml \
  contributing/samples/secureadk_quickstart
```

`adk deploy agent_engine` supports SecureADK runtime policy, signing,
provenance, and artifact sealing. When SecureADK config is bundled for Agent
Engine, the staged package also pins `google-adk` to the current repo version.

## Extend the sample config

The bundled `secureadk.yaml` is intentionally minimal. To explore the newer
SecureADK features, add these top-level sections as needed:

- `gateway` for app-level access control before tool policy
- `lineage` for versioned runtime and eval lineage
- `trusted_evaluators` for signed eval results
- `tenant_isolation` and `tenant_crypto` for multi-tenant separation and
  per-tenant signing scope
- `deployment_attestation` for deploy-time source manifests
- `trust_scoring` for operational trust reports
- `anomaly_detection` for runtime alerts
