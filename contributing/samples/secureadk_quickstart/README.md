# SecureADK Quickstart

This sample shows the config-driven SecureADK runtime in the smallest possible
agent:

- `secureadk.yaml` is autodiscovered from the agent folder.
- model responses are signed and written to the SecureADK ledger
- tool calls are checked against runtime policy before execution

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

- `adk web`
- `adk api_server`
- `adk deploy cloud_run`
- `adk deploy gke`
- `adk deploy agent_engine`

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

`adk deploy agent_engine` supports SecureADK runtime policy, signing, and
provenance loading. It does not support SecureADK artifact sealing because the
Agent Engine path does not expose artifact-service wrapping in this repo.
