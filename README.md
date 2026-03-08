# Agent Development Kit (ADK)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/google-adk)](https://pypi.org/project/google-adk/)
[![Python Unit Tests](https://github.com/google/adk-python/actions/workflows/python-unit-tests.yml/badge.svg)](https://github.com/google/adk-python/actions/workflows/python-unit-tests.yml)
[![r/agentdevelopmentkit](https://img.shields.io/badge/Reddit-r%2Fagentdevelopmentkit-FF4500?style=flat&logo=reddit&logoColor=white)](https://www.reddit.com/r/agentdevelopmentkit/)
<a href="https://codewiki.google/github.com/google/adk-python"><img src="https://www.gstatic.com/_/boq-sdlc-agents-ui/_/r/Mvosg4klCA4.svg" alt="Ask Code Wiki" height="20"></a>

<html>
    <h2 align="center">
      <img src="https://raw.githubusercontent.com/google/adk-python/main/assets/agent-development-kit.png" width="256"/>
    </h2>
    <h3 align="center">
      An open-source, code-first Python framework for building, evaluating, and deploying sophisticated AI agents with flexibility and control.
    </h3>
    <h3 align="center">
      Important Links:
      <a href="https://google.github.io/adk-docs/">Docs</a>,
      <a href="https://github.com/google/adk-samples">Samples</a>,
      <a href="https://github.com/google/adk-java">Java ADK</a>,
      <a href="https://github.com/google/adk-go">Go ADK</a> &
      <a href="https://github.com/google/adk-web">ADK Web</a>.
    </h3>
</html>

Agent Development Kit (ADK) is a flexible and modular framework that applies
software development principles to AI agent creation. It is designed to
simplify building, deploying, and orchestrating agent workflows, from simple
tasks to complex systems. While optimized for Gemini, ADK is model-agnostic,
deployment-agnostic, and compatible with other frameworks.

---

## 🔥 What's new

- **Custom Service Registration**: Add a service registry to provide a generic way to register custom service implementations to be used in FastAPI server. See [short instruction](https://github.com/google/adk-python/discussions/3175#discussioncomment-14745120). ([391628f](https://github.com/google/adk-python/commit/391628fcdc7b950c6835f64ae3ccab197163c990))

- **Rewind**: Add the ability to rewind a session to before a previous invocation ([9dce06f](https://github.com/google/adk-python/commit/9dce06f9b00259ec42241df4f6638955e783a9d1)).

- **New CodeExecutor**: Introduces a new AgentEngineSandboxCodeExecutor class that supports executing agent-generated code using the Vertex AI Code Execution Sandbox API ([ee39a89](https://github.com/google/adk-python/commit/ee39a891106316b790621795b5cc529e89815a98))

## ✨ Key Features

- **Rich Tool Ecosystem**: Utilize pre-built tools, custom functions,
  OpenAPI specs, MCP tools or integrate existing tools to give agents diverse
  capabilities, all for tight integration with the Google ecosystem.

- **Code-First Development**: Define agent logic, tools, and orchestration
  directly in Python for ultimate flexibility, testability, and versioning.

- **Agent Config**: Build agents without code. Check out the
  [Agent Config](https://google.github.io/adk-docs/agents/config/) feature.

- **Tool Confirmation**: A [tool confirmation flow(HITL)](https://google.github.io/adk-docs/tools/confirmation/) that can guard tool execution with explicit confirmation and custom input.

- **Modular Multi-Agent Systems**: Design scalable applications by composing
  multiple specialized agents into flexible hierarchies.

- **Deploy Anywhere**: Easily containerize and deploy agents on Cloud Run or
  scale seamlessly with Vertex AI Agent Engine.

## 🚀 Installation

### Stable Release (Recommended)

You can install the latest stable version of ADK using `pip`:

```bash
pip install google-adk
```

The release cadence is roughly bi-weekly.

This version is recommended for most users as it represents the most recent official release.

### Development Version
Bug fixes and new features are merged into the main branch on GitHub first. If you need access to changes that haven't been included in an official PyPI release yet, you can install directly from the main branch:

```bash
pip install git+https://github.com/google/adk-python.git@main
```

Note: The development version is built directly from the latest code commits. While it includes the newest fixes and features, it may also contain experimental changes or bugs not present in the stable release. Use it primarily for testing upcoming changes or accessing critical fixes before they are officially released.

## 🤖 Agent2Agent (A2A) Protocol and ADK Integration

For remote agent-to-agent communication, ADK integrates with the
[A2A protocol](https://github.com/google-a2a/A2A/).
See this [example](https://github.com/a2aproject/a2a-samples/tree/main/samples/python/agents)
for how they can work together.

## 📚 Documentation

Explore the full documentation for detailed guides on building, evaluating, and
deploying agents:

* **[Documentation](https://google.github.io/adk-docs)**

## 🔐 SecureADK Runtime

This repository also includes an optional SecureADK runtime extension. It adds
runtime identity binding, policy-gated tool execution, response signing,
provenance logging, and optional artifact sealing on top of the normal ADK
execution path.

SecureADK is not a separate runner or fork of ADK. It attaches to the existing
ADK runtime through the normal `App`, `Runner`, plugin, and artifact-service
extension points.

### What SecureADK Adds

- Runtime identity binding for agents.
- Policy and gateway checks before tool execution.
- Short-lived capability issuance for allowed tool calls.
- Optional approval-required flow for high-risk actions.
- Signed model responses, including response-chain hashes in metadata.
- Provenance records written to a ledger.
- Versioned lineage records for prompts, tools, responses, artifacts, evals,
  and deployment attestations.
- Trusted evaluator signatures on eval outputs.
- Optional artifact sealing through the artifact service wrapper.
- Runtime anomaly detection plus logging/export/webhook alert sinks.
- Secure observability sinks, telemetry redaction, and policy recommendations.
- Deployment attestation for packaged runtimes.
- Trust scoring for agents, tools, evaluators, and deployments.
- Replay diffing across invocation history and exported evidence bundles.
- Optional per-tenant signing scope for capabilities, responses, artifacts,
  bundles, eval signatures, and deploy attestations.

### How It Fits Into ADK

At runtime, SecureADK layers onto the existing code path:

1. ADK loads the agent or app normally.
1. `SecureRuntimeBuilder` appends `SecureRuntimePlugin` to the app.
1. The plugin binds agent names to registered identities.
1. If configured, a dedicated gateway validates run-level and tool-level access
   before the call reaches agent logic.
1. Before a tool executes, SecureADK evaluates policy and either:
   - issues a capability token and allows the tool call, or
   - requests approval, or
   - returns a structured denial result.
1. After a model response, SecureADK signs the response metadata and records
   provenance and lineage.
1. Trusted evaluator signatures and trust updates are applied on eval paths.
1. If artifact sealing is enabled, the artifact service is wrapped so saved
   artifacts include a seal.
1. If tenant crypto is enabled, signing scopes switch from global keys to
   tenant-derived keys.

At deploy time, `adk deploy cloud_run`, `gke`, and `agent_engine` can bundle
SecureADK config and emit a staged `.secureadk.attestation.json` that is later
verified during runtime startup.

This means you keep the standard ADK programming model while getting stronger
runtime controls.

### Enable SecureADK

SecureADK config resolution works like this:

1. `--secure_config /path/to/config` has highest precedence.
1. If no explicit config is passed and `ADK_DISABLE_SECURE_RUNTIME=1` is set,
   SecureADK file resolution is skipped for that process.
1. Otherwise, `ADK_SECURE_CONFIG=/path/to/config` is used if present.
1. Otherwise, ADK autodiscovers `secureadk.yaml`, `secureadk.yml`, or
   `secureadk.json` from the loaded app root.

The explicit `--secure_config` flag is supported by:

- `adk run`
- `adk eval`
- `adk web`
- `adk api_server`
- `adk deploy cloud_run`
- `adk deploy gke`
- `adk deploy agent_engine`

### Config File

SecureADK config is file-backed and validated on load. YAML and JSON are both
supported.

Minimal example:

```yaml
enabled: true
signing_keys:
  dev-key:
    secret: change-me-for-dev-only
identities:
  - agent_name: secure_hello_agent
    key_id: dev-key
    roles: [case_writer]
policy:
  default_effect: deny
  default_capability_ttl_seconds: 300
  rules:
    - name: allow-record-evidence
      principals: [secure_hello_agent]
      roles: [case_writer]
      tools: [record_evidence]
      actions: [record_evidence]
runtime:
  plugin_name: secure_runtime
  tenant_state_key: tenant_id
  case_state_key: case_id
  enforce_agent_identity: true
  sign_model_responses: true
  sign_partial_responses: false
artifact_sealing:
  enabled: false
ledger:
  path: .adk/secureadk/demo-ledger.jsonl
```

Advanced example:

```yaml
enabled: true
signing_keys:
  primary:
    secret_env: SECUREADK_PRIMARY_SECRET
identities:
  - agent_name: judge
    key_id: primary
    roles: [judge]
    tenant_id: tenant-a
policy:
  default_effect: deny
  approval_risk_score_threshold: 0.8
  default_approval_hint: "Judicial approval required."
  rules:
    - name: judge-read-evidence
      principals: [judge]
      roles: [judge]
      tools: [sealed_evidence]
      actions: [sealed_evidence]
      tenant_ids: [tenant-a]
gateway:
  enabled: true
  rules:
    - name: judge-run-access
      operations: [run]
      resource_types: [agent]
      principals: [judge]
      tenant_ids: [tenant-a]
lineage:
  enabled: true
trusted_evaluators:
  enabled: true
  evaluator_name: court-evaluator
  signing_key_id: primary
tenant_isolation:
  enabled: true
  bindings:
    - user_id: alice
      tenant_id: tenant-a
tenant_crypto:
  enabled: true
  require_tenant: true
deployment_attestation:
  enabled: true
  signing_key_id: primary
trust_scoring:
  enabled: true
artifact_sealing:
  enabled: true
  signing_key_id: primary
anomaly_detection:
  enabled: true
  logging:
    enabled: true
```

#### Top-Level Fields

| Field | Purpose | Default |
| --- | --- | --- |
| `enabled` | Enables SecureADK for the loaded app. | `true` |
| `signing_keys` | Named signing key definitions used for response signing, capability issuance, and optional artifact sealing. | required |
| `identities` | Runtime identity registrations keyed by agent name. | required |
| `policy` | Tool authorization policy engine config. | deny-by-default |
| `runtime` | Plugin behavior and state-key mapping. | built-in defaults |
| `artifact_sealing` | Artifact seal configuration. | disabled |
| `ledger` | Provenance ledger output location. | `.adk/secureadk/ledger.jsonl` |
| `gateway` | Optional run/tool access gateway ahead of policy. | disabled |
| `anomaly_detection` | Runtime anomaly thresholds and alert sinks. | disabled |
| `lineage` | Versioned lineage storage. | disabled |
| `trusted_evaluators` | Eval signing and verification settings. | disabled |
| `telemetry_privacy` | Redaction/tokenization for secure telemetry. | disabled |
| `observability` | Secure event export to log/file/webhook/OTEL/SIEM sinks. | disabled |
| `policy_recommendations` | Capture and report least-privilege suggestions. | disabled |
| `tenant_isolation` | User-to-tenant bindings for sessions and artifacts. | disabled |
| `tenant_crypto` | Per-tenant signing scope derived from shared keys. | disabled |
| `deployment_attestation` | Deploy-time manifest signing and startup verification. | disabled |
| `trust_scoring` | Persistent trust score tracking. | disabled |

#### `signing_keys`

Each key must define exactly one of:

- `secret`: inline secret value.
- `secret_env`: environment variable containing the secret.

Use `secret_env` for anything outside local development.

#### `identities`

Each identity entry supports:

| Field | Purpose |
| --- | --- |
| `agent_name` | ADK agent name that SecureADK binds at runtime. |
| `key_id` | Signing key used for that agent. |
| `roles` | Role claims used by policy matching. |
| `tenant_id` | Optional default tenant binding if state does not provide one. |
| `attributes` | Extra claims copied into policy context. |

When `runtime.enforce_agent_identity` is `true`, missing identities fail fast
at runtime.

#### `policy`

Policy evaluation is rule-based and deny-by-default.

Global policy fields:

- `default_effect`: `allow` or `deny`. Default is `deny`.
- `default_capability_ttl_seconds`: fallback TTL for issued capabilities.
- `rules`: ordered rule set.

Each rule supports:

| Field | Purpose |
| --- | --- |
| `name` | Rule identifier recorded in decisions and the ledger. |
| `effect` | `allow` or `deny`. |
| `principals` | Agent-name patterns. |
| `roles` | Role intersection requirement. |
| `tools` | Tool-name patterns. |
| `actions` | Action-name patterns. |
| `app_names` | Optional app-name patterns. |
| `tenant_ids` | Optional tenant filters. |
| `required_context` | Context key/value filters. |
| `required_tool_args` | Tool-argument key/value filters. |
| `max_ttl_seconds` | Per-rule override for issued capability TTL. |
| `risk_score` | Numeric score recorded on decisions and denials. |

Important behavior:

- Deny rules override allow rules.
- If no rule matches, the policy engine uses `default_effect`.
- Tool `action` defaults to the tool name.
- You can override a tool action by setting
  `tool.custom_metadata["secure_action"]`.

Policy context currently includes tenant, case, tool name, and user ID, plus
any custom identity attributes.

#### `runtime`

Runtime plugin settings:

| Field | Purpose | Default |
| --- | --- | --- |
| `plugin_name` | Name of the injected app plugin. | `secure_runtime` |
| `tenant_state_key` | Session state key used to resolve tenant. | `tenant_id` |
| `case_state_key` | Session state key used to resolve case ID. | `case_id` |
| `enforce_agent_identity` | Fail if an active agent has no registered identity. | `true` |
| `sign_model_responses` | Sign non-empty model responses. | `true` |
| `sign_partial_responses` | Also sign partial/streaming responses. | `false` |

#### `artifact_sealing`

Artifact sealing is off by default. When enabled:

- `signing_key_id` becomes required.
- artifacts saved through the wrapped ADK artifact service are sealed.
- seal metadata is written alongside the artifact.

#### `ledger`

`ledger.path` controls where provenance entries are written. If omitted,
SecureADK writes JSONL records to:

```text
.adk/secureadk/ledger.jsonl
```

#### `gateway`

Use `gateway` when you want a separate allow/deny layer before policy
evaluation. This is useful for app-level or tenant-level access control where
the request should be blocked before tool authorization logic runs.

Important fields:

- `enabled`: turns the gateway on.
- `default_effect`: `allow` or `deny`.
- `approval_risk_score_threshold`: convert high-risk gateway matches into
  approval-required decisions.
- `rules`: ordered `GatewayRule` entries with principals, operations,
  resource types, app names, tenant IDs, and optional context filters.

#### `anomaly_detection`

`anomaly_detection` enables runtime anomaly and collusion heuristics.

Important fields:

- `repeated_denials_threshold`
- `capability_burst_threshold`
- `duplicate_response_agents_threshold`
- `high_risk_score_threshold`
- `block_severity_threshold`

Alert sinks:

- `logging.enabled`
- `export.enabled` with optional `path`
- `webhook.enabled` with `url`, `headers`, `timeout_seconds`, and optional
  `signing_key_id`

#### `lineage`

When `lineage.enabled` is `true`, SecureADK writes versioned JSONL lineage
records to `.adk/secureadk/lineage.jsonl` unless `lineage.path` is overridden.

#### `trusted_evaluators`

Trusted evaluators sign `InferenceResult`, `EvalCaseResult`, and
`EvalSetResult` metadata. Key fields:

- `enabled`
- `evaluator_name`
- `signing_key_id`
- `trusted_evaluators`
- `sign_inference_results`
- `sign_eval_case_results`
- `sign_eval_set_results`

#### `telemetry_privacy`

Use this to redact or tokenize secure telemetry before it reaches provenance,
lineage, anomaly sinks, or observability sinks.

Important fields:

- `mode`: `redact` or `tokenize`
- `replacement_text`
- `field_names`
- `redact_email`
- `redact_phone`
- `redact_ssn`
- `redact_credit_card`
- `tokenization_key_id` for tokenize mode

#### `observability`

Secure event export supports:

- logging
- JSONL export
- webhook
- OpenTelemetry
- Splunk HEC
- Datadog logs
- BigQuery

Enable `observability.enabled: true` before enabling any child sink.

#### `policy_recommendations`

Policy recommendations record runtime decisions and generate least-privilege
reports from actual usage.

Important fields:

- `path`
- `minimum_evidence_count`
- `high_risk_threshold`

#### `tenant_isolation`

Tenant isolation namespaces sessions and artifacts by tenant. It does not
create OS-level sandboxes; it enforces SecureADK-level separation inside ADK
services.

Important fields:

- `require_tenant`
- `enforce_identity_tenant_match`
- `require_session_scoped_artifacts`
- `bindings`: static `user_id -> tenant_id`

#### `tenant_crypto`

When enabled, SecureADK derives tenant-scoped signing keys from the configured
shared keys. The tenant is resolved from session state, app namespaced tenant
markers, explicit fallback values, user bindings, or loaded session state.

Important fields:

- `enabled`
- `require_tenant`

When `require_tenant` is `true`, signing fails if SecureADK cannot resolve a
tenant for the operation.

#### `deployment_attestation`

Deployment attestation signs a manifest of staged source files and verifies it
again when the runtime starts.

Important fields:

- `enabled`
- `signing_key_id`
- `actor`
- `file_name`

Default staged filename:

```text
.secureadk.attestation.json
```

Deploy commands generate this file automatically when deployment attestation is
enabled in the bundled SecureADK config.

#### `trust_scoring`

Trust scoring persists a score history for:

- agents
- tools
- evaluators
- deployments

Important fields:

- `path`
- `base_score`
- `min_score`
- `max_score`

### CLI Usage

Run locally with autodiscovery:

```bash
adk run path/to/agent
```

Override config explicitly:

```bash
adk run \
  --secure_config /absolute/path/to/secureadk.yaml \
  path/to/agent
```

Run evaluations through the secured app path:

```bash
adk eval \
  --secure_config /absolute/path/to/secureadk.yaml \
  path/to/agent \
  path/to/eval_set.json
```

Start the web UI or API server:

```bash
adk web --secure_config /absolute/path/to/secureadk.yaml path/to/agents_dir
adk api_server --secure_config /absolute/path/to/secureadk.yaml path/to/agents_dir
```

Deploy with SecureADK bundled:

```bash
adk deploy cloud_run --secure_config /absolute/path/to/secureadk.yaml ...
adk deploy gke --secure_config /absolute/path/to/secureadk.yaml ...
adk deploy agent_engine --secure_config /absolute/path/to/secureadk.yaml ...
```

For `adk deploy agent_engine`, SecureADK config is packaged into the generated
deployment source, and the staged `requirements.txt` is pinned to the current
`google-adk` version when needed so the deployed runtime matches the generated
SecureADK wrapper code.

Deployment attestation is generated during deploy packaging when
`deployment_attestation.enabled: true` is present in the bundled SecureADK
config.

### Secure Operations CLI

SecureADK also exposes audit, explainability, and verification commands:

```bash
adk secure verify-eval APP_ROOT EVAL_RESULT.json
adk secure verify-lineage APP_ROOT
adk secure replay-ledger APP_ROOT --show_entries
adk secure verify-attestation APP_ROOT
adk secure trust-report APP_ROOT
adk secure explain-policy APP_ROOT REQUEST.json
adk secure explain-gateway APP_ROOT REQUEST.json
adk secure export-invocation-bundle APP_ROOT INVOCATION_ID
adk secure export-eval-bundle APP_ROOT EVAL_RESULT.json
adk secure verify-bundle APP_ROOT BUNDLE.json
adk secure diff-invocations APP_ROOT INVOCATION_A INVOCATION_B
adk secure diff-bundles APP_ROOT LEFT_BUNDLE.json RIGHT_BUNDLE.json
adk secure recommend-policies APP_ROOT
adk secure dashboard APP_ROOT
```

The most useful operational workflows are:

- verify a staged deployment attestation after packaging or deployment
- inspect trust score drift after anomalies, denials, or signature failures
- export an invocation evidence bundle for audit handoff
- replay and diff two invocations when behavior changes unexpectedly

### Direct Python Integration

If you do not want to rely on file-based config discovery, you can wire
SecureADK directly in Python:

```python
from google.adk import Runner, SecureRuntimeBuilder
from google.adk.apps import App
from google.adk.secure import (
    AgentIdentity,
    CapabilityVault,
    HmacKeyring,
    IdentityRegistry,
    InMemoryProvenanceLedger,
    SimplePolicyEngine,
)

keyring = HmacKeyring({"dev-key": "change-me"})
builder = SecureRuntimeBuilder(
    identity_registry=IdentityRegistry([
        AgentIdentity(
            agent_name="secure_agent",
            key_id="dev-key",
            roles=("case_writer",),
        )
    ]),
    capability_vault=CapabilityVault(
        policy_engine=SimplePolicyEngine(
            rules=[],
            default_effect="deny",
            default_capability_ttl_seconds=300,
        ),
        keyring=keyring,
    ),
    ledger=InMemoryProvenanceLedger(),
    response_keyring=keyring,
    artifact_signing_key_id="dev-key",
    artifact_keyring=keyring,
)

app = App(name="secure_app", root_agent=root_agent)
secure_app = builder.apply_to_app(app)
secure_artifact_service = builder.wrap_artifact_service(artifact_service)

runner = Runner(
    app=secure_app,
    artifact_service=secure_artifact_service,
    session_service=session_service,
)
```

### What You Will See At Runtime

With SecureADK enabled:

- model responses include SecureADK metadata under `custom_metadata["secureadk"]`
- denied tool calls return a structured denial payload instead of silently
  proceeding
- approval-required actions pause and resume through the normal ADK resumable
  execution path
- provenance events are written to the configured ledger
- lineage records are written when lineage tracking is enabled
- sealed artifacts include seal metadata when artifact sealing is enabled
- eval outputs can carry trusted evaluator signatures
- anomaly alerts, trust score updates, and evidence bundles become available
  when those features are enabled
- deploy targets can carry a runtime-verifiable attestation manifest
- signed metadata includes `keyScope` and `tenantId` when tenant crypto is
  enabled

### Recommended Adoption Path

1. Start with response signing and provenance only.
1. Add identities for every active agent.
1. Turn on deny-by-default policy and allow only the tools you want.
1. Add lineage and trusted evaluators if you need reproducibility and auditable
   evals.
1. Enable artifact sealing for workflows that persist evidence or case files.
1. Turn on tenant isolation and tenant crypto before multi-tenant rollout.
1. Add deployment attestation and trust scoring for deployment and operations
   monitoring.
1. Move secrets out of inline config and into environment variables.

For a minimal working example, see
`contributing/samples/secureadk_quickstart`.

## 🏁 Feature Highlight

### Define a single agent:

```python
from google.adk.agents import Agent
from google.adk.tools import google_search

root_agent = Agent(
    name="search_assistant",
    model="gemini-2.5-flash", # Or your preferred Gemini model
    instruction="You are a helpful assistant. Answer user questions using Google Search when needed.",
    description="An assistant that can search the web.",
    tools=[google_search]
)
```

### Define a multi-agent system:

Define a multi-agent system with coordinator agent, greeter agent, and task execution agent. Then ADK engine and the model will guide the agents to work together to accomplish the task.

```python
from google.adk.agents import LlmAgent, BaseAgent

# Define individual agents
greeter = LlmAgent(name="greeter", model="gemini-2.5-flash", ...)
task_executor = LlmAgent(name="task_executor", model="gemini-2.5-flash", ...)

# Create parent agent and assign children via sub_agents
coordinator = LlmAgent(
    name="Coordinator",
    model="gemini-2.5-flash",
    description="I coordinate greetings and tasks.",
    sub_agents=[ # Assign sub_agents here
        greeter,
        task_executor
    ]
)
```

### Development UI

A built-in development UI to help you test, evaluate, debug, and showcase your agent(s).

<img src="https://raw.githubusercontent.com/google/adk-python/main/assets/adk-web-dev-ui-function-call.png"/>

###  Evaluate Agents

```bash
adk eval \
    samples_for_testing/hello_world \
    samples_for_testing/hello_world/hello_world_eval_set_001.evalset.json
```

## 🤝 Contributing

We welcome contributions from the community! Whether it's bug reports, feature requests, documentation improvements, or code contributions, please see our
- [General contribution guideline and flow](https://google.github.io/adk-docs/contributing-guide/).
- Then if you want to contribute code, please read [Code Contributing Guidelines](./CONTRIBUTING.md) to get started.

## Community Repo

We have [adk-python-community repo](https://github.com/google/adk-python-community) that is home to a growing ecosystem of community-contributed tools, third-party
service integrations, and deployment scripts that extend the core capabilities
of the ADK.

## Vibe Coding

If you want to develop agent via vibe coding the [llms.txt](./llms.txt) and the [llms-full.txt](./llms-full.txt) can be used as context to LLM. While the former one is a summarized one and the later one has the full information in case your LLM has big enough context window.

## Community Events

- [Completed] ADK's 1st community meeting on Wednesday, October 15, 2025. Remember to [join our group](https://groups.google.com/g/adk-community) to get access to the [recording](https://drive.google.com/file/d/1rpXDq5NSH8-MyMeYI6_5pZ3Lhn0X9BQf/view), and [deck](https://docs.google.com/presentation/d/1_b8LG4xaiadbUUDzyNiapSFyxanc9ZgFdw7JQ6zmZ9Q/edit?slide=id.g384e60cdaca_0_658&resourcekey=0-tjFFv0VBQhpXBPCkZr0NOg#slide=id.g384e60cdaca_0_658).

## 📄 License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

---

*Happy Agent Building!*
