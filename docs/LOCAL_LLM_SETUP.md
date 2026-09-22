# Local LLM Setup Guide (vLLM Primary)

## Current Project Setup

The active deployment uses **vLLM** as the primary LLM backend.
The configured provider is `vllm`, and the application calls the
OpenAI-compatible vLLM chat-completions API.

The application uses these vLLM settings:

- `vllm_base_url`
- `vllm_model`
- `vllm_api_key` when authentication is required

Keep deployment-specific URLs, credentials, and model identifiers out of
committed documentation.

## Why Self-Hosted vLLM?

- Threat intelligence data can remain within the approved infrastructure.
- The deployment can be tuned for the available GPU and serving capacity.
- Model serving, access control, retention, and audit requirements remain
  under the deployment owner's control.

## Provisioning vLLM

Run vLLM using the deployment method approved for your environment. The
service must expose an OpenAI-compatible API and serve the model ID used by
the application.

Verify that the service exposes the expected model list:

```bash
curl "<vllm-endpoint-url>/v1/models"
```

## Configuration

Edit the deployment-local `config.yaml`:

```yaml
llm:
  provider: vllm
  vllm_base_url: "<vllm-endpoint-url>"
  vllm_model: "<served-model-id>"
  vllm_api_key: "<api-key-if-required>"
```

The application appends `/v1/chat/completions` to `vllm_base_url`.
Use the base URL format expected by the application.

## Selecting the Served Model

The value of `vllm_model` must exactly match the model ID returned by the
vLLM `/v1/models` endpoint. GPU memory, batching, context length, and
quantization are deployment-specific vLLM settings.

## Testing

### Test IOC Analysis

```bash
python -m src.soc_agent ioc 8.8.8.8
```

Expected output should include an LLM analysis section with:

- Verdict
- Confidence score
- Analysis summary
- Recommendations

### Test Email Analysis

```bash
python -m src.soc_agent email sample.eml
```

### Test File Analysis

```bash
python -m src.soc_agent file sample.exe
```

LLM-assisted analysis remains supplementary; deterministic scoring remains
authoritative.

## Performance Tuning

Tune context length, batching, quantization, and GPU allocation in the vLLM
deployment. Exact options depend on the vLLM version and serving
environment.

For slow responses:

1. Confirm that the requested model is loaded and matches `vllm_model`.
2. Check GPU memory and server-side batching settings.
3. Review vLLM service logs without exposing credentials.

## Troubleshooting

### vLLM Unavailable

Check that the vLLM service is running and that `vllm_base_url` points to
the intended service.

### Served Model Not Found

Compare `vllm_model` with the model ID returned by:

```bash
curl "<vllm-endpoint-url>/v1/models"
```

### Authentication Failure

For services requiring authentication, configure the deployment-local
`vllm_api_key`. Never place a real key in documentation or committed files.

### Request or Connection Failure

Confirm that the endpoint is reachable from the application runtime and
that the service exposes the OpenAI-compatible chat-completions route.

## Optional Backends

The codebase also retains support for Ollama as an optional local fallback.
Ollama is not the current backend for this deployment and should not be
documented as an equivalent active setup.

The code also contains an optional Anthropic integration path. The current
deployment does not use Anthropic, so this guide intentionally does not
include an Anthropic configuration block or API-key example.

## Recommended Setup for This Project

```yaml
llm:
  provider: vllm
  vllm_base_url: "<vllm-endpoint-url>"
  vllm_model: "<served-model-id>"
  vllm_api_key: "<api-key-if-required>"
```

## Commit Safety

Use placeholders such as `<vllm-endpoint-url>` and `<served-model-id>` in
documentation. Never commit real endpoints, API keys, tokens, or credentials.
