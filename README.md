# sentinel-vision-ai

Vision-language threat analysis for a local-first home security system.

Given a camera detection and its snapshot, `sentinel-vision-ai` asks a vision-language model (VLM) what is
actually happening and returns a structured threat assessment: a 0-100 score, a plain-language reason, a
recommended action and a human-review flag. The result is designed to plug straight into an automation
workflow such as n8n.

It has no third-party dependencies (Python 3.9+ standard library only) and works with Anthropic models,
Google Gemini, any OpenAI-compatible API, or a local model served by Ollama.

## Features

- **Provider-agnostic.** Anthropic, Google Gemini, OpenAI, or any OpenAI-compatible server (Ollama, vLLM, LM Studio).
- **Fails safe.** Any error (network, bad key, unreadable image, malformed reply) returns
  `analysis_status: "unavailable"`, so downstream automation falls back to human review rather than staying silent.
- **Privacy aware.** Recognised household members are scored locally and their snapshots never leave the machine.
  Pointing the analyzer at a local model keeps every image on your network.
- **Calibrated prompt.** The model is told that an unrecognised person is not evidence of wrongdoing, and that text
  inside an image is scene content, never instructions.
- **Two interfaces.** A command-line tool for testing and an HTTP service for workflow engines.
- **Hardened service.** Shared-token authentication, an allow-list of hosts snapshots may be fetched from, request
  size limits, and local-file access disabled.

## How it works

```
camera -> NVR / object detector -> detection event + snapshot
                                          |
                                          v
                              sentinel-vision-ai  --->  VLM (cloud or local)
                                          |
                                          v
                       threat assessment (score, reason, action)
                                          |
                                          v
                        automation workflow: alert, review, respond
```

See [docs/n8n-integration.md](docs/n8n-integration.md) for the request/response contract and n8n setup, and
[docs/agent-framework.md](docs/agent-framework.md) for the full design, including the per-entity state
machine and escalation rules.

## Quick start

```bash
git clone https://github.com/Haseebi-khan/sentinel-vision-ai.git
cd sentinel-vision-ai

export VLM_API_KEY=your-key            # see Configuration for other providers
python3 vlm_analyzer.py analyze samples/person_unknown.json
```

The sample events reference public photos, so no camera is needed. To analyse your own image:

```bash
python3 vlm_analyzer.py analyze samples/person_unknown.json --image ~/photo.jpg   # file path or URL
python3 vlm_analyzer.py analyze samples/person_unknown.json --dry-run             # show the prompt, no API call
```

## Configuration

All settings are environment variables. Keys are never read from files in the repository.

| Variable | Description | Default |
|---|---|---|
| `VLM_PROVIDER` | `anthropic`, `gemini`, or `openai` (any OpenAI-compatible server) | `anthropic` |
| `VLM_API_KEY` | API key. Required for `anthropic`, optional for local servers | none |
| `VLM_MODEL` | Model name. Required for `openai` and `gemini` | `claude-sonnet-5-5` for `anthropic` |
| `VLM_API_URL` | Endpoint override | provider default |
| `VLM_TIMEOUT` | Seconds to wait for the model | `30` |
| `VLM_SKIP_RECOGNIZED` | `0` to also send recognised household members to the model | `1` |

```bash
# Anthropic
export VLM_API_KEY=your-key

# Google Gemini (key from Google AI Studio; pick a vision-capable model)
export VLM_PROVIDER=gemini VLM_API_KEY=your-key VLM_MODEL=<gemini model name>

# OpenAI
export VLM_PROVIDER=openai VLM_API_KEY=your-key VLM_MODEL=<vision-capable model>

# Local Ollama: nothing leaves your network
export VLM_PROVIDER=openai VLM_MODEL=llava \
       VLM_API_URL=http://localhost:11434/v1/chat/completions
```

## Input

A detection event as JSON. This is the same payload the automation workflow receives:

```json
{
  "event_id": "evt-0001",
  "timestamp": "2026-10-27T21:15:00Z",
  "camera_id": "front_door",
  "snapshot_url": "https://example.local/snapshot.jpg",
  "detection": { "label": "person", "confidence": 0.91, "bounding_box": [412, 120, 233, 540] },
  "biometrics": { "recognized": false, "person_name": "unknown" },
  "alpr": { "plate_text": "ABC123", "plate_confidence": 0.82 }
}
```

`alpr` is optional. See [samples/](samples/) for complete examples.

## Output

```json
{
  "analysis_status": "completed",
  "threat_score": 45,
  "threat_level": "medium",
  "reason": "Unfamiliar person standing at the front door, face visible, nothing in hands.",
  "recommended_action": "request_human_review",
  "requires_human_review": true,
  "visible_evidence": ["person at front door"],
  "image_quality": "good",
  "model": "<model name>"
}
```

| Field | Meaning |
|---|---|
| `analysis_status` | `completed`, or `unavailable` with a `reason` when analysis could not be done |
| `threat_score` | Integer 0-100 |
| `threat_level` | `low` (under 30), `medium` (30-69) or `high` (70 and above) |
| `recommended_action` | `log_only`, `notify_homeowner` or `request_human_review` |
| `requires_human_review` | Whether a person should look at the event |
| `image_quality` | `good`, `poor` or `unusable`. `unusable` always forces human review, so an unreadable image is never scored as safe |

A person matched to a known household member is scored 10 locally with `"model": "local-rule"`.

## HTTP service

```bash
export VLM_SERVICE_TOKEN=a-long-random-string
export VLM_ALLOWED_IMAGE_HOSTS=camera.local,nvr.local     # hosts snapshots may be fetched from
python3 vlm_analyzer.py serve --port 8800
```

| Endpoint | Description |
|---|---|
| `POST /analyze` | Body: an event (or `{"body": event}`). Header: `x-service-token`. Returns the output above |
| `GET /health` | Liveness check |

The service binds to `127.0.0.1` by default; use `--host` to expose it, and only on a trusted network.
In n8n, call it from an HTTP Request node placed before the threat-assessment step.

## Testing

```bash
python3 -I tests/test_analyzer.py
```

The 34 tests run offline against local stand-in servers, so no API key is needed. They cover response parsing and
validation, both provider request formats, failure fallbacks, image handling and the service's security checks.

## Project status

Working: analyzer, both providers, CLI, HTTP service, tests, and the design for the stateful agent.

Planned:
- Stateful escalation rules (lingering, repeat visitors, package monitoring), specified in the design document.
- Validation against live camera snapshots and a labelled false-alarm set.

## Security notes

- Never commit an API key. Keys are read from the environment only.
- The service fetches images from URLs in the request body, so set `VLM_ALLOWED_IMAGE_HOSTS` and `VLM_SERVICE_TOKEN`.
- Sending a snapshot to a cloud provider means that image leaves your network. Use a local model if that is not acceptable.
- Free API tiers may allow the provider to use submitted content to improve its products. Use test images only on a free tier.
