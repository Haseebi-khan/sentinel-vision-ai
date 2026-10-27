# sentinel-vision-ai

Track 1 (Vision AI & Edge Ingestion) of an AI-powered home security system. Turns a detection
event plus its snapshot into a threat assessment that the n8n automation workflow ("Stage 1: Event
Validation") already accepts. Works with Anthropic models or any OpenAI-compatible server,
including a local Ollama, so video analysis can stay on the local network.

```
vlm_analyzer.py          analyzer: CLI and HTTP service (Python standard library only)
docs/agent-framework.md  design: pipeline, state machine, escalation rules, privacy
samples/                 webhook-shaped example events (person and vehicle use real public photos)
tests/test_analyzer.py   29 tests, no API key needed
```

## Configuration

All settings are environment variables. Never commit a key.

| Variable | Meaning |
|---|---|
| `VLM_PROVIDER` | `anthropic` (default) or `openai` (any OpenAI-compatible server) |
| `VLM_API_KEY` | API key. Required for `anthropic`, optional for local servers |
| `VLM_MODEL` | Model name. Default for `anthropic`, required for `openai` |
| `VLM_API_URL` | Override the endpoint |
| `VLM_TIMEOUT` | Seconds to wait for the model (default 30) |
| `VLM_SKIP_RECOGNIZED` | Set to `0` to also send recognised household members to the model |

```bash
# Anthropic
export VLM_API_KEY=your-key

# OpenAI
export VLM_PROVIDER=openai VLM_API_KEY=your-key VLM_MODEL=<a vision-capable model>

# Local Ollama (nothing leaves the network)
export VLM_PROVIDER=openai VLM_MODEL=llava \
       VLM_API_URL=http://localhost:11434/v1/chat/completions
```

## Try it

```bash
# The samples point at real public photos, so no --image is needed:
python3 vlm_analyzer.py analyze samples/person_unknown.json
python3 vlm_analyzer.py analyze samples/vehicle_with_plate.json

# Your own photo (path or URL):
python3 vlm_analyzer.py analyze samples/person_unknown.json --image ~/photo.jpg

python3 vlm_analyzer.py analyze samples/package.json --dry-run   # prompt only, no API call
python3 -I tests/test_analyzer.py
```

`samples/package.json` still has a placeholder camera URL: pass `--image` with a real photo.

## Service for n8n

```bash
export VLM_SERVICE_TOKEN=pick-a-long-random-string
export VLM_ALLOWED_IMAGE_HOSTS=frigate.local      # hosts snapshots may be fetched from
python3 vlm_analyzer.py serve --port 8800
```

In n8n add an HTTP Request node: `POST http://<host>:8800/analyze`, header `x-service-token`,
body = the webhook payload (or `{"body": ...}`). The response is the analysis object below.
`GET /health` checks it is up. It listens on 127.0.0.1 unless you pass `--host`.

## Output contract (the `analysis` object)

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

| Field | Rule |
|---|---|
| `threat_score` | Integer 0-100. n8n derives the level: under 30 low, 30-69 medium, 70+ high |
| `recommended_action` | `log_only`, `notify_homeowner` or `request_human_review` (the values n8n allows) |
| `analysis_status` | `completed` on success. On any failure: `{"analysis_status":"unavailable","reason":"..."}`, which n8n turns into a human-review fallback |
| `image_quality` | `unusable` forces `requires_human_review: true`, so a dark or blocked image is never scored safe |

A person matched to a known household member is scored 10 locally (`model: "local-rule"`) and the
snapshot is never sent to any model.

## Known gaps

1. Stage 1 drops a payload `analysis` outside manual tests, so n8n must call the service. See `docs/agent-framework.md` section 5.
2. Verified with a stand-in model server and real downloaded photos, not yet with a live model API key.
3. Score rules (lingering, repeat visitor, package watch) are specified in the design doc, not yet coded.
