# Track 1: Vision AI & Edge Ingestion (VLM handoff)

Owner: Haseeb Khan. Turns a detection event plus its snapshot into a threat assessment that the
Track 2 n8n workflow ("Stage 1: Event Validation") already accepts.

```
track1-vision-ai/
  vlm_analyzer.py        analyzer: CLI and HTTP service (standard library only)
  docs/agent-framework.md  design for the Track 1 lead card
  samples/               webhook-shaped example events
  tests/test_analyzer.py 17 tests, no API key needed
```

## Quick start

```bash
export ANTHROPIC_API_KEY=...            # never commit this
# optional: export VLM_MODEL=claude-haiku-5-5   (faster and cheaper; default is claude-sonnet-5-5)

python3 vlm_analyzer.py analyze samples/person_unknown.json --image /path/to/snapshot.jpg
python3 vlm_analyzer.py analyze samples/person_unknown.json --dry-run     # prompt only, no API call
python3 -I tests/test_analyzer.py
```

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
  "model": "claude-sonnet-5-5"
}
```

| Field | Rule |
|---|---|
| `threat_score` | Integer 0-100. n8n derives the level: under 30 low, 30-69 medium, 70+ high |
| `recommended_action` | `log_only`, `notify_homeowner` or `request_human_review` (the values n8n allows) |
| `analysis_status` | `completed` on success. On any failure: `{"analysis_status":"unavailable","reason":"..."}`, which n8n turns into a human-review fallback |
| `image_quality` | `unusable` forces `requires_human_review: true`, so a dark or blocked image is never scored safe |

Extra fields (`visible_evidence`, `image_quality`, `model`) are ignored by Stage 1 today and are
there for the log and for Nimra's alert text.

## Known gaps

1. Stage 1 drops a payload `analysis` outside manual tests, so n8n must call the service. See `docs/agent-framework.md` section 5.
2. Not yet run against the live API or real Frigate snapshots. Tests use a fake model. Needs a key and a few real images.
3. Sending snapshots to an API conflicts with the "all video stays local" goal. See section 6 of the design doc.
4. Score rules (lingering, repeat visitor, package watch) are specified, not yet coded. That is Umer's card.
