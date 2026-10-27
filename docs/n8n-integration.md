# n8n integration

How to call the analyzer from an n8n workflow. The service has been tested with `curl` and automated tests; it has
not yet been exercised against a running n8n instance.

## Endpoint

| | |
|---|---|
| URL | `POST http://<host>:8800/analyze` |
| Auth | Header `x-service-token: <VLM_SERVICE_TOKEN>` |
| Content type | `application/json` |
| Health check | `GET http://<host>:8800/health` |

## Request

Send the event. Three shapes are accepted, so the call can be made from any point in a workflow:

1. The original webhook body (nested `detection` and `biometrics`).
2. The webhook item, `{"body": { ...original body... }}`.
3. A validated item with flat fields, `{"event": { ... }}` (what the Stage 1 validation step produces).

Flat form:

```json
{
  "event": {
    "event_id": "evt-0001",
    "timestamp": "2026-10-27T21:15:00Z",
    "camera_id": "front_door",
    "label": "person",
    "confidence": 0.91,
    "bounding_box": [412, 120, 233, 540],
    "recognized": false,
    "person_name": "unknown",
    "plate_text": null,
    "plate_confidence": null,
    "snapshot_url": "http://nvr.local:5000/api/events/evt-0001/snapshot.jpg"
  }
}
```

Required for a useful result: `snapshot_url`, `label`, and `recognized` / `person_name`. A person with
`recognized: true` and a real name is scored locally and the image is never sent to a model.

## Response

Always JSON. Model and image problems return HTTP 200 with `analysis_status: "unavailable"`, so a workflow does not
need a separate error path to stay safe.

```json
{
  "analysis_status": "completed",
  "threat_score": 45,
  "threat_level": "medium",
  "reason": "Unfamiliar person at the front door, face visible, nothing in hands.",
  "recommended_action": "request_human_review",
  "requires_human_review": true,
  "visible_evidence": ["person at front door"],
  "image_quality": "good",
  "model": "<model name>"
}
```

| Field | Values |
|---|---|
| `analysis_status` | `completed`, or `unavailable` (then only `reason` is present) |
| `threat_score` | integer 0-100 |
| `threat_level` | `low` under 30, `medium` 30-69, `high` 70 and above (same thresholds as the workflow) |
| `recommended_action` | `log_only`, `notify_homeowner`, `request_human_review` |
| `requires_human_review` | boolean |
| `image_quality` | `good`, `poor`, `unusable` (`unusable` forces human review) |
| `model` | model name, or `local-rule` for a recognised resident |

Unavailable example:

```json
{"analysis_status": "unavailable", "reason": "snapshot host 'x' is not in the allowed list"}
```

## HTTP status codes

| Code | Meaning |
|---|---|
| 200 | Result returned (including `unavailable`) |
| 400 | Body missing, not valid JSON, not an object, or over 64 KB |
| 401 | Missing or wrong `x-service-token` |
| 404 | Unknown path |

## Hooking it into a workflow

Replace the code of the node that produces `analysis_result` with a call to the service. Every branch can keep
feeding the same node, so no rewiring is needed:

```js
// Run Once for Each Item
const data = $input.item.json;
const branch = data.branch || {};
let analysis_result;
let analysis_source = 'vlm';

if (branch.type === 'manual_review') {
  analysis_result = null;                       // unsupported label: use the human-review fallback
  analysis_source = 'none';
} else if (branch.type === 'routine') {
  analysis_result = {                           // animals: no model call needed
    analysis_status: 'completed', threat_score: 5, threat_level: 'low',
    reason: 'Animal detected; routine.', recommended_action: 'log_only',
    requires_human_review: false
  };
} else {
  try {
    analysis_result = await this.helpers.httpRequest({
      method: 'POST',
      url: 'http://<host>:8800/analyze',
      headers: { 'x-service-token': '<token>' },
      body: { event: data.event },
      json: true,
      timeout: 60000
    });
  } catch (e) {
    analysis_result = { analysis_status: 'unavailable', reason: 'VLM service error: ' + (e.message || 'unknown') };
  }
}

return { json: { ...data, analysis_result, analysis_source } };
```

If your n8n restricts `this.helpers` in the Code node, use an **HTTP Request** node with a Header Auth credential
instead, and a **Merge** node (Combine, by position) to bring the branch data and the response back together.

## Deployment notes

- **Reachability.** The service binds to `127.0.0.1`. If n8n runs in Docker or on another machine, start the service
  with `--host 0.0.0.0` (trusted network only) and use that machine's address, or `host.docker.internal` from a container.
- **Allowed image hosts.** Set `VLM_ALLOWED_IMAGE_HOSTS` to the host names that serve snapshots. Any other host is refused.
- **Timeout.** A model call can take several seconds. Use a node timeout of at least 45 seconds.
- **Credentials.** Keep the token in an n8n credential or environment variable rather than in the workflow JSON.
- **Cost.** Only person, vehicle and package events need a model call. Recognised residents and animals can be
  handled without one, as above.
