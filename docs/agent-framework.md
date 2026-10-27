# Agentic Framework for Perimeter Defense

Design document, draft v0.1. Values in `[brackets]` are starting points to tune against real data, not validated standards.

## 1. Goal

Watch a property's perimeter continuously with no human trigger, decide how concerned to be about each situation,
and hand a structured result to an automation layer that owns alerts and physical responses.

The agent decides and explains. It never operates sirens, locks or lights itself.

## 2. Pipeline

```
Camera (RTSP) -> NVR + object detector -> MQTT event
      -> Agent (this framework): context + per-entity state
            -> face match / licence-plate fields as metadata
            -> VLM analysis of the snapshot   (vlm_analyzer.py)
            -> risk score + escalation rules
      -> automation webhook (JSON contract)
      -> alerts, human review, smart-home actions
```

The detector only reports that a person or vehicle was seen. The VLM answers what is happening. The agent adds time:
how long, how often, and what came before.

## 3. Per-entity state machine

The agent keeps one record per tracked entity, keyed by the detector's track id (or camera + label + zone as a fallback).

| State | Meaning | Moves on when |
|---|---|---|
| `observed` | First detection, nothing evaluated | VLM analysis requested |
| `evaluated` | Has a score and a reason | Score under 30 and recognised or routine: `resolved`. Otherwise `watching` |
| `watching` | Still present, or likely to return | Gone for `[120 s]`: `resolved`. Lingers or score rises: `escalated` |
| `escalated` | Sent to the automation layer for review or alert | Human decision or timeout: `resolved` |
| `resolved` | Closed, kept as history for context | Expires after `[24 h]` |

Invariants:
- A score never falls just because time passes while the entity is still present.
- Any failure moves the entity to `escalated` with `analysis_status: unavailable`. The system fails toward human
  review, never toward silence.

## 4. Escalation rules (initial set)

| Rule | Trigger | Effect |
|---|---|---|
| Lingering | Unrecognised person in the same zone for over `[60 s]` | +20 to score, re-run the VLM on a fresh snapshot |
| Repeat visitor | Same unrecognised face or plate seen `[3]` times within `[30 min]` | +25 |
| Package watch | A package appears: open a watch. It disappears and the last person near it was not recognised | Score at least 60, request review |
| Package dwell | Package unattended for over `[4 h]` | Notify homeowner (awareness, low score) |
| After hours | Unrecognised person at an entrance between `[22:00-06:00]` | +10 |
| Obscured face near an entry point | VLM reports a covered face at a door or window | VLM score already high, force review |
| Camera loss | Stream heartbeat fails on a camera that saw a person in the last `[5 min]` | Escalate immediately |

The final score is capped at 100. The automation layer derives the level from the score (`low` under 30, `medium`
30-69, `high` 70 and above). A level supplied by the agent that disagrees with the score is ignored and logged.

## 5. Handoff to the automation layer

The agent sends the event payload described in the README. The VLM result is the `analysis` object.

**Integration note.** A workflow that accepts `analysis` only from manual test runs will drop it in production. Two fixes:

- **A (recommended):** the workflow calls `POST /analyze` on this service from an HTTP Request node, between event
  routing and threat assessment.
- **B:** change the workflow to accept `analysis` from a trusted source, authenticated with a shared secret header.

## 6. Privacy and safety

- Raw video stays on the local network. Only the single snapshot the detector already produced is sent to a model,
  and never video.
- Recognised household members are never sent. They are scored 10 locally; `VLM_SKIP_RECOGNIZED=0` turns this off.
- For deployments where no image may leave the network, point the analyzer at a local model (`VLM_PROVIDER=openai`
  with Ollama), which keeps every image on-premises.
- The VLM is told that an unrecognised person is not evidence of wrongdoing, and that text inside images is scene
  content, not instructions.
- The service fetches snapshot URLs from network payloads, so it only fetches from allow-listed hosts and requires a
  shared token.
- No automatic calls to emergency services. People decide, through the human-in-the-loop alert step.

## 7. Success measures

- Detection to bounding box under 800 ms. VLM analysis runs after that and is not on the rendering path.
- Zero false alarms for animals, weather and shadows, measured against a labelled set of routine snapshots.
- Every failure mode ends in human review, never silence.
