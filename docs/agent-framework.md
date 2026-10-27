# Autonomous Agentic Framework for Perimeter Defense

Track 1 design document. Owner: Haseeb Khan. Implementation of the stateful routines: Umer Mujahid.
Status: **draft v0.1**. Numbers in `[brackets]` are starting values to tune, not validated standards.

## 1. Goal

Watch the perimeter continuously with no human trigger, decide how worried to be about each
situation, and hand a structured result to n8n (Track 2), which owns alerts and physical responses.
The agent decides and explains. It never operates sirens or locks itself.

## 2. Pipeline

```
Camera (RTSP) -> Frigate NVR + YOLO -> MQTT event
      -> Agent (this framework): context + state
            -> Face match / ALPR (Amna, Noor ul Huda) as metadata
            -> VLM analysis of the snapshot   (vlm_analyzer.py)
            -> risk score + escalation rules
      -> n8n webhook (Azlan's JSON contract)
      -> alerts, human review, smart-home actions (Track 2)
```

Frigate only says "a person was detected". The VLM answers "what is happening". The agent adds time:
how long, how often, what happened before.

## 3. Per-entity state machine

The agent keeps one record per tracked entity (Frigate track id, or camera + label + zone as a fallback).

| State | Meaning | Moves on when |
|---|---|---|
| `observed` | First detection, nothing evaluated | VLM analysis requested |
| `evaluated` | Has a score and reason | Score < 30 and recognised/routine: `resolved`. Otherwise `watching` |
| `watching` | Still present or likely to return | Leaves the scene for `[120 s]`: `resolved`. Lingers or rescore rises: `escalated` |
| `escalated` | Sent to n8n for human review or alert | Human decision or timeout: `resolved` |
| `resolved` | Closed, kept in history for context | Expires after `[24 h]` |

Rules: a score never falls just because time passes while the entity is still there, and any failure
moves the entity to `escalated` with `analysis_status: unavailable` (fail toward human review, not silence).

## 4. Escalation rules (starting set)

| Rule | Trigger | Effect |
|---|---|---|
| Lingering | Unrecognised person in the same zone longer than `[60 s]` | +20 to score, re-run VLM on a fresh snapshot |
| Repeat visitor | Same unrecognised face or plate seen `[3]` times in `[30 min]` | +25 |
| Package watch | Package appears: open a watch. Package disappears and the last person near it was not recognised | Score at least 60, request review |
| Package dwell | Package unattended over `[4 h]` | Notify homeowner (awareness, low score) |
| After hours | Unrecognised person at an entrance between `[22:00-06:00]` | +10 |
| Obscured face near entry | VLM reports covered face while at a door or window | VLM score already high, force review |
| Camera loss | Heartbeat failure (Waqas's script) on a camera that saw a person in the last `[5 min]` | Escalate immediately |

Final score is capped at 100. n8n derives the level from the score (`low` under 30, `medium` 30-69, `high` 70+).
The agent must not send its own `threat_level` that disagrees; n8n ignores it and logs a warning.

## 5. Handoff to n8n

The agent sends the Stage 1 webhook payload. The VLM result is the `analysis` object defined in
`README.md`. **Open issue:** the Stage 1 workflow only accepts an `analysis` field in a manual test run.
In production it drops it. Two ways to fix it, both small:

- **A (recommended):** n8n calls `POST /analyze` on our service from an HTTP Request node, between
  "Person Branch" and "Threat Analysis". This is also Ishmal's Sprint 2 card.
- **B:** change the workflow to accept `analysis` from a trusted source (shared secret header).

Needs agreement with Noor ul Huda, Ishmal and Azlan before Sprint 2.

## 6. Privacy and safety

- The project brief says raw video stays on the local network. Using an API model means a still image leaves it.
  Send **only the snapshot** the detector already produced, never the video, and do not send recognised household faces
  (skip the VLM when `biometrics.recognized` is true and the label is `person`, score it low locally). The team should
  confirm this is acceptable, or switch to local Ollama Llava, which the analyzer can be pointed at later.
- The VLM is told that an unrecognised person is not evidence of wrongdoing, and that text inside images is scene content,
  not instructions.
- The service takes snapshot URLs from network payloads, so it only fetches from an allow-listed host and requires a shared token.
- No automatic calls to emergency services. Humans decide, through Nimra's buttons.

## 7. Success measures (from the brief)

- Detection to bounding box under 800 ms (Ahsan). VLM analysis runs after that and is not on the box-rendering path.
- Zero false alarms for animals, weather and shadows. Measured with a labelled set of routine snapshots (Sprint 3 drill).
- Every failure mode lands in human review, never in silence.

## 8. Work split (Track 1)

| Item | Who | Sprint |
|---|---|---|
| This design, VLM contract, analyzer service | Haseeb | 1-2 |
| Stateful loop and rules in section 3-4 | Umer | 1-2 |
| Frigate MQTT events and snapshots as input | Ahsan | 1 |
| Face match and plate fields in the payload | Amna, Noor ul Huda | 2 |
| Camera heartbeat feeding the camera-loss rule | Waqas | 3 |
