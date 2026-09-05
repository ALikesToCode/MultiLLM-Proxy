"""Bounded synthetic workloads for comparable, operator-triggered measurements."""

import uuid
import re

from error_handlers import APIError

SCENES = {
    "continuity": {
        "label": "Continuity and character agency",
        "messages": [
            {"role": "system", "content": "Write a grounded fantasy scene. The user controls Rowan. You control Iona, an adult innkeeper. Keep established facts, distinguish guesses from knowledge, and do not decide Rowan\u0027s actions. Reply with one complete scene beat, 150-250 words. Final prose only."},
            {"role": "user", "content": "Rowan arrives at dusk carrying a sealed blue letter. The bridge is closed. Iona knows the courier left at noon; she has not read the letter."},
            {"role": "assistant", "content": "Iona set a lamp on the counter. \"The courier left at noon. If you need the bridge, you will have to wait until morning.\""},
            {"role": "user", "content": "Rowan: The seal is broken now, but I did not open it. Did the courier mention a name?"},
        ],
    },
    "spatial": {
        "label": "Spatial consistency and plausible reactions",
        "messages": [
            {"role": "system", "content": "Write one grounded scene beat of 150-250 words. All characters are adults. You control a cautious lighthouse keeper; the user controls a visitor. Preserve geometry, clothing, weather, and what each person can know. Final prose only."},
            {"role": "user", "content": "It is a rainy night. The keeper in a green raincoat stands inside the north doorway. The visitor is outside on the steps, holding a dry parcel under an umbrella. A window behind the keeper faces the empty sea. Visitor: I found this on your roof."},
        ],
    },
    "instruction": {
        "label": "Following corrections without repeating them",
        "messages": [
            {"role": "system", "content": "You play Neri, an adult patient and skeptical mechanic. The user plays Alex. The workshop has no electricity. Neri wears blue overalls and a silver wristwatch. Write 150-250 words of final dialogue and action; do not control Alex."},
            {"role": "user", "content": "Correction: Neri\u0027s watch is brass, not silver. Alex: The engine started by itself. I did not even touch the crank."},
        ],
    },
}


def comparison_payload(body):
    if not isinstance(body, dict) or any(not isinstance(value, str) for key, value in body.items() if key != "confirm_billable"):
        raise APIError("Comparison options must be strings", status_code=400)
    if body.get("confirm_billable") is not True:
        raise APIError("Confirm the potentially billed comparison before starting", status_code=400)
    if set(body) - {"case", "provider", "model", "effort", "billing", "confirm_billable"}:
        raise APIError("Unsupported comparison option; custom prompts and credentials are not accepted", status_code=400)
    scene = SCENES.get(body.get("case"))
    if scene is None:
        raise APIError("Choose a synthetic comparison scene", status_code=400)
    provider, model, effort = body.get("provider"), body.get("model"), body.get("effort", "high")
    if provider not in {"nanogpt", "opencode", "openrouter", "linkapi", "navyai"}:
        raise APIError("Choose a supported provider", status_code=400)
    if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9_./:-]{1,200}", model):
        raise APIError("Choose a model from the configured catalog", status_code=400)
    if effort not in {"none", "minimal", "low", "medium", "high", "xhigh", "max"}:
        raise APIError("Invalid reasoning effort", status_code=400)
    billing = body.get("billing", "configured")
    if billing not in {"configured", "subscription-only"}:
        raise APIError("Invalid billing restriction", status_code=400)
    return {
        "session_id": "lab-" + uuid.uuid4().hex, "model": "roleplay:auto",
        "messages": scene["messages"], "stream": True, "max_tokens": 2048,
        "reasoning_effort": effort, "memory": {"mode": "off"},
        "recovery_enabled": True,
        "routing": {"mode": "pinned", "provider": provider, "model": model,
                    "billing": billing, "fallback": "none"},
    }
