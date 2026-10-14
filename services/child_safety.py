"""Optional sexual/minors text screening with metadata-only audit decisions."""

import json
import logging
import math

from flask import g, jsonify, request

from services import audit_log
from services.child_safety_inputs import generation_kind, generation_texts
from services.child_safety_settings import SafetyError
from services.openai_safety import principal_safety_identifier

logger = logging.getLogger(__name__)
HEADER = "X-MultiLLM-Child-Safety"


def moderation_decision(body, count):
    """An absent or malformed category is unavailable evidence, never a clean result."""
    results = body.get("results") if isinstance(body, dict) else None
    if not isinstance(results, list) or len(results) != count:
        raise SafetyError("moderation_result_invalid")
    flagged, scores = False, []
    for result in results:
        categories = result.get("categories") if isinstance(result, dict) else None
        if not isinstance(categories, dict) or type(categories.get("sexual/minors")) is not bool:
            raise SafetyError("moderation_result_invalid")
        flagged = flagged or categories["sexual/minors"]
        score = result.get("category_scores", {}).get("sexual/minors") if isinstance(result.get("category_scores"), dict) else None
        if score is not None:
            if type(score) not in (float, int) or not math.isfinite(score) or not 0 <= score <= 1:
                raise SafetyError("moderation_result_invalid")
            scores.append(score)
    return flagged, max(scores) if scores else None


def _refusal(code, status):
    message = ("The text prompt was refused by the child-safety screen." if status == 403
               else "The child-safety screen is unavailable. Try again later.")
    return jsonify({"error": {"code": code, "message": message}}), status


def _audit(kind, settings, decision, reason, count, score=None):
    metadata = {"kind": "child_safety", "decision": decision, "reason": reason,
                "input_count": count, "revision": settings.revision, "score": score}
    detail = json.dumps(metadata, separators=(",", ":"))
    actor = principal_safety_identifier()
    logger.info("Child-safety decision principal=%s operation=%s metadata=%s", actor, kind, detail)
    try:
        audit_log.record("safety_check", "refused" if decision == "blocked" else "succeeded",
                         actor=actor, target=kind, detail=detail)
    except Exception as error:
        logger.warning("Child-safety audit failed type=%s", type(error).__name__)


class ChildSafetyScreen:
    def __init__(self, store, moderate):
        self.store, self.moderate = store, moderate

    def before_dispatch(self):
        kind = generation_kind(request.path) if request.method == "POST" else None
        if kind is None or getattr(g, "child_safety_checked", False):
            return None
        g.child_safety_checked = True
        try:
            settings = self.store.get()
        except SafetyError:
            g.child_safety_result = "settings-unavailable"
            return _refusal("safety_settings_unavailable", 503)
        if not settings.enabled:
            return None
        form = request.form if request.mimetype == "multipart/form-data" else None
        texts = generation_texts(kind, request.get_json(silent=True) if form is None else None, form)
        if not texts:
            g.child_safety_result = "no-text"
            return None
        try:
            flagged, score = moderation_decision(self.moderate(texts), len(texts))
        except Exception as error:
            logger.warning("Child-safety moderation failed type=%s", type(error).__name__)
            blocked = settings.failure_mode == "block"
            g.child_safety_result = "unavailable-blocked" if blocked else "unavailable-allowed"
            _audit(kind, settings, "blocked" if blocked else "allowed", "moderation_unavailable", len(texts))
            return _refusal("child_safety_unavailable", 503) if blocked else None
        g.child_safety_result = "blocked" if flagged else "passed"
        _audit(kind, settings, "blocked" if flagged else "allowed", "sexual_minors" if flagged else "clear", len(texts), score)
        return _refusal("child_safety_blocked", 403) if flagged else None
