"""Request modes, bounded single re-ask and counts-only repair telemetry."""

import logging
import os
import re

from services.tool_call_repair import MAX_CALLS, declared_functions, empty_report, matching_function, repair_tool_calls

HEADER = "X-MultiLLM-Tool-Repair"
MODES = frozenset({"off", "repair", "full"})
SKIP_REASK = object()
logger = logging.getLogger(__name__)


def repair_mode(headers=None, config=None):
    default = (config or {}).get("TOOL_CALL_REPAIR_DEFAULT", os.environ.get("TOOL_CALL_REPAIR_DEFAULT", "repair"))
    default = default.strip().lower() if isinstance(default, str) else "repair"
    default = default if default in MODES else "repair"
    override = next((v for k, v in (headers or {}).items() if k.lower() == HEADER.lower()), default)
    override = override.strip().lower() if isinstance(override, str) else default
    return override if override in MODES else default


def summary_header(report):
    return " ".join(f"{key}={report.get(key, 0)}" for key in ("checked", "repaired", "extracted", "invalid", "reasked"))


def log_report(report, model, provider):
    # Restrict metadata as well as excluding all model output and argument values.
    safe = lambda value: re.sub(r"[^A-Za-z0-9_.:/-]", "_", str(value or "unknown"))[:128]
    logger.info("tool_call_repair model=%s provider=%s %s", safe(model), safe(provider), summary_header(report))


def merge_report(target, source):
    for key in ("checked", "repaired", "invalid", "extracted"):
        target[key] += source[key]
    for key in ("fixes", "errors"):
        target[key].extend(source[key][:MAX_CALLS - len(target[key])])


def repair_payload(payload, tools, tool_choice=None, *, mode="repair", allow_extraction=True):
    report = {**empty_report(), "reasked": 0}
    if mode == "off" or not isinstance(payload, dict):
        return payload, report
    choices = payload.get("choices")
    if not isinstance(choices, list) or len(choices) > MAX_CALLS:
        return payload, report
    repaired = []
    for choice in choices:
        if not isinstance(choice, dict):
            repaired.append(choice)
            continue
        message, part = repair_tool_calls(choice.get("message"), tools, tool_choice=tool_choice,
                                          mode=mode, allow_extraction=allow_extraction)
        merge_report(report, part)
        if message is choice.get("message"):
            repaired.append(choice)
        else:
            repaired.append({**choice, "message": message,
                             "finish_reason": "tool_calls" if part["extracted"] else choice.get("finish_reason")})
    return ({**payload, "choices": repaired} if repaired != choices else payload), report


def followup_payload(request_payload, message, report):
    calls = message.get("tool_calls", [])
    instructions = []
    for item in report["errors"][:MAX_CALLS]:
        index = item["index"]
        function = calls[index].get("function", {}) if index < len(calls) and isinstance(calls[index], dict) else {}
        name = function.get("name", "declared function")
        instructions.append(f"Call {index}, tool {str(name)[:128]}: " + "; ".join(item["errors"][:32]))
    instruction = "Return only the corrected tool calls, preserving their order. Fix these validation errors:\n" + "\n".join(instructions)
    # Request-level gateway metadata never belongs to the same-model follow-up.
    body = {k: v for k, v in request_payload.items() if k not in {"routing", "stream_options"}}
    body["stream"] = False
    body["messages"] = [*request_payload.get("messages", []), message,
                        {"role": "user", "content": instruction[:16384]}]
    return body


def add_usage(first, second):
    """Keep known counts from both calls, including nested cached/reasoning details."""
    if not isinstance(first, dict):
        return second if isinstance(second, dict) else first
    if not isinstance(second, dict):
        return first
    result = dict(first)
    for key, value in second.items():
        if isinstance(value, dict):
            result[key] = add_usage(result.get(key, {}), value)
        elif type(value) is int and value >= 0:
            previous = result.get(key, 0)
            result[key] = (previous if type(previous) is int else 0) + value
    return result


def _reask_message(choices, request_payload):
    calls, positions, errors, messages = [], [], [], []
    for choice_index, choice in enumerate(choices):
        if not isinstance(choice, dict) or not isinstance(choice.get("message"), dict):
            return None
        message = choice["message"]
        message_calls = message.get("tool_calls", [])
        if not isinstance(message_calls, list) or len(calls) + len(message_calls) > MAX_CALLS:
            return None
        _, part = repair_tool_calls(message, request_payload.get("tools"),
                                    tool_choice=request_payload.get("tool_choice"), allow_extraction=False)
        errors.extend({**item, "index": item["index"] + len(calls)} for item in part["errors"])
        positions.extend((choice_index, index) for index in range(len(message_calls)))
        calls.extend(message_calls)
        messages.append(message)
    if not calls or not errors:
        return None
    message = messages[0] if len(messages) == 1 else {"role": "assistant", "content": None, "tool_calls": calls}
    return message, positions, errors


def repair_completion(payload, request_payload, *, mode="repair", reask=None):
    """Repair all choices with at most one same-model follow-up per request."""
    repaired, report = repair_payload(payload, request_payload.get("tools"), request_payload.get("tool_choice"),
                                      mode=mode, allow_extraction=not request_payload.get("stream"))
    choices = repaired.get("choices", []) if isinstance(repaired, dict) else []
    if mode != "full" or request_payload.get("stream") or not report["invalid"] or reask is None:
        return repaired, report
    planned = _reask_message(choices, request_payload)
    if planned is None:
        return repaired, report
    message, positions, errors = planned
    body = followup_payload(request_payload, message, {"errors": errors})
    if len(choices) > 1:
        body["n"] = 1
    report["reasked"] = 1
    try:
        reply = reask(body)
    except Exception:
        return repaired, report
    if reply is SKIP_REASK:
        report["reasked"] = 0
        return repaired, report
    if not isinstance(reply, dict):
        return repaired, report
    combined_usage = add_usage(repaired.get("usage"), reply.get("usage"))
    repaired = {**repaired, "usage": combined_usage}
    corrected, final = repair_payload(reply, request_payload.get("tools"), request_payload.get("tool_choice"))
    final_choices = corrected.get("choices", [])
    if (final["invalid"] or not isinstance(final_choices, list) or len(final_choices) != 1
            or not isinstance(final_choices[0], dict) or not isinstance(final_choices[0].get("message"), dict)):
        return repaired, report
    corrected_calls = final_choices[0].get("message", {}).get("tool_calls", [])
    calls = message["tool_calls"]
    if not isinstance(corrected_calls, list) or len(corrected_calls) != len(calls):
        return repaired, report
    invalid = {item["index"] for item in errors}
    functions = declared_functions(request_payload.get("tools"))
    for index in invalid:
        original = calls[index].get("function", {}) if isinstance(calls[index], dict) else {}
        function = matching_function(original.get("name"), functions)
        if function and corrected_calls[index]["function"]["name"] != function["name"]:
            return repaired, report
    replacement = [dict(choice) for choice in choices]
    for index in invalid:
        if index >= len(calls):
            return repaired, report
        call = {**corrected_calls[index]}
        if isinstance(calls[index], dict) and calls[index].get("id"):
            call["id"] = calls[index]["id"]
        choice_index, call_index = positions[index]
        current = replacement[choice_index]
        current_calls = list(current["message"]["tool_calls"])
        current_calls[call_index] = call
        current["message"] = {**current["message"], "tool_calls": current_calls}
        current["finish_reason"] = "tool_calls"
        report["fixes"].append({"index": index, "fixes": ["reask"]})
    report["repaired"] += len(invalid)
    report["invalid"] = 0
    report["errors"] = []
    return {**repaired, "choices": replacement}, report
