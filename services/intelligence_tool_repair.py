"""Repair hooks that retain intelligence attempt, token and deadline ceilings."""

import json

from services.intelligence_output import decode_completion, visible_completion, with_thinking_tokens
from services.intelligence_policy import input_reservation
from services.intelligence_transport import remaining
from services.tool_repair_runtime import SKIP_REASK, log_report, repair_completion, repair_mode
from services.tool_repair_stream import ToolCallBuffer


class IntelligenceToolRepair:
    def __init__(self, gateway):
        self.gateway = gateway
        self.mode = repair_mode(config=gateway.transport.config)
        self.buffer = ToolCallBuffer(gateway.request.payload.get("tools"),
                                     gateway.request.payload.get("tool_choice"), self.mode)
        self.reasked = False

    def completion(self, completion, candidate, payload, token):
        already_reasked = self.reasked
        repaired, report = repair_completion(
            completion, payload, mode=self.mode,
            reask=lambda body: self._reask(body, candidate, token),
        )
        if report["reasked"] and (already_reasked or not self.reasked):
            report["reasked"] = 0
        self.buffer.report = report
        if payload.get("tools") and self.mode != "off":
            log_report(report, candidate["model"], candidate["model"].split(":", 1)[0])
        return repaired

    def _reask(self, body, candidate, token):
        gateway = self.gateway
        if self.reasked or gateway.attempts >= gateway.request.max_attempts:
            return SKIP_REASK
        # The conservative request byte estimate includes the invalid call and instruction.
        prompt = len(json.dumps({k: v for k, v in body.items() if k in {"messages", "tools", "response_format"}}, ensure_ascii=False).encode())
        prompt += 256 + 64 * len(body["messages"])
        prompt += input_reservation(candidate, gateway.request) - gateway.request.input_tokens
        output = min(gateway.request.output_tokens, gateway.request.max_total_tokens - gateway.consumed - prompt)
        if output < 1 or prompt + output > candidate["context_window"]:
            return SKIP_REASK
        remaining(gateway.deadline, gateway.cancelled)
        self.reasked = True
        field = "max_completion_tokens" if "max_completion_tokens" in body else "max_tokens"
        body = {**body, field: output}
        gateway.exchange.close()
        gateway.exchange = gateway.transport.start(candidate, body, token, gateway.deadline,
                                                   gateway.cancelled, gateway.policy["max_response_bytes"])
        gateway.attempts += 1
        gateway.unresolved = True
        head = gateway.exchange.head()
        if 400 <= head.status_code < 500:
            gateway.unresolved = False
            return None
        if head.status_code != 200:
            return None
        decoded = decode_completion(gateway.exchange.read())
        usage = decoded.get("usage")
        if candidate["model"].startswith("gemini:"):
            usage = with_thinking_tokens(usage)
        gateway._account(usage, prompt + output)
        return visible_completion(decoded, candidate["model"])

    def events(self, event):
        if not self.gateway.request.payload.get("tools") or self.mode == "off":
            yield event
            return
        self.buffer.mode = self.mode
        yield from self.buffer.process(event)

    def flush(self):
        if self.gateway.request.payload.get("tools") and self.mode != "off":
            yield from self.buffer.flush()

    def finish_stream(self, parsed, candidate):
        if not self.gateway.request.payload.get("tools") or self.mode == "off":
            return
        # Validation sees the same complete calls already delivered to the client.
        from services.tool_call_repair import repair_tool_calls
        message, _ = repair_tool_calls(parsed.completion()["choices"][0]["message"],
                                       self.gateway.request.payload["tools"],
                                       tool_choice=self.gateway.request.payload.get("tool_choice"),
                                       allow_extraction=False)
        if message.get("tool_calls"):
            parsed.calls = dict(enumerate(message["tool_calls"]))
        log_report(self.buffer.report, candidate["model"], candidate["model"].split(":", 1)[0])
