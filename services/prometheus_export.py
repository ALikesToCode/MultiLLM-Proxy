"""Pure, bounded Prometheus exposition of the Flask ledger's rolling window."""
import math

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
MAX_SERIES = 512
MAX_BYTES = 256 * 1024
_STATUS_CLASSES = ("2xx", "3xx", "4xx", "5xx", "other")
_TRUNCATION_HELP = (
    "# HELP multillm_prometheus_truncated Whether exposition was truncated.\n"
    "# TYPE multillm_prometheus_truncated gauge\n"
)


def enabled(value):
    return str(value or "").strip().lower() == "true"


def escape_label(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _finite(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


class Exposition:
    """Reserve one sample and its declaration for an explicit truncation gauge."""

    def __init__(self):
        self.parts = []
        self.families = set()
        self.series = 0
        self.size = 0
        self.truncated = False

    def add(self, name, help_text, value, labels=None):
        if not _finite(value):
            return
        declaration = "" if name in self.families else f"# HELP {name} {help_text}\n# TYPE {name} gauge\n"
        entries = ",".join(f'{key}="{escape_label(label)}"' for key, label in (labels or {}).items())
        sample = f"{name}{'{' + entries + '}' if entries else ''} {value:.15g}\n"
        body = declaration + sample
        size = len(body.encode("utf-8"))
        reserve = len((_TRUNCATION_HELP + "multillm_prometheus_truncated 1\n").encode("utf-8"))
        if self.series >= MAX_SERIES - 1 or self.size + size > MAX_BYTES - reserve:
            self.truncated = True
            return
        self.parts.append(body)
        self.families.add(name)
        self.series += 1
        self.size += size

    def finish(self):
        return "".join(self.parts) + _TRUNCATION_HELP + f"multillm_prometheus_truncated {int(self.truncated)}\n"


def render_metrics(stats):
    """Select aggregate gauges only; never serialize provider or request metadata."""
    output = Exposition()
    total = stats.get("total_requests")
    output.add("multillm_observed_requests_window", "Observed requests; excludes unrecorded native edge traffic.",
               total, {"window": "24h", "source": "flask_ledger"})
    breakdown = stats.get("status_code_breakdown")
    if isinstance(breakdown, dict):
        for status_class in _STATUS_CLASSES:
            output.add("multillm_requests_window", "Observed requests by response class in a rolling window.",
                       breakdown.get(status_class), {"window": "24h", "status_class": status_class})
    if _finite(total) and total > 0:
        for quantile, field in (("0.50", "p50_response_time"), ("0.95", "p95_response_time")):
            latency = stats.get(field)
            if _finite(latency):
                output.add("multillm_latency_window_seconds", "Observed request latency quantile in seconds.",
                           latency / 1000, {"window": "24h", "quantile": quantile})
    return output.finish()
