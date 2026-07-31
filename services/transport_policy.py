RAW_PASSTHROUGH_PROVIDERS = frozenset(
    {"codex-easy", "kimi-code", "linkapi", "nanogpt", "navyai"}
)
MIXED_PASSTHROUGH_PROVIDERS = frozenset({"opencode"})


def provider_circuit_mode(provider: str | None) -> str:
    """Describe how a provider participates in process-local circuits."""
    normalized = str(provider or "").strip().lower()
    if normalized in RAW_PASSTHROUGH_PROVIDERS:
        return "bypassed"
    if normalized in MIXED_PASSTHROUGH_PROVIDERS:
        return "mixed"
    return "managed"


def request_bypasses_circuit(
    provider: str | None,
    path: str | None,
) -> bool:
    """Return whether this request uses a fidelity-first raw transport."""
    normalized = str(provider or "").strip().lower()
    if normalized in RAW_PASSTHROUGH_PROVIDERS:
        return True
    first_segment = str(path or "").strip("/").split("/", 1)[0].lower()
    return (
        normalized in MIXED_PASSTHROUGH_PROVIDERS
        and first_segment == normalized
    )
