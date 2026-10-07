"""Query parameter parsing for memo administration."""

from services.knowledge_client import KnowledgeError


def purge_query(args):
    payload = {}
    for key, value in args.items(multi=True):
        if key not in {"product", "all"} or key in payload:
            raise KnowledgeError("invalid_request", "Unsupported or duplicate memo query fields.", 400)
        payload[key] = value
    if "all" in payload:
        if payload["all"] not in {"true", "false"}:
            raise KnowledgeError("invalid_request", "all must be true or false.", 400)
        payload["all"] = payload["all"] == "true"
    return payload
