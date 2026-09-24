"""The Knowledge MCP contract served by Flask and, unchanged, by the edge Worker.

The edge copy is generated: run `python scripts/build_knowledge_mcp_catalogue.py`
after changing this module or the tool contracts it imports.
"""

import json
from pathlib import Path

from routes import knowledge_alexandria as alexandria
from routes import knowledge_management as management

CATALOGUE_PATH = Path(__file__).resolve().parents[1] / "worker" / "knowledge-mcp-catalogue.json"
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26")
SERVER_INFO = {"name": "multillm-knowledge", "version": "1.0.0"}
INSTRUCTIONS = (
    "Use knowledge_context or knowledge_search for source evidence, including the actual "
    "product and dependency version when known. Read excerpts, original citations, related "
    "versions and coverage gaps before answering; insufficient evidence is not a verified answer. "
    "For Alexandria, first use knowledge_alexandria_search, then knowledge_alexandria_inspect "
    "on a returned quote. These catalogue calls cost zero credits. Execute only a discovered "
    "quote with authorized spending, contract-valid options and a unique request_id. "
    "Report each call's actual cost and cost state; reserve_credits is not an upstream price cap. "
    "After interruption use knowledge_alexandria_receipt or replay the identical payload with "
    "the same request_id; never purchase again under a new ID to resolve an unknown outcome. "
    "Use knowledge_status and the available source, job and policy tools for administration. "
    "Management tools require knowledge:manage; retrieval tools require knowledge:read. "
    "Registering a source does not fetch it; refresh and verify publication before querying. "
    "Read /llms.txt and /agent-onboarding/SKILL.md on this server for complete setup."
)
QUERY_SCHEMA = {
    "type": "object", "required": ["query"], "additionalProperties": False,
    "properties": {
        "query": {"type": "string", "minLength": 1, "maxLength": 500},
        "product": {"type": "string", "maxLength": 100},
        "version": {"type": "string", "maxLength": 80},
        "repository": {"type": "string", "maxLength": 200, "pattern": r"^[\w.-]+/[\w.-]+$"},
        "mode": {"type": "string", "enum": ["economy", "smart", "deep"], "default": "smart"},
        "token_budget": {"type": "integer", "minimum": 256, "maximum": 16000, "default": 6000},
        "freshness": {"type": "string", "enum": ["normal", "fresh"], "default": "normal"},
    },
}


def _query_tool(operation, description):
    return {"name": f"knowledge_{operation}", "description": description, "inputSchema": QUERY_SCHEMA,
            "annotations": {"readOnlyHint": True, "openWorldHint": True}}


def catalogue():
    """Tools in discovery order with the domain operation and scope each one requires."""
    tools = [
        (_query_tool("context", "Retrieve cited technical excerpts with explicit version evidence and gaps."), "context"),
        (_query_tool("search", "Search technical sources and inspect normalized retrieval diagnostics."), "search"),
        *((tool, "alexandria." + tool["name"].removeprefix("knowledge_alexandria_")) for tool in alexandria.TOOLS),
        *((tool, management.OPERATIONS[tool["name"]]) for tool in management.TOOLS),
    ]
    return {
        "protocolVersions": list(PROTOCOL_VERSIONS), "serverInfo": SERVER_INFO, "instructions": INSTRUCTIONS,
        "tools": [{"operation": operation, "scope": management.required_scope(tool["name"]), "definition": tool}
                  for tool, operation in tools],
    }


def catalogue_json():
    return json.dumps(catalogue(), indent=2, ensure_ascii=False) + "\n"
