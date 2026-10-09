# MCP schema compatibility digests

`MCP_CONTRACT_DIGESTS_ENABLED` defaults to false. Empty, `false`, and `0` disable it;
`true` and `1` enable it (case-insensitive, surrounding whitespace ignored). A malformed
value disables it and logs one warning per process or isolate, without the value.

When disabled, discovery and tool calls retain their existing output and a supplied
`X-MultiLLM-MCP-Contract` header is ignored. When enabled, discovery adds
`_meta.contract_digest` to each visible tool and to the tools/list result. The result
digest covers only tools authorized for that caller and selected toolsets. Filtering
and discovery order stay the same. Tool digests cover name, complete input/output
schemas, and contract version `1.0.0`; descriptions and annotations outside schemas
are excluded. Missing outputSchema is represented as null.

An enabled client may pin the **individual tool** digest with:

```http
X-MultiLLM-MCP-Contract: <64 lowercase hexadecimal characters from tool._meta.contract_digest>
```

The catalogue digest is for comparing discovery sets, not for pinning an individual
call. After authentication and tool authorization, a mismatch (including a malformed
or empty supplied pin) returns HTTP 409 with error code `mcp_contract_mismatch`
and message `The pinned MCP tool contract has changed. Refresh discovery.` before
execution, tool storage lookup, metering or provider dispatch. Unpinned calls keep working
when schemas change. No automatic retry is introduced. With the flag disabled, even
an invalid pin is ignored. A matching pin authorizes no additional permissions.

## Registered HTTP paths

Both the Flask gateway and the public edge Worker serve `POST /mcp`. Their
`tools/list` results include digests when enabled. `/mcp?toolsets=core,exa` restricts
discovery before hashing. Each tool includes `_meta.contract_digest`, and the
result includes `_meta.contract_digest` over its visible tools. Administrator,
reader and manager discovery follows the existing authorization rules.

`tools/call` checks the pin against the same contract used by discovery, after
authentication and tool authorization and before dispatch. A rejected pin returns
this JSON-RPC error with HTTP status 409 and `Cache-Control: no-store`:

```json
{"jsonrpc":"2.0","id":7,"error":{"code":"mcp_contract_mismatch","message":"The pinned MCP tool contract has changed. Refresh discovery."}}
```

The check covers every public Knowledge tool, including native provider tools and
tools forwarded to the private Knowledge service. Unauthorized calls keep the
existing scope-denial response and never expose a digest. Disabled calls keep
existing response bytes, status codes, headers and private dispatch payloads.
REST paths do not interpret this pin header. Status outputs report existing
operation names and native hash checks; they do not list tool schema definitions.
The offline catalogue and baseline remain independent of the runtime flag.

Set `MCP_CONTRACT_DIGESTS_ENABLED=true` on the public edge, Flask Container and
private Knowledge Worker consistently. The Container environment allowlist must
forward this key. Native Worker dispatch also checks an explicitly supplied
`options.contractPin` before authority, storage, metering and provider calls.
There are no new routes, response headers, migrations or runtime middleware hooks.

## Canonical format and bounds

`multillm-mcp-contract-v1` hashes UTF-8 compact JSON of typed nodes. Null is
`["null"]`, booleans and strings are `[type,value]`, arrays are `["array",nodes]`,
and objects are `["object",[[key,node],...]]` sorted by Unicode scalar key order.
Numbers use `["number",hex]`, where hex is the exact big-endian IEEE-754 binary64
representation. Equal integer/float values hash identically; negative zero becomes
positive zero. Tags prevent collisions between numbers and schema strings. Unknown
schema keywords remain intact and all arrays retain their order. This is a versioned
local canonical format, not RFC 8785. Changing the format requires new baselines.

Numbers must be finite with absolute value at most `2**53-1`; strings must contain
Unicode scalar values. Each canonical value is limited to 256 KiB, 64 nested levels,
and 65,536 nodes. These are bounds on trusted tool schemas and offline inputs, not
new limits on tool argument payloads. No hashing happens for disabled or unpinned
preflight. A digest identifies a declared schema, not a provider capability or a
promise that a provider result conforms to an output schema.

## Offline baseline and diff

From the repository root, using the installed Python environment:

```sh
python scripts/build_knowledge_mcp_catalogue.py --baseline docs/mcp-contract-baseline.json
python scripts/build_knowledge_mcp_catalogue.py --diff docs/mcp-contract-baseline.json
```

Both modes use local tool definitions and perform no network calls. The baseline
contains declared schemas, digests, and shared Python/Worker canonical vectors with
no timestamp, prompts, responses or credentials. Repeating a build yields identical
bytes. These modes do not regenerate `worker/knowledge-mcp-catalogue.json`; that
catalogue can be regenerated separately after tool schema changes. The existing
`--check` and no-argument catalogue build retain their prior behavior.

Diff output lists paths, change kinds and a combined classification. Tool/property
removal, required-field addition and type narrowing are breaking. Optional input
property additions and type widening are compatible. Unknown keyword changes,
constraint/composition/reference changes, output schema additions, version changes,
and ambiguous changes require review. Compatibility is a conservative structural
report, not a full JSON Schema implication proof. Tool renames appear as removal
plus addition. Existing schema fields remain in the digest even if the classifier
cannot interpret them. Baseline input is limited to 4 MiB. CLI exit status is 0 for
compatible, 1 for breaking/review-required, and 2 for an invalid baseline or operation.

This feature invokes no providers, spends no credits, stores no request content,
and adds no retention policy. Offline files contain public contract declarations;
protect them as source artifacts rather than request logs. Enabling the flag does
not change existing allowances, authentication, caching or retry permission.
