# Protected candidate context windows

Set the Worker environment variable `ROLEPLAY_CANDIDATE_CONTEXT_REFIT=window`
to fit roleplay generation history separately for each eligible candidate.
The default is `off`; missing or invalid values also select `off`. There is
no new request field. Ordinary Chat, Responses and Messages routes are unchanged.

Before dispatch, each known candidate window reserves the requested output
(up to that candidate's output limit) and `ROLEPLAY_CONTEXT_SAFETY_TOKENS`.
Requests without an explicit output limit reserve
`ROLEPLAY_CONTEXT_REPLY_RESERVE_TOKENS`; their actual output allowance still
uses the existing provider capacity calculation. Unknown windows retain the
existing capacity behavior. Fitting uses the existing estimated token count,
not a native provider tokenizer.

The fitter removes the oldest complete unprotected dialogue groups until the
view fits. A group contains a user message and its following assistant/tool
exchange, ending before the next user message. System and developer directives
remain in their original order. The latest user message, including multimodal
content, and everything following it remain intact. Tool calls and results
are retained or omitted together. Unanswered users, unmatched tool calls/results
and legacy function exchanges that cannot be proven complete stay protected.
Individual messages are never sliced or rewritten by the fitter.

An unfit candidate is skipped before any generation request is sent. If every
candidate is unfit, the response is the existing HTTP 413 with
`roleplay_context_too_large`. Fitting makes no summarization or generation calls
and does not change the existing rules for retries or stream validation.
Grouping traverses the existing bounded roleplay history once per plan;
binary search bounds repeated token estimates over candidate views. The
configured eligible candidate list and request/session limits still apply.

Payload construction, prompt-cache decisions, input estimates and automatic
continuation start from the selected candidate's view. When selection omits
at least one group, the response includes:

- `X-MultiLLM-Context-Refit: window`
- `X-MultiLLM-Context-Refit-Omitted-Groups: <integer>`

`X-Roleplay-Estimated-Input-Tokens`,
`X-MultiLLM-Estimated-Input-After` and the prompt-cache estimated-token header
describe that selected view. Omission headers contain no conversation content.
Existing optimization counts include messages omitted for selection, and the
optimization mode is `window` on a refitted response. Headers describe the
initial selected dispatch; continuation retains its existing response and
diagnostic conventions.

Windowing is request-local. Durable conversation storage, protected directives,
compaction checkpoints and opt-in recovery templates do not use the shortened
candidate view. Existing memory compaction and recovery size/retention limits
remain independent; windowing does not delete stored history or create a
migration. The public roleplay parser's existing text-only schema is unchanged;
multimodal/tool preservation is covered directly by the pure fitter tests.

## Tests

`tests/test_roleplay_candidate_context_worker.mjs` runs in `npm run test:worker`.
The data-URL import map in `tests/helpers/load_cloudflare_worker.mjs` resolves
the `./candidate-context.mjs` imports in capacity and endpoint for the other
roleplay suites.
