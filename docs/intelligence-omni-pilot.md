# Omni subscription pilot

The accompanying [policy](intelligence-omni-pilot.json) allows only NanoGPT
subscription chat. It contains no provider credentials. Its principal and global
allowances are both 262,144 tokens over the gateway's rolling 24-hour window.
Omni separately enforces its owner's local-day limit and includes Jev calls in
that allowance. Pending and uncertain usage remains reserved.

The account and public model catalog were checked on 2026-09-23. The account
reported an active subscription, available included quota and paid overage
disabled. The subscription catalog included both exact model IDs below:

| Candidate | Profile preference | Reviewed capabilities |
| --- | --- | --- |
| `nanogpt:z-ai/glm-5.3-flash` | Balanced and fast | Tools, JSON, streaming, reasoning |
| `nanogpt:z-ai/glm-5.3` | Quality | Tools, JSON, streaming, reasoning |

The quality tiers express a deployment preference, not benchmark scores. The
policy omits latency estimates and task scores. Both models advertise a
1,048,576-token context window and 131,072-token output ceiling; this pilot limits
output to 4,096 tokens and each aggregate request to 131,072 tokens. GLM 5.3's
subscription input multiplier is two, while Flash's is one. Gateway accounting
records reported tokens, not that provider-specific subscription multiplier.

The public metadata lists `low`, `high` and `max` reasoning efforts. The existing
GLM transport policy translates Omni's `xhigh` into `max`; explicit native effort
choices remain intact. Thinking otherwise follows the provider's native behavior.

The two candidates may fall back within the same reviewed subscription. Three
attempts and one escalation are ceilings, not guaranteed retries. Paid overage,
unreviewed providers and model substitution for an explicit selection are refused.
The isolated `INTELLIGENCE_NANOGPT_SUBSCRIPTION_API_KEY` must be configured before
activation so these calls cannot select an unreviewed general-pool credential.

Media routes and multimodal input remain disabled. This policy does not assert a
subscription entitlement for transcription, speech or embeddings. Its integration
principal needs only `chat` and `models` scopes.

Validate the full policy before insert-only seeding with the
[operator CLI](intelligence-d1.md#operator-cli). Recheck account entitlement and
model capabilities before reusing this dated review for another deployment.

Public metadata: [NanoGPT model catalog](https://nano-gpt.com/api/v1/models?detailed=true).
Account entitlement was checked through the authenticated subscription usage and
model endpoints; no credential or account identifier is recorded here.
