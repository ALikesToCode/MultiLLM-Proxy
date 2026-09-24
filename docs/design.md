# MultiLLM interface design

## Direction

MultiLLM is infrastructure. Operator screens are a console, not a provider
marketplace: dense, high-signal views with a restrained hierarchy. Neutral ink
surfaces carry the structure, cyan marks interaction and focus, and green,
amber and rose appear only when state requires them. Compact monospaced labels
expose machine state; prose stays in the sans-serif face.

Public pages explain the product and hand off quickly to setup. They may use
larger editorial type and the dark ink panel, but they reuse the same tokens,
brand mark, buttons and code blocks as the console. Provider-brand gradients,
decorative icons and invented metrics are not part of the language.

## Audiences and primary tasks

- **Operators** check routing health, find failing requests, adjust automatic
  model priorities, manage scoped keys and administer Knowledge sources.
- **Agent developers** connect Codex or Claude to the Knowledge MCP endpoint and
  need copyable, credential-free configuration.
- **Visitors** need to understand what the deployment provides and where to
  sign in. Public pages never show account, source or configuration state.

## Information architecture

- Signed-in navigation, in order of use: Operations, Knowledge and Workbench
  (administrators), OpenRouter lab, Access, Setup guide. The current page is
  marked with `aria-current="page"`; below 1200 CSS pixels the navigation,
  identity and sign-out move into a disclosure menu.
- Guests see a public header with Agent setup, `llms.txt` and Sign in, and a
  footer linking every machine-readable resource.
- Long pages (Knowledge, Setup guide, agent setup) use a sticky local
  navigation whose current section is highlighted as the reader scrolls.
- `/` stays the login-protected Operations dashboard. The OpenRouter lab lives
  at `/openrouter-lab` because `/openrouter` belongs to the provider namespace.

## Honest state

- Configured is not verified. A stored credential means "configured"; only
  successful traffic or an explicit check counts as evidence of connectivity.
  Providers without traffic show no success rate or latency, never `0%`/`0ms`.
- Costs show their basis (provider-reported, reservation estimate, mixed or
  unpriced). Unpriced requests are counted, never treated as free.
- Knowledge indexing, Alexandria receipts and job states keep the service's
  wording: pending, unknown and partial outcomes stay visible. Alexandria keeps
  discover → inspect (free) → paid retrieval with an explicit spending control.
- Every async surface has deliberate loading, empty, filtered-empty, error,
  restricted, disabled and pending states. Pending buttons use `aria-busy`.

## Components

Shared styles live in `static/css/`:

| File | Owns |
| --- | --- |
| `shell.css` | Tokens, base elements, brand, application and public headers, page header, local navigation, footer |
| `controls.css` | Buttons (primary, secondary, quiet, danger, small, busy), links, form fields, label notes and checks |
| `components.css` | Panels, cards, meta lists, status pills and tones, tags, callouts, state banners, disclosures, empty and loading states, dialogs, toasts |
| `content.css` | Tables with scroll affordance, code blocks, copy buttons, tabs, numbered steps, endpoint strips |

Page stylesheets add layout only and must not redefine these components.
Canonical values live in [`static/design-tokens.json`](../static/design-tokens.json)
and are mirrored as CSS variables in `shell.css`.

- Panels have one job and one header; secondary context goes in helper text
  or a compact tag.
- Status pills always pair color with text. Managed circuit states use
  `closed`, `degraded`, `open` and `half_open` verbatim; raw transports use
  `passthrough`.
- Tables keep semantic headings and scroll horizontally with an edge shadow
  rather than collapsing comparisons into ambiguous cards. Record lists whose
  rows carry their own actions may stack on narrow screens with labelled cells.
- Copy controls (`data-copy-value` or `data-copy-target`) confirm with a
  visible "Copied" state and a polite announcement; if the clipboard is
  unavailable the source text is selected for manual copying.
- Tabs are progressive: without JavaScript every panel is visible.
- Buttons use text labels. Destructive actions require confirmation.

## Typography and tokens

Interface text is 14 px, reading text 15 px, and nothing readable is smaller
than 12 px. Page titles scale from 28 to 40 px; editorial display type is
reserved for public pages. Numbers in metrics and tables use tabular figures.
Muted text uses `ink-600` or `ink-500`, both of which meet WCAG AA on white and
on the page background; `ink-400` is decorative only.

## Accessibility baseline

- Semantic landmarks, headings, labels, tables and native dialogs; a skip link
  targets the focusable main region.
- Visible 3 px focus rings on every interactive element; targets are at least
  40 px (44 px for primary form controls and mobile navigation).
- Color is never the only cue; live regions announce copy results and async
  status.
- Plain-text rendering for model output and remote content.
- Motion is limited to state feedback and respects `prefers-reduced-motion`.

## Local preview

`scripts/preview_ui.py` serves the application with synthetic accounts, 24
hours of synthetic traffic and simulated Knowledge, Workbench and OpenRouter
responses. It never reads `.env`, stores state in a temporary directory and
refuses non-loopback connections, so reviewing a state cannot call or bill a
provider. `--knowledge setup|unavailable` switches the Knowledge fixtures.
