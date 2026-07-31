# MultiLLM control-plane design

## Direction

The interface is an operator console, not a provider marketplace. It uses dense,
high-signal views with restrained visual hierarchy: neutral ink surfaces, cyan
for interaction, and semantic green, amber, and rose only when state requires it.
Large editorial headings orient the user; compact monospaced labels expose
machine state.

The visual language deliberately avoids provider-brand gradients and decorative
dashboard chrome. MultiLLM should feel like infrastructure: precise, calm, and
easy to scan under pressure.

## Information architecture

- **Operations** is the default surface: traffic, response classes, provider
  circuits, route traces, request records, endpoint catalog, and configured cost.
- **Access** separates account creation from account inspection. Complete API
  keys appear in a modal once after creation or rotation.
- **OpenRouter lab** is a contained provider workbench. Provider credentials stay
  server-side; the browser only calls authenticated dashboard endpoints.
- **Error states** retain the request ID and give one primary recovery action
  without exposing internal exception details.

## Component rules

- Panels have one job and one header. Secondary context belongs in short helper
  copy or a compact tag.
- Health labels always combine text with color. Managed circuit states use
  `closed`, `degraded`, `open`, and `half_open` verbatim; raw transports use
  `passthrough`.
- Tables retain semantic headings and scroll horizontally rather than collapsing
  columns into ambiguous cards.
- Buttons use text labels. Destructive account actions require confirmation.
- Focus rings are visible on every interactive element. Target height is at least
  40 pixels, with 44 pixels used for primary form controls.
- Motion is limited to state transitions and a loading spinner, and respects
  `prefers-reduced-motion`.

## Tokens and implementation

Canonical values live in [`static/design-tokens.json`](../static/design-tokens.json).
Runtime CSS variables live in `static/css/shell.css`. Page-specific rules are
split into `operations.css` and `surfaces.css`; each file owns a coherent surface
and remains below the repository's hand-written source limit.

Tailwind remains available for legacy templates and generated utility output, but
new control-plane surfaces use named components so interaction states and
responsive behavior stay consistent.

## Accessibility baseline

- Semantic landmarks, headings, labels, tables, and native dialogs.
- Skip navigation and current-page navigation state.
- Text alternatives for live state and chart data; color is never the sole cue.
- Keyboard-safe copy, filtering, account actions, and model execution.
- Plain-text model rendering with no HTML interpretation.
- Responsive layouts at 1024 and 768 CSS pixels, with reduced-motion support.
