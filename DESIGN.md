# SentinelAPI design direction

## Reference and intent

This interface takes its visual direction from the [Orderful design reference](https://getdesign.md/design-md/orderful?q=tech&category=fintech): a calm, editorial white canvas; fine technical lines; oversized, low-weight type; and a single high-contrast signal colour. Do not copy Orderful's logo, wording, illustrations, or brand assets. Apply the visual language to SentinelAPI's own security-scanning workflow.

SentinelAPI should feel like a precise security instrument, not a generic SaaS dashboard or a "hacker" interface. A judge should understand three things immediately:

1. The target is a controlled local sandbox.
2. The scanner compares access between two authenticated users.
3. Any finding is backed by evidence and an exact reproduction request.

## Visual principles

- **Editorial before dashboard:** use generous whitespace, large plain-language headings, and only the information needed for the current decision.
- **Technical, not decorative:** connection lines, coordinate marks, and small monospaced labels may explain the scanner flow. They must never obscure text or simulate a vulnerability.
- **One action per moment:** the primary scan action is visually unmistakable. Secondary actions are quiet outlined buttons.
- **Evidence earns emphasis:** red-orange means a confirmed high-severity issue, not a general accent for every element.
- **Safety is visible:** retain the local-only and sandbox labels in the shell and near the scan action.

## Tokens

Use CSS custom properties. The values below are starting points; do not introduce gradients, glass effects, rounded pills, or a second accent colour.

```css
:root {
  --canvas: #f7f7f4;
  --surface: #ffffff;
  --ink: #101010;
  --muted-ink: #6f6f69;
  --line: #deded8;
  --line-strong: #b9b9b1;
  --signal: #f23312;
  --signal-deep: #ca260c;
  --critical-wash: #fff0ec;
  --warning: #d89000;
  --warning-wash: #fff7df;
  --success: #23694e;
  --success-wash: #edf6ef;
  --mono: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  --sans: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
}
```

- Use `--sans` for all product copy and `--mono` for endpoint methods, paths, IDs, scan states, timestamps, and reproduction requests.
- Use black for normal hierarchy. Reserve `--signal` for the scan button, confirmed critical findings, and the most important scanner state.
- Keep surfaces square or nearly square: `0–4px` corner radius. Borders should generally be `1px solid var(--line)`.
- Use a subtle dotted or dashed line motif in a non-interactive background layer only. Keep its contrast low enough to meet text legibility and disable it in `prefers-reduced-motion` mode.

## App shell

### Desktop

Use a full-width shell with a restrained top navigation bar instead of a heavy left sidebar.

```
┌───────────────────────────────────────────────────────────────────────────┐
│ SentinelAPI   Scanner / Overview          LOCAL SANDBOX  ● 127.0.0.1      │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  01 / AUTHORIZED API SECURITY                                             │
│  Find broken object access before release.                   [Run scan]   │
│  Two-user, specification-driven checks against a local demo.             │
│                                                                           │
│  [ OpenAPI definition ]  [ Base URL ]  [ Identity comparison ]            │
│                                                                           │
│  02 / SCAN RESULTS                                           3 confirmed  │
│  [ Critical 1 ] [ High 1 ] [ Medium 1 ] [ Low 0 ]                         │
│                                                                           │
│  03 / CONFIRMED FINDINGS                                      JSON  MD    │
│  CRITICAL  Broken object-level authorization       GET /orders/{id}      │
│  Evidence, expected vs observed behaviour, and reproduction request       │
└───────────────────────────────────────────────────────────────────────────┘
```

- Top bar: `64–72px` high, white or canvas background, a bottom border, and compact monospaced status information aligned right.
- Keep the SentinelAPI wordmark text-only or use the existing `S` mark. Do not recreate Orderful's red symbol.
- The main content column is `min(1320px, calc(100vw - 96px))`, with `48px` desktop gutters and `56–72px` vertical section separation.
- Use a small numeric section index (`01`, `02`, `03`) plus uppercase mono label before each major area. The actual heading remains sentence case and large.

### Mobile

- Collapse the top navigation to the product name, scan status, and a compact menu only if additional destinations are added.
- Preserve `Run scan` as a full-width primary action below the introductory copy.
- Stack target fields, metrics, evidence columns, and download controls into one column.
- Do not hide the local-sandbox warning, finding severity, endpoint, or reproduction action.

## Type and spacing

- Hero heading: `clamp(2.25rem, 5vw, 5.5rem)`, weight `300–400`, tight letter spacing, line-height `0.94–1.02`.
- Section headings: `1.35–1.8rem`, weight `500–600`.
- Body: `0.95–1rem`, line-height `1.5–1.65`; descriptions should be plain English rather than security jargon.
- Technical labels: `10–12px`, uppercase, mono, `0.08–0.12em` tracking.
- Build spacing on an 8px scale: 8, 16, 24, 32, 48, 64, 80. Use a larger jump between major sections than between cards.

## Component direction

### Primary action

- Use a rectangular `--signal` button with black or white label text chosen for contrast.
- Label it **Run authorized scan** when space allows; preserve the short **Run scan** label on narrow screens.
- Include a compact play/arrow glyph only as supporting detail. During scanning, show a textual state such as `Testing object ownership…`; never rely on a spinner alone.

### Scan target strip

- Present the OpenAPI file, base URL, and identity comparison as one bordered three-column strip on desktop.
- Each item gets an uppercase mono label, a prominent value, and one useful supporting line.
- Use `LOCAL ONLY` / `SANDBOX` as an outlined safety stamp, not a soft green success chip.

### Severity summary

- Keep four equal metric blocks. Use large numerical counts, a tiny severity label, and a thin bottom rule.
- Critical uses `--signal`; high uses `--warning`; medium uses muted ochre; low uses neutral grey or restrained green.
- An empty count should be `0`, never an em dash after a completed scan.

### Findings

- Treat each finding as a wide bordered editorial row, not a dense card stack.
- First line: severity, finding title, score, and verification state.
- Second line: method and endpoint in mono, followed by a one-sentence explanation of impact.
- Expanded evidence uses a two-column layout: **Expected** versus **Observed**. Place **Remediation** below them as a direct engineering action.
- The reproduction command lives in a dark, high-contrast code block with a visibly labelled copy control. Clearly mark it as a test-only request.
- Preserve the empty state, but make it reassuring: `No confirmed findings. The sandbox checks completed without an ownership violation.`

### Connection-line motif

- Use an absolutely positioned SVG or CSS background in the hero/scan-target area: fine dashed lines linking small labelled nodes such as `SPEC`, `USER A`, `USER B`, `OBJECT ID`, and `EVIDENCE`.
- Lines should be decorative and non-interactive. Keep all information represented in normal HTML too.
- Use the signal colour only for the currently active node or confirmed evidence path. Avoid animated lines unless the scan is actively running; respect `prefers-reduced-motion`.

## Content voice

Use direct, understandable language.

| Avoid | Prefer |
| --- | --- |
| "Leverage autonomous attack surfaces" | "Test whether one user can access another user's order." |
| "Threat intelligence dashboard" | "Scan results" |
| "Vulnerability detected" | "User A received User B's order." |
| "Mitigation recommendation" | "Require an ownership check before returning the order." |

Always say **confirmed** only when the comparison has actually run. Before a scan, use **ready to scan** or **not yet scanned**.

## Interaction and accessibility

- Visible keyboard focus: a `2px` ink or signal outline with at least `3px` offset.
- Do not communicate severity by colour alone; pair it with text and a labelled status.
- Meet WCAG AA contrast for all text, control states, and code blocks.
- Buttons must retain their labels while loading and disabled states must explain why when relevant.
- `<details>` evidence sections must have descriptive summaries, be keyboard operable, and remain usable without animation.
- Use `aria-live="polite"` for scan progress and result count updates. Do not announce every request log line.

## Implementation guardrails

- Reuse the existing local-only scanner workflow and its report data. This is a visual/content refactor, not a change to scanning behaviour or authorization testing.
- Keep user-provided OpenAPI file selection, JSON/Markdown report download, exact endpoints, and proof-of-concept commands intact.
- Do not expose demo credentials or tokens more prominently than the existing controlled-demo documentation requires.
- Do not add third-party fonts, trackers, images, or remote assets merely to imitate the reference. The technical motif should be built locally with CSS/SVG.
- Do not call the demo API "production-ready" or imply that SentinelAPI may scan unapproved systems.

## Acceptance checklist

- [ ] The first screen clearly says this is an authorized local sandbox.
- [ ] One high-contrast action starts the scan, and scan progress uses human-readable text.
- [ ] The two-user access comparison is visually understandable before results load.
- [ ] Confirmed findings make severity, endpoint, evidence, expected behaviour, observed behaviour, remediation, and reproduction easy to locate.
- [ ] The UI feels sparse, exact, and technical at desktop and mobile sizes.
- [ ] No Orderful trademarks, copy, logo, or proprietary artwork appear in the product.
