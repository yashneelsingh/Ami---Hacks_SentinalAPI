# SentinelAPI product experience and design direction

## Purpose and reference

This document guides SentinelAPI's browser interface. The supplied image is a visual reference, not a feature specification. Borrow its calm light workspace, left navigation, soft card boundaries, readable central data area, and compact summary row. Do not copy its healthcare brand, people, metrics, chart, labels, or actions.

SentinelAPI is a local, specification-driven API scanner. It proves whether User A can read User B's object, shows what the API returned, and gives an engineer a safe way to reproduce and fix the issue. Completing and understanding that task matters more than visual polish. The reference is adapted to SentinelAPI's workflow rather than copied literally.

## The user's path

1. **Orient:** see the local target, selected OpenAPI document, and authorized, loopback-only, read-only boundary.
2. **Set up:** use the default sandbox or choose a supported OpenAPI YAML/JSON file and local base URL. Explain that the scanner uses two fixed sandbox identities; credentials are not entered in the browser.
3. **Run:** place one obvious **Run authorized scan** action beside the setup. While it runs, disable repeat submission and show **Testing object ownership…** as text.
4. **Understand:** show an overall outcome, the endpoint tested, owner baselines, and the cross-user response. A severity count alone does not explain the test.
5. **Act:** show expected and observed behavior, impact, remediation, and a redacted test-only reproduction request. Offer JSON and Markdown reports when generated.
6. **Check the control:** explain how to use `openapi-secure.yaml` with `http://127.0.0.1:8011`. Never imply the control ran unless it did.

Before a scan, the page should answer **what will be tested, whether the target is allowed, and what to do next**. After a scan, it should answer **what happened, how strong the evidence is, and what to fix**.

## Translating the image into SentinelAPI

| Reference pattern | SentinelAPI use | Reason |
| --- | --- | --- |
| Quiet application frame | Compact brand header, local-sandbox state, target host, and API reference | Preserve orientation without dedicating a full sidebar to one-page anchor links. |
| Greeting and location | Direct product heading and current local target | Orientation is more useful than a personal greeting, location picker, or notification badge. |
| Three tinted summary tiles | Omitted from the final interface | The same facts already appear in scan setup and result status; repeating them adds visual noise. |
| Large central chart | Ownership comparison: A's object, B's object, and A's request for B's object | HTTP response and object match are the decisive evidence; a trend chart would mislead. |
| Right-side people card | Omitted from the final interface | Target, specification, identities, and endpoint already appear where they are configured or tested. |
| Bottom tracker table | Tested endpoints and outcomes, then confirmed findings | Let engineers scan results and open detail. Only show rows backed by live audit data. |

Do not add decorative search, alerts, charts, filters, or sharing controls without a working task behind them. The reference's balance is useful; its feature set is not SentinelAPI's feature set.

## Page structure

### App shell and setup

- Use a compact top bar with SentinelAPI, the **Local sandbox** marker, target host, and local API reference. Do not add a sidebar when every destination already appears in one short page.
- Keep the current target and scan status near the page heading. A connection indicator is not proof that authorization is safe.
- Keep setup limited to the **OpenAPI definition**, **Local API base URL**, and the primary scan action. Label the checked-in default document and any uploaded file accurately.
- Explain the supported URL near its input: HTTP on `localhost`, `127.0.0.1`, or `::1` only. A rejected target needs a specific inline error and focus returned to the field.
- Show User A and User B only in the live ownership evidence after the scan discovers their objects. Default order IDs `1001` and `1002` can explain the seeded demo; do not present them as discovered results for another target.
- Place the scan action after the target and safety context. Keep bounded, read-only GET behavior visible near it.
- Avoid a dashboard full of empty modules before the first scan. Setup is the primary content then.

### Result overview

- Lead with a plain-language verdict: **Ready**, **Running**, **Completed with findings**, **Completed clean**, **Inconclusive**, or **Failed**.
- Distinguish a completed clean scan from an incomplete scan. Zero confirmed findings does not mean every endpoint was tested successfully.
- After a scan, show the actual target, tested endpoint, owner IDs, cross-user status, outcome, and confirmed finding count. Before values exist, show **Not yet tested**.
- Do not add standalone severity cards when the finding list already labels each confirmed issue. The ownership verdict and evidence are the primary result.

### Ownership comparison

The main panel tells the causal story in this order:

1. **What was tested:** authenticated collection/detail `GET` discovered from the selected OpenAPI document.
2. **Owner baselines:** User A's and User B's separate object IDs and successful owner responses.
3. **Cross-user request:** User A requests User B's object ID.
4. **Observed response:** actual HTTP status and whether returned JSON matched B's owner baseline.
5. **Expected response:** HTTP 403 or 404 for a protected object.
6. **Decision:** confirm BOLA only when the live cross-user response is HTTP 200 and matches B's object. Otherwise show the specific pass, inconclusive, or error reason.

Use a compact sequence or comparison grid with text labels and actual values. Do not imply a match the server did not establish. Keep detailed evidence accessible through disclosure controls without making the initial view a wall of JSON.

### Findings and outcomes

- Order confirmed findings by severity. Each row/card has severity, title, method and endpoint, a plain-language evidence sentence, and **View evidence**.
- Expanded detail contains **Expected**, **Observed**, **Why it matters**, **Fix**, and **Safe reproduction request**. Use the redacted report contract; never put tokens, passwords, or raw authorization headers into the page or clipboard.
- Give excessive data exposure its own finding. Explain that sensitive fields in User A's own response are separate from the cross-user ownership flaw.
- Show endpoint `pass`, `fail`, `inconclusive`, and `error` outcomes separately when audit data exists. Failed requests and malformed responses are never confirmed vulnerabilities.
- Keep JSON and Markdown downloads near the result heading. Disable or omit them until a server-generated report exists. Do not add a prominent sharing action.

## Visual system

- **Canvas:** very light lavender-gray or neutral gray; white or near-white work surfaces.
- **Surfaces:** subtle borders and modest corner rounding. Soft shadow may separate the workspace, but hierarchy must work without it.
- **Ink:** near-black primary text and accessible medium-gray supporting text.
- **Accent:** restrained indigo for selection and focus. Reserve deep red for confirmed Critical risk and amber/brown for High risk. Green or neutral clean/pass states always need text labels.
- **Summary surfaces:** use gentle tints only where they clarify a real scan outcome. Do not add standalone summary tiles.
- **Type:** local system sans-serif for copy and a local monospace stack for methods, paths, IDs, HTTP statuses, and commands. No remote fonts.
- **Density:** generous space around setup and the main decision; tighter rows for endpoints and findings. Avoid oversized decorative headings.
- **Icons:** simple local SVGs only when they clarify action or status. No avatars, stock photography, medical symbols, or animated background texture.

These are directional values, not exact sampled colors. Contrast, readable text, and clear state labels take priority over matching the screenshot precisely.

## States and copy

| State | Main message | Next step |
| --- | --- | --- |
| Ready | “Ready to test the selected local API.” | Review target and run scan. |
| Running | “Testing object ownership…” | Wait; keep target context visible. |
| Completed with findings | “User A received User B's order.” when live evidence confirms it | Read comparison and fix guidance; download report. |
| Completed clean | “No confirmed findings in the completed checks.” | Review tested endpoints and the secure control if useful. |
| Inconclusive | “The ownership comparison could not prove a result.” | Read the reason and correct or retry. |
| Failed | “The scan could not finish.” | Show a safe, specific error and retry path. |

Use **confirmed** only after a valid live comparison. Avoid “secure,” “all clear,” “autonomous attack,” and production-grade claims. This is a narrow local demonstration, not general API coverage.

## Responsive and accessible behavior

- **Wide screens:** keep setup in one compact panel, followed by full-width ownership evidence, the endpoint result, and findings.
- **Medium screens:** split setup into two columns while preserving its reading order.
- **Small screens:** stack setup, ownership evidence, endpoint result, and findings. Controls must not require horizontal scrolling; long paths or commands may scroll within their own block.
- Keep file selection, URL input, scan, evidence disclosures, copy, links, and downloads keyboard reachable in logical order. Use visible focus and descriptive labels.
- Announce meaningful scan-state changes through a polite live region, not every internal request.
- Meet WCAG AA contrast, pair color with text, use practical touch targets, and keep mobile input text at least 16px.
- Limit motion to functional state changes and honor `prefers-reduced-motion`.

## Implementation boundaries

- Keep scanner, authentication, bounded GET execution, comparison, redaction, and reporting policies intact unless separately requested.
- Loopback-only enforcement, redirect blocking, timeouts, and size limits remain server-side.
- Never hardcode findings, response statuses, endpoint outcomes, or downloaded reports for a demo.
- Do not add remote assets, trackers, or services to recreate the image.
- Clearly label the intentionally vulnerable target **local-only and unsafe for production**.

## Acceptance checks

- A first-time user can identify the target, specification, two-user test, and next action without repository documentation.
- Running and final states are distinct, especially clean versus inconclusive.
- The live ownership comparison is understandable before opening raw details.
- BOLA and excessive exposure each show specific evidence, expected behavior, and a fix.
- Secure 403/404 produces no BOLA finding; mismatched or malformed HTTP 200 is not called confirmed.
- Reports and copied requests are redacted and available only when generated.
- The layout works with keyboard, screen reader, mobile width, and reduced motion.
