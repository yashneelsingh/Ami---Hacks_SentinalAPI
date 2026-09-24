# SentinelAPI submission artifacts

These files are current, repository-owned evidence for the local-only MVP.

Repository: <https://github.com/yashneelsingh/Ami---Hacks_SentinalAPI>

Copy-ready project text for an organizer-provided form is in
`SUBMISSION_COPY.md`.

## Presentation

- `SentinelAPI_AMIHACKS_Deck_v2.pptx` — validated 9-slide 16:9 deck covering
  the problem, proposed solution, architecture, live vulnerable result,
  explainable evidence, safety and automated verification, secure negative
  control, demonstrated scope, and future scope.
- The finalization check found zero package-integrity findings and zero layout
  findings. The deck uses only Arial and contains speaker-note source references.

## Demo screenshots

- `screenshots/vulnerable-overview.png` — live result with one Critical and one
  High finding.
- `screenshots/vulnerable-findings.png` — expanded expected behavior, observed
  behavior, remediation, and redacted reproduction evidence.
- `screenshots/secure-clean.png` — secure control with zero findings.
- `screenshots/mobile-vulnerable.png` — 375-pixel viewport verification with no
  horizontal overflow.

The images come from live local requests after `python -m app.seed`; they are not
canned finding output. Recreate the flow with the commands in the root
`README.md` and the steps in `SUBMISSION_CHECKLIST.md`.

## Deployment status

No public deployment link applies. SentinelAPI deliberately accepts only
`localhost`, `127.0.0.1`, and `::1` targets, and the intentionally vulnerable
sandbox must never be exposed publicly.

## Participant-owned fields still required

Before submission, registered participants must confirm that the two
commit-derived contributors in `TEAM_CONTRIBUTIONS.md` are the registered team,
record the participant who reviewed the AI-assisted work, record organizer
approval for any pre-event or starter material, and upload the final artifacts
through the organizers' current process.
