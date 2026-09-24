# AMIHACKS SentinelAPI Submission Checklist

Complete this checklist against the organizers' current deadline and portal. Do not mark an item complete from assumption alone.

Repository-owned verification was completed on **2026-09-24**. Unchecked items
require organizer confirmation, registered-participant details, a final remote
repository URL, or action in the event portal.

## Eligibility and provenance

- [ ] Organizers have explicitly confirmed whether this pre-existing repository may be used.
- [x] The official event-period starting commit or tag is recorded.
- [x] The final submission commit or tag is recorded.
- [ ] Every substantial contribution is assigned to a registered participant in `TEAM_CONTRIBUTIONS.md`.
- [x] Open-source and AI-assisted development use is accurately disclosed where required.
- [ ] Every team member can explain the submitted implementation.

## Technical deliverables

- [x] GitHub repository link is final and accessible to judges.
- [x] Source code is present.
- [x] Architecture diagram is present in `ARCHITECTURE.md`.
- [x] Deployment link is supplied if the team uses one; otherwise it is clearly marked not applicable because the MVP is local-only.
- [x] Setup, reset, demo, testing, scope, and limitations are documented in `README.md`.
- [ ] Team contribution details are completed with names and evidence.

## Presentation deliverables

- [x] PPT or PDF deck contains no more than 8-10 slides.
- [x] The deck states the problem and affected stakeholders.
- [x] The deck explains the proposed solution and two-user comparison.
- [x] The deck includes the system architecture.
- [x] The deck includes current demo screenshots.
- [x] The deck separates demonstrated scope from future scope.
- [x] The deck avoids claims of production readiness or complete OWASP coverage.

## Live demo rehearsal

Database recovery command: `python -m app.seed`. If the app has the database
open, stop Uvicorn, run the command, then restart Uvicorn.

- [x] Reset the database with `python -m app.seed`.
- [x] Start the vulnerable app and open the local dashboard.
- [x] Run the vulnerable scan and show exactly one Critical and one High finding.
- [x] Expand both findings and explain expected, observed, remediation, and redacted reproduction.
- [x] Download and open the JSON and Markdown reports.
- [x] Start the secure control on port `8011`.
- [x] Select `openapi-secure.yaml`, scan `http://127.0.0.1:8011`, and show a clean result with zero findings.
- [x] Demonstrate that an external target is rejected.
- [x] Explain request and response bounds, secret redaction, and why ambiguous results are inconclusive.
- [x] Confirm the demo uses live requests rather than hardcoded output.

## Final checks

- [x] `python -m scripts.ci` passes in the submission environment.
- [x] Generated reports contain no passwords, bearer tokens, or authorization secrets.
- [x] The dashboard is usable at desktop and mobile widths.
- [x] The repository excludes the local database, virtual environment, caches, and review artifacts.
- [ ] The final submission is uploaded before the deadline.
- [ ] The team is ready for the mandatory final presentation when called.
