# AMIHACKS SentinelAPI Submission Checklist

Complete this checklist against the organizers' current deadline and portal. Do not mark an item complete from assumption alone.

## Eligibility and provenance

- [ ] Organizers have explicitly confirmed whether this pre-existing repository may be used.
- [ ] The official event-period starting commit or tag is recorded.
- [ ] The final submission commit or tag is recorded.
- [ ] Every substantial contribution is assigned to a registered participant in `TEAM_CONTRIBUTIONS.md`.
- [ ] Open-source and AI-assisted development use is accurately disclosed where required.
- [ ] Every team member can explain the submitted implementation.

## Technical deliverables

- [ ] GitHub repository link is final and accessible to judges.
- [x] Source code is present.
- [x] Architecture diagram is present in `ARCHITECTURE.md`.
- [ ] Deployment link is supplied if the team uses one; otherwise it is clearly marked not applicable because the MVP is local-only.
- [x] Setup, reset, demo, testing, scope, and limitations are documented in `README.md`.
- [ ] Team contribution details are completed with names and evidence.

## Presentation deliverables

- [ ] PPT or PDF deck contains no more than 8-10 slides.
- [ ] The deck states the problem and affected stakeholders.
- [ ] The deck explains the proposed solution and two-user comparison.
- [ ] The deck includes the system architecture.
- [ ] The deck includes current demo screenshots.
- [ ] The deck separates demonstrated scope from future scope.
- [ ] The deck avoids claims of production readiness or complete OWASP coverage.

## Live demo rehearsal

- [ ] Reset the database with `python -m app.seed`.
- [ ] Start the vulnerable app and open the local dashboard.
- [ ] Run the vulnerable scan and show exactly one Critical and one High finding.
- [ ] Expand both findings and explain expected, observed, remediation, and redacted reproduction.
- [ ] Download and open the JSON and Markdown reports.
- [ ] Start the secure control on port `8011`.
- [ ] Select `openapi-secure.yaml`, scan `http://127.0.0.1:8011`, and show a clean result with zero findings.
- [ ] Demonstrate that an external target is rejected.
- [ ] Explain request and response bounds, secret redaction, and why ambiguous results are inconclusive.
- [ ] Confirm the demo uses live requests rather than hardcoded output.

## Final checks

- [ ] `python -m scripts.ci` passes in the submission environment.
- [ ] Generated reports contain no passwords, bearer tokens, or authorization secrets.
- [ ] The dashboard is usable at desktop and mobile widths.
- [ ] The repository excludes the local database, virtual environment, caches, and review artifacts.
- [ ] The final submission is uploaded before the deadline.
- [ ] The team is ready for the mandatory final presentation when called.
