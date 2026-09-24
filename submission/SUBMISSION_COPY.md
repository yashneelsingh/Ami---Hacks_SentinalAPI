# SentinelAPI submission copy

## Project name

SentinelAPI

## Repository

<https://github.com/yashneelsingh/Ami---Hacks_SentinalAPI>

## Deployment

Not applicable. SentinelAPI is intentionally restricted to loopback targets,
and its deliberately vulnerable sandbox must remain local-only.

## Problem

Valid API requests can still violate object ownership. Conventional signature
scanners often miss this because both requests are authenticated and structurally
valid. Engineers need reproducible evidence that one controlled user can access
another user's object, along with a direct remediation path.

## Solution

SentinelAPI is a safe, specification-driven scanner that proves whether one
authenticated API user can access another user's data. It parses a bounded
OpenAPI 3.x definition, authenticates two controlled local users, discovers
their objects, performs a read-only cross-user comparison, and produces
severity-ranked JSON, Markdown, and browser evidence with redacted reproduction
requests.

## Demonstrated result

The vulnerable local sandbox produces exactly one Critical BOLA finding and one
High excessive-data-exposure finding. The secure negative control returns HTTP
403 for cross-user access and produces zero confirmed findings. External targets
are rejected, requests and response sizes are bounded, redirects are blocked,
and ambiguous comparisons remain inconclusive.

## Technical evidence

- 49 automated tests pass through `python -m scripts.ci` in the documented
  virtual environment.
- Deterministic reset restores two users and orders `1001` and `1002`.
- Reports contain redacted bearer values and no seeded passwords.
- Desktop and 375-pixel mobile browser flows are captured under `screenshots/`.
- The 9-slide deck is `SentinelAPI_AMIHACKS_Deck_v2.pptx`.

## Current scope and future work

The demonstrated MVP supports a narrow OpenAPI 3.x shape, fixed local test
identities, and bounded authenticated GET collection/detail endpoints. External
scanning, write-operation testing, full `$ref` resolution, arbitrary auth,
pagination, LLM-generated findings, CI enforcement, and production multi-tenancy
remain outside the demonstrated scope. A separately tested hosted persistence
foundation documents how tenant-isolated scan history, encrypted credentials,
leases, retention, and PostgreSQL migrations could support later deployment
without weakening target restrictions.

## AI assistance disclosure

OpenAI Codex assisted with implementation and verification, including database
hardening, hosted-persistence foundations, tests, documentation, local browser
verification, screenshots, and the presentation deck. Registered participants
remain responsible for reviewing, understanding, and explaining all submitted
work.
