# SentinelAPI Team Contributions

Complete this record with the registered team before submission. Use commit history and actual work completed during the official hackathon period. Do not credit planned, pre-event, mentor-built, or externally implemented work as participant work.

## Eligibility confirmation

- Organizer approval for any pre-event repository or starter material: **Not yet recorded**
- Official hackathon development start time: **24 September 2026, 12:30 PM IST** ([official schedule](https://amihacks2026.vercel.app/timeline))
- Final submission time: **Organizer confirmation still required; the published schedule lists final presentations on 25 September 2026, 1:00–3:00 PM IST but does not publish a portal cutoff**
- Repository commit or tag at the official start: **`b098120` is the first repository commit, created 24 September 2026 at 1:58 PM IST, after the published start time**
- Repository commit or tag at final submission: **`amihacks-submission-ready`**

If the organizers do not approve pre-existing implementation, do not submit this repository as work created during the event.

## Participant record

| Repository contributor (registration must be confirmed by the team) | Commit-derived responsibilities | Main commits | Verification or demo responsibility |
| --- | --- | --- | --- |
| Divyanshu Saraswat | Initial problem statement record; scanner checks, reporting, safety architecture, secure-control work, documentation, and submission preparation | `b098120`, `aaaabd9`, `9df8e5d`, `7471ac0`, `c296e06`, `3f7917e` | Explain comparison policy, reports, secure control, safety boundaries, and architecture |
| Yashneel Singh | Vulnerable sandbox and deterministic database; scanner orchestration and OpenAPI discovery; dashboard; reset, redaction, and safety testing | `bbc22f9`, `5c93661`, `5bef1fe` | Run reset and live vulnerable/secure demos; explain local API, database fixture, UI, and test evidence |

Add one row per registered participant. Keep descriptions concrete, such as OpenAPI parsing, comparison logic, dashboard implementation, negative-control tests, documentation, or presentation delivery.

## Allowed assistance and attribution

| Tool, library, mentor, or source | How it was used | Participant who reviewed and can explain it |
| --- | --- | --- |
| FastAPI, Uvicorn, HTTPX, PyYAML, SQLAlchemy, Alembic, psycopg, cryptography, Argon2 | Open-source runtime, persistence, migration, credential-protection, and password-hashing dependencies listed in `requirements.txt` | To be completed |
| OpenAI Codex | AI-assisted implementation and verification, including database hardening and hosted-persistence foundations, automated tests, documentation, live local browser verification, screenshots, and the presentation deck. Participants remain responsible for review, understanding, attribution, and truthful submission. | Participant reviewer must be recorded before submission |
| Mentor feedback | No mentor feedback was supplied in this repository. Add only feedback actually received; mentors must not contribute implementation. | Not applicable unless feedback is received |

## Final team declaration

Before submission, every registered participant should confirm that:

- the record above is accurate;
- substantial submitted work was completed within the official event period or explicitly approved by organizers;
- no external individual implemented submitted code;
- the team can explain the architecture, scanner logic, safety controls, test evidence, and known limitations;
- the demo and reports come from live local requests rather than hardcoded output.
