# SentinelAPI Scan Report

**Target:** Local intentionally vulnerable Order API
**Generated:** 2026-09-24T08:51:44.598082+00:00

## Summary

| Critical | High | Medium | Low | Pass |
| --- | --- | --- | --- | --- |
| 1 | 1 | 1 | 0 | 0 |

## Findings

### 1. [Critical] Broken Object Level Authorization

- **Endpoint:** `GET /orders/{id}`
- **Score:** 9.5/10
- **Evidence:** User A requested order 1002, owned by User B, and received HTTP 200 with User B's order data.
- **Expected:** HTTP 403 or HTTP 404 because order 1002 is not owned by User A.
- **Observed:** HTTP 200 with another user's order data.
- **Fix:** Verify resource ownership for every object ID before reading, updating, or deleting it.

**Safe reproduction command**

```bash
curl -X GET "http://localhost:5000/orders/1002" -H "Authorization: Bearer <TEST_USER_TOKEN>"
```

### 2. [High] Excessive Data Exposure

- **Endpoint:** `GET /orders/{id}`
- **Score:** 7.0/10
- **Evidence:** The response included sensitive field(s): internalNotes, paymentReference
- **Expected:** A normal user response should omit internal or secret fields.
- **Observed:** Sensitive fields were returned in the API response.
- **Fix:** Return an allowlisted response DTO for this endpoint and exclude internal notes, payment references, tokens, and secrets.

**Safe reproduction command**

```bash
curl -X GET "http://localhost:5000/orders/1002" -H "Authorization: Bearer <TEST_USER_TOKEN>"
```

### 3. [Medium] Possible Missing Rate Limiting

- **Endpoint:** `POST /auth/login`
- **Score:** 5.5/10
- **Evidence:** All 5 controlled sandbox requests succeeded without a limiting response.
- **Expected:** A sensitive endpoint should enforce a documented rate limit.
- **Observed:** No limiting response was observed during the safe low-volume probe.
- **Fix:** Add endpoint-appropriate rate limiting and return HTTP 429 when the threshold is exceeded.

**Safe reproduction command**

```bash
curl -X POST "http://localhost:5000/auth/login" -H "Content-Type: application/json" -d '{"email":"user-a@example.test"}'
```
