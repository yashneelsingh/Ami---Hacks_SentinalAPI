# SentinelAPI Scan Report

**Target:** SentinelAPI Vulnerable Demo
**Generated:** 2026-09-24T09:56:25.633115+00:00

## Summary

| Critical | High | Medium | Low | Pass |
| --- | --- | --- | --- | --- |
| 1 | 1 | 0 | 0 | 0 |

## Findings

### 1. [Critical] Broken Object Level Authorization

- **Endpoint:** `GET /orders/{order_id}`
- **Score:** 9.5/10
- **Evidence:** user-a@example.test requested /orders/1002 (owned by user-b@example.test) and received HTTP 200 with the same object User B received.
- **Expected:** HTTP 403 or HTTP 404 for another user's object.
- **Observed:** HTTP 200; object ID 1002 was returned.
- **Fix:** Verify object ownership before returning order details.

**Safe reproduction command**

```bash
curl -X GET "http://127.0.0.1:8000/orders/1002" -H "Authorization: Bearer <TEST_USER_TOKEN>"
```

### 2. [High] Excessive Data Exposure

- **Endpoint:** `GET /orders/{order_id}`
- **Score:** 7.0/10
- **Evidence:** The response included sensitive field(s): internal_notes, payment_reference
- **Expected:** A normal user response should omit internal or secret fields.
- **Observed:** Sensitive fields were returned in the API response.
- **Fix:** Return an allowlisted response DTO for this endpoint and exclude internal notes, payment references, tokens, and secrets.

**Safe reproduction command**

```bash
curl -X GET "http://127.0.0.1:8000/orders/1001" -H "Authorization: Bearer <TEST_USER_TOKEN>"
```
