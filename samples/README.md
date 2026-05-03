# Sample Alerts

Synthetic incident-response alert payloads for testing and demo. All cases are
fabricated for documentation purposes; no real customer data is included.

| File | Threat pattern | Expected verdict |
|---|---|---|
| `ssrf_sqli_probe.json` | SSRF to AWS metadata + SQL injection in DNS | BLOCK |
| `path_traversal.json` | Directory traversal in file fetch parameter | BLOCK |
| `command_injection.json` | Shell metacharacters in process exec | BLOCK |
| `benign_login_alert.json` | High-volume successful logins (false alarm) | PASS |

Use these with `pq-sift-defender investigate <file>` to see the agent's
end-to-end triage flow.
