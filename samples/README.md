# Sample Alerts

Synthetic incident-response alert payloads for testing and demo. All cases are
fabricated for documentation purposes; no real customer data is included.

## Threat cases (expected BLOCK)

| File | Threat pattern |
|---|---|
| `cloud_metadata_ssrf.json` | SSRF to AWS instance metadata endpoint |
| `command_injection.json` | Shell metacharacters in process exec |
| `malware_memory_dump.json` | Memory dump with suspicious process activity |
| `multi_vector_attack.json` | Combined SSRF + SQL injection probe |
| `path_traversal.json` | Directory traversal in file fetch parameter |
| `prompt_injection_alert.json` | Payload directs agent to SSRF endpoint |
| `shadow_file_read.json` | Unauthorized read of /etc/shadow |
| `ssrf_sqli_probe.json` | SSRF to AWS metadata + SQL injection in DNS |

## Benign cases (expected PASS)

| File | Description |
|---|---|
| `benign_login_alert.json` | High-volume successful logins (false alarm) |
| `clean_health_check.json` | Routine health check probe |
| `benign_disk_image_backup.json` | Scheduled disk image backup |
| `benign_internal_monitoring_ip.json` | Internal monitoring probe |
| `benign_k8s_health_check.json` | Kubernetes liveness check |
| `benign_log_rotation.json` | Log rotation with filesystem paths |
| `benign_memory_dump_backup.json` | Scheduled memory dump for backup |
| `benign_proc_monitor.json` | Process monitoring alert |

## Ambiguous / adversarial benign (expected PASS, debatable)

| File | Description |
|---|---|
| `ambiguous_high_sev_backup.json` | High-severity backup event |
| `ambiguous_high_sev_pentest.json` | Authorized penetration test |
| `adversarial_benign_cmd_lookalike.json` | Benign with shell metacharacters |
| `adversarial_benign_path_traversal_lookalike.json` | Benign with traversal patterns |
| `adversarial_benign_ssrf_lookalike.json` | Benign with cloud metadata URL |

## Audit chain artifact

| File | Description |
|---|---|
| `audit_chain_export.json` | Real signed audit chain from a real investigation (3 entries, ML-DSA-65 signatures, hash-linked) |

## Usage

```bash
pq-sift-defender investigate samples/path_traversal.json
pq-sift-defender investigate samples/benign_login_alert.json --brief
```
