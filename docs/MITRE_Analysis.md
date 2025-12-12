# MITRE ATT&CK Analysis — SSH Brute Force

## Technique
- ID: T1110
- Name: Brute Force
- Tactic: Credential Access

## Why this applies
Repeated SSH authentication failures (“Failed password”) from a single source IP over a short time window indicates password guessing.

## Evidence
Example log line:
Failed password for invalid user admin from <IP> port <PORT>

## Detection logic
- Splunk: SPL flags source IPs with >20 failed attempts.
- Python: regex extracts IPs and counts failures; alerts when count >20.

## Recommended controls
- Block IP / rate-limit at firewall
- Enable fail2ban
- Disable password auth for SSH (use keys)
- MFA where applicable
