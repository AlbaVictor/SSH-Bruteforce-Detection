# Incident Report — SSH Brute Force Attempt

## Summary
A high volume of failed SSH authentication attempts was observed on a Linux host. The activity originated from a single external source IP and targeted multiple common usernames, consistent with brute-force credential guessing.

## Environment / Scope
- Host: ubuntu (Linux)
- Service: OpenSSH (port 22)
- Log sources: `auth.log`, `syslog`
- Suspected source IP: 203.0.113.91
- Primary time window (from evidence): Dec 12 14:03:04 → Dec 12 14:06:07

## Timeline (as logged)
- 14:03:01 — Initial SSH connection observed from 203.0.113.91
- 14:03:04 — First “Failed password” event recorded
- 14:03–14:04 — Repeated failures across multiple usernames (admin/root/test/ubuntu/oracle/pi)
- 14:05:01 — Analyst/admin reviews logs via sudo (`tail -n 50 /var/log/auth.log`)
- 14:05:15 — Legitimate key-based login for user `victor` from internal IP 10.0.2.15
- 14:06:02 — Additional SSH failures continue from 203.0.113.91

## Evidence (log extracts)
From `auth.log`:
- Failed password for invalid user admin from 203.0.113.91 port 42201 ssh2
- Failed password for invalid user root from 203.0.113.91 port 42208 ssh2
- Failed password for invalid user ubuntu from 203.0.113.91 port 42222 ssh2
- Accepted publickey for victor from 10.0.2.15 port 53522 ssh2: RSA SHA256:3m5xQe1p8vV3d9YgY9JcRk2HqkS0aZbYp9mQk1aBcDe

From `syslog`:
- pam_unix(sshd:auth): authentication failure; ... rhost=203.0.113.91

## Detection Logic (high level)
- SIEM (Splunk): count SSH failures by source IP in 10-minute bins; alert when failures >= 20
- Python: parse “Failed password” events; group by source IP; alert when failures >= threshold within a time window

## MITRE ATT&CK Mapping
- Technique: T1110 — Brute Force
- Tactic: Credential Access

## Impact Assessment
No successful password-based authentication from the external source IP was observed in the provided logs. The activity appears to be an attempted compromise (credential guessing) without confirmed access.

## Recommended Actions
1. Block or rate-limit the offending IP at the firewall / edge
2. Enable fail2ban (or equivalent SSH rate-limiting controls)
3. Disable password-based SSH authentication; enforce key-based authentication
4. Review SSH exposure (restrict by IP/VPN if possible); consider MFA where applicable
5. Continue monitoring for repeated attempts or lateral movement indicators

## Severity
Medium — brute-force attempt detected; no confirmed compromise in the provided evidence, but repeated attempts indicate active malicious intent.
