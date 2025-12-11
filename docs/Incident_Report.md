# Incident Report — SSH Brute Force Attempt

## Summary
A high volume of SSH authentication failures was detected on a Linux server, originating from a single external IP address. Pattern analysis indicates a credential brute-force attempt.

## Timeline
- 14:03 — First failed SSH attempt
- 14:04–14:10 — 125 failed attempts
- 14:11 — Alert triggered in Splunk
- 14:12 — Python enrichment flags the IP
- 14:15 — Analyst review and escalation

## Evidence (Extract)
Failed password for invalid user admin from 185.242.56.91 port 42311

## MITRE Technique
T1110 - Brute Force (Credential Access)

## Recommended Actions
1. Block offending IP at firewall
2. Enforce fail2ban on SSH
3. Review server authentication logs
4. Consider MFA and disabling password-based SSH login

## Severity
Medium (attempt detected early, no access gained)
