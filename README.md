# SSH-Bruteforce-Detection

This project simulates a real SOC investigation of an SSH brute-force attack originating from a single external IP by combining Linux log analysis, Splunk SIEM correlation, and Python automation to build a complete detection pipeline. It demonstrates key blue-team skills including identifying repeated SSH authentication failures, parsing logs using regex, grouping patterns programmatically, writing correlation searches in Splunk, and mapping detections to MITRE ATT&CK (T1110 – Brute Force). The project includes raw Linux logs (auth.log, syslog), SPL queries, Python scripts for automated detection, and detailed documentation such as an incident report and MITRE technique mapping, forming a complete end-to-end demonstration of detection, analysis, and reporting for entry-level cybersecurity roles

## Included Documentation
- [Incident_Report.md](docs/Incident_Report.md) – Full incident write-up
- [MITRE_Analysis.md](docs/MITRE_Analysis.md) – MITRE ATT&CK mapping and explanation
