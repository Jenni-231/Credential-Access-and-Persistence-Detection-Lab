# Lateral Movement with Ticket Forgery – SOC Monitoring and Response
This document demonstrates how a SOC team can monitor Active Directory credential abuse and Kerberos ticket forgery attacks, detect anomalies, and implement remediation and control measures.


[Compromised Host]
        |
   Credential Dump
        |
   LSASS Memory (SafetyKatz)
        |
   |---------------------------|
   |                           |
DC Sync -> KRBTGT Hash        Service Account Hash
        |                           |
  Golden Ticket                Silver Ticket
        |                           |
 Domain-wide Access            Single Service Access
        |
  Diamond Ticket (Hybrid)
        |
  Privileged Access + Stealth



SOC Incident Response Playbook (Mini)
	1.	Detection
	•	Monitor LSASS access, abnormal TGT/TGS events, replication anomalies.
	2.	Analysis
	•	Correlate logs across hosts, users, and services.
	3.	Containment
	•	Isolate affected hosts and accounts.
	4.	Eradication
	•	Rotate KRBTGT and service account passwords.
	5.	Recovery
	•	Restore normal AD replication, validate ticket issuance.
	6.	Post-Incident
	•	Audit privileged accounts, update detection rules, refine Splunk dashboards.