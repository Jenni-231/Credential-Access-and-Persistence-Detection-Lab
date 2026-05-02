# Lateral Movement with Ticket Forgery – SOC Monitoring and Response
This document demonstrates how a SOC team can monitor Active Directory credential abuse and Kerberos ticket forgery attacks, detect anomalies, and implement remediation and control measures.

Attack Simulation Summary

The DC Sync attack simulates abusing AD replication privileges to retrieve KRBTGT secrets. Accounts with Replicating Directory Changes or Replicating Directory Changes All can request replication data.

Command Used: 

mimikatz.exe "lsadump::dcsync /domain:dcorp.local /user:krbtgt"

Splunk Detection Logs: 

Detection Category: Active Directory Replication Abuse

| Log Source | Event ID | Detection Indicator | Description |
|-----------|----------|--------------------|-------------|
| Security | 4662 | Directory replication operation | Account requesting AD replication |
| Security | 4624 | Logon Type 3 | Network authentication prior to replication request |
| Security | 4672 | Special privileges assigned | Privileged account access |
| Directory Services | 4928 / 4929 | Replication events | Unusual replication activity |


SOC Investigation Actions
	1.	Determine requesting account and host.
	2.	Confirm whether account normally performs replication.
	3.	Identify sensitive targets (e.g., KRBTGT).
	4.	Escalate to incident response for non-DC origin requests.


Remediation & Security Controls
	•	Restrict replication privileges to domain controllers only
	•	Regularly audit accounts with replication rights
	•	Rotate KRBTGT password twice if compromised
	•	Implement tiered admin model
	•	Monitor replication from non-DC hosts


MITRE ATT&CK Mapping
	•	T1003.006 – DC Sync
	•	T1078 – Valid Accounts


index=wineventlog EventCode=4662 OR EventCode=4928 OR EventCode=4929
| table _time, ComputerName, User, ObjectName, Operation