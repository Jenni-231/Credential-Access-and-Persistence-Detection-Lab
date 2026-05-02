# Lateral Movement with Ticket Forgery – SOC Monitoring and Response
This document demonstrates how a SOC team can monitor Active Directory credential abuse and Kerberos ticket forgery attacks, detect anomalies, and implement remediation and control measures.

Attack Simulation Summary

Golden Tickets allow an attacker to impersonate any domain user, including Domain Admins, by forging Kerberos TGTs offline using the KRBTGT hash.

Command Used: 

mimikatz.exe "kerberos::golden /user:Administrator /domain:dcorp.local /sid:S-1-5-21-XXXXXXXX /krbtgt:<KRBTGT_HASH> /ptt"


Splunk Detection Logs:

Detection Category: Golden Ticket Forgery

| Log Source | Event ID | Detection Indicator | Description |
|-----------|----------|--------------------|-------------|
| Security | 4769 | Service ticket request anomalies | Requests without prior TGT issuance |
| Security | 4624 | Logon Type 3 | Network logon using forged TGT |
| Security | 4672 | Privileged logon | Elevated privileges assigned unexpectedly |
| Security | 4770 | Ticket renewal | Abnormal ticket lifetimes |

SOC Investigation Actions
	•	Identify tickets with unusual lifetimes
	•	Review privileged logons without prior authentication
	•	Correlate access across multiple servers
	•	Trigger incident response if forged tickets detected

⸻

Remediation & Security Controls
	•	Rotate KRBTGT password twice
	•	Reduce Kerberos ticket lifetimes
	•	Implement Privileged Access Management (PAM)
	•	Monitor impossible privilege escalation patterns

⸻

MITRE ATT&CK Mapping
	•	T1098 – Account Manipulation
	•	T1078 – Valid Accounts
	•	T1558.001 – Kerberos Golden Ticket


Splunk Query (SPL):

index=wineventlog EventCode=4769 OR EventCode=4770
| search TicketOptions="0x40810000"
| table _time, ComputerName, User, TicketOptions, ServiceName