# Lateral Movement with Ticket Forgery – SOC Monitoring and Response
This document demonstrates how a SOC team can monitor Active Directory credential abuse and Kerberos ticket forgery attacks, detect anomalies, and implement remediation and control measures.

Attack Simulation Summary

Diamond Tickets blend legitimate TGT requests with offline ticket manipulation, creating tickets that appear valid. This makes them more OPSEC safe than Golden Tickets and harder to detect.


Command Used: 

 Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /krbkey:<KRBTGT_AES256> /domain:dcorp.local /dc:dcorp-dc.dcorp.local /ptt

 
Splunk Detection Logs:

Detection Category: Diamond Ticket Forgery

| Log Source | Event ID | Detection Indicator | Description |
|-----------|----------|--------------------|-------------|
| Security | 4768 | Kerberos TGT request | Legitimate request from unusual host |
| Security | 4769 | Service ticket request | Abnormal service access |
| Security | 4624 | Logon Type 3 | Network logon using forged ticket |
| Security | 4672 | Privileged logon | Elevated privileges assigned unexpectedly |


SOC Investigation Actions
	•	Identify TGT requests from abnormal hosts
	•	Review privilege escalation following standard user authentication
	•	Correlate TGT issuance with service access patterns

⸻

Remediation & Security Controls
	•	Rotate KRBTGT password if compromised
	•	Restrict delegation privileges
	•	Implement privileged account monitoring
	•	Monitor Kerberos anomalies

⸻

MITRE ATT&CK Mapping
	•	T1558.003 – Kerberos Diamond Ticket
	•	T1078 – Valid Accounts
	•	T1098 – Account Manipulation


Splunk Query (SPL):

index=wineventlog EventCode=4768 OR EventCode=4769
| search TicketOptions="0x40810000" OR TicketOptions="0x40000000"
| table _time, ComputerName, User, TicketOptions, ServiceName