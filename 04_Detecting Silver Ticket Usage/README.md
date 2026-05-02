# Lateral Movement with Ticket Forgery – SOC Monitoring and Response
This document demonstrates how a SOC team can monitor Active Directory credential abuse and Kerberos ticket forgery attacks, detect anomalies, and implement remediation and control measures.

Attack Simulation Summary

Silver Tickets forge service tickets using a service account hash. Authentication occurs directly with the service; the DC is not involved, making detection challenging.

Command Used:

mimikatz.exe "kerberos::golden /domain:dcorp.local /sid:S-1-5-21-XXXXXXXX /target:dcorp-server.dcorp.local /service:cifs /rc4:<SERVICE_HASH> /user:Administrator /ptt"

Splunk Detection Logs:

Detection Category: Silver Ticket Forgery

| Log Source | Event ID | Detection Indicator | Description |
|-----------|----------|--------------------|-------------|
| Security | 4624 | Logon Type 3 | Network logon to service |
| Security | 5140 | Network share access | Access to CIFS share |
| Security | 4672 | Privileged logon | Privileged access to service |



SOC Investigation Actions
	•	Review service log access
	•	Correlate with Kerberos authentication patterns
	•	Investigate accounts accessing services without TGT issuance

⸻

Remediation & Security Controls
	•	Rotate service account passwords regularly
	•	Implement gMSAs
	•	Restrict admin privileges on service hosts

⸻

MITRE ATT&CK Mapping
	•	T1558.002 – Kerberos Service Ticket (Silver)
	•	T1078 – Valid Accounts


Splunk Query (SPL): 

index=wineventlog EventCode=4624 OR EventCode=5140
| search ServiceName="cifs"
| table _time, ComputerName, User, ServiceName, ShareName