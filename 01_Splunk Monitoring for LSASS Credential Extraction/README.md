# Lateral Movement with Ticket Forgery – SOC Monitoring and Response
This document demonstrates how a SOC team can monitor Active Directory credential abuse and Kerberos ticket forgery attacks, detect anomalies, and implement remediation and control measures.

Attack Simulation Summary

Credential extraction was simulated using SafetyKatz, an in-memory Mimikatz variant, targeting LSASS to extract cached credentials from logged-on users and service accounts. Remote execution was done via WinRM.


Command Used:

" SafetyKatz.exe "sekurlsa::logonpasswords exit" "


Detection Category: Credential Dumping / LSASS Access

| Log Source | Event ID | Detection Indicator | Description |
|-----------|----------|--------------------|-------------|
| Security | 4688 | Suspicious process creation | Execution of SafetyKatz or Mimikatz binaries |
| Sysmon | 10 | Process accessing LSASS memory | Unauthorized memory access of lsass.exe |
| Security | 4624 | Logon Type 3 / 10 | Remote WinRM authentication prior to credential dump |
| Sysmon | 1 | Process creation | Execution of unsigned or unusual binaries | 



SOC Investigation Actions
	1.	Identify parent process spawning the suspicious binary.
	2.	Confirm whether binary hash matches known credential dumping tools.
	3.	Investigate user account and logon source from Event ID 4624.
	4.	Track lateral movement patterns after credential dumping.
	5.	Isolate host if compromise confirmed.


Remediation & Security Controls
	•	Enable LSASS protection (RunAsPPL)
	•	Deploy EDR with memory protection
	•	Restrict WinRM access to admins only
	•	Enable Credential Guard
	•	Monitor unauthorized LSASS access attempts


MITRE ATT&CK Mapping
	•	T1003 – Credential Dumping
	•	T1078 – Valid Accounts


Splunk Query (SPL)


index=wineventlog EventCode=4688 OR 
EventCode=10
| search Image="*mimikatz*" OR Image="*safetykatz*"
| table _time, ComputerName, User, Image, CommandLine