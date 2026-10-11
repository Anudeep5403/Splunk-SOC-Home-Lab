Splunk SOC Lab — Detection Rules

This document contains SPL searches developed in my home lab using Windows Security Event Logs and Sysmon telemetry forwarded to Splunk Enterprise.

1. Windows Failed Logon — Possible Brute Force

Purpose: Identify accounts with five or more failed logon attempts.

Data source: Windows Security Event ID 4625.

index=windows sourcetype=XmlWinEventLog:Security
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=4625
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| stats count by TargetUserName
| where count >= 5
| sort - count

Investigation: Review the username, source IP, logon type, workstation, and timestamps. Repeated failures are suspicious but do not prove compromise.

2. Suspicious PowerShell — Execution Policy Bypass

Purpose: Find PowerShell process creation events whose command lines contain ExecutionPolicy Bypass.

Data source: Sysmon Event ID 1 — Process Creation.

index=sysmon
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| where like(Image,"%powershell.exe")
| where like(CommandLine,"%ExecutionPolicy Bypass%")
| table _time Image CommandLine
| sort - _time

Investigation: Examine the full command line, parent process, user, and surrounding events. Execution policy bypass alone does not establish malicious activity.

3. Suspicious Script File Created in Temp

Purpose: Find script files created in temporary directories.

Data source: Sysmon Event ID 11 — File Creation.

index=sysmon
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=11
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='TargetFilename'>(?<TargetFilename>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| where like(TargetFilename,"%SOC_Lab_Suspicious.ps1")
| table _time User Image TargetFilename
| sort - _time

Lab validation: A controlled test script named SOC_Lab_Suspicious.ps1 was observed in the user's temporary directory.

Note: This query searches for the specific test filename. Broader temporary-directory detections require appropriate filtering and tuning.

4. PowerShell Network Connection — Non-Standard Port

Purpose: Identify initiated PowerShell network connections to ports other than 443, 80, and 9997.

Data source: Sysmon Event ID 3 — Network Connection.

index=sysmon
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=3
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIp>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>\d+)</Data>"
| rex field=_raw "<Data Name='Initiated'>(?<Initiated>[^<]+)</Data>"
| where like(Image,"%powershell.exe")
| where Initiated="true"
| where DestinationPort!="443" AND DestinationPort!="80" AND DestinationPort!="9997"
| table _time Image DestinationIp DestinationPort Initiated
| sort - _time

Lab validation: A PowerShell connection to 1.1.1.1:8080 was observed during testing. This is a test observation, not proof of malicious communication.

Investigation: Verify the destination, port, process command line, initiating user, and whether the connection was expected.

5. General Process Creation Review

Purpose: Review process creation activity and identify command interpreters for further investigation.

Data source: Sysmon Event ID 1.

index=sysmon
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| where like(Image,"%powershell.exe") OR like(Image,"%cmd.exe") OR like(Image,"%wscript.exe") OR like(Image,"%cscript.exe")
| where NOT like(Image,"%SplunkUniversalForwarder%")
| where NOT like(ParentImage,"%SplunkUniversalForwarder%")
| table _time Image ParentImage CommandLine
| sort - _time
| head 30

Alert Inventory

Alert

Purpose

Windows Failed Login - Possible Brute Force

Repeated failed logons

Suspicious PowerShell - Execution Policy Bypass

PowerShell using execution policy bypass

Suspicious Script File Created in Temp

Script file activity in temporary directories

PowerShell Network Connection - Non-Standard Port

PowerShell network connections on selected non-standard ports

Notes and Limitations

These searches use rex to extract fields from raw XML events.

The lab uses a Windows 10 virtual machine and Splunk Enterprise on a Windows 11 host.

Alert thresholds and exclusions are initial lab settings and should be tuned for the environment.

A detection result is an investigation lead, not a verdict. Validate findings with related telemetry before drawing conclusions.
