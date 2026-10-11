Incident Report: Windows Failed Logon Investigation

1. Overview

Project: Splunk SOC Home Lab
Platform: Splunk Enterprise on Windows 11
Log Source: Windows Security Event Logs
Data Collection: Splunk Universal Forwarder
Detection Type: Repeated Failed Logon Attempts

2. Objective

Detect repeated failed Windows logon attempts, investigate the affected account, review event details, and document the findings using Splunk Search Processing Language (SPL).

3. Detection Logic

Windows Security Event ID 4625 indicates a failed logon attempt.

The detection searches for repeated failed logons associated with the same username and flags accounts with five or more failures.

index=windows sourcetype=XmlWinEventLog:Security
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=4625
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| stats count by TargetUserName
| where count >= 5
| sort - count

4. Investigation Findings

During controlled lab testing, multiple failed logon attempts were generated against a test account named fakeuser.

Field

Observation

Event ID

4625

Target account

fakeuser

Failed attempts observed

20

Source IP

::1

Logon type

2 — Interactive

Workstation

DESKTOP-V423OIB

Observed duration

Approximately 3 minutes 48 seconds

The source IP ::1 is the IPv6 loopback address, indicating a local connection. The activity was generated during lab testing and is not evidence of an actual external attack.

5. Alert Configuration

Alert name: Windows Failed Login - Possible Brute Force

Condition: Five or more failed logons for the same username.

Severity: Medium.

Schedule: Every five minutes.

Trigger condition: Number of results greater than zero.

Action: Add to Triggered Alerts.

6. Investigation and Response

Identify accounts with repeated failed logons.

Review timestamps, source IP addresses, logon types, and workstation details.

Correlate activity with other Windows and Sysmon events.

Determine whether the activity is expected, accidental, or suspicious.

Escalate or contain the activity only when supported by investigation findings.

7. Limitations

This is a controlled home lab. The detection threshold is a starting point and may require tuning to reduce false positives. Failed logons alone do not prove a successful compromise.

8. Skills Demonstrated

Windows Security Event Log analysis

Splunk SPL searches and field extraction using rex

Failed logon detection

Scheduled alert configuration

Event timeline investigation

Security incident documentation

9. Next Steps

Analyze Sysmon process creation and network connection events.

Develop PowerShell and suspicious script-file detections.

Correlate alerts and investigations in the SOC Home Lab Dashboard.

Document additional detections and their limitations.
