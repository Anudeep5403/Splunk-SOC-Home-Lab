SOC Home Lab Dashboard Guide

Overview

The SOC Home Lab Dashboard provides a centralized view of Windows security events, Sysmon telemetry, and suspicious activity detected during controlled testing.

Platform: Splunk Enterprise
Data sources: Windows Security Event Logs and Sysmon Operational logs
Purpose: Security monitoring, detection validation, and investigation.

Dashboard Panels

1. Windows Failed Login Trend

Purpose: Visualize failed Windows logon activity over time.

Source: Windows Security Event ID 4625.

Displays event counts across time intervals.

Helps identify spikes in failed authentication attempts.

Supports investigation of repeated failures against individual accounts.

2. PowerShell Execution Policy Bypass

Purpose: Review PowerShell process creation events containing ExecutionPolicy Bypass.

Source: Sysmon Event ID 1.

Displays timestamps, executable paths, and command lines.

Helps analysts investigate potentially suspicious PowerShell execution.

Legitimate administrative activity may also trigger this detection.

3. Suspicious Script Files in Temp

Purpose: Review script-file activity in temporary directories.

Source: Sysmon Event ID 11.

Displays process image paths and target filenames.

Helps identify scripts that require further investigation.

Temporary script creation alone is not proof of malware.

4. PowerShell Network Connections — Unusual Ports

Purpose: Review initiated PowerShell network connections to ports outside the configured exclusions.

Source: Sysmon Event ID 3.

Displays timestamps, destination IP addresses, destination ports, and process paths.

Helps investigate unexpected outbound connections.

Non-standard ports can be used by legitimate software as well as malicious tools.

Investigation Workflow

Identify an unusual event or spike in a dashboard panel.

Open the corresponding Splunk search and inspect individual events.

Review the user, process image, parent process, command line, timestamps, and network details where available.

Correlate related Windows Security and Sysmon events.

Validate whether the activity is expected or suspicious.

Record evidence, conclusions, and recommended actions in an incident report.

Validation

The dashboard was populated with events from the home lab. Controlled tests included repeated failed logons, PowerShell commands using execution policy bypass, creation of a test script, and a PowerShell network connection to a non-standard port.

These tests demonstrate detection and investigation workflows. They do not establish that a real system was compromised.

Limitations

The dashboard uses lab telemetry rather than production enterprise data.

Some XML fields are extracted using SPL rex.

Detection filters and thresholds require tuning for different environments.

Analysts should validate alerts against contextual evidence before escalating incidents.

Skills Demonstrated

Splunk dashboard creation

SPL searches and event-field extraction

Windows and Sysmon log analysis

Detection validation

Alert investigation and triage

Security documentation
