Splunk SOC Home Lab

A hands-on Security Operations Center (SOC) lab built with Splunk Enterprise, Windows Security Event Logs, and Sysmon to practice security monitoring, threat detection, alerting, and incident investigation.

Project Overview

This project simulates selected SOC analyst workflows in a controlled virtual lab. Windows telemetry is collected using Splunk Universal Forwarder and analyzed in Splunk Enterprise using SPL searches, scheduled alerts, and dashboards.

Lab Architecture

Windows 10 Lab VM
       |
       | Windows Event Logs + Sysmon
       v
Splunk Universal Forwarder
       |
       | TCP 9997
       v
Splunk Enterprise (Windows 11 Host)
       |
       +-- Windows Security Analysis
       +-- Sysmon Process Monitoring
       +-- Detection Searches and Alerts
       +-- SOC Home Lab Dashboard
       +-- Incident Investigation

Technologies Used

Splunk Enterprise

Splunk Universal Forwarder

Windows 10 virtual machine

Windows Security Event Logs

Microsoft Sysmon

SPL (Search Processing Language)

VirtualBox

Windows PowerShell

Detection Use Cases

Detection

Data source

Objective

Repeated failed logons

Windows Event ID 4625

Identify accounts with repeated authentication failures

PowerShell execution policy bypass

Sysmon Event ID 1

Investigate potentially suspicious PowerShell execution

Script files in temporary locations

Sysmon Event ID 11

Identify script-file activity for investigation

PowerShell network connections on unusual ports

Sysmon Event ID 3

Investigate unexpected network connections

Process creation review

Sysmon Event ID 1

Review command interpreters, parent processes, and command lines

Alerts

The lab includes scheduled Splunk alerts for:

Windows Failed Login - Possible Brute Force

Suspicious PowerShell - Execution Policy Bypass

Suspicious Script File Created in Temp

PowerShell Network Connection - Non-Standard Port

Detection results require investigation and do not independently prove malicious activity.

Dashboard

The SOC Home Lab Dashboard brings together:

Windows failed logon trends

PowerShell execution policy bypass events

Suspicious script-file activity

PowerShell network connections on unusual ports

Documentation

Incident Report

Dashboard Guide

Splunk Detection Rules

Example Investigation

During controlled testing, repeated failed logon attempts against a test account generated Windows Event ID 4625 records. Splunk searches were used to count failures, identify the account, and examine timestamps, logon type, workstation, and source address.

Additional controlled tests generated Sysmon process creation, script-file, and network connection telemetry to validate the corresponding searches.

Security and Scope

This project uses a controlled home lab and test activity. It does not represent a production SOC deployment or prove that a real environment was compromised. Detection thresholds and filters are initial lab settings and may require tuning.

Skills Demonstrated

Windows event log analysis

SIEM monitoring with Splunk

SPL searches and field extraction using rex

Security detection engineering

Scheduled alert configuration

Sysmon telemetry analysis

Incident investigation and documentation

SOC dashboard development

Future Improvements

Improve Windows event field extraction using the appropriate Splunk add-on

Tune detections to reduce false positives

Add more event correlation and investigation scenarios

Export sanitized dashboard and alert configurations

Document additional detection tests and results
