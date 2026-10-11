Splunk SOC Home Lab

A hands-on Security Operations Center (SOC) lab built with Splunk Enterprise, Windows Security Event Logs, and Sysmon to practice security monitoring, threat detection, alerting, and incident investigation.

Project Overview

This project simulates selected SOC analyst workflows in a controlled virtual lab. Windows telemetry is collected using Splunk Universal Forwarder and analyzed in Splunk Enterprise using Search Processing Language (SPL), scheduled alerts, and dashboards.

Lab Architecture

Endpoint: Windows 10 virtual machine

Telemetry: Windows Security, System, Application, and Sysmon events

Log collection: Splunk Universal Forwarder

SIEM: Splunk Enterprise on the Windows host

Data forwarding: TCP port 9997 over a host-only lab network

Detections and Investigations

Repeated Windows failed logon attempts (Event ID 4625)

PowerShell execution using -ExecutionPolicy Bypass

Suspicious PowerShell process execution

Script files created in temporary directories

PowerShell network connections to unusual ports

Detection results are leads for investigation, not proof of malicious activity. Lab-generated events were used for testing.

Dashboard

The SOC Home Lab Dashboard presents failed-logon trends, PowerShell activity, suspicious script-file events, and unusual network connections.

Technologies Used

Splunk Enterprise and SPL

Splunk Universal Forwarder

Windows Event Logs

Sysmon

Windows 10 and VirtualBox

Detection engineering and incident investigation

Project Evidence

SOC Home Lab Screenshots

Splunk Dashboard PDF

Detection Rules

Incident Report

Dashboard Guide
