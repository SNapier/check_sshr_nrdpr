# check_sshr_nrdpr
Agentless monitoring plugin for NagiosXI that uses a single Windows_SSH service to request Windows LCD Metrics (CPU Utilization, Memory Utilization, Disk Utilization) and Service Status that are returned individually to NagiosXI via NRDP.

## .NAME
check_sshr_nrdpr.ps1.py

### .DESCRIPTION
A PowerShell based plugin for NagiosXI to be executed via the Nagios Enterprises Windows_SSH Python3 Wrapper.

### .VERSION
1.0.0

### .SYNOPSIS
This Plugin, executed via SSH, gathers and evaluates multiple metrics and then submits the results to NagiosXI via NRDP with a single execution;
- CPU Utilization percent
- Memory Usage Percent
- Disk Usage Percent
- Windows Service Status

### .NOTES
- This plugin will return performance data for all but Service Status.
- Thresholds violations result when a metric value is "equal to or greater than" the threshold provided.
  - E.g. -warning 10 will need the number of files to be equal to 10 or higher to throw a WARNING.

### .PARAMETERS
-myhost
  - The hostaddress configured in NagiosXI used in the NRDP response.
- nrdpurl
  - The address of the server receiving NRDP signals
- nrdptoken
  - The configured Nagios NRDP token.
- cpuwarn
  - The CPU utilization you will tolerate before throwing a WARNING
- cpucrit
  - The CPU utilization you will tolerate before throwing a CRITICAL
- memwarn
  - The Memory utilization you will tolerate before throwing a WARNING
- memcrit
  - The Memory utilization you will tolerate before throwing a CRITICAL
- diskwarn
  - The Disk utilization you will tolerate before throwing a WARNING
- diskcrit
  - The Disk utilization you will tolerate before throwing a CRITICAL
- service
  - The double quote encapsulated comma seperated list of services to monitor
- servicecrit
  - The state of the service to match when throwing a CRITICAL
  - e.g. Spooler = Stopped = CRITICAL  

### EMBEDED POWERSEHLL EXAMPLE
PS> .\check_sshr_nrdpr.ps1 -myhost "the.host.fqdn" -nrdpurl "192.168.1.138/nrdp" -nrdptoken "mytoken" -cpuwarn 80 -cpucrit 90 -memwarn 80 -memcrit 90 -diskwarn 80 -diskcrit 90 -services 'spooler' -servicecrit stopped
