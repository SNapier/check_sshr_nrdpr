#!/usr/bin/env python3
import sys
from sys import argv
from subprocess import Popen
from subprocess import PIPE
import argparse

argument_parser = argparse.ArgumentParser()

argument_parser.add_argument( '-H',
                     '--host',
                     required=True,
                     type=str,
                     help='The host you wish to run a plugin against.')

argument_parser.add_argument( '-u',
                     '--user',
                     required=True,
                     type=str,
                     help='Username for connecting to the remote system.')


argument_parser.add_argument( '-a',
                     '--args',
                     required=False,
                     type=str,
                     help='Arguments to be sent to the plugin. e.g. -warning 80 -critical 90'
)

arguments = argument_parser.parse_args(argv[1:])
plugin_code = """

<#
.NAME
sshr_nrdpr.ps1
.VERSION
1.0.0
.DESCRIPTION
A PowerShell based plugin for NagiosXI to be executed via the Nagios Enterprises Windows_SSH Python3 Wrapper.
.SYNOPSIS
This Plugin, executed via SSH, gathers and evaluates multiple metrics and then submits the results to NagiosXI via NRDP with a single execution;
1. CPU Utilization percent
2. Memory Usage Percent
3 .Disk Usage Percent
4. Windows Service Status
.NOTES
This plugin will return performance data for all but Service Status.
Thresholds violations result when a metric value is "equal to or greater than" the threshold provided.
E.g. -warning 10 will need the number of files to be equal to 10 or higher to throw a WARNING.
.PARAMETER nrdpurl
The address of the server receiving NRDP signals
.PARAMETER nrdptoken
The configured Nagios NRDP token.
.PARAMETER cpuwarn
The CPU utilization you will tolerate before throwing a WARNING
.PARAMETER cpucrit
The CPU utilization you will tolerate before throwing a CRITICAL
.PARAMETER memwarn
The Memory utilization you will tolerate before throwing a WARNING
.PARAMETER memcrit
The Memory utilization you will tolerate before throwing a CRITICAL
.PARAMETER diskwarn
The Disk utilization you will tolerate before throwing a WARNING
.PARAMETER diskcrit
The Disk utilization you will tolerate before throwing a CRITICAL
.PARAMETER service
The double quote encapsulated comma seperated list of services to monitor
.PARAMETER servicecrit
The state of the service to match when throwing a CRITICAL
e.g. Spooler = Stopped = CRITICAL  
.EXAMPLE
PS> .\sshr_nrdpr.ps1 -myhost "the.host.fqdn" -nrdpurl "192.168.1.138/nrdp" -nrdptoken "mytoken" -cpuwarn 80 -cpucrit 90 -memwarn 80 -memcrit 90 -diskwarn 80 -diskcrit 90 -services 'spooler' -servicecrit stopped
#>

#SCRIPT INPUT
param(
    [Parameter(Mandatory=$true)][string]$nrdpurl,
    [Parameter(Mandatory=$true)][string]$nrdptoken,
    [Parameter(Mandatory=$false)][string]$myhost,
    [Parameter(Mandatory=$true)][int]$cpuwarn,
    [Parameter(Mandatory=$true)][int]$cpucrit,
    [Parameter(Mandatory=$true)][int]$memwarn,
    [Parameter(Mandatory=$true)][int]$memcrit,
    [Parameter(Mandatory=$true)][int]$diskwarn,
    [Parameter(Mandatory=$true)][int]$diskcrit,
    [Parameter(Mandatory=$false)][string]$services,
    [Parameter(Mandatory=$false)][string]$servicecrit
)

#SET HOSTNAME TO BE VALUE OTHER THAN SENT BY NAGIOS HOSTNAME
#$myHost = $env:COMPUTERNAME.ToLower()

#SET HOSTNAME TO LOWER
$myhost = $myhost.ToLower()

#SANITY VARS
$response = "Nothing changed the status output!"
$exitcode = 3

#HOST CHECK
function host_check{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $naghostname
    )

    #HOST CHECK OUT
    $hostServiceState = 0
    $hostDisplayState = "OK"
    $hostCheckMsg = 'SSHR-NRDP Response, '+$($myHost)+' is up!'

    #NAGIOS HOST CHECK JSON
    $hostcheck = '{"checkresult": {"type": "host","checktype": "1"},"hostname": "'+$($naghostname)+'","state": "'+$($hostServiceState)+'","output":"'+$($hostDisplayState)+': '+$($hostCheckMsg)+'"}'

    #RETRUN HOST CHECK
    return $hostcheck
}

#CHECK MEMORY
function check_memory{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]
        $myhost,
        [Parameter(Mandatory=$True)]
        [int]
        $mwarning,
        [Parameter(Mandatory=$True)]
        [int]
        $mcritical
    )
    
    #GET TOTAL MEM
    $totalmem = (get-WMIObject win32_operatingsystem -computername $myhost | Measure-Object TotalVisibleMemorySize -sum).sum / 1024
    $totalmem = [math]::Round($totalmem,2)
    
    #GET FREE MEM
    $freemem = ((get-WMIObject -computername $myhost -class win32_operatingsystem).freephysicalmemory) / 1024
    $freemem = [math]::Round($freemem,2)
    
    #GET USED MEM
    $used = [math]::Round(($totalmem - $freemem),2)
    $usedpercent = [math]::Round(($used / $totalmem ) * 100,2)
    
    #EVALUATE WARNING AND CRITICAL
    if ($usedpercent -ge $mcritical) {
        #STATEID
        $mem_check_state_id = 2
        #STATE
        $mem_check_msg = "CRITICAL"
    }
    elseif (($usedpercent -ge $mwarning) -and ($usedpercent -lt $mcritical)) {
        #STATEID
        $mem_check_state_id = 1
        #STATE
        $mem_check_state = "WARNING"
    }
    else {
        #STATEID
        $mem_check_state_id = 0
        #STATE
        $mem_check_state = "OK"
    }

    #MESSAGE
    $mem_check_msg = "$($mem_check_state): Used memory is $($usedpercent)%. | totalMem=$($totalmem)MB; usedMem=$($used)MB;"

    #CHECK RESULT
    $mem_check = '{"checkresult": {"type": "service","checktype": "1"},"hostname": "'+$($myhost)+'", "servicename":"SSHR_NRDPR check_memory", "state":"'+$($mem_check_state_id)+'", "output":"'+$($mem_check_msg)+'"}'

    #RETURN CHECK
    return $mem_check
}

#CPU CHECK
function check_cpu_utilization{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        $cpuval,
        [Parameter(Mandatory=$true)]
        [int]
        $cpuwrn,
        [Parameter(Mandatory=$true)]
        [int]
        $cpucrt
    )

    if ($cpuval -ge $cpucrt) {
        #STATEID
        $cpu_check_state_id = 2
        #STATE
        $cpu_check_state = "CRITICAL"
    }
    elseif (($cpuval -ge $cpuwrn) -and ($cpuval -lt $cpucrt)) {
        #STATEID
        $cpu_check_state_id = 1
        #STATE
        $cpu_check_state = "WARNING"
    }
    else {
        #STATEID
        $cpu_check_state_id = 0
        #STATE
        $cpu_check_state = "OK"
    }

    #MESSAGE
    $cpu_check_msg = "$($cpu_check_state): \\Processor(_Total)\\% Processor Time is $($cpuval)%. | totalProcessorTime=$($cpuval)%;$($cpuwrn);$($cpucrt);"

    #CHECK RESULT
    $cpu_check = '{"checkresult": {"type": "service","checktype": "1"},"hostname": "'+$($myhost)+'", "servicename":"SSHR_NRDPR check_cpu", "state":"'+$($cpu_check_state_id)+'", "output":"'+$($cpu_check_msg)+'"}' 

    #SHIP IT
    return $cpu_check
}

#WINDOWS SERVICE CHECK (LIST)
function check_service_state{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][alias("service")][string]$svcs,
        [Parameter(Mandatory=$true)][alias("crit")][string]$critstate,
        [Parameter(Mandatory=$false)][alias("type")][string]$qtype = "l"
    )

    #BUILD AN ARRAY FOR SERIVCES
    $services = @()
    
    #PROCESS EXTENDED OPTIONS
    #LIST
    if($qtype -eq "l"){
        ##SPLIT THE INPUT INTO AN ARRAY
        $mylist = $svcs.Split(',')
        [array]::Reverse($mylist)
        
        ##LOOP THROUGH THE ARRAY
        foreach($s in $mylist){
            #QUERY FOR SERICE/S IN A LIST WITH EXACT MARCH
            $services += Get-Service | Where-Object{$_.Name -like "$($s)"}
        }
    }
    #WILDCARD MATCH
    elseif($qtype -eq "m"){
        ##QUERY FOR SERICE/S MATCHING WITH WILDCARD
        $services = Get-Service | Where-Object{$_.Name -like "$($svcs)*"}
    }
    #DEAFULT IS EXACT MATCH
    else{
        ##QUERY FOR SERICE/S EXACT MATCH
        $services = Get-Service | Where-Object{$_.Name -like "$($svcs)"}
    }
    
    #COUNTS
    $total = 0
    $critCount = 0
    
    #OUTPUT STRINGS
    $msg = ""
    $out = ""

    #SERVICE STATE EVALUATION
    foreach($svc in $services){
        if($svc.status -eq $critstate){
            #APPEND CRITICAL COUNT
            $critCount ++
        }
        
        #APPEND OUTPUT TO SUPPORT MULTIPLE FOUND SERVICES
        if($total -eq 0){
            $msg += "$($svc.name) is $($svc.status)"    
        }else{
            $msg += ", $($svc.name) is $($svc.status)"
        }
        
        #INCREMENT COUNT
        $total ++;
    }
    
    #SERVICE STATE EVALUATION WITH STANDARD NAGIOS OUTPUT
    ##CRITICAL
    if($total -gt 0 -and $critCount -gt 0){
        $service_check_state = "CRITICAL"
        $service_check_state_id = "2"
        $out = "$($service_check_state):$($msg)"
    ##OK
    }elseif($total -gt 0 -and $critCount -eq 0){
        $service_check_state = "OK"
        $service_check_state_id = "0"
        $out = "$($service_check_state):$($msg)"
    ##UNKNOWN
    }else{
        $service_check_state_id = "3"
        $out = "UNKNOWN:Service/s name like ($($svcs)) not found."
    }

    #MESSAGE
    $service_check_msg = "$($service_check_state): $($out)"

    #CHECK RESULT
    $service_check = '{"checkresult": {"type": "service","checktype": "1"},"hostname": "'+$($myhost)+'", "servicename":"SSHR_NRDPR check_servicestate", "state":"'+$($service_check_state_id)+'", "output":"'+$($service_check_msg)+'"}' 

    #SHIP IT
    return $service_check

}

#DISK USAGE
function check_disk_usage{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [int]
        $dskwarn,
        [Parameter(Mandatory=$true)]
        [int]
        $dskcrit
    )
    
    #GET DISK METRICS
    $disks = @()
    $disks += (Get-WmiObject win32_logicalDisk -Filter "DriveType=3")

    #EVALUATE DISK METRICS
    $critCount = 0
    $warnCount = 0
    $out = ""

    foreach($disk in $disks){
        #GET RID OF THE COLON FOR NAGIOS DISPLAY
        $diskid = $disk.DeviceID -replace ":",""
        
        #SIZE
        $capacity = [math]::Round($disk.Size / 1024 / 1024 / 1024)

        #USED
        $used = ($disk.Size - $disk.FreeSpace)
        $usedPercent = [math]::Round(($used / $disk.Size) * 100, 2)
        $used = [math]::Round($used / 1024 / 1024 / 1024)
        
        #CHECK MESSAGE
        $out += "Disk-$($diskid)-Used=$($usedPercent)%"
        $perfdata += "diskid-$($diskid)-used-percent=$($usedPercent)%;$($dskwarn);$($dskcrit); diskid-$($diskid)-capacity=$($capacity)GB;"

        #EVALUATE METRICS
        if($usedPercent -ge $dskcrit){
            $critCount += 1
        }
        elseif($usedPercent -lt $diskcrit -and $usedPercent -ge $diskwarn){
            $warnCount += 1
        }
    }

    if($critCount -gt 0){
        $check_disk_state_id = 2
        $check_disk_state = "CRITICAL"
    }
    elseif($critCount -eq 0 -and $warnCount -gt 0){
        $check_disk_state_id = 1
        $check_disk_state = "WARNING"
    }
    else{
        $check_disk_state_id = 0
        $check_disk_state = "OK"
    }

    #MESSAGE
    $check_disk_msg = "$($check_disk_state): $($out) | $($perfdata)"

    #CHECK RESULT
    $disk_check = '{"checkresult": {"type": "service","checktype": "1"},"hostname": "'+$($myhost)+'", "servicename":"SSHR_NRDPR check_disk_usage", "state":"'+$($check_disk_state_id)+'", "output":"'+$($check_disk_msg)+'"}' 

    #SHIP IT
    return $disk_check

}

#GENERIC FUNCTION TO GET COUNTER DATA
function get_windows_counter{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $counterName
    )

    #METRIC
    $counterData = (Get-Counter -Counter "$counterName" -SampleInterval 1 -MaxSamples 1).CounterSamples.CookedValue

    if(!$counterData){
        $counterData = 0
    }

    #FORMAT
    $metricData = [math]::Round($counterData,2)

    #SHIP IT
    return $metricData
}

#SEND NRDP JSON
function submit_nrdp_response{
    #PARAMS
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $hostchk,
        [Parameter(Mandatory=$true)]
        [string]
        $cpuchk,
        [Parameter(Mandatory=$true)]
        [string]
        $memchk,
        [Parameter(Mandatory=$true)]
        [string]
        $dskchk,
        [Parameter(Mandatory=$true)]
        [string]
        $svcchk,
        [Parameter(Mandatory=$true)]
        [string]
        $nrdp,
        [Parameter(Mandatory=$true)]
        [string]
        $token
    )

    # ----------------------------------
    # HOSTCHECK AND JSONDATA
    # ----------------------------------

    $jsondata_open = 'JSONDATA={"checkresults":['
    $jsondata_close = ']}'
    
    #JSON PAYLOAD
    $jsond = "$($jsondata_open) $($hostchk),$($cpuchk),$($memchk),$($dskchk),$($svcchk) $($jsondata_close)"

    #POST TO NRDP
    $post = @()
    $post += @(Invoke-WebRequest -UseBasicParsing "$($nrdpurl)?token=$($token)&cmd=submitcheck&$($jsond)" -Contenttype "application/json" -Method POST)

    #POST RESULTS
    return $post
}

#-------------------------------------------------------------------
#GET HOST CHECK DATA
#-------------------------------------------------------------------
$hostcheck = host_check -naghostname $myhost

#-------------------------------------------------------------------
#GET MEM CHECK DATA
#-------------------------------------------------------------------
$memorycheck = check_memory -myhost $myhost -mwarning $memwarn -mcritical $memcrit

#-------------------------------------------------------------------
#GET CPU UTILIZATION
#-------------------------------------------------------------------
$cpumetric = (get_windows_counter -counterName '\Processor(_Total)\% User Time')
$cpucheck = check_cpu_utilization -cpuval $cpumetric -cpuwrn $cpuwarn -cpucrt $cpucrit

#-------------------------------------------------------------------
#GET DISK CHECK DATA
#-------------------------------------------------------------------
$diskcheck = check_disk_usage -dskwarn $diskwarn -dskcrit $diskcrit

#-------------------------------------------------------------------
#GET SERVICE STATE
#-------------------------------------------------------------------
$servicecheck = check_service_state -svcs $services -critstate $servicecrit

#-------------------------------------------------------------------
# SEND NRDP JSON
#-------------------------------------------------------------------
$response = submit_nrdp_response -nrdp $nrdpurl -token $nrdptoken -hostchk $hostcheck -cpuchk $cpucheck -memchk $memorycheck -svcchk $servicecheck -dskchk $diskcheck
$exit = $response | convertfrom-json

#IF EXIT STATE IS -1 THE POST FAILED AND WE WILL EXIT WITH STATE_ID=2/CRITICAL FOR NAGIOS
if($exit.result.status -ne 0){
    $exitcode = 2
}
else{
    $exitcode = $exit.result.status 
}

#TRAP "BAD TOKEN" AND POPULATE EMPTY MESSAGE
if($exit.result.message -eq "BAD TOKEN"){
    $nagiosout = "$($exit.result.message): Validate that the token and the check command are properly configured."    
}
#TRAP BAD JSON AND POPULATE EMPTY MESSAGE
elseif($exit.result.message -eq "BAD JSON"){
    $nagiosout = "$($exit.result.message): NRDP JSON Payload is improperly formatted."
}
else{
    $nagiosout = "$($exit.result.message): $($exit.result.meta.output)"
}

#-------------------------------------------------------------------
#NAGIOS EXIT WITH NRDP RESPONSE
#-------------------------------------------------------------------
write-host "$nagiosout,$exitcode"

#-------------------------------------------------------------------
#SYSTEM EXIT (USE LAST EXIT CODE)
#-------------------------------------------------------------------
exit $exitcode

"""

echo_process = ""
arguments_length = 0
if arguments.args is not None:
    echo_process = Popen(["echo", "function checkplugin {\n", plugin_code, " }\n", "checkplugin ", arguments.args, "\n"], stdout=PIPE)
    arguments_length = len(arguments.args) + 1
else:
    echo_process = Popen(["echo", "function checkplugin {\n", plugin_code, " }\n", "checkplugin  \n"], stdout=PIPE)

ssh_process = Popen(["ssh", "-T", "-l", arguments.user, arguments.host, "powershell.exe"], stdin=echo_process.stdout, stdout=PIPE)
echo_process.stdout.close()
process_output = [ssh_process.communicate(), ssh_process.returncode]

decoded_stdout = process_output[0][0].decode()

if(process_output[1] == 255):
    print("CRITICAL: Connection to host failed. Check that the nagios user can passwordlessly connect to the host.")
    sys.exit(2)     

output_substring = decoded_stdout[(decoded_stdout.find("checkplugin  ") + 18 + arguments_length):(len(decoded_stdout) - 1)].rstrip()
split_output_substring = output_substring.split(',')

exit_status_code = int(split_output_substring[-1])
exit_message = ','.join(split_output_substring[:-1]) 
print(exit_message)
sys.exit(exit_status_code)