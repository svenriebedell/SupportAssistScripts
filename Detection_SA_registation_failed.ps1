<#
_author_ = dell
_version_ = 1.0.2
_Dev_Status_ = Test
Copyright ©2025 Dell Inc. or its subsidiaries. All Rights Reserved.

No implied support and test in test environment/device before using in any production environment.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
#>

<#Version Changes

        1.0.0   inital version
        1.0.1   Correct output text and format of value registered time
        1.0.2   SupportAssist change Name to SupportAssist switch to file check and not app name to cover SA 4.5 and SA 4.9 installations

#>

<#
.Synopsis
   This PowerShell helping you to get a feedback of your client if Dell SupportAssist for Business is installed and registered correctly to Dell TechDirect
.DESCRIPTION
   Powershell to check if Dell SupportAssist for Business is installed and registered correctly to Dell TechDirect.

#>


#########################################################################################################
####                                    Function Section                                             ####
#########################################################################################################
function write-DellRemediationEvent
    {
        <#
        .Synopsis
        This function write Events to Microsoft Eventlog. Need adminrights for execution.

        .Description
        This function writes standardized information from Dell Detection and Remediation scripts to EventLog Application Logname Dell Source Remediation Scripts. This makes it possible to access the information historically later for monitoring or analysis.

        Event ID 0 - 3 for Main Script (0 - Success / 1 - Error / 2 - Information / 3 - Warning )
        Event ID 10 - 13 for feedback of functions (10 - Success / 11 - Error / 12 - Information / 13 - Warning )
        Event ID 20 - 23 for Software Installation  (20 - Success / 21 - Error / 22 - Information / 23 - Warning )

        .Parameter Logname
        Value is the Name of the Eventlog it will be later under Application and Service Logs Default Dell

        .Parameter Source
        Value is the Resource and will be visible in the Event for filter options Default is RemediationScript

        .Parameter EntryType
        Value is the type of a Event like Error, Information, FailureAudit, SuccessAudit, Warning

        .Parameter EventID
        Value is a number for this event for filter options, the values are predefined for categories like MainScript, Function and Software Installation

        .Parameter Message
        Value is a message that will be visible in Event, it could be a string or JSON or XML but only one message for each event.

        Changelog:
            1.0.0   Initial Version
            1.0.1   Delete Try and Catch for testing Logname/Ressource exit and change to allway add Logname/Ressource and if exist ignor error silten.
                    Correct issue all logs are warning
            1.0.2   change commannds to make function powershell 7 ready
            1.1.0   updating issue with logsize and adding new LogName and Source
            1.1.1   correct issue to size eventlog because sometime it change to existing value

        .Example
        # Write a Microsoft Event to Application and Service Logs for LogName Dell and Source RemediationScript with ID 2 for Information with the message body "Test message"
        write-DellRemediationEvent -Logname Dell -Source RemediationScript -EntryType Information -EventID '2-InformationScript' -Message "Test message"

        #>
        param
            (

                [Parameter(mandatory=$false)][ValidateSet('Dell','DellRemediation')]$Logname,
                [Parameter(mandatory=$false)][ValidateSet('RemediationScript','RemediationFunction','RemediationInstall','RemediationTranscript','SupportAssistDiagnostic')]$Source,
                [Parameter(mandatory=$false)][ValidateSet('Error', 'Information', 'FailureAudit', 'SuccessAudit', 'Warning')]$EntryType='Information',
                [Parameter(mandatory=$true)][ValidateSet('0-SuccessScript','1-ErrorScript','2-InformationScript','3-WarningScript','10-SuccessFunction','11-ErrorFunction','12-InformationFunction','13-WarningFunction','20-SuccessInstall','21-ErrorInstall','22-InformationInstall','23-WarningInstall')][String]$EventID,
                [Parameter(mandatory=$true)]$Message

            )
        #########################################################################################################
        ####                                    Variable Section                                             ####
        #########################################################################################################

        # Log Parameters
        [int64]$LogSize = 15420KB

        #########################################################################################################
        ####                                Function Program Section                                         ####
        #########################################################################################################
        # prepare the logname and ressource name
        $checkSource = [System.Diagnostics.EventLog]::SourceExists($source)
        if ($checkSource -ne $true)
            {
                try
                    {
                        [System.Diagnostics.EventLog]::CreateEventSource($source, $logName)
                        Write-Verbose "Event source '$source' created for log '$logName'." -Verbose
                    }
                catch
                    {
                        Write-Verbose "Event source '$source' fail to create for log '$logName'." -Verbose
                        return $false
                    }

            }
        else
            {
                Write-Verbose "Event source '$source' already exists." -Verbose
            }


        # Change the size of the event log if it is not $LogSize
        $EventLog = Get-WinEvent -ListLog $Logname
        if ($EventLog.MaximumSizeInBytes -lt $LogSize)
            {
                try
                    {
                        $EventLog.MaximumSizeInBytes = $LogSize
                        $EventLog.SaveChanges()
                        Write-Verbose "Event log '$Logname' size changed to $LogSize." -Verbose
                    }
                catch
                    {
                        Write-Verbose "Event log '$Logname' failed to change size to $LogSize." -Verbose
                        return $false
                    }
            }
        else
            {
                Write-Verbose "Event log '$Logname' is already $LogSize." -Verbose
            }

        # modify EventID to number only
        [int]$EventID = switch ($EventID)
                    {
                        '0-SuccessScript'             {0}
                        '1-ErrorScript'               {1}
                        '2-InformationScript'         {2}
                        '3-WarningScript'             {3}
                        '10-SuccessFunction'          {10}
                        '11-ErrorFunction'            {11}
                        '12-InformationFunction'      {12}
                        '13-WarningFunction'          {13}
                        '20-SuccessInstall'           {20}
                        '21-ErrorInstall'             {21}
                        '22-InformationInstall'       {22}
                        '23-WarningInstall'           {23}
                        Default {2}
                    }

        # Value validation if Entrytype match to EventID if not it change the Entrytype to the correct type

        if ($EventID -eq 0 -or $EventID -eq 10 -or $EventID -eq 20)
            {
                $EntryType = 'SuccessAudit'
            }
        if (($EventID -eq 1) -or ($EventID -eq 11) -or ($EventID -eq 21))
            {
                $EntryType = 'Error'
            }
        if (($EventID -eq 2) -or ($EventID -eq 12) -or ($EventID -eq 22))
            {
                $EntryType = 'Information'
            }
        if (($EventID -eq 3) -or ($EventID -eq 13) -or ($EventID -eq 23))
            {
                $EntryType = 'Warning'
            }

        try
            {
                # Initialize Eventlog for reporting and Debugging
                $evt=new-object System.Diagnostics.EventLog($logName)
                $evt.Source=$source

                #write event by .net
                $evt.WriteEntry($Message,$EntryType,$EventID)
                Write-Verbose "Eventlog is created successful" -Verbose
                Return $true
            }
        catch
            {
                Write-Verbose "Eventlog could not created" -Verbose
                Return $false
            }
    }

function Test-RegistryStatus
    {

            <#
            .Synopsis
            Return true or false if specific specific value is found or not in the device registry

            .Description
            This function searches for a specific path, key or keydata in device registry.

            Return:
            False means the registry key / path or keydata does not exist
            True means the registry key / path or keydata is exist

            Changelog:
                1.0.0 Initial Version
                1.0.1 feature to check if Path exist, Key exist or Key Data have a specific value

            .Parameter Path
            This is the registry path of the Registry Key

            .Parameter Key
            This is the Registry key Name you want to check

            .Parameter KeyData
            This is the registry path of the Registry Key

            .Parameter Check
            This is for chose the kind of test, if registry path exist or if a Key exist in this Reg Path or if a Key have a specific Keydata value.
            Option:
                Path: Check if a Path exist in the registry
                Key: Check if Key exist in the registry path
                KeyData: Check if a Key in the registry path have a defined Keydata value


            .Example
            # Show if the path HKLM:\SOFTWARE\DELL\UpdateService\Service is exist
            Test-RegistryStatus -Path HKLM:\SOFTWARE\DELL\UpdateService\Service -Check Path

            .Example
            # Show if the Key LastUpdateTimestamp is exist in path HKLM:\SOFTWARE\DELL\UpdateService\Service
            Test-RegistryStatus -Path HKLM:\SOFTWARE\DELL\UpdateService\Service -Check Key -KeyName LastUpdateTimestamp

            .Example
            # Show if keydata 2024-04-16T13:24:49 is exist in Key LastUpdateTimestamp on path HKLM:\SOFTWARE\DELL\UpdateService\Service
            Test-RegistryStatus -Path HKLM:\SOFTWARE\DELL\UpdateService\Service -Check KeyData -KeyName LastUpdateTimestamp -KeyData 2024-04-16T13:24:49

            #>

            param
                (

                [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()]$Path,
                [parameter(Mandatory=$false)] [ValidateNotNullOrEmpty()]$KeyName,
                [parameter(Mandatory=$false)] [ValidateNotNullOrEmpty()]$KeyData,
                [Parameter(mandatory=$true)][ValidateSet('Path','Key','KeyData')]$Check

                )

    try
        {

            If ($Check -eq "Path")
                {

                    #############################################
                    ####           Validation Path           ####
                    #############################################

                    try
                        {

                            Test-Path -Path $Path

                        }
                    Catch
                        {

                            return $false

                        }

                }

            If ($Check -eq "Key")
                {

                    #############################################
                    ####          Validation Reg Key         ####
                    #############################################

                    $PathExist = Test-Path -Path $Path

                    If($PathExist -eq $true)
                        {

                            try
                                {
                                    Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $KeyName -ErrorAction Stop | Out-Null
                                    return $true
                                }
                            catch
                                {
                                    return $false
                                }

                        }
                  else
                        {
                           Write-Output "$Path does not exist"
                        }

                }

            If ($Check -eq "KeyData")
                {

                    #############################################
                    ####     Validation Reg Key Value        ####
                    #############################################

                    $PathExist = Test-Path -Path $Path

                    If($PathExist -eq $true)
                        {

                            try
                                {
                                    Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $KeyName -ErrorAction Stop | Out-Null
                                    $KeyExist = $true

                                    If ($KeyExist -eq $true)
                                        {
                                            $ValueExist = Get-ItemPropertyValue -Path $Path -Name $KeyName

                                            If ($ValueExist -eq $KeyData)
                                                {
                                                    return $true
                                                }
                                            else
                                                {
                                                    return $false
                                                }
                                        }
                                }
                            catch
                                {
                                    Write-Output "Key $KeyName does not exist"
                                }

                        }
                  else
                        {
                           Write-Output "Path $Path does not exist"
                        }

                }
        }

    catch
        {

        return $false

        }

    }

#########################################################################################################
####                                    Variable Section                                             ####
#########################################################################################################

$SADiagnosticPath = $env:ProgramW6432 + "\Dell\SupportAssistAgent\bin\"
$SADiagnosticExe = "SelfDiagnosis.exe"
$SADiagnosticFull = $SADiagnosticPath + $SADiagnosticExe
$SAPath = "$env:ProgramFiles\Dell\SupportAssistAgent\bin\SupportAssistAgent.exe"

#########################################################################################################
####                                    Program Section                                              ####
#########################################################################################################

Write-Host "**************************************************************************************"
Write-Host "* Version: 1.0.2                                                                     *"
Write-Host "* File: Detection_SA_registration_failed.ps1                                         *"
Write-Host "**************************************************************************************"

try
    {
        # check if Dell SupportAssist for Business is installed
        Write-Output "Checking Windows Application install database for Dell SupportAssist for Business install"
        Write-Output "This will take a few minutes"
        $CheckInstall = Test-Path -Path $SAPath

        if ($null -ne $CheckInstall)
            {
                # get SA registry status
                $RegisterStatus = Get-CimInstance -Namespace root/SupportAssist -ClassName DSA_RegistrationInformation

                If ($RegisterStatus.IsRegistrationDone -eq $true)
                    {
                        Write-Verbose "Dell SupportAssist for Business is successfully registered" -Verbose

                        # write the result to Microsoft Eventlog
                        $ScriptMessage = @{
                                                NameScript = "SA-RegisterCheck";
                                                Registered = $RegisterStatus.IsRegistrationDone
                                                RegistrationErrorCode = $RegisterStatus.RegistrationErrorCode
                                                RegistrationTime = Get-Date ($RegisterStatus.RegistrationTime) -Format "yyyy/MM/dd hh:mm:ss"
                                                Success = $true
                                            }
                        $ScriptMessageJSON = $ScriptMessage | ConvertTo-Json
                        write-DellRemediationEvent -Logname Dell -Source SupportAssistDiagnostic -EventId '2-InformationScript' -Message $ScriptMessageJSON

                        Write-Output "Device successfully registered"
                        Write-Output "Device was originally registered on: "
                        Write-Output $ScriptMessage.RegistrationTime
                        Write-Output "|Register success|"
                        exit 0
                    }
                else
                    {
                        try
                            {
                                #get diagnostic details
                                $process = New-Object System.Diagnostics.Process
                                $process.StartInfo.FileName = $SADiagnosticFull
                                $process.StartInfo.Arguments = ""
                                $process.StartInfo.RedirectStandardOutput = $true
                                $process.StartInfo.UseShellExecute = $false
                                $process.StartInfo.CreateNoWindow = $true
                                $process.Start() | Out-Null | Out-Null

                                $Diagnostic = $process.StandardOutput.ReadToEnd() | ConvertFrom-Csv -Header Diagnostic | Select-Object -ExpandProperty Diagnostic
                                $process.WaitForExit()

                                Write-Verbose "Diagnostic finished" -Verbose

                                # write the result to Microsoft Eventlog
                                $ScriptMessage = @{
                                                        NameScript = "SA-RegisterCheck";
                                                        Registered = $RegisterStatus.IsRegistrationDone
                                                        RegistrationErrorCode = $RegisterStatus.RegistrationErrorCode
                                                        RegistrationTime = Get-Date ($RegisterStatus.RegistrationTime) -Format "yyyy/MM/dd hh:mm:ss"
                                                        Success = $false
                                                    }
                                $ScriptMessageJSON = $ScriptMessage | ConvertTo-Json
                                write-DellRemediationEvent -Logname Dell -Source SupportAssistDiagnostic -EventId '3-WarningScript' -Message $ScriptMessageJSON

                                # write diagnostic details to Microsoft Eventlog
                                $ScriptMessage = @{
                                                        NameScript = "SA-RegisterCheck";
                                                        Diagnostic = $Diagnostic
                                                    }
                                $ScriptMessageJSON = $ScriptMessage | ConvertTo-Json
                                write-DellRemediationEvent -Logname Dell -Source SupportAssistDiagnostic -EventId '3-WarningScript' -Message $ScriptMessageJSON

                                Write-Output "Diagnostic has collect data"
                                Write-Output "|Diagnostic stage|"
                                Exit 1
                            }
                        catch
                            {
                                Write-Verbose "Diagnostic failed" -Verbose

                                # write the result to Microsoft Eventlog
                                $ScriptMessage = @{
                                    NameScript = "SA-RegisterCheck";
                                    Registered = $RegisterStatus.IsRegistrationDone
                                    RegistrationErrorCode = $RegisterStatus.RegistrationErrorCode
                                    RegistrationTime = Get-Date ($RegisterStatus.RegistrationTime) -Format "yyyy/MM/dd hh:mm:ss"
                                    Success = $false
                                                    }
                                $ScriptMessageJSON = $ScriptMessage | ConvertTo-Json
                                write-DellRemediationEvent -Logname Dell -Source SupportAssistDiagnostic -EventId '3-WarningScript' -Message $ScriptMessageJSON

                                Write-Output "Diagnostic failed"
                                Write-Output "|Script error|"
                                Exit 1
                            }
                    }
            }
        else
            {
                Write-Verbose "No Dell SupportAssist for Business found" -Verbose

                # write the result to Microsoft Eventlog
                $ScriptMessage = @{
                                        NameScript = "SA-RegisterCheck";
                                        Registered = "not found"
                                        RegistrationErrorCode = ""
                                        RegistrationTime = ""
                                        Success = $false
                                    }
                $ScriptMessageJSON = $ScriptMessage | ConvertTo-Json
                write-DellRemediationEvent -Logname Dell -Source SupportAssistDiagnostic -EventId '3-WarningScript' -Message $ScriptMessageJSON

                Write-Output "Software is not installed"
                Write-Output "|no software installed|"
                Exit 1
            }
    }
catch
    {
        $ScriptMessage = @{
                                NameScript = "SA-RegisterCheck";
                                Registered = "Script failed"
                                RegistrationErrorCode = ""
                                RegistrationTime = ""
                                Success = $false
                            }
        $ScriptMessageJSON = $ScriptMessage | ConvertTo-Json
        write-DellRemediationEvent -Logname Dell -Source SupportAssistDiagnostic -EventId '3-WarningScript' -Message $ScriptMessageJSON

        Write-Output "Software is not installed"
        Write-Output "|no software installed|"
        Exit 1
    }
#########################################################################################################
####                                    END                                                          ####
#########################################################################################################