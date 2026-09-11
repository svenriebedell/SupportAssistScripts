<#
_author_ = Sven Riebe <sven_riebe@Dell.com>
_twitter_ = @SvenRiebe
_version_ = 1.0.0
_Dev_Status_ = Test
Copyright © 2026 Dell Inc. or its subsidiaries. All Rights Reserved.

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

#>

<#
.Synopsis
   This PowerShell is for custom compliance scans and is checking this device of missing critical or security drivers .
   IMPORTANT: This script need a client installation of Dell SupportAssit for Business 5.2 or later.
   IMPORTANT: This script does not reboot the system to apply or query system.
.DESCRIPTION
   Powershell using Dell SupportAssist to check missing dirvers with serverity level of critical or security. This script need to be upload in Intune Compliance / Script and need a JSON file additional for reporting this value.

#>
#########################################################################################################
####                                    Variable Section                                             ####
#########################################################################################################
$SACLIPath = "$env:ProgramFiles\Dell\SupportAssistAgent\bin\"
$SACLIEXE = "supportassist.exe"
$SACLIParameters = "--driverscan --resultpath"
$ServiceTag = (Get-CimInstance -ClassName Win32_ComputerSystemProduct).IdentifyingNumber
$XMLReportPath = "C:\Temp\DellSA"
$XMLReportFileName = $ServiceTag +"_SupportAssist_DriverScanResult_*"


#########################################################################################################
####                                    Function Section                                             ####
#########################################################################################################

function Test-FileAccessible
    {
        param (
                    [Parameter(Mandatory = $true)][string]$FilePath
                )

        <#
    .SYNOPSIS
        Tests if a file is accessible and exists.

    .DESCRIPTION
        This function checks if a specified file path exists and is accessible.
        It returns true if the file is found and accessible, false otherwise.

    .PARAMETER FilePath
        The path to the file to check for accessibility.

    .EXAMPLE
        Test-FileAccessible -FilePath "C:\Program Files\Dell\SupportAssist\Bin\supportassist.exe"
    #>
        # Check if the file exists
        if (Test-Path -Path $FilePath -PathType Leaf)
            {
                try
                    {
                        # Test if the file is accessible by attempting to get its properties
                        Get-Item -Path $FilePath -ErrorAction Stop | Out-Null
                        return $true
                    }
                catch
                    {
                        # File exists but is not accessible
                        return $false
                    }
            }
        else
            {
                # File does not exist
                return $false
            }
    }

function New-Directory
    {
        [CmdletBinding(SupportsShouldProcess = $true)]
        [OutputType([bool])]
        param (
                    [Parameter(Mandatory = $true)][string]$Path
                )

        <#
    .SYNOPSIS
        Creates a directory if it does not already exist.

    .DESCRIPTION
        This function checks if a specified directory path exists. If the directory
        does not exist, it creates it. Returns true if the directory exists or was
        successfully created, false otherwise.

    .PARAMETER Path
        The path to the directory to check/create.

    .EXAMPLE
        New-Directory -Path "C:\Temp\DellSA"
    #>
        if (Test-Path -Path $Path -PathType Container)
            {
                # Directory already exists
                return $true
            }
        else
            {
                if ($PSCmdlet.ShouldProcess($Path, "Create directory"))
                    {
                        try
                            {
                                # Create the directory
                                New-Item -Path $Path -ItemType Directory -ErrorAction Stop | Out-Null
                                return $true
                            }
                        catch
                            {
                                # Failed to create directory
                                Write-Warning "Failed to create directory: $Path"
                                return $false
                            }
                    }
                else
                    {
                        return $false
                    }
            }
    }

function Test-SoftwareInstalled
    {
        param(
                    [Parameter(mandatory=$false)][string]$NamePattern,
                    [Parameter(mandatory=$false)][ValidateSet("Equal","Not equal","Less than","Less than or equal","Greater than","Greater than or equal")][String]$ISPattern,
                    [Parameter(mandatory=$false)][Version]$VersionPattern
            )

        # Uninstall-Path (64-bit & 32-bit)
        $paths = @(
                    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
                )


        # cover name conversion of Dell SupportAssist for Business PCs to Dell SupportAssist.
        if($NamePattern -eq "Dell Supportassist" -and [Version]$VersionPattern -lt "5.0")
            {
                $NamePattern = "Dell Supportassist*Business*PCs"
            }

        $items = foreach ($path in $paths)
            {
                try
                    {
                        If ($NamePattern -notmatch "Microsoft.*Windows.*Desktop.*Runtime.*(x64).*" -and $NamePattern -notmatch "Microsoft.*ASP.Net.*Core.*(x64).*")
                            {
                                Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -like $NamePattern}
                            }
                        else
                            {
                                If ($path -like $paths[1])
                                    {
                                        # try to cover wrong .net Version seen with some installer
                                        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -like $NamePattern -and ([version]$_.DisplayVersion).Major -eq $VersionPattern.Major }
                                    }
                            }
                    }
                catch
                    {
                        Write-Output "Path no found" | Out-Null
                    }
            }

        #Checking be different operators if displayversion match
        if($ISPattern -eq "Equal")
            {
                $match = $items | Where-Object {[version]$_.DisplayVersion -eq [version]$VersionPattern}
            }
        elseif($ISPattern -eq "Not equal")
            {
                $match = $items | Where-Object {[version]$_.DisplayVersion -ne [version]$VersionPattern}
            }
        elseif($ISPattern -eq "Less than")
            {
                $match = $items | Where-Object {[version]$_.DisplayVersion -lt [version]$VersionPattern}
            }
        elseif($ISPattern -eq "Less than or equal")
            {
                $match = $items | Where-Object {[version]$_.DisplayVersion -le [version]$VersionPattern}
            }
        elseif($ISPattern -eq "Greater than")
            {
                $match = $items | Where-Object {[version]$_.DisplayVersion -gt [version]$VersionPattern}
            }
        elseif($ISPattern -eq "Greater than or equal")
            {
                $match = $items | Where-Object {[version]$_.DisplayVersion -ge [version]$VersionPattern}
            }

        return $match
    }

#########################################################################################################
####                                    Program Section                                              ####
#########################################################################################################
try
    {
        #### generate Logging Resources
        try
            {
                [System.Diagnostics.EventLog]::CreateEventSource("SupportAssistCompliance", "Dell")
                Write-Verbose "Event source Dell Software Install created for log Dell." -Verbose
            }
        catch
            {
                Write-Verbose "Event source Dell Software Install exist." -Verbose
            }

        # Check if SupportAssist executable exists
        $ExeFullPath = Join-Path $SACLIPath $SACLIEXE
        $SACLIExists = Test-FileAccessible -FilePath $ExeFullPath
        if ($null -eq $SACLIExists)
            {
                Write-Warning "SupportAssist executable not found at: $ExeFullPath"
                $urgentCount = 0
                $RestartRequired = $false
                $SAVersionSupported = $false
                $DiagnoseError = $false

                #prepare variable for Intune
                $hash = @{ MissingCriticalUpdates = $urgentCount; UpdatesRequiredRestart = $RestartRequired; DiagnoseError = $DiagnoseError; SAVersionSupported = $SAVersionSupported }
                $Message = $hash | ConvertTo-Json

                # write eventlog
                try
                    { Write-EventLog -LogName Dell -Source "SupportAssistCompliance" -EntryType error -EventId 11 -Message $Message }
                catch
                { Write-Verbose "EventLog write failed" }

                #convert variable to JSON format
                return $hash | ConvertTo-Json -Compress
            }

        $DSAInstalled = Test-SoftwareInstalled -NamePattern "Dell SupportAssist" -ISPattern "Greater than or equal" -VersionPattern "5.2"

        Write-Information "DSA Installed: $($DSAInstalled.DisplayVersion)" -InformationAction Continue

        #check if min version 5.2 is installed
        if ($null -eq $DSAInstalled)
            {
                Write-Warning "DSA version 5.2 or higher is not installed"
                $urgentCount = 0
                $RestartRequired = $false
                $SAVersionSupported = $false
                $DiagnoseError = $false

                #prepare variable for Intune
                $hash = @{ MissingCriticalUpdates = $urgentCount; UpdatesRequiredRestart = $RestartRequired; DiagnoseError = $DiagnoseError; SAVersionSupported = $SAVersionSupported }
                $Message = $hash | ConvertTo-Json

                # write eventlog
                try { Write-EventLog -LogName Dell -Source "SupportAssistCompliance" -EntryType error -EventId 11 -Message $Message } catch { Write-Verbose "EventLog write failed" }

                #convert variable to JSON format
                return $hash | ConvertTo-Json -Compress
            }

        Write-Information "SupportAssist executable found at: $SACLIPath" -InformationAction Continue

        # Create directory if it doesn't exist
        $DirectoryCreated = New-Directory -Path $XMLReportPath
        if (-not $DirectoryCreated)
            {
                Write-Warning "Failed to create directory: $XMLReportPath"
                $urgentCount = 0
                $RestartRequired = $false
                $SAVersionSupported = $true
                $DiagnoseError = $true

                #prepare variable for Intune
                $hash = @{ MissingCriticalUpdates = $urgentCount; UpdatesRequiredRestart = $RestartRequired; DiagnoseError = $DiagnoseError; SAVersionSupported = $SAVersionSupported }
                $Message = $hash | ConvertTo-Json

                # write eventlog
                try { Write-EventLog -LogName Dell -Source "SupportAssistCompliance" -EntryType error -EventId 11 -Message $Message } catch { Write-Verbose "EventLog write failed" }

                #convert variable to JSON format
                return $hash | ConvertTo-Json -Compress
            }

        Write-Information "Directory created or exists: $XMLReportPath" -InformationAction Continue

        # start driverscan
        $ArgumentFull = $SACLIParameters+" "+ $XMLReportPath

        $process = Start-Process -FilePath $ExeFullPath -WorkingDirectory $SACLIPath -ArgumentList $ArgumentFull -Wait -PassThru -WindowStyle Hidden
        $exitCode = $process.ExitCode
        $exitTime = $process.ExitTime
        Write-Information "Exit code: $exitCode" -InformationAction Continue
        Write-Information "Exit time: $exitTime" -InformationAction Continue

        # write eventlog
        try { Write-EventLog -LogName Dell -Source "SupportAssistCompliance" -EntryType Information -EventId $exitCode -Message "DSA driverscan completed with exit code: $exitCode" } catch { Write-Verbose "EventLog write failed" }


        # get available XLM files
        $availableXML = Get-ChildItem -Path $XMLReportPath -Filter $XMLReportFileName | Sort-Object LastWriteTime | Select-Object -Last 1

        If ($null -ne $availableXML)
            {
                # Check if XML file is not older than 5 minutes compared to exit time
                $fileAge = New-TimeSpan -Start $availableXML.LastWriteTime -End $exitTime
                if ($fileAge.TotalMinutes -gt 5)
                    {
                        Write-Warning "XML file is older than 5 minutes from exit time. File age: $($fileAge.TotalMinutes) minutes"
                        $urgentCount = 0
                    }
                else
                    {
                        # Read XML and count urgent drivers
                        try
                            {
                                $xmlContent = [xml](Get-Content -Path $availableXML.FullName)
                                $urgentDrivers = $xmlContent.AvailableUpdates.Drivers.Driver | Where-Object { $_.DriverImportanceLevel -eq "Urgent" -or $_.DriverImportanceLevel -eq "Security" -or $_.DriverImportanceLevel -eq "Critical"}
                                $urgentCount = ($urgentDrivers | Measure-Object).Count
                                Write-Information "Urgent drivers count: $urgentCount" -InformationAction Continue
                            }
                        catch
                            {
                                Write-Warning "Failed to parse XML file: $($availableXML.FullName)"
                                $urgentCount = 0
                            }
                    }

                if ($exitCode -eq 0)
                    {
                        Write-Information "success" -InformationAction Continue
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $false
                    }
                elseif ($exitCode -eq 1009)
                    {
                        Write-Warning "Command line error"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1010)
                    {
                        Write-Warning "Service not available"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1011)
                    {
                        Write-Warning "Service busy"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1012)
                    {
                        Write-Warning "Unknown Command"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1013)
                    {
                        Write-Warning "Not supported"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1014)
                    {
                        Write-Warning "BDB error"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1015)
                    {
                        Write-Warning "Scan timeout"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1016)
                    {
                        Write-Warning "Cant run"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1017)
                    {
                        Write-Warning "Invalid arguments"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1018)
                    {
                        Write-Information "Device is full updated" -InformationAction Continue
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $false
                    }
                elseif ($exitCode -eq 1019)
                    {
                        Write-Information "No updates found for installation" -InformationAction Continue
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $false
                    }
                elseif ($exitCode -eq 1020)
                    {
                        Write-Information "Device requires restart" -InformationAction Continue
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $true
                        $SAVersionSupported = $true
                        $DiagnoseError = $false
                    }
                elseif ($exitCode -eq 1021)
                    {
                        Write-Warning "Custom catalog download failed"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1022)
                    {
                        Write-Warning "Updates install error"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1023)
                    {
                        Write-Warning "Updates install code exception"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1024)
                    {
                        Write-Warning "Scan install operation success xml error"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1025)
                    {
                        Write-Warning "Code exception"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1026)
                    {
                        Write-Warning "Plugin not loaded"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1027)
                    {
                        Write-Warning "Invalid input file"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1028)
                    {
                        Write-Warning "RDP mode not supported"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                else
                    {
                        Write-Warning "Unknown error"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
            }
        else
            {
                Write-Warning "XML report not found matching pattern: $XMLReportFileName in $XMLReportPath"
                $urgentCount = 0

                if ($exitCode -eq 0)
                    {
                        Write-Information "success" -InformationAction Continue
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $false
                    }
                elseif ($exitCode -eq 1009)
                    {
                        Write-Warning "Command line error"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1010)
                    {
                        Write-Warning "Service not available"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1011)
                    {
                        Write-Warning "Service busy"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1012)
                    {
                        Write-Warning "Unknown Command"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1013)
                    {
                        Write-Warning "Not supported"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1014)
                    {
                        Write-Warning "BDB error"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1015)
                    {
                        Write-Warning "Scan timeout"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1016)
                    {
                        Write-Warning "Cant run"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1017)
                    {
                        Write-Warning "Invalid arguments"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1018)
                    {
                        Write-Information "Device is full updated" -InformationAction Continue
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $false
                    }
                elseif ($exitCode -eq 1019)
                    {
                        Write-Information "No updates found for installation" -InformationAction Continue
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $false
                    }
                elseif ($exitCode -eq 1020)
                    {
                        Write-Information "Device requires restart" -InformationAction Continue
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $true
                        $SAVersionSupported = $true
                        $DiagnoseError = $false
                    }
                elseif ($exitCode -eq 1021)
                    {
                        Write-Warning "Custom catalog download failed"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1022)
                    {
                        Write-Warning "Updates install error"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1023)
                    {
                        Write-Warning "Updates install code exception"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1024)
                    {
                        Write-Warning "Scan install operation success xml error"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1025)
                    {
                        Write-Warning "Code exception"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1026)
                    {
                        Write-Warning "Plugin not loaded"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1027)
                    {
                        Write-Warning "Invalid input file"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                elseif ($exitCode -eq 1028)
                    {
                        Write-Warning "RDP mode not supported"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
                else
                    {
                        Write-Warning "Unknown error"
                        $urgentCountValue = $urgentCount
                        $RestartRequired = $false
                        $SAVersionSupported = $true
                        $DiagnoseError = $true
                    }
            }

        #prepare variable for Intune
        $hash = @{ MissingCriticalUpdates = $urgentCountValue; UpdatesRequiredRestart = $RestartRequired; DiagnoseError = $DiagnoseError; SAVersionSupported = $SAVersionSupported }
        $Message = $hash | ConvertTo-Json

        # write eventlog
        try { Write-EventLog -LogName Dell -Source "SupportAssistCompliance" -EntryType Information -EventId $exitCode -Message $Message } catch { Write-Verbose "EventLog write failed" }

        #convert variable to JSON format
        return $hash | ConvertTo-Json -Compress
    }
catch
    {
        $hash = @{ MissingCriticalUpdates = 0; UpdatesRequiredRestart = $false; DiagnoseError = $true; SAVersionSupported = $true }

        # write eventlog
        try { Write-EventLog -LogName Dell -Source "SupportAssistCompliance" -EntryType error -EventId 11 -Message "Script Error $($_.Exception.Message)" } catch { Write-Verbose "EventLog write failed" }

        #convert variable to JSON format
        return $hash | ConvertTo-Json -Compress
    }