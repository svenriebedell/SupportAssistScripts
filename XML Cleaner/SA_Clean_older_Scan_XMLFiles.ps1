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
   This PowerShell is for using with your Dell SupportAssist for business Commandline actions. This script will clean up older XML files.
   IMPORTANT: This script need a client installation of Dell SupportAssit for Business 5.2 or later.
   IMPORTANT: This script does not reboot the system to apply or query system.
.DESCRIPTION
   PowerShell script using Dell SupportAssist to clean up older XML files. This script performs cleanup to remove older XML files and reports back to Dell TechDirect Remediation or Intune Remediation.

.PARAMETER XMLType
   Specifies the type of XML files to clean. Options are "All", "Scan", or "Install".
   Default is "All".

.PARAMETER CleanupMode
   Specifies the cleanup mode for XML files. Options are "DeleteAll" or "Keep1" through "Keep10".
   Default is "Keep2".

.PARAMETER CustomTempPath
   Specifies the custom temporary path for XML files.
   Default is "C:\temp".

.EXAMPLE
   .\SA_Clean_older_Scan_XMLFiles.ps1 -CustomTempPath "C:\Temp\DSA" -CleanupMode "Keep3" -XMLType "Install"
   Cleans XML files in the specified custom path, keeping only the 3 latest versions of Install XML files.

.EXAMPLE
   .\SA_Clean_older_Scan_XMLFiles.ps1 -CleanupMode "DeleteAll" -XMLType "Scan"
   Deletes all Scan XML files in all temp paths (System, User, Custom).

.EXAMPLE
   .\SA_Clean_older_Scan_XMLFiles.ps1 -CleanupMode "Keep2" -XMLType "All"
   Cleans XML files in all temp paths (default C:\temp for custom path), keeping only the 2 latest versions.

#>


#########################################################################################################
####                                    Parameter Section                                            ####
#########################################################################################################
param (
    [Parameter(Mandatory = $false)]
    [string]$CustomTempPath,

    [Parameter(Mandatory = $false)]
    [ValidateSet("DeleteAll", "Keep1", "Keep2", "Keep3", "Keep4", "Keep5", "Keep6", "Keep7", "Keep8", "Keep9", "Keep10")]
    [string]$CleanupMode,

    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Install", "Scan")]
    [string]$XMLType
)

# Set default values if parameters are not provided
if ([string]::IsNullOrEmpty($CustomTempPath))
    {
        $CustomTempPath = "C:\temp"
    }

if ([string]::IsNullOrEmpty($CleanupMode))
    {
        $CleanupMode = "Keep2"
    }

if ([string]::IsNullOrEmpty($XMLType))
    {
        $XMLType = "All"
    }

#########################################################################################################
####                                    Variable Section                                             ####
#########################################################################################################
$SystemTempPath = Join-path $env:windir -ChildPath "SystemTemp"
$UserTempPath = $env:TEMP
$ServiceTag = Get-CimInstance -ClassName CIM_BIOSElement | Select-Object -ExpandProperty SerialNumber
$XMLReport = @(
                [PSCustomObject]@{Name = "All"; File = $ServiceTag +"_SupportAssist_Driver*Result_*"},
                [PSCustomObject]@{Name = "Scan"; File = $ServiceTag +"_SupportAssist_DriverScanResult_*"},
                [PSCustomObject]@{Name = "Install"; File = $ServiceTag +"_SupportAssist_DriverInstallResult_*"}
                )

#########################################################################################################
####                                    Function Section                                             ####
#########################################################################################################

function Remove-OlderXMLFile
    {
        [CmdletBinding(SupportsShouldProcess = $true)]
        [OutputType([int])]
        param (
                    [Parameter(Mandatory = $true)][string]$Path,
                    [Parameter(Mandatory = $true)][string]$FileNamePattern,
                    [Parameter(Mandatory = $true)][ValidateSet("DeleteAll", "Keep1", "Keep2", "Keep3", "Keep4", "Keep5", "Keep6", "Keep7", "Keep8", "Keep9", "Keep10")][string]$CleanupMode
                )

        <#
    .SYNOPSIS
        Removes older XML files matching a pattern, keeping only the specified number of latest versions.

    .DESCRIPTION
        This function searches for files in the specified path that match the given file name pattern.
        It sorts the files by last write time (newest first) and keeps only the specified number of
        latest versions. If CleanupMode is set to "DeleteAll", all files are deleted.

    .PARAMETER Path
        The directory path to search for XML files.

    .PARAMETER FileNamePattern
        The file name pattern to match (e.g., "*_SupportAssist_DriverScanResult_*").

    .PARAMETER CleanupMode
        The cleanup mode. Valid values are "DeleteAll" or "Keep1" through "Keep10".
        If set to "DeleteAll", all matching files will be deleted. If set to "KeepX", the X latest files are kept.

    .EXAMPLE
        Remove-OlderXMLFiles -Path "C:\Temp\DSA" -FileNamePattern "*_SupportAssist_DriverScanResult_*" -CleanupMode "Keep3"
    #>
        # Check if the path exists
        if (-not (Test-Path -Path $Path -PathType Container))
            {
                Write-Error "Path does not exist: $Path"
                return 0
            }

        # Get all files matching the pattern
        $allFiles = Get-ChildItem -Path $Path -Filter $FileNamePattern -ErrorAction SilentlyContinue

        if ($null -eq $allFiles -or $allFiles.Count -eq 0)
            {
                Write-Information "No files found matching pattern: $FileNamePattern in $Path" -InformationAction Continue
                return 0
            }

        # Sort files by LastWriteTime (newest first)
        $sortedFiles = $allFiles | Sort-Object LastWriteTime -Descending

        # If CleanupMode is "DeleteAll", delete all files
        if ($CleanupMode -eq "DeleteAll")
            {
                $filesToDelete = $sortedFiles
                $deletedCount = 0

                # Delete all files
                foreach ($file in $filesToDelete)
                    {
                        if ($PSCmdlet.ShouldProcess($file.FullName, "Delete file"))
                            {
                                try
                                    {
                                        Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                                        Write-Verbose "Deleted file: $($file.FullName)" -Verbose
                                        $deletedCount++
                                    }
                                catch
                                    {
                                        Write-Error "Failed to delete file: $($file.FullName). Error: $($_.Exception.Message)"
                                    }
                            }
                    }

                Write-Information "Deleted $deletedCount XML file(s) (CleanupMode set to 'DeleteAll')." -InformationAction Continue
                return $deletedCount
            }

        # Extract the number from CleanupMode (e.g., "Keep3" -> 3)
        $keepCount = [int]($CleanupMode -replace "Keep", "")

        # If total files is less than or equal to keep count, nothing to delete
        if ($sortedFiles.Count -le $keepCount)
            {
                Write-Information "Total files ($($sortedFiles.Count)) is less than or equal to keep count ($keepCount) - no files will be deleted" -InformationAction Continue
                return 0
            }

        # Get files to delete (all except the first N)
        $filesToDelete = $sortedFiles | Select-Object -Skip $keepCount
        $deletedCount = 0

        # Delete older files
        foreach ($file in $filesToDelete)
            {
                if ($PSCmdlet.ShouldProcess($file.FullName, "Delete file"))
                    {
                        try
                            {
                                Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                                Write-Verbose "Deleted file: $($file.FullName)" -Verbose
                                $deletedCount++
                            }
                        catch
                            {
                                Write-Error "Failed to delete file: $($file.FullName). Error: $($_.Exception.Message)"
                            }
                    }
            }

        Write-Information "Deleted $deletedCount older XML file(s). Kept $keepCount latest version(s) (CleanupMode: $CleanupMode)." -InformationAction Continue
        return $deletedCount
    }

#########################################################################################################
####                                    Program Section                                              ####
#########################################################################################################
try
    {
        #### generate Logging Resources
        try
            {
                [System.Diagnostics.EventLog]::CreateEventSource("SupportAssistRemediation", "Dell")
                Write-Verbose "Event source Dell Software Install created for log Dell." -Verbose
            }
        catch
            {
                Write-Verbose "Event source Dell Software Install exist." -Verbose
            }

        # Determine which XML files to process based on XMLType parameter
        $XMLReportFileName = Switch ($XMLType)
            {
                "All" { $XMLReport | Where-Object { $_.Name -eq "All" } | Select-Object -ExpandProperty File }
                "Scan" { $XMLReport | Where-Object { $_.Name -eq "Scan" } | Select-Object -ExpandProperty File }
                "Install" { $XMLReport | Where-Object { $_.Name -eq "Install" } | Select-Object -ExpandProperty File }
                default { $XMLReport | Where-Object { $_.Name -eq "All" } | Select-Object -ExpandProperty File }
            }


        # Delete XML files created by System Context
        try
            {
                if(Test-Path $SystemTempPath)
                    {
                        $ResultSystem = Remove-OlderXMLFile -Path $SystemTempPath -FileName $XMLReportFileName -CleanupMode $CleanupMode
                        Write-Output "System Context XML files cleaned. Deleted $ResultSystem files."
                        $message = [PSCustomObject]@{
                                                        Name = $SystemTempPath
                                                        Value = $ResultSystem
                                                    }
                        try
                            { Write-EventLog -LogName Dell -Source "SupportAssistRemediation" -EntryType Information -EventId 11 -Message ($message | ConvertTo-Json) }
                        catch
                            { Write-Verbose "EventLog write failed" }
                    }
                else
                    {
                        Write-Output "$SystemTempPath not found"
                        $message = [PSCustomObject]@{
                                                        Name = $SystemTempPath
                                                        Value = "Folder not found"
                                                    }
                        try
                            { Write-EventLog -LogName Dell -Source "SupportAssistRemediation" -EntryType Information -EventId 11 -Message ($message | ConvertTo-Json) }
                        catch
                            { Write-Verbose "EventLog write failed" }
                    }
            }
        catch
            {
                Write-Error "Failed to remove older XML files. Error: $($_.Exception.Message)"
                try
                    { Write-EventLog -LogName Dell -Source "SupportAssistRemediation" -EntryType Error -EventId 12 -Message "Failed to remove older XML files. Error: $($_.Exception.Message)" }
                catch
                    { Write-Verbose "EventLog write failed" }
            }

        # Delete XML files created by User Context
        try
            {
                if(Test-Path $UserTempPath)
                    {
                        $ResultUser = Remove-OlderXMLFile -Path $UserTempPath -FileName $XMLReportFileName -CleanupMode $CleanupMode
                        Write-Output "System Context XML files cleaned. Deleted $ResultUser files."
                        $message = [PSCustomObject]@{
                                                        Name = $UserTempPath
                                                        Value = $ResultUser
                                                    }
                        try
                            { Write-EventLog -LogName Dell -Source "SupportAssistRemediation" -EntryType Information -EventId 11 -Message ($message | ConvertTo-Json) }
                        catch
                            { Write-Verbose "EventLog write failed" }
                    }
                else
                    {
                        Write-Output "$UserTempPath not found"
                        $message = [PSCustomObject]@{
                                                        Name = $UserTempPath
                                                        Value = "Folder not found"
                                                    }
                        try
                            { Write-EventLog -LogName Dell -Source "SupportAssistRemediation" -EntryType Information -EventId 11 -Message ($message | ConvertTo-Json) }
                        catch
                            { Write-Verbose "EventLog write failed" }
                    }
            }
        catch
            {
                Write-Error "Failed to remove older XML files. Error: $($_.Exception.Message)"
                try
                    { Write-EventLog -LogName Dell -Source "SupportAssistRemediation" -EntryType Error -EventId 12 -Message "Failed to remove older XML files. Error: $($_.Exception.Message)" }
                catch
                    { Write-Verbose "EventLog write failed" }
            }

        # Delete XML files created by custom path
        try
            {
                if(Test-Path $CustomTempPath)
                    {
                        $ResultCustom = Remove-OlderXMLFile -Path $CustomTempPath -FileName $XMLReportFileName -CleanupMode $CleanupMode
                        Write-Output "System Context XML files cleaned. Deleted $ResultCustom files."
                        $message = [PSCustomObject]@{
                                                        Name = $CustomTempPath
                                                        Value = $ResultCustom
                                                    }
                        try
                            { Write-EventLog -LogName Dell -Source "SupportAssistRemediation" -EntryType Information -EventId 11 -Message ($message | ConvertTo-Json) }
                        catch
                            { Write-Verbose "EventLog write failed" }
                    }
                else
                    {
                        Write-Output "$CustomTempPath not found"
                        $message = [PSCustomObject]@{
                                                        Name = $CustomTempPath
                                                        Value = "Folder not found"
                                                    }
                        try
                            { Write-EventLog -LogName Dell -Source "SupportAssistRemediation" -EntryType Information -EventId 11 -Message ($message | ConvertTo-Json) }
                        catch
                            { Write-Verbose "EventLog write failed" }
                    }
            }
        catch
            {
                Write-Error "Failed to remove older XML files. Error: $($_.Exception.Message)"
                try
                    { Write-EventLog -LogName Dell -Source "SupportAssistRemediation" -EntryType Error -EventId 12 -Message "Failed to remove older XML files. Error: $($_.Exception.Message)" }
                catch
                    { Write-Verbose "EventLog write failed" }
            }
    }
catch
    {
        # write eventlog
        try
            {
                Write-EventLog -LogName Dell -Source "SupportAssistDetection" -EntryType error -EventId 11 -Message "Script Error $($_.Exception.Message)"
            }
        catch
            {
                Write-Verbose "EventLog write failed"
            }

        Write-Output "~~Script Error: $($_.Exception.Message)~~"
        Write-Output "|Script Error|"
        Exit 1
    }