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

1.0.0   initial version

#>

<#
.SYNOPSIS
   This PowerShell script creates CIM classes based on XML data from Dell SupportAssist.
   IMPORTANT: This script need a client installation of Dell SupportAssist for Business 5.2 or later.
   IMPORTANT: This script requires Administrator privileges to create CIM classes.
.DESCRIPTION
   PowerShell script that reads XML data from Dell SupportAssist and creates CIM classes
   under the root/SupportAssist namespace. The script creates three classes:

   - DSA_InstallStatus: Contains installation result data
   - DSA_AvailableUpdates: Contains available update information
   - DSA_DriverInstall: Contains driver installation details
   - DSA_DriverScan: Contains driver scan details

.PARAMETER XMLCustomPath
   Specifies the path to the XML file or directory containing XML files.
   Default is "C:\temp\DSA".

.PARAMETER Namespace
   Specifies the CIM namespace for the classes.
   Default is "root/SupportAssist".

.EXAMPLE
   .\SA_Create_CIM_Classes.ps1 -XMLPath "C:\Temp\DSA" -Force
   Creates CIM classes from XML files in the specified path, forcing recreation of existing classes.

.EXAMPLE
   .\SA_Create_CIM_Classes.ps1 -Namespace "root/SupportAssist"
   Creates CIM classes in the default namespace using XML files from C:\temp.

#>

#########################################################################################################
####                                    Parameter Section                                            ####
#########################################################################################################
param (
    [Parameter(Mandatory = $false)]
    [string]$XMLCustomPath,

    [Parameter(Mandatory = $false)]
    [string]$Namespace

)

# fallback in case no XML path is provided
if ([string]::IsNullOrEmpty($XMLCustomPath))
    {
        $XMLCustomPath = "C:\temp\DellSA"
    }

if ([string]::IsNullOrEmpty($Namespace))
    {
        $Namespace = "root/SupportAssist"
    }
#########################################################################################################
####                                    Variable Section                                             ####
#########################################################################################################
$ServiceTag = Get-CimInstance -ClassName CIM_BIOSElement | Select-Object -ExpandProperty SerialNumber
$HostName = Get-CimInstance -ClassName CIM_ComputerSystem  | Select-Object -ExpandProperty Name

$XMLPaths = @(
                [PSCustomObject]@{Name = "System"; Path=Join-path $env:windir -ChildPath "SystemTemp"},
                [PSCustomObject]@{Name = "User"; Path=$env:TEMP},
                [PSCustomObject]@{Name = "Custom"; Path=$XMLCustomPath }
            )

$XMLReport = @(
                [PSCustomObject]@{Name = "All"; File = $ServiceTag +"_SupportAssist_Driver*Result_*"},
                [PSCustomObject]@{Name = "Scan"; File = $ServiceTag +"_SupportAssist_DriverScanResult_*"},
                [PSCustomObject]@{Name = "Install"; File = $ServiceTag +"_SupportAssist_DriverInstallResult_*"}
                )

$CIMNameSpace = $Namespace
$ErrorAction = "stop"
$CIMClasses = @(
                    [PSCustomObject]@{Classname = "DSA_InstallStatus"},
                    [PSCustomObject]@{Classname = "DSA_DriverInstall"},
                    [PSCustomObject]@{Classname = "DSA_AvailableUpdates"}
                    [PSCustomObject]@{Classname = "DSA_DriverScan"}
                )

#### Enable/Disable Console logging messages
[bool]$LoggingConsole = $true

$EventName = "Dell"
$EventSource = "SupportAssistCIMXLM"

#########################################################################################################
####                                    MOF Section                                                  ####
#########################################################################################################

$MOFClasses = @"
#pragma namespace ("\\\\.\\root\\supportassist")
#pragma autorecover

class DSA_InstallStatus
{
    [Key]
    string ServiceTag;
    [Key]
    string HostName;
    [Key]
    string InstallTimestamp;
    [Key]
    string InstallFileName;
    string OverallStatus;
    uint32 TotalDrivers;
};

class DSA_DriverInstall
{
    [Key]
    string ServiceTag;
    [Key]
    string HostName;
    [Key]
    string InstallTimestamp;
    [Key]
    string InstallFileName;
    [Key]
    string DriverId;

    string RecordID;
    string DriverTitle;
    string DriverType;
    string DriverFileName;
    string Status;
    uint32 PercentCompleted;
    string DriverFileSizeMB;
    string DownloadedMB;
    string SavedFolder;
    string ResultCode;
    string ErrorMessage;
    string FileUniqueId;
};

class DSA_AvailableUpdates
{
    [Key]
    string ServiceTag;
    [Key]
    string HostName;
    [Key]
    string ScanTimestamp;
    [Key]
    string ScanFileName;
    string CatalogVersion;
    uint32 AvailableUpdates;
    uint32 DriverCritical;
    uint32 DriverRecommand;
    uint32 DriverOptional;
};

class DSA_DriverScan
{
    [Key]
    string ServiceTag;
    [Key]
    string HostName;
    [Key]
    string ScanTimestamp;
    [Key]
    string ScanFileName;
    [Key]
    string DriverId;

    string RecordId;
    string DriverTitle;
    string DriverDescription;
    string DeviceDescription;
    string DriverReleaseDate;
    string DriverCategory;
    string DriverType;
    string DriverTypeName;
    string DriverCategoryName;
    string CatalogVersion;
    boolean RebootRequired;
    string DriverImportanceLevel;
    uint64 DriverSize;
    string DriverFileName;
    string DownloadUrl;
    string CatalogPnpId;
    string ModifiedTime;
    string ImportantUrl;
    string HashAlgorithm;
    boolean IsDependency;
    boolean HasDependency;
    string HashValue;
    boolean IsInventoryComponent;
    uint32 SortOrder;
    string ComponentIdMatchingInventory;
    string InventoryVersion;
    boolean IsDockUpdate;
    boolean IsIsvLocked;
    boolean IsBSodCausing;
    boolean IsPowerAdapterRequired;
    string BsodRate;
    string BsodVersion;
    string FileUniqueId;
    string IsBiosPasswordSet;
    string ReclassifiedDriverImportance;
    string BiosCodeStatus;
    string DriverDellVersion;
    boolean InstallRequired;
};

"@

#########################################################################################################
####                                    Function Section                                             ####
#########################################################################################################

function Write-CustomOutput
    {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)][string]$Message,
            [Parameter(Mandatory=$false)][ValidateSet('Default', 'Error', 'Warning', 'Verbose', 'Debug', 'Success')][string]$Type = 'Default',
            [Parameter(Mandatory=$false)][bool]$OutputConsole = $true,
            [Parameter(Mandatory=$false)][System.Collections.ArrayList]$LogMessages = $null
        )

        # Add to log messages if provided (for function-level logging)
        if ($null -ne $LogMessages)
            {
                [void]$LogMessages.Add($Message)
            }

        if (-not $OutputConsole)
            {
                return
            }

        switch ($Type)
            {
                'Default'
                    {
                        Write-Output -InputObject $Message
                    }
                'Error'
                    {
                        Write-Output -InputObject "Error: $Message"
                    }
                'Warning'
                    {
                        Write-Warning -Message $Message
                    }
                'Verbose'
                    {
                        Write-Verbose -Message $Message -Verbose
                    }
                'Debug'
                    {
                        Write-Debug -Message $Message
                    }
                'Success'
                    {
                        Write-Output -InputObject $Message
                    }
            }
    }

function Get-SAXMLDetail
    {
        <#
    .SYNOPSIS
        Finds all XML files in the specified directories matching the SupportAssist pattern.

    .DESCRIPTION
        This function searches for XML files in the System temp, User temp, and Custom temp paths
        that match the SupportAssist file naming pattern for the current Service Tag.

    .PARAMETER XMLPaths
        Array of PSCustomObjects with Name and Path properties for directories to search.

    .PARAMETER ServiceTag
        The Service Tag used to construct the file pattern.

    .EXAMPLE
        Get-SAXMLDetail -XMLPaths $XMLPaths -ServiceTag "ABC123"
    #>
        param (
                    [Parameter(Mandatory = $true)][PSCustomObject[]]$XMLPaths,
                    [Parameter(Mandatory = $true)][string]$ServiceTag
                )

        $filePattern = $ServiceTag + "_SupportAssist_Driver*Result_*"
        $allXMLFiles = @()

        foreach ($pathObj in $XMLPaths)
            {
                $path = $pathObj.Path
                if (Test-Path -Path $path -PathType Container)
                    {
                        $files = Get-ChildItem -Path $path -Filter $filePattern -ErrorAction SilentlyContinue
                        if ($files)
                            {
                                foreach ($file in $files)
                                    {
                                        $fileDetails = [PSCustomObject]@{
                                                                FullName = $file.FullName
                                                                Name = $file.Name
                                                                LastWriteTime = $file.LastWriteTime
                                                                Length = $file.Length
                                                                Directory = $file.DirectoryName
                                                                Source = $pathObj.Name
                                                            }
                                        $allXMLFiles += $fileDetails
                                    }
                            }
                    }
            }

        return $allXMLFiles
    }

function Write-SAXMLToCIM
    {
        <#
    .SYNOPSIS
        Writes XML scan and install data to CIM classes.

    .DESCRIPTION
        This function reads SupportAssist XML files and writes the data to CIM classes.
        It creates summary instances in DSA_AvailableUpdates/DSA_InstallStatus and detail instances in DSA_DriverScan/DSA_DriverInstall.

    .PARAMETER XMLPaths
        Array of PSCustomObjects with Name and Path properties for directories to search.

    .PARAMETER ServiceTag
        The Service Tag for the system.

    .PARAMETER HostName
        The hostname for the system.

    .PARAMETER Namespace
        The CIM namespace to write to.

    .EXAMPLE
        Write-SAXMLToCIM -XMLPaths $XMLPaths -ServiceTag "ABC123" -HostName "Server01" -Namespace "root/SupportAssist"
    #>
        param (
                    [Parameter(Mandatory = $true)][PSCustomObject[]]$XMLPaths,
                    [Parameter(Mandatory = $true)][string]$ServiceTag,
                    [Parameter(Mandatory = $true)][string]$HostName,
                    [Parameter(Mandatory = $true)][string]$Namespace
                )

        # Get Scan XML files
        $scanPattern = $XMLReport | Where-Object { $_.Name -eq "Scan"} | Select-Object -ExpandProperty File
        $scanFiles = @()
        foreach ($pathObj in $XMLPaths)
            {
                $path = $pathObj.Path
                if (Test-Path -Path $path -PathType Container)
                    {
                        $files = Get-ChildItem -Path $path -Filter $scanPattern -ErrorAction SilentlyContinue
                        if ($files)
                            {
                                foreach ($file in $files)
                                    {
                                        $fileDetails = [PSCustomObject]@{
                                                                FullName = $file.FullName
                                                                Name = $file.Name
                                                                LastWriteTime = $file.LastWriteTime
                                                                Length = $file.Length
                                                                Directory = $file.DirectoryName
                                                                Source = $pathObj.Name
                                                            }
                                        $scanFiles += $fileDetails
                                    }
                            }
                    }
            }

        # Get Install XML files
        $installPattern = $XMLReport | Where-Object { $_.Name -eq "Install"} | Select-Object -ExpandProperty File
        $installFiles = @()
        foreach ($pathObj in $XMLPaths)
            {
                $path = $pathObj.Path
                if (Test-Path -Path $path -PathType Container)
                    {
                        $files = Get-ChildItem -Path $path -Filter $installPattern -ErrorAction SilentlyContinue
                        if ($files)
                            {
                                foreach ($file in $files)
                                    {
                                        $fileDetails = [PSCustomObject]@{
                                                                FullName = $file.FullName
                                                                Name = $file.Name
                                                                LastWriteTime = $file.LastWriteTime
                                                                Length = $file.Length
                                                                Directory = $file.DirectoryName
                                                                Source = $pathObj.Name
                                                            }
                                        $installFiles += $fileDetails
                                    }
                            }
                    }
            }

        if (($null -eq $scanFiles -or $scanFiles.Count -eq 0) -and ($null -eq $installFiles -or $installFiles.Count -eq 0))
            {
                Write-CustomOutput -Message "No XML files found for ServiceTag: $ServiceTag" -Type Warning
                return "NoFiles"
            }

        # Process Scan files
        foreach ($xmlFile in $scanFiles)
            {
                try
                    {
                        Write-CustomOutput -Message "Processing Scan XML file: $($xmlFile.FullName)" -Type Verbose

                        # Read XML content
                        $xmlContent = [xml](Get-Content -Path $xmlFile.FullName)
                        if ($xmlContent.AvailableUpdates)
                            {
                                $scanTimestamp = $xmlContent.AvailableUpdates.ScanTimestamp
                                $catalogVersion = $xmlContent.AvailableUpdates.CatalogVersion
                                $scanFileName = $xmlFile.Name

                                $drivers = $xmlContent.AvailableUpdates.Drivers.Driver


                                # Create summary instance in DSA_AvailableUpdates
                                $summaryProps = @{
                                    ServiceTag = $ServiceTag
                                    HostName = $HostName
                                    ScanTimestamp = $scanTimestamp
                                    ScanFileName = $scanFileName
                                    CatalogVersion = $catalogVersion
                                    AvailableUpdates = [uint32]($drivers | Measure-Object).Count
                                    DriverCritical = [uint32]($drivers | Where-Object { $_.DriverImportanceLevel -in @("Urgent", "Security", "Critical") } | Measure-Object).Count
                                    DriverRecommand = [uint32]($drivers | Where-Object { $_.DriverImportanceLevel -eq "Recommended" } | Measure-Object).Count
                                    DriverOptional = [uint32]($drivers | Where-Object { $_.DriverImportanceLevel -eq "Optional" } | Measure-Object).Count
                                }

                                # Remove existing instances with same keys
                                $existingInstances = Get-CimInstance -Namespace $Namespace -ClassName DSA_AvailableUpdates -Filter "ServiceTag = '$ServiceTag' AND ScanTimestamp = '$scanTimestamp' AND ScanFileName = '$scanFileName'" -ErrorAction SilentlyContinue
                                if ($existingInstances)
                                    {
                                        foreach ($instance in $existingInstances)
                                            {
                                                Remove-CimInstance -InputObject $instance
                                            }
                                    }

                                # Create new summary instance
                                New-CimInstance -Namespace $Namespace -ClassName DSA_AvailableUpdates -Property $summaryProps -ErrorAction Stop
                                Write-CustomOutput -Message "Created DSA_AvailableUpdates instance for $scanTimestamp" -Type Verbose

                                # Process each driver
                                $drivers = $xmlContent.AvailableUpdates.Drivers.Driver
                                if ($drivers)
                                    {
                                        foreach ($driver in $drivers)
                                            {
                                                # Create driver instance in DSA_DriverScan
                                                $driverProps = @{
                                                    ServiceTag = $ServiceTag
                                                    HostName = $HostName
                                                    ScanTimestamp = $scanTimestamp
                                                    ScanFileName = $scanFileName
                                                    DriverId = if ($driver.DriverId) { $driver.DriverId } else { $driver.DriverUniqeID }
                                                    RecordId = $driver.RecordID
                                                    DriverTitle = $driver.DriverTitle
                                                    DriverDescription = $driver.DriverDescription
                                                    DeviceDescription = $driver.DeviceDescription
                                                    DriverReleaseDate = $driver.DriverReleaseDate
                                                    DriverCategory = $driver.DriverCategory
                                                    DriverType = $driver.DriverType
                                                    DriverTypeName = $driver.DriverTypeName
                                                    DriverCategoryName = $driver.DriverCategoryName
                                                    CatalogVersion = $driver.CatalogVersion
                                                    RebootRequired = if ($driver.RebootRequired -eq "true") { $true } else { $false }
                                                    DriverImportanceLevel = $driver.DriverImportanceLevel
                                                    DriverSize = if ($driver.DriverSize) { [uint64]$driver.DriverSize } else { 0 }
                                                    DriverFileName = $driver.FileName
                                                    DownloadUrl = $driver.DownloadUrl
                                                    CatalogPnpId = $driver.CatalogPnpId
                                                    ModifiedTime = $driver.ModifiedTime
                                                    ImportantUrl = $driver.ImportantUrl
                                                    HashAlgorithm = $driver.HashAlgorithm
                                                    IsDependency = if ($driver.IsDependency -eq "true") { $true } else { $false }
                                                    HasDependency = if ($driver.HasDependency -eq "true") { $true } else { $false }
                                                    HashValue = $driver.HashValue
                                                    IsInventoryComponent = if ($driver.IsInventoryComponent -eq "true") { $true } else { $false }
                                                    SortOrder = if ($driver.SortOrder) { [uint32]$driver.SortOrder } else { 0 }
                                                    ComponentIdMatchingInventory = $driver.ComponentIdMatchingInventory
                                                    InventoryVersion = $driver.InventoryVersion
                                                    IsDockUpdate = if ($driver.IsDockUpdate -eq "true") { $true } else { $false }
                                                    IsIsvLocked = if ($driver.IsIsvLocked -eq "true") { $true } else { $false }
                                                    IsBSodCausing = if ($driver.IsBSodCausing -eq "true") { $true } else { $false }
                                                    IsPowerAdapterRequired = if ($driver.IsPowerAdapterRequired -eq "true") { $true } else { $false }
                                                    BsodRate = $driver.BsodRate
                                                    BsodVersion = $driver.BsodVersion
                                                    FileUniqueId = $driver.FileUniqueId
                                                    IsBiosPasswordSet = $driver.IsBiosPasswordSet
                                                    ReclassifiedDriverImportance = $driver.ReclassifiedDriverImportance
                                                    BiosCodeStatus = $driver.BiosCodeStatus
                                                    DriverDellVersion = $driver.DriverDellVersion
                                                    InstallRequired = if ($driver.InstallRequired -eq "true") { $true } else { $false }
                                                }

                                                # Remove existing driver instances with same keys
                                                $existingDriverInstances = Get-CimInstance -Namespace $Namespace -ClassName DSA_DriverScan -Filter "ServiceTag = '$ServiceTag' AND ScanTimestamp = '$scanTimestamp' AND ScanFileName = '$scanFileName' AND DriverId = '$($driverProps.DriverId)'" -ErrorAction SilentlyContinue
                                                if ($existingDriverInstances)
                                                    {
                                                        foreach ($instance in $existingDriverInstances)
                                                            {
                                                                Remove-CimInstance -InputObject $instance
                                                            }
                                                    }

                                                # Create new driver instance
                                                New-CimInstance -Namespace $Namespace -ClassName DSA_DriverScan -Property $driverProps -ErrorAction Stop
                                                Write-CustomOutput -Message "Created DSA_DriverScan instance for driver: $($driverProps.DriverTitle)" -Type Verbose
                                            }
                                    }
                            }
                    }
                catch
                    {
                        Write-CustomOutput -Message "Failed to process Scan XML file $($xmlFile.FullName): $($_.Exception.Message)" -Type Warning
                    }
            }

        # Process Install files
        foreach ($xmlFile in $installFiles)
            {
                try
                    {
                        Write-CustomOutput -Message "Processing Install XML file: $($xmlFile.FullName)" -Type Verbose

                        # Read XML content
                        $xmlContent = [xml](Get-Content -Path $xmlFile.FullName)

                        # Process Install XML
                        if ($xmlContent.DriverInstallResults)
                            {
                                $installTimestamp = $xmlContent.DriverInstallResults.InstallTimestamp
                                $totalDrivers = $xmlContent.DriverInstallResults.TotalDrivers
                                $overallStatus = $xmlContent.DriverInstallResults.OverallStatus
                                $installFileName = $xmlFile.Name

                                # Create summary instance in DSA_InstallStatus
                                $installSummaryProps = @{
                                    ServiceTag = $ServiceTag
                                    HostName = $HostName
                                    InstallTimestamp = $installTimestamp
                                    InstallFileName = $installFileName
                                    OverallStatus = $overallStatus
                                    TotalDrivers = if ($totalDrivers) { [uint32]$totalDrivers } else { 0 }
                                }

                                # Remove existing instances with same keys
                                $existingInstallInstances = Get-CimInstance -Namespace $Namespace -ClassName DSA_InstallStatus -Filter "ServiceTag = '$ServiceTag' AND InstallTimestamp = '$installTimestamp' AND InstallFileName = '$installFileName'" -ErrorAction SilentlyContinue
                                if ($existingInstallInstances)
                                    {
                                        foreach ($instance in $existingInstallInstances)
                                            {
                                                Remove-CimInstance -InputObject $instance
                                            }
                                    }

                                # Create new summary instance
                                New-CimInstance -Namespace $Namespace -ClassName DSA_InstallStatus -Property $installSummaryProps -ErrorAction Stop
                                Write-CustomOutput -Message "Created DSA_InstallStatus instance for $installTimestamp" -Type Verbose

                                # Process each installed driver
                                $installedDrivers = $xmlContent.DriverInstallResults.Drivers.Driver
                                if ($installedDrivers)
                                    {
                                        foreach ($installedDriver in $installedDrivers)
                                            {
                                                # Create driver instance in DSA_DriverInstall
                                                $driverInstallProps = @{
                                                    ServiceTag = $ServiceTag
                                                    HostName = $HostName
                                                    InstallTimestamp = $installTimestamp
                                                    InstallFileName = $installFileName
                                                    DriverId = $installedDriver.Id
                                                    RecordID = $installedDriver.RecordID
                                                    DriverTitle = $installedDriver.Title
                                                    DriverType = $installedDriver.Type
                                                    DriverFileName = $installedDriver.FileName
                                                    Status = $installedDriver.Status
                                                    PercentCompleted = if ($installedDriver.PercentCompleted) { [uint32]$installedDriver.PercentCompleted } else { 0 }
                                                    DriverFileSizeMB = $installedDriver.FileSizeMB
                                                    DownloadedMB = $installedDriver.DownloadedMB
                                                    SavedFolder = $installedDriver.SavedFolder
                                                    ResultCode = $installedDriver.ResultCode
                                                    ErrorMessage = $installedDriver.ErrorMessage
                                                    FileUniqueId = $installedDriver.FileUniqueId
                                                }

                                                # Remove existing driver install instances with same keys
                                                $existingDriverInstallInstances = Get-CimInstance -Namespace $Namespace -ClassName DSA_DriverInstall -Filter "ServiceTag = '$ServiceTag' AND InstallTimestamp = '$installTimestamp' AND InstallFileName = '$installFileName' AND DriverId = '$($driverInstallProps.DriverId)'" -ErrorAction SilentlyContinue
                                                if ($existingDriverInstallInstances)
                                                    {
                                                        foreach ($instance in $existingDriverInstallInstances)
                                                            {
                                                                Remove-CimInstance -InputObject $instance
                                                            }
                                                    }

                                                # Create new driver install instance
                                                New-CimInstance -Namespace $Namespace -ClassName DSA_DriverInstall -Property $driverInstallProps -ErrorAction Stop
                                                Write-CustomOutput -Message "Created DSA_DriverInstall instance for driver: $($driverInstallProps.DriverTitle)" -Type Verbose
                                            }
                                    }
                            }
                    }
                catch
                    {
                        Write-CustomOutput -Message "Failed to process Install XML file $($xmlFile.FullName): $($_.Exception.Message)" -Type Warning
                    }
            }

        Write-CustomOutput -Message "Successfully processed XML files and wrote to CIM classes" -Type Success
    }

function Test-Administrator
    {
        <#
        .SYNOPSIS
            Checks if the current session has Administrator privileges.

        .DESCRIPTION
            This function checks if the current PowerShell session is running with
            Administrator privileges, which is required for CIM class creation.

        .OUTPUTS
            Boolean indicating whether the session has Administrator privileges.
        #>
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

function Test-NameSpace
    {
        <#
        .SYNOPSIS
            Checks if a CIM namespace exists.

        .DESCRIPTION
            This function checks if the specified CIM namespace exists by attempting
            to retrieve a class from it.

        .PARAMETER Namespace
            The namespace to check.

        .PARAMETER ErrorAction
            The error action preference. Default is "Stop".

        .OUTPUTS
            Boolean indicating whether the namespace exists.
        #>
        param (
            [Parameter(Mandatory = $true)][string]$Namespace,
            [Parameter(Mandatory = $false)][string]$ErrorHandling = "Stop"
        )

        try
            {
                Get-CimClass -Namespace $Namespace -ErrorAction $ErrorHandling | Out-Null
                Write-CustomOutput -Message "$Namespace exist" -Type Verbose
                return $true
            }
        catch
            {
                Write-CustomOutput -Message "NameSpace $Namespace not found" -Type Warning
                return $false
            }
    }

function Remove-CIMClass
    {
        <#
        .SYNOPSIS
            Removes a CIM class and all its instances.

        .DESCRIPTION
            This function removes the specified CIM class and all its instances from the given namespace.
            Requires Administrator privileges.

        .PARAMETER Namespace
            The namespace containing the class.

        .PARAMETER ClassName
            The name of the class to remove.

        .EXAMPLE
            Remove-CIMClass -Namespace "root/SupportAssist" -ClassName "DSA_Scan"
        #>
        [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
        param (
            [Parameter(Mandatory = $true)][string]$Namespace,
            [Parameter(Mandatory = $true)][string]$ClassName
        )

        try
            {
                # Remove all instances first
                $instances = Get-CimInstance -Namespace $Namespace -ClassName $ClassName -ErrorAction SilentlyContinue
                if ($instances)
                    {
                        foreach ($instance in $instances)
                            {
                                if ($PSCmdlet.ShouldProcess($instance.CimInstanceProperties["__PATH"].Value, "Remove CIM instance"))
                                    {
                                        Remove-CimInstance -InputObject $instance -ErrorAction SilentlyContinue
                                    }
                            }
                        Write-CustomOutput -Message "Removed all instances of class: $ClassName" -Type Information
                    }

                # Remove the class itself
                $class = Get-CimClass -Namespace $Namespace -ClassName $ClassName -ErrorAction SilentlyContinue
                if ($class)
                    {
                        if ($PSCmdlet.ShouldProcess("$Namespace\$ClassName", "Remove CIM class"))
                            {
                                # Use WMI to delete the class (CIM doesn't support class deletion directly)
                                $wmiPath = "\\.\root\supportassist:$ClassName"
                                $wmiClass = [wmiclass]$wmiPath
                                $wmiClass.Delete()
                                Write-CustomOutput -Message "Removed class: $ClassName" -Type Information
                                return true
                            }
                    }
            }
        catch
            {
                Write-CustomOutput -Message "Failed to remove class '$ClassName': $($_.Exception.Message)" -Type Warning
                return false
            }
    }

function Import-CIMMOF
    {
        <#
        .SYNOPSIS
            Compiles and imports a MOF file to create CIM classes.

        .DESCRIPTION
            This function takes MOF content as input, saves it to a temporary file,
            compiles it using mofcomp.exe, and cleans up the temporary file.
            Requires Administrator privileges.

        .PARAMETER MofContent
            The MOF content to be compiled.

        .PARAMETER Namespace
            The CIM namespace for the classes (optional, for informational purposes).

        .EXAMPLE
            Import-CIMMOF -MofContent $mofContent
            Compiles the provided MOF content and creates the CIM classes.

        .EXAMPLE
            $mofContent = Get-Content -Path "C:\temp\classes.mof" -Raw
            Import-CIMMOF -MofContent $mofContent
        #>
        param (
            [Parameter(Mandatory = $true)][string]$MofContent
        )

        # Generate timestamp for unique filename
        $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

        # Save MOF to temp file
        $mofFile = Join-Path -Path $env:TEMP -ChildPath "CIM_Classes_$($Timestamp).mof"
        $MofContent | Out-File -FilePath $mofFile -Encoding ASCII -Force

        # Compile MOF using mofcomp with explicit namespace and verbose output
        $mofcompResult = & mofcomp.exe $mofFile 2>&1
        Write-CustomOutput -Message "MOF compilation output: $mofcompResult" -Type Verbose

        # Clean up temp file
        Remove-Item -Path $mofFile -Force -ErrorAction SilentlyContinue

        # Return result based on exit code
        if ($LASTEXITCODE -eq 0)
            {
                Write-CustomOutput -Message "MOF compilation successful" -Type Verbose
                return $true
            }
        else
            {
                Write-CustomOutput -Message "MOF compilation failed with exit code: $LASTEXITCODE" -Type Warning
                return $false
            }
    }

function Test-CIMClass
    {
        <#
        .SYNOPSIS
            Tests if a CIM class exists in the specified namespace.

        .DESCRIPTION
            This function checks if a CIM class exists in the given namespace
            by attempting to retrieve an instance of the class.

        .PARAMETER Namespace
            The namespace to check for the class.

        .PARAMETER ClassName
            The name of the class to test.

        .PARAMETER ErrorAction
            The error action preference. Default is "stop".

        .OUTPUTS
            Boolean indicating whether the class exists.
        #>
        param (
            [Parameter(Mandatory = $true)][string]$Namespace,
            [Parameter(Mandatory = $true)][string]$ClassName,
            [Parameter(Mandatory = $false)][string]$ErrorHandling = "stop"
        )

        try
            {
                Get-CimInstance -Namespace $Namespace -ClassName $ClassName -ErrorAction $ErrorHandling | Out-Null
                return $true
            }
        catch
            {
                Write-CustomOutput -Message "$ClassName not exist" -Type Warning
                return $false
            }
    }

#########################################################################################################
####                                    Program Section                                              ####
#########################################################################################################
try
    {
        #### generate Logging Resources
        try
            {
                [System.Diagnostics.EventLog]::CreateEventSource($EventSource, $EventName)
                Write-CustomOutput -Message "Event source $EventSource created for log $EventName." -Type Success
            }
        catch
            {
                Write-CustomOutput -Message "Event source $EventSource exist or creation failed (non-critical)." -Type Warning
            }

        # Check for Administrator privileges
        if ((Test-Administrator) -ne $true)
            {
                Write-CustomOutput -Message "This script requires Administrator privileges to create CIM classes." -Type Warning
                Write-CustomOutput -Message "Please run PowerShell as Administrator and try again." -Type Information
                                # write eventlog
                try
                    {
                        Write-EventLog -LogName Dell -Source "SupportAssistCIMXLM" -EntryType error -EventId 11 -Message "This script requires Administrator privileges to create CIM classes."
                    }
                catch
                    {
                        Write-CustomOutput -Message "EventLog write failed" -Type Warning
                    }
                exit 1
            }

        # Validate and adjust XML paths for current context
        $ValidatedXMLPaths = @()
        foreach ($pathObj in $XMLPaths)
            {
                $path = $pathObj.Path
                # Check if path exists and is accessible
                if (Test-Path -Path $path -PathType Container -ErrorAction SilentlyContinue)
                    {
                        # Try to access the path to verify permissions
                        try
                            {
                                $null = Get-ChildItem -Path $path -ErrorAction Stop | Select-Object -First 1
                                $ValidatedXMLPaths += $pathObj
                                Write-CustomOutput -Message "Path accessible: $($pathObj.Name) - $path" -Type Success
                            }
                        catch
                            {
                                Write-CustomOutput -Message "Path not accessible in current context: $($pathObj.Name) - $path" -Type Warning
                            }
                    }
                else
                    {
                        Write-CustomOutput -Message "Path does not exist: $($pathObj.Name) - $path" -Type Warning
                    }
            }

        try
            {
                $ValidatedXMLPathsString = $ValidatedXMLPaths | Out-String
                Write-EventLog -LogName Dell -Source "SupportAssistCIMXLM" -EntryType Information -EventId 10 -Message "Validated XML paths: $ValidatedXMLPathsString"
            }
        catch
            {
                Write-CustomOutput -Message "EventLog write failed" -Type Warning
            }

        # Ensure at least one valid path exists
        if ($ValidatedXMLPaths.Count -eq 0)
            {
                Write-CustomOutput -Message "No valid XML paths accessible in current context. Please check paths and permissions." -Type Warning

                try
                    {
                        Write-EventLog -LogName Dell -Source "SupportAssistCIMXLM" -EntryType Error -EventId 11 -Message "No valid XML paths accessible in current context. Please check paths and permissions."
                    }
                catch
                    {
                        Write-CustomOutput -Message "EventLog write failed" -Type Warning
                    }
                exit 1
            }

        # Replace XMLPaths with validated paths
        $XMLPaths = $ValidatedXMLPaths

        # check if namespace exist
        $namespaceExists = Test-NameSpace -Namespace $CIMNameSpace -ErrorHandling $ErrorAction
        if ($namespaceExists -eq $false)
            {
                Write-CustomOutput -Message "NameSpace does not exist." -Type Warning
                try
                    {
                        Write-EventLog -LogName Dell -Source "SupportAssistCIMXLM" -EntryType Error -EventId 11 -Message "NameSpace does not exist."
                    }
                catch
                    {
                        Write-CustomOutput -Message "EventLog write failed" -Type Warning
                    }
                exit 1
            }

        # Checking all CIM Classes are availible
        foreach ($CIMClass in $CIMClasses)
            {
                # Test if CIM Class exist
                $classExists = Test-CIMClass -Namespace $CIMNameSpace -ClassName $($CIMClass.Classname) -ErrorHandling $ErrorAction
                $CIMClass | Add-Member -MemberType NoteProperty -Name CIMClassExist -Value $classExists
            }

        try
            {
                $CIMClassResults = $CIMClasses | Out-String
                Write-EventLog -LogName Dell -Source "SupportAssistCIMXLM" -EntryType Information -EventId 10 -Message "Validated CIM Classes: `n $CIMClassResults"
            }
        catch
            {
                Write-CustomOutput -Message "EventLog write failed" -Type Warning
            }

        # if one or more are not availible
        if ($CIMClasses.CIMClassExist -contains $false)
            {
                Write-CustomOutput -Message "One or more CIM Classes are missing" -Type Warning

                # Clean existing CIM Classes first
                foreach ($CIMClass in $CIMClasses)
                    {
                        If (($CIMClass.CIMClassExist) -eq $true)
                            {
                                $RemoveResult = Remove-CIMClass -Namespace $CIMNameSpace -ClassName $CIMClass.Classname

                                If ($RemoveResult -eq $true)
                                    {
                                        Write-CustomOutput -Message "$($CIMClass.Classname) is deleted successful" -Type Information
                                        $CIMClass | Add-Member -MemberType NoteProperty -Name DeleteCIM -Value $true
                                    }
                                else
                                    {
                                        Write-CustomOutput -Message "$($CIMClass.Classname) is not deleted" -Type Warning
                                        $CIMClass | Add-Member -MemberType NoteProperty -Name DeleteCIM -Value $false
                                    }
                            }
                        else
                            {
                                Write-CustomOutput -Message "$($CIMClass.Classname) is not found" -Type Information
                                $CIMClass | Add-Member -MemberType NoteProperty -Name DeleteCIM -Value $false
                            }
                    }

                $CIMClassResults = $CIMClasses | Out-String
                try
                    {
                        Write-EventLog -LogName Dell -Source "SupportAssistCIMXLM" -EntryType Information -EventId 10 -Message "Validated CIM Classes: `n $CIMClassResults"
                    }
                catch
                    {
                        Write-CustomOutput -Message "EventLog write failed" -Type Warning
                    }

                # import MOF file to create the CIM Classes
                $ImportResult = Import-CIMMOF -MofContent $MOFClasses

                if ($ImportResult)
                    {
                        Write-CustomOutput -Message "Import MOF file successful" -Type Success -OutputConsole $LoggingConsole

                        try
                            {
                                Write-EventLog -LogName Dell -Source "SupportAssistCIMXLM" -EntryType Information -EventId 10 -Message "Import MOF file successful"
                            }
                        catch
                            {
                                Write-CustomOutput -Message "EventLog write failed" -Type Warning
                            }
                    }
                else
                    {
                        Write-CustomOutput -Message "Import MOF file failed" -Type Warning -OutputConsole $LoggingConsole

                        try
                            {
                                Write-EventLog -LogName Dell -Source "SupportAssistCIMXLM" -EntryType Error -EventId 11 -Message "Import MOF file failed"
                            }
                        catch
                            {
                                Write-CustomOutput -Message "EventLog write failed" -Type Warning
                            }
                        Exit 1
                    }
            }
        else
            {
                Write-CustomOutput -Message "All CIM Classes are availible" -Type Success

                try
                    {
                        Write-EventLog -LogName Dell -Source "SupportAssistCIMXLM" -EntryType Information -EventId 10 -Message "CIM Classes are availible"
                    }
                catch
                    {
                        Write-CustomOutput -Message "EventLog write failed" -Type Warning
                    }
            }

        #get XMLFiles
        foreach ($XMLPath in $XMLPaths)
            {
                # Temp array
                $TempXMLFiles = @()

                Write-CustomOutput -Message "Getting XML files from $XMLPath" -Type Verbose
                $TempXMLFiles = Get-SAXMLDetail -XMLPaths $XMLPath -ServiceTag $ServiceTag

                # Add to main array
                $XMLFiles += $TempXMLFiles
            }

        $XMLResults = $XMLFiles | Out-String
        try
            {
                Write-EventLog -LogName Dell -Source "SupportAssistCIMXLM" -EntryType Information -EventId 10 -Message "Validated XML Files: `n $XMLResults"
            }
        catch
            {
                Write-CustomOutput -Message "EventLog write failed" -Type Warning
            }

        # Process XML files - Write-SAXMLToCIM handles both Scan and Install types automatically
        $XMLImportResult = Write-SAXMLToCIM -XMLPaths $XMLPaths -ServiceTag $ServiceTag -HostName $HostName -Namespace $CIMNameSpace

        $XMLImportResultString = $XMLImportResult | Out-String
        try
            {
                Write-EventLog -LogName Dell -Source "SupportAssistCIMXLM" -EntryType Information -EventId 10 -Message "Imported Information: `n $XMLImportResultString"
            }
        catch
            {
                Write-CustomOutput -Message "EventLog write failed" -Type Warning
            }

        Write-CustomOutput -Message "Script completed successfully" -Type Success
        Exit 0
    }
catch
    {
        Write-CustomOutput -Message "An error occurred: $($_.Exception.Message)" -Type Warning
        Exit 1
    }