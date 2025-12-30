<#
_author_ = dell
_version_ = 1.0.0
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

#>

<#
    .Synopsis
    This function retrieves data from the Dell SupportAssist for Business CIM class and returns the results
    .DESCRIPTION
    This powershell function queries the Dell SupportAssist for Business WMI/CIM class to collect system-specific information, such as hardware details, warranty status, and telemetry data, and outputs it for further processing or reporting.

    .Parameter Output
        This parameter is the short name of the CIM Class:

        System = DSA_SystemInformation
        Case = DSA_CaseInformation
        Alert = DSA_AlertInformation
        Registration = DSA_RegistrationInformation
        RemoteAction = DSA_RemoteAction (only for Business version 4.9 and later)


    .Example
        To get the warranty details of a device by using SA CIM Class
        get-SupportAssistCIMData -Output System
#>

function get-SupportAssistCIMData
    {
        param   (
                    [Parameter(mandatory=$true)][ValidateSet("System","Case","Alert","Registration","RemoteAction")][String]$Output
                )

        ##################################################
        #### Static Values                            ####
        ##################################################
        $today = Get-Date
        $WarningDays = 90

        try
            {
                $CIMClassName = switch ($Output)
                    {
                        "System" { "DSA_SystemInformation" }
                        "Case" { "DSA_CaseInformation" }
                        "Alert" { "DSA_AlertInformation" }
                        "Registration" { "DSA_RegistrationInformation" }
                        "RemoteAction" { "DSA_RemoteAction" }
                    }

                $CIMDetails = Get-CimInstance -Namespace root/SupportAssist -ClassName $CIMClassName -ErrorAction Stop

                # cover if CIM Class is not available
                if ($null -eq $CIMDetails)
                    {
                        Write-Information -MessageData "$CIMClassName have no datas" -InformationAction Continue
                        Return "noData"
                    }

                # Additional Values and translations based on the CIM Class

                # DSA_SystemInformation

                if ($Output -eq "System")
                    {
                        $SupportPackage = switch ($CIMDetails.Entitlement)
                            {
                                0 {""}
                                1 {"Basic"}
                                2 {"ProSupport"}
                                3 {"ProSupport Plus"}
                                4 {"Premium"}
                                5 {"Premium Support Plus"}
                                6 {"ProSupport Flex for Client"}
                                7 {"Unknown Warranty"}
                                Default {"Unknown Warranty"}
                            }

                        $EntitlementExpiryDate = [datetime]$CIMDetails.EntitlementExpiryDate
                        $DaysCount = (New-TimeSpan -Start $today -End $EntitlementExpiryDate).Days

                        # waring if support is less than 90 days of support
                        If ($DaysCount -lt $WarningDays)
                            {
                                $CIMDetails | Add-Member -MemberType NoteProperty -Name "SupportLessThan$WarningDays" -Value $true
                            }
                        else
                            {
                                $CIMDetails | Add-Member -MemberType NoteProperty -Name "SupportLessThan$WarningDays" -Value $false
                            }

                        # Add new members to the CIM Class
                        $CIMDetails | Add-Member -MemberType NoteProperty -Name "EntitlementName" -Value $SupportPackage
                        $CIMDetails | Add-Member -MemberType NoteProperty -Name "SupportExpiryInDays" -Value $DaysCount

                    }
                elseif ($Output -eq "Case")
                    {
                        $SupportType = switch ($CIMDetails.Type)
                            {
                                0 {"any other support request"}
                                1 {"support request to get support from Dell technical support"}
                                2 {"support request for parts dispatch"}
                                Default {"Unknown"}
                            }

                        $SupportStatus = switch ($CIMDetails.Status)
                            {
                                0 {"the support request has been submitted"}
                                1 {"the support request is open"}
                                2 {"the support request is reopened"}
                                3 {"the support request is closed"}
                                4 {"the support request is in progress"}
                                5 {"the customer has deferred the support request"}
                                6 {"the support request is closed"}
                                Default {"Unknown"}
                            }

                        # Add new members to the CIM Class
                        $CIMDetails | Add-Member -MemberType NoteProperty -Name "TypeName" -Value $SupportType
                        $CIMDetails | Add-Member -MemberType NoteProperty -Name "StatusName" -Value $SupportStatus
                    }
                elseif ($Output -eq "Alert")
                    {
                        # no translation required
                    }
                elseif ($Output -eq "Registration")
                    {
                        $AppRegistration = switch ($CIMDetails.IsRegistrationDone)
                            {
                                $true {"SupportAssist is registered with Dell"}
                                Default {"SupportAssist is not registered with Dell"}
                            }

                        # Split RegistrationErrorCode value
                        $AppRegistrationCode = ($CIMDetails.RegistrationErrorCode).Split(" : ")[1]
                        $CIMDetails.RegistrationErrorCode = ($CIMDetails.RegistrationErrorCode).Split(" : ")[0]

                        # Add new members to the CIM Class
                        $CIMDetails | Add-Member -MemberType NoteProperty -Name "IsRegistrationName" -Value $AppRegistration
                        $CIMDetails | Add-Member -MemberType NoteProperty -Name "RegistrationCodeName" -Value $AppRegistrationCode
                    }
                elseif ($Output -eq "RemoteAction")
                    {
                        <# Action when this condition is true #>
                    }

                # Remove PSComputerName from the object
                $CIMDetails = $CIMDetails | Select-Object -Property * -ExcludeProperty PSComputerName,CimInstanceProperties,CimSystemProperties

                # Return the object
                Return $CIMDetails
            }
        catch
            {
                if($Output -eq "RemoteAction")
                    {
                        Write-Information -MessageData "Infromation: Class RemoteAction is supported by SupportAssist for Business Version 4.9 and later" -InformationAction Continue
                    }
                else
                    {
                        Write-Information -MessageData "Error: $($_.Exception.Message)" -InformationAction Continue
                    }
            }
    }

# call the function first and run this line later in your script
#get-SupportAssistCIMData -Output System
#get-SupportAssistCIMData -Output Case
#get-SupportAssistCIMData -Output Alert
#get-SupportAssistCIMData -Output Registration
#get-SupportAssistCIMData -Output RemoteAction