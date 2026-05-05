# SupportAssistScripts
This script library include different scripts for SupportAssist deployment and management.

|Script|Description|
|---|---|
|Detection_SA_registation_failed.ps1|Checking registration status of Dell SupportAssist|
|get-SupportAssistCIMData.ps1|A function you can integrate in your own scripts to get SupportAssist CIM data|



## Checking registration status.
Detection_SA_registation_failed.ps1

There are scanarien at the the deployment where we are not secure if a device would be registered at the Dell TechDirect. To help you not checking your asset list with Dell TechDirect this script will check by WMI the SupportAssist registration status. If it fail it will run the selfdiagnose.exe and stored the result at the Microsoft Event Viewer. This will give you the required details for a toubleshooting why the registration fails.

This example is for Intune detection rule, shows you easy how to dectect missing devices on your Dell TechDirect.



## Getting SupportAssist CIM Data
function get-SupportAssistCIMData.ps1