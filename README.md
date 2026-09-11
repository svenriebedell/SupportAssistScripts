# SupportAssist Projects

This repository contains a library of PowerShell scripts and projects designed for the deployment, management, and troubleshooting of Dell SupportAssist for Business PCs.

## Available Scripts/Projects

| Script | Description | Category | Folder |
|---|---|---|---|
| `Intune_Compliance_Sensor_DSA_Missing_critical_drivers.ps1` | Using with MS Intune Compliance Sensor to detect missing critical drivers | Intune Compliance | IntuneCompliance |
| `Intune_Compliance_Sensor_DSA_Missing_critical_drivers.json` | Using with MS Intune Compliance Sensor to detect missing critical drivers | Intune Compliance | IntuneCompliance |
| `02_Detection_SA_missing_Critical_DriverUpdates.ps1` | Checks the registration status of Dell SupportAssist via WMI and provides automated troubleshooting logs. | Detection | Detection and Remediation |
| `02_Remediation_SA_missing_Critical_DriverUpdates` | Checks the registration status of Dell SupportAssist via WMI and provides automated troubleshooting logs. | Remediation | Detection and Remediation |
| `01_Detection_SA_registation_failed.ps1` | Checks the registration status of Dell SupportAssist via WMI and provides automated troubleshooting logs. | Detection | Detection and Remediation |
| `get-SupportAssistCIMData.ps1` | A reusable function that retrieves Dell SupportAssist CIM data and translates numeric status codes into clear text. | Function | FunctionSet |
| `SA_Create_CIM_Classes.ps1` | Updates by SupportAssist CLI create XML files for Scan and Install. These XML files are then converted to CIM classes. | Converter | XML to CIM |
| `SA_Clean_older_Scan_XMLFiles.ps1` | Helping delete older Scan/Install XML-files from a device. | Tool | Cleaner |

---
## Intune Compliance

### Intune Compliance Sensor for Missing Critical Drivers

This project provides a Microsoft Intune Compliance Sensor that detects missing critical drivers on Dell Business PCs. The sensor uses PowerShell scripts to query Dell SupportAssist and identify devices with missing critical drivers, allowing IT administrators to enforce compliance policies.

**Files:**
- `Intune_Compliance_Sensor_DSA_Missing_critical_drivers.ps1` - PowerShell script for detecting missing critical drivers
- `Intune_Compliance_Sensor_DSA_Missing_critical_drivers.json` - JSON configuration for Intune Compliance Sensor

**Usage:**
1. Deploy the PowerShell script as an Intune Compliance Script
2. Configure the Compliance Sensor in Intune to run the script
3. Set up compliance policies based on the sensor results

**Detection Logic:**
- Queries Dell SupportAssist via WMI to check driver status
- Identifies missing critical drivers
- Returns compliance status for Intune policies

**Checked conditionals**
<img width="988" height="345" alt="Screenshot 2026-07-30 141700" src="https://github.com/user-attachments/assets/4c49882c-8e32-4009-96cc-89fe2b535b3c" />

Explain the compliance status:
| Status | Description |
|---|---|
| DiagnoseError | Error occurred during diagnosis like script errors |
| MissingCriticalUpdates | Missing critical updates found on the device |
| SAVersionSupported | SupportAssist version is supported, Version is not 5.2 or higher |
| UpdatesRequiredRestart | Updates require restart to complete update, as example Dell BIOS update |


**Intune Compliance report**
<img width="1004" height="886" alt="image" src="https://github.com/user-attachments/assets/75ffba1f-a4f6-42e0-b760-bacf89700064" />

**User Interface by Company Portal**

<img width="596" height="405" alt="image" src="https://github.com/user-attachments/assets/76cad226-8099-491b-90d3-b797abbf07b5" />
<img width="633" height="382" alt="image" src="https://github.com/user-attachments/assets/4edd5f36-76a4-408b-97be-fa020a811b33" />

---

## Checking Registration Status

**Script:** `01_Detection_SA_registration_failed.ps1`

During automated deployments, it can be difficult to confirm whether a device has successfully registered with Dell TechDirect. Instead of manually cross-referencing your asset lists, this script queries Windows Management Instrumentation (WMI) to verify the SupportAssist registration status.

If the registration check fails, the script automatically executes `selfdiagnose.exe` and logs the output to the Windows Event Viewer. This provides immediate, actionable details for troubleshooting why the registration failed.

**Use Case:**
This script serves as an excellent Microsoft Intune Detection Rule, making it easy to identify unregistered devices missing from your Dell TechDirect portal.

<img width="1397" height="173" alt="Screenshot 2026-05-05 145311" src="https://github.com/user-attachments/assets/e3cc6af3-e93f-41bc-bc5a-28483bb8a506" />

You can drill down into the Event Viewer (or similar monitoring tools) for more detailed telemetry:

<img width="1433" height="615" alt="image" src="https://github.com/user-attachments/assets/7b3a0ad6-57ba-49f1-9d72-366ae1a50555" />


You can use simulare tools too.

---

## Detection and Remediation for use with Dell Techdirect Remediation or Microsoft Intune

### Detection and Remediation script to detect and remediate missing critical drivers

This script package includes a detection script and a remediation script to identify and install missing critical drivers on Dell devices.

**Files:**
- `02_Detection_MissingCriticalDrivers.ps1` - Detection script
- `02_Remediation_InstallMissingCriticalDrivers.ps1` - Remediation script

**Usage:**
- Run the detection script to identify missing critical drivers
- Run the remediation script to install missing critical drivers

This script is designed to be used with Dell Techdirect Remediation or Microsoft Intune.

**Intune Remediation**
<img width="1498" height="529" alt="image" src="https://github.com/user-attachments/assets/465d22c0-6411-4924-bff2-9a718499b801" />

**Dell TechDirect Remediation**
<img width="1077" height="499" alt="image" src="https://github.com/user-attachments/assets/4177d45e-5202-4eda-92df-746dfb662ee9" />

---

## Getting SupportAssist CIM Data

**Script:** `get-SupportAssistCIMData.ps1`

This PowerShell function can be easily integrated into your custom scripts to retrieve Dell SupportAssist CIM data. As an added enhancement, the function automatically translates numeric values into readable text (for example, it translates Entitlement `3` to `Dell ProSupport`).

### Parameters

The `-Output` parameter accepts the short name of the target CIM Class:

| Short Name | CIM Class |
|---|---|
| `System` | `DSA_SystemInformation` |
| `Case` | `DSA_CaseInformation` |
| `Alert` | `DSA_AlertInformation` |
| `Registration` | `DSA_RegistrationInformation` |
| `RemoteAction` | `DSA_RemoteAction` *(Requires SupportAssist for Business PCs version 4.9 or later)* |


### Example

To retrieve the warranty details of a device by calling the SupportAssist System CIM Class:

get-SupportAssistCIMData -Output System

Example for CIM direct

<img width="538" height="186" alt="image" src="https://github.com/user-attachments/assets/50ef232c-81e6-4d0e-ba95-d044b9b13730" />


Same with the function

<img width="1077" height="372" alt="image" src="https://github.com/user-attachments/assets/f99a6af7-cc6b-49a2-ad60-b28b087bce1a" />

---

## Getting SupportAssist XML to CIM Conversion

**Script:** `SA_Create_CIM_Classes.ps1`

This PowerShell script reads SupportAssist XML files and creates CIM classes. All datas of SupportAssist are converted to CIM classes and stored in the specified namespace.

### Parameters

The script accepts the following parameters:

- `-Namespace`: The CIM namespace where the classes will be created (default: `root/SupportAssist`)
- `-XMLCustomPath`: The path to the directory containing the XML files (default: `C:\Temp\DSA`)


### Example

**How looking the XML Files**
*Scan*

<img width="684" height="509" alt="2026-08-10 17_28_15-Quick Assist" src="https://github.com/user-attachments/assets/231bba11-100e-4371-91e2-cf300e81cff2" />

*Install*

<img width="927" height="362" alt="2026-08-12 11_49_04-Quick Assist" src="https://github.com/user-attachments/assets/b4992f7e-3cb3-4758-a4e4-603f0803d21a" />

The script read all SupportAssist data from XML files and create CIM classes at Namespace `root/SupportAssist`:

 .\SA_Create_CIM_Classes.ps1 -Namespace "root/SupportAssist" -$XMLCustomPath "C:\Temp\DSA"

Example for CIM *Scan* Details

*Scan package view*

CLI Call: Get-CimInstance -Namespace root/SupportAssist -ClassName DSA_DriverScan

<img width="1162" height="350" alt="image" src="https://github.com/user-attachments/assets/e7f7b0ee-ffae-482b-8206-a0164eb807cb" />


*Scan summary*

CLI Call: Get-CimInstance -Namespace root/SupportAssist -ClassName DSA_AvailableUpdates
<img width="480" height="269" alt="image" src="https://github.com/user-attachments/assets/1ba943a6-e3c7-4b3a-8eb6-89bf3d7299a9" />


Example for *Installation* status
*Package view*

CLI Call: Get-CimInstance -Namespace root/SupportAssist -ClassName DSA_DriverInstall
<img width="708" height="321" alt="image" src="https://github.com/user-attachments/assets/58783cda-984d-4356-8784-7b877a61cdae" />

*Install summary*

CLI Call: Get-CimInstance -Namespace root/SupportAssist -ClassName DSA_InstallStatus
<img width="653" height="125" alt="image" src="https://github.com/user-attachments/assets/60b3197b-5b5f-4074-960c-958f1f0a4637" />

---

## Clean older SupportAssist XML files from report path or profile

**Script:** `SA_Clean_older_Scan_XMLFiles.ps1`

This PowerShell is for using with your Dell SupportAssist for business Commandline actions. This script will clean up older XML files.

### Parameters

The script accepts the following parameters:

PARAMETER XMLType
   Specifies the type of XML files to clean. Options are "All", "Scan", or "Install".
   Default is "All".

PARAMETER CleanupMode
   Specifies the cleanup mode for XML files. Options are "DeleteAll" or "Keep1" through "Keep10".
   Default is "Keep2".

PARAMETER CustomTempPath
   Specifies the custom temporary path for XML files.
   Default is "C:\temp".

EXAMPLE
   .\SA_Clean_older_Scan_XMLFiles.ps1 -CustomTempPath "C:\Temp\DSA" -CleanupMode "Keep3" -XMLType "Install"
   Cleans XML files in the specified custom path, keeping only the 3 latest versions of Install XML files.


---
**new script will following.**
