# SupportAssist Scripts

This repository contains a library of PowerShell scripts and projects designed for the deployment, management, and troubleshooting of Dell SupportAssist for Business PCs.

## 📋 Available Scripts

| Script | Description | Category | Folder |
|---|---|---|---|
| `Intune_Compliance_Sensor_DSA_Missing_critical_drivers.ps1` | Detects missing critical drivers via MS Intune Compliance Sensor | Intune Compliance | IntuneCompliance |
| `Intune_Compliance_Sensor_DSA_Missing_critical_drivers.json` | JSON configuration for Intune Compliance Sensor | Intune Compliance | IntuneCompliance |
| `02_Detection_SA_missing_Critical_DriverUpdates.ps1` | Detects missing critical driver updates on Dell devices | Detection | Detection and Remediation |
| `02_Remediation_SA_missing_Critical_DriverUpdates.ps1` | Installs missing critical driver updates on Dell devices | Remediation | Detection and Remediation |
| `01_Detection_SA_registration_failed.ps1` | Checks SupportAssist registration status via WMI | Detection | Detection and Remediation |
| `get-SupportAssistCIMData.ps1` | Retrieves SupportAssist CIM data with readable text translation | Function | FunctionSet |
| `SA_Create_CIM_Classes.ps1` | Converts SupportAssist XML files to CIM classes | Converter | XML to CIM |
| `SA_Clean_older_Scan_XMLFiles.ps1` | Cleans up older Scan/Install XML files | Tool | XML Cleaner |


---


## 📊 Intune Compliance

### Intune Compliance Sensor for Missing Critical Drivers

**Overview**
This project provides a Microsoft Intune Compliance Sensor that detects missing critical drivers on Dell Business PCs. The sensor use a PowerShell script to query Dell SupportAssist and identify devices with missing critical drivers, allowing IT administrators to enforce compliance policies.

**Files**
- `Intune_Compliance_Sensor_DSA_Missing_critical_drivers.ps1` - PowerShell script for detecting missing critical drivers
- `Intune_Compliance_Sensor_DSA_Missing_critical_drivers.json` - JSON configuration for Intune Compliance Sensor

**Usage**
1. Deploy the PowerShell script as an Intune Compliance Script
2. Configure the Compliance Sensor in Intune to run the script
3. Set up compliance policies based on the sensor results

**Detection Logic**
- Queries Dell SupportAssist via Command line interface to check driver status
- Identifies missing critical drivers
- Returns compliance status for Intune policies

**Compliance Status**

| Status | Description |
|---|---|
| DiagnoseError | Error occurred during diagnosis (e.g., script errors) |
| MissingCriticalUpdates | Missing critical updates found on the device |
| SAVersionSupported | SupportAssist version is supported (version is 5.2.1 or higher) |
| UpdatesRequiredRestart | Updates require restart to complete (e.g., Dell BIOS update) |

**Screenshots**

*Checked conditionals*
<img width="988" height="345" alt="Screenshot 2026-07-30 141700" src="https://github.com/user-attachments/assets/4c49882c-8e32-4009-96cc-89fe2b535b3c" />

*Intune Compliance report*
<img width="1004" height="886" alt="image" src="https://github.com/user-attachments/assets/75ffba1f-a4f6-42e0-b760-bacf89700064" />

*User Interface by Company Portal*

<img width="596" height="405" alt="image" src="https://github.com/user-attachments/assets/76cad226-8099-491b-90d3-b797abbf07b5" />
<img width="633" height="382" alt="image" src="https://github.com/user-attachments/assets/4edd5f36-76a4-408b-97be-fa020a811b33" />


---


## 🔍 Checking Registration Status

### Detection Script for Registration Status

**Script:** `01_Detection_SA_registration_failed.ps1`

**Overview**
During automated deployments, it can be difficult to confirm whether a device has successfully registered with Dell TechDirect. Instead of manually cross-referencing your asset lists, this script queries Common Information Model (CIM) to verify the SupportAssist registration status.

If the registration check fails, the script automatically executes `selfdiagnose.exe` and logs the output to the Windows Event Viewer. This provides immediate, actionable details for troubleshooting why the registration failed.

**Use Case**
This script serves as an excellent Microsoft Intune Detection Rule, making it easy to identify unregistered devices missing from your Dell TechDirect portal.

**Screenshots**

*Registration status check*
<img width="1397" height="173" alt="Screenshot 2026-05-05 145311" src="https://github.com/user-attachments/assets/e3cc6af3-e93f-41bc-bc5a-28483bb8a506" />

*Event Viewer detailed telemetry*
<img width="1433" height="615" alt="image" src="https://github.com/user-attachments/assets/7b3a0ad6-57ba-49f1-9d72-366ae1a50555" />

**Note:** You can use similar monitoring tools for detailed telemetry analysis.


---


## 🛠️ Detection and Remediation

### Missing Critical Drivers Detection and Remediation

**Overview**
This script package includes a detection script and a remediation script to identify and install missing critical drivers on Dell devices. Designed for use with Dell TechDirect Remediation or Microsoft Intune.

**Files**
- `02_Detection_SA_missing_Critical_DriverUpdates.ps1` - Detection script
- `02_Remediation_SA_missing_Critical_DriverUpdates.ps1` - Remediation script

**Usage**
- Run the detection script to identify missing critical drivers
- Run the remediation script to install missing critical drivers

**Screenshots**

*Intune Remediation*
<img width="1498" height="529" alt="image" src="https://github.com/user-attachments/assets/465d22c0-6411-4924-bff2-9a718499b801" />

*Dell TechDirect Remediation*
<img width="1077" height="499" alt="image" src="https://github.com/user-attachments/assets/4177d45e-5202-4eda-92df-746dfb662ee9" />


---


## 🔧 Getting SupportAssist CIM Data

### SupportAssist Common Information Model (CIM) Data Retrieval Function

**Script:** `get-SupportAssistCIMData.ps1`

**Overview**
This PowerShell function can be easily integrated into your custom scripts to retrieve Dell SupportAssist CIM data. The function automatically translates numeric values into readable text (e.g., translates Entitlement `3` to `Dell ProSupport`).

**Parameters**

| Parameter | Description |
|---|---|
| `-Output` | Short name of the target CIM Class (see table below) |

**Available CIM Classes**

| Short Name | CIM Class | Notes |
|---|---|---|
| `System` | `DSA_SystemInformation` | System information |
| `Case` | `DSA_CaseInformation` | Case information |
| `Alert` | `DSA_AlertInformation` | Alert information |
| `Registration` | `DSA_RegistrationInformation` | Registration status |
| `RemoteAction` | `DSA_RemoteAction` | Requires SupportAssist for Business PCs version 4.9 or later |

**Example**
To retrieve the warranty details of a device by calling the SupportAssist System CIM Class:

```powershell
get-SupportAssistCIMData -Output System
```

**Screenshots**

*CIM direct query*

<img width="538" height="186" alt="image" src="https://github.com/user-attachments/assets/50ef232c-81e6-4d0e-ba95-d044b9b13730" />

*Using the function*
<img width="1077" height="372" alt="image" src="https://github.com/user-attachments/assets/f99a6af7-cc6b-49a2-ad60-b28b087bce1a" />


---


## 🔄 XML File to Common Information Model (CIM) Conversion

### SupportAssist XML to Common Information Model (CIM) Class Converter

**Script:** `SA_Create_CIM_Classes.ps1`

**Overview**
This PowerShell script reads SupportAssist XML files and creates CIM classes. All SupportAssist data is converted to CIM classes and stored in the specified namespace.

**Parameters**

| Parameter | Description | Default |
|---|---|---|
| `-Namespace` | The CIM namespace where the classes will be created | `root/SupportAssist` |
| `-XMLCustomPath` | The path to the directory containing the XML files | `C:\Temp\DSA` |

**Example**
```powershell
.\SA_Create_CIM_Classes.ps1 -Namespace "root/SupportAssist" -XMLCustomPath "C:\Temp\DSA"
```

**Screenshots**

*XML file structure - Scan*

<img width="684" height="509" alt="2026-08-10 17_28_15-Quick Assist" src="https://github.com/user-attachments/assets/231bba11-100e-4371-91e2-cf300e81cff2" />

*XML file structure - Install*
<img width="927" height="362" alt="2026-08-12 11_49_04-Quick Assist" src="https://github.com/user-attachments/assets/b4992f7e-3cb3-4758-a4e4-603f0803d21a" />

*CIM Scan Details - Package view*
```powershell
Get-CimInstance -Namespace root/SupportAssist -ClassName DSA_DriverScan
```
<img width="1162" height="350" alt="image" src="https://github.com/user-attachments/assets/e7f7b0ee-ffae-482b-8206-a0164eb807cb" />

*CIM Scan Details - Summary*
```powershell
Get-CimInstance -Namespace root/SupportAssist -ClassName DSA_AvailableUpdates
```
<img width="480" height="269" alt="image" src="https://github.com/user-attachments/assets/1ba943a6-e3c7-4b3a-8eb6-89bf3d7299a9" />

*CIM Installation Status - Package view*
```powershell
Get-CimInstance -Namespace root/SupportAssist -ClassName DSA_DriverInstall
```
<img width="708" height="321" alt="image" src="https://github.com/user-attachments/assets/58783cda-984d-4356-8784-7b877a61cdae" />

*CIM Installation Status - Summary*
```powershell
Get-CimInstance -Namespace root/SupportAssist -ClassName DSA_InstallStatus
```
<img width="653" height="125" alt="image" src="https://github.com/user-attachments/assets/60b3197b-5b5f-4074-960c-958f1f0a4637" />

---

## 🧹 SupportAssist CLI XML File Cleanup

### SupportAssist XML File Cleaner

**Script:** `SA_Clean_older_Scan_XMLFiles.ps1`

**Overview**
This PowerShell script is designed for use with Dell SupportAssist for Business Commandline actions. It cleans up older XML files from the report path or profile, helping maintain storage efficiency.

**Parameters**

| Parameter | Description | Default |
|---|---|---|
| `-XMLType` | Specifies the type of XML files to clean. Options: "All", "Scan", or "Install" | "All" |
| `-CleanupMode` | Specifies the cleanup mode. Options: "DeleteAll" or "Keep1" through "Keep10" | "Keep2" |
| `-CustomTempPath` | Specifies the custom temporary path for XML files | "C:\temp" |

**Example**
```powershell
.\SA_Clean_older_Scan_XMLFiles.ps1 -CustomTempPath "C:\Temp\DSA" -CleanupMode "Keep3" -XMLType "Install"
```
This command cleans XML files in the specified custom path, keeping only the 3 latest versions of Install XML files.


---


## 📝 Additional Information

More scripts will be added in the future. Check back regularly for updates.
