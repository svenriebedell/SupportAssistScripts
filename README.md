# SupportAssistScripts

This repository contains a library of PowerShell scripts designed for the deployment, management, and troubleshooting of Dell SupportAssist.

## Available Scripts

| Script | Description |
|---|---|
| `Detection_SA_registration_failed.ps1` | Checks the registration status of Dell SupportAssist via WMI and provides automated troubleshooting logs. |
| `get-SupportAssistCIMData.ps1` | A reusable function that retrieves Dell SupportAssist CIM data and translates numeric status codes into human-readable text. |

---

## Checking Registration Status

**Script:** `Detection_SA_registration_failed.ps1`

During automated deployments, it can be difficult to confirm whether a device has successfully registered with Dell TechDirect. Instead of manually cross-referencing your asset lists, this script queries Windows Management Instrumentation (WMI) to verify the SupportAssist registration status.

If the registration check fails, the script automatically executes `selfdiagnose.exe` and logs the output to the Windows Event Viewer. This provides immediate, actionable details for troubleshooting why the registration failed.

**Use Case:**
This script serves as an excellent Microsoft Intune Detection Rule, making it easy to identify unregistered devices missing from your Dell TechDirect portal.

<img width="1397" height="173" alt="Screenshot 2026-05-05 145311" src="https://github.com/user-attachments/assets/e3cc6af3-e93f-41bc-bc5a-28483bb8a506" />

You can drill down into the Event Viewer (or similar monitoring tools) for more detailed telemetry:

<img width="1433" height="615" alt="image" src="https://github.com/user-attachments/assets/7b3a0ad6-57ba-49f1-9d72-366ae1a50555" />


You can use simulare tools too.



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
<img width="751" height="281" alt="image" src="https://github.com/user-attachments/assets/b2cc34b3-f7a5-4eb4-9f29-4a344e524811" />

Same with the function
<img width="1077" height="372" alt="image" src="https://github.com/user-attachments/assets/f99a6af7-cc6b-49a2-ad60-b28b087bce1a" />

new script will follwing.

