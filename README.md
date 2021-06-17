# Goal
Custom data retention based on custom criteria provided by configuration.

Generates PDF reports of scans that will be removed, prior to running data retention.

**By default, the script runs in dry run mode – and does not run DR. This is a fail-safe to prevent accidentally deleting data.**

*To actually run DR, the -exec parameter needs to be explicitly provided.*

# Pre-Requisites
-	Powershell V5 (Ex. Windows 10 has powershell 5.1 installed). https://docs.microsoft.com/en-us/powershell/scripting/install/installing-windows-powershell?view=powershell-6
-	The custom data retention script talks to the Checkmarx database. The powershell script uses the “Invoke-SqlCmd2” module for database functionality. To install the module, execute “Install-Module -Name Invoke-SqlCmd2” in an admin powershell window.

# JSON configuration file
- The configuration file has details of the Checkmarx server (URL and service account), as well as the Checkmarx database server (Instance and optional account).
- If using SQLServer Integrated Authentication, the database account and password fields can be left empty. If explicitly using a database account (SQLServer authentication), make sure the account has access to the Checkmarx databases.
- The Checkmarx service account MUST have the following permissions (I’d recommend creating a custom role for this account in Access Control):
    - Delete Sast Scan
    - Generate Scan Report
- The default configuration is set to retain/keep scans going back one year (365 days). Look for “daysToRetain” in the JSON config file.

You will need to update the relevant fields in the JSON file:
```
{
    "log": {
        "timeFormat" : "R"
    },
    "cx": {
        "host" : "http(s)://YOUR_CHECKMARX_SERVER",
        "username" : "CHECKMARX_SERVICE_ACCOUNT",
        "password" : "CHECKMARX_SERVICE_ACCOUNT_PASSWORD",
        "db": {
            "instance": "YOUR_SQLSERVER\\INSTANCE",
            "username": "SQLSERVER_ACCOUNT",
            "password": "SQLSERVER_PASSWORD"
        }
    },
    "reports": {
        "nParallel": 10,
        "folder": "c:\\temp\\cx_reports"
    },
    "dataRetention": {
        "daysToRetain" : 365,
        "durationLimitHours" : 4
    }
}
```

# Powershell Data Retention Script
The dataretention.ps1 script does the following:
-	Based on criteria defined in the config file, locks scans that need to be preserved.
-	Generates and downloads PDF reports for scans that will be deleted.
-	Initiates the data retention process.

# Running the Powershell Data Retention Script

Here’re the parameters that you can provide to the script:

`-exec`
Explicit flag to run the Data Retention process. If not provided, the script will default to a dry-run.

`-noreports`
If report generation is NOT required. If not provided, the script WILL generate reports by default.

`-v`
Verbose output.

## Examples
Here’re a few example runs:

`>.\dataretention.ps1 -v `

This will run the script in dry-run mode, with verbose output.

`>.\dataretention.ps1 -v -exec`

This will generate backup PDF reports, and then execute the data retention process on the manager, with verbose output.

`>.\dataretention.ps1 -v -exec -noreports`

This will run the data retention on the manager, with verbose output. No backup PDF reports will be generated. Use this ONLY if you do NOT want PDF reports generated.
