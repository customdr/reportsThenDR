[CmdletBinding()]
Param(

    [Parameter(Mandatory = $False)]
    [String]
    $cxDB = "localhost\\SQLExpress",

    [Parameter(Mandatory = $False)]
    [String]
    $dbUser = "",

    [Parameter(Mandatory = $False)]
    [String]
    $dbPass = "",

    [Parameter(Mandatory = $False)]
    [String]
    $cxHost,

    [Parameter(Mandatory = $False)]
    [String]
    $cxUser,

    [Parameter(Mandatory = $False)]
    [String]
    $cxPass,

    [Parameter(Mandatory = $False)]
    [int]
    $runLimitHours,

    [Parameter(Mandatory=$False)]
    [switch]
    $exec,

    [Parameter(Mandatory=$False)]
    [switch]
    $noreports,

    [Parameter(Mandatory=$False)]
    [switch]
    $v
)

# -----------------------------------------------------------------
# This custom data retention script depends
# on the Invoke-SqlCmd2 module
#
# If the module is not already installed,
# execute the following in a Powershell window:
#      Install-Module -Name Invoke-SqlCmd2
# -----------------------------------------------------------------
Import-Module "Invoke-SqlCmd2" -DisableNameChecking

# CxSAST REST API auth values
[String] $CX_REST_GRANT_TYPE = "password"
[String] $CX_REST_SCOPE = "sast_rest_api"
[String] $CX_REST_CLIENT_ID = "resource_owner_client"
# Constant shared secret between this client and the Checkmarx server.
[String] $CX_REST_CLIENT_SECRET = "014DF517-39D1-4453-B7B3-9930C563627C"


# -----------------------------------------------------------------
# Reads config from JSON file
# -----------------------------------------------------------------
Class Config {

    hidden $config
    hidden [IO] $io
    [String] $configFile

    # Constructs and loads configuration from given path
    Config ([String] $configFile) {
        $this.io = [IO]::new()
        $this.configFile = $configFile
        $this.LoadConfig()
    }

    # Loads configuration from configured path
    LoadConfig () {
        try {
            $cp = $this.configFile
            $configFilePath = (Get-Item -Path $cp).FullName
            $this.io.Log("Loading config from $configFilePath")
            $this.config = Get-Content -Path $configFilePath -Raw | ConvertFrom-Json
        }
        catch {
            $this.io.Log("Provided configuration file at [" + $this.configconfigFile + "] is missing / corrupt.")
            exit -1
        }
    }

    [PsCustomObject] GetConfig() {
        return $this.config
    }
}

# -----------------------------------------------------------------
# DateTime Utility
# -----------------------------------------------------------------
Class DateTimeUtil {

    # Gets timestamp in UTC in configured format
    [String] NowUTCFormatted() {
        return $this.Format($this.NowUTC())
    }

    # Gets timestamp in UTC
    [DateTime] NowUTC() {
        return (Get-Date).ToUniversalTime()
    }

    # Converts to UTC and formats
    [String] ToUTCAndFormat([DateTime] $dateTime) {
        return $this.Format($dateTime.ToUniversalTime())
    }

    # Formats time based on configured format
    [String] Format([DateTime] $dateTime) {
        return $dateTime.ToString($script:config.log.timeFormat)
    }

}

# -----------------------------------------------------------------
# Input/Output Utility
# -----------------------------------------------------------------
Class IO {

    # General logging
    static [String] $LOG_FILE = "cx_data_retention.log"
    hidden [DateTimeUtil] $dateUtil = [DateTimeUtil]::new()

    # Logs given message to configured log file
    Log ([String] $message) {
        # Write to log file
        $this.WriteToFile($message, [IO]::LOG_FILE)
        # Also write to console
        $this.Console($message)
    }

    # Write given string to host console
    Console ([String] $message) {
        Write-Host $this.AddTimestamp($message)
    }

    # Write a pretty header output
    WriteHeader() {
        $this.Log("------------------------------------------------------------------------")
        $this.Log("Checkmarx Data Retention (based on locking scans that meet criteria)")
        $this.Log("Checkmarx Manager: $($script:config.cx.host)")
        $this.Log("Checkmarx Database: $($script:config.cx.db.instance)")
        if ($($script:config.cx.db.username)) {
            $this.Log("Database Auth: Using SQLServer Authentication.")
            $this.Log("Please ensure SQLServer Account [$($script:config.cx.db.username)] has sufficient privileges to access data.")
        }
        else {
            $this.Log("Database Auth: Using SQLServer Integrated (Windows) Authentication")
        }
        $this.Log("== Data Retention Parameters ==")
        $this.Log("Days To Retain (Going Back From Today): $($script:config.dataRetention.daysToRetain)")
        $this.Log("Data Retention Runtime Limit (Hours): $($script:config.dataRetention.durationLimitHours)")
        $this.Log("------------------------------------------------------------------------")
    }

    # Utility that writes to given file
    hidden WriteToFile([String] $message, [String] $file) {
        Add-content $file -Value $this.AddTimestamp($message)
    }

    hidden [String] AddTimestamp ([String] $message) {
        return $this.dateUtil.NowUTCFormatted() + ": " + $message
    }
}

# -----------------------------------------------------------------
# Credentials Utility
# -----------------------------------------------------------------
Class CredentialsUtil {

    # Returns a PSCredential object from given plaintext username/password
    [PSCredential] GetPSCredential ([String] $username, [String] $plainTextPassword) {
        [SecureString] $secPassword = ConvertTo-SecureString $plainTextPassword -AsPlainText -Force
        return New-Object System.Management.Automation.PSCredential ($username, $secPassword)
    }
}

# -----------------------------------------------------------------
# Database Client
# -----------------------------------------------------------------
Class DBClient {

    hidden [IO] $io = [IO]::new()
    hidden [PSCredential] $sqlAuthCreds
    hidden [String] $serverInstance

    # Constructs a DBClient based on given server and creds
    DBClient ([String] $serverInstance, [String]$dbUser, [String] $dbPass) {
        $this.serverInstance = $serverInstance
        if ($dbUser -and $dbPass) {
            $this.sqlAuthCreds = [CredentialsUtil]::new().GetPSCredential($dbUser, $dbPass)
        }
    }

    # Executes given SQL using either SQLServer authentication or Windows, depending on given PSCredential object
    [PSObject] ExecSQL ([String] $sql, [PSCustomObject] $parameters) {
        # $this.io.Console("Executing $sql")
        try {
            if ($this.sqlAuthCreds.UserName) {
                $cred = $this.sqlAuthCreds
                return Invoke-Sqlcmd2 -ServerInstance $this.serverInstance -Credential @cred -Query $sql -SqlParameters $parameters
            }
            else {
                return Invoke-Sqlcmd2 -ServerInstance $this.serverInstance -Query $sql -SqlParameters $parameters
            }
        }
        catch {
            $this.io.Log("Database execution error. $($_.Exception.GetType().FullName), $($_.Exception.Message)")
            # Force exit during dev run - runtime savior
            Exit
        }
    }

}


# -----------------------------------------------------------------
# Report Service 
# -----------------------------------------------------------------
Class ReportService {

    hidden [IO] $io
    hidden [DBClient] $dbClient
    hidden [RESTClient] $cxSastRestClient
    hidden [DateTimeUtil] $dateUtil
    hidden [PSCustomObject] $config

    # Constructs a ReportService
    ReportService ([DBClient] $dbClient, [PSCustomObject] $config) {
        $this.io = [IO]::new()
        $this.dateUtil = [DateTimeUtil]::new()
        $this.dbClient = $dbClient
        $this.config = $config
    }

    # Generates reports for given set of scanIds
    GenerateReports(){

        [Hashtable] $sqlParams = @{ }
        # Note the negative daysToRetain, resulting in subtraction
        # where this parameter is used.
        $sqlParams.Add("lookbackInDays", - $($this.config.dataRetention.daysToRetain))

        # Scans for which reports need to be generated.
        # These are the scans that will be DELETED
        [String] $scansToDeleteSQL =
        "SELECT ts.StartTime AS ScanDate, ts.id AS ScanId, p.Name AS ProjectName, p.id AS ProjectId
            FROM cxdb.dbo.taskScans ts JOIN cxdb.dbo.projects p ON ts.ProjectId = p.Id
            WHERE ts.startTime < DATEADD(DAY, @lookbackInDays, GETDATE()) AND ts.is_deprecated = 0"

        [PSObject] $deleteScanIds = $this.dbClient.ExecSQL($scansToDeleteSQL, $sqlParams)
        if ($deleteScanIds) {
            $this.io.Log("Found [$($deleteScanIds.Count)] scans that match removal/report generation criteria.")
        }

        if ($deleteScanIds) {

            # Create a RESTBody specific to CxSAST REST API calls
            $cxSastRestBody = [RESTBody]::new($script:CX_REST_GRANT_TYPE, $script:CX_REST_SCOPE, $script:CX_REST_CLIENT_ID, $script:CX_REST_CLIENT_SECRET)
            # Create a REST Client for CxSAST REST API
            $this.cxSastRestClient = [RESTClient]::new($this.config.cx.host, $cxSastRestBody)
            # Login to the CxSAST server
            [bool] $isLoginOk = $this.cxSastRestClient.login($this.config.cx.username, $this.config.cx.password)

            if ($isLoginOk -eq $True) {
                if ($script:v) {
                    $this.io.Log("Login was successful.")
                }
            }

            # Generate reports for the scans that will be removed by DR
            $this.io.Log("Generating reports for scans that will be removed.")
            $this.io.Log("****")
            $this.io.Log("**** Caution : Generating a large number of reports may cause performance degradation on your Checkmarx deployment during report generation.")
            $this.io.Log("****")

            # Make sure target reports folder exists
            [String] $reportsFolder = $this.config.reports.folder
            If (!(Test-Path $reportsFolder)) {
                New-Item -ItemType Directory -Force -Path $reportsFolder
            }
            $reportsFolder = (Get-Item -Path $reportsFolder).FullName
            
            # Push scans to delete into a stack so we can pop them off later
            [System.Collections.Stack] $scanStack = [System.Collections.Stack]::new()
            [System.Collections.Hashtable] $processingQ = [System.Collections.Hashtable]::new()
            foreach ($result in $deleteScanIds) {            
                $scanStack.Push($result)
            }
            
            do {                

                # Enqueue scans to be processed
                # If we have scans in the stack, pop one, submit report generation and add to processingQ
                while ($processingQ.Count -lt $this.config.reports.nParallel -and $scanStack.Count -gt 0) {
                    
                    # Pop item from stack
                    $result = $scanStack.Pop()
                    $scanId = [int]$result["ScanId"]
                    $projectName = $result["ProjectName"]
                    $scanDate = $result["ScanDate"].ToString()
                    $filename = $reportsFolder + "\CxSAST_" + $projectName.replace(" ", "_") + "_" + $scanDate.replace(" ", "_").replace("/",".").replace(":",".") + ".pdf"

                    # Issue report generation call
                    if ($script:exec) {
                        $reportId = $this.GenerateReport($scanId)
                        $this.io.Log("Requested report for Project: [$projectName], ScanId: [$scanId], Date: [$scanDate]. Report ID is [$reportId].")
                    
                        # Backups are a pre-requisite to data retention. 
                        # Do not proceed if report cannot be generated.
                        if ($reportId -eq -1) {
                            $this.io.Log("Could not generate report for Project: [$projectName], ScanId: [$scanId], Date: [$scanDate]")
                            $this.io.Log("Data retention process cannot proceed without backups. Exiting.")
                            exit -1
                        }

                        # Add the report request to the processing queue
                        $processingQ.Add($reportId, $filename)
                    }
                }

                # If there are report generation requests to track
                if ($processingQ.Count -gt 0) {                    

                    [System.Collections.Hashtable] $toDownload = [System.Collections.Hashtable]::new()
                    foreach ($reportId in $processingQ.Keys) {
                    
                        $filename = $processingQ[$reportId]

                        $status = $this.checkReport($reportId)
                        if ($status -eq "Created") {
                            $toDownload.Add($reportId, $filename)
                        }
                        elseif ($status -eq "Failed") {
                            $this.io.Log("The manager could not generate report file: [$filename]")
                            $this.io.Log("Data retention process cannot proceed without backups. Exiting.")
                            exit -1
                        }
            
                    }
                    # If we have reports that are ready to be downloaded
                    if ($toDownload.Count -gt 0) {
                        foreach ($reportId in $toDownload.Keys) {
                            $filename = $toDownload[$reportId]
                            $this.DownloadReport($reportId, $filename)
                            $processingQ.Remove($reportId)
                        }
                    }

                    Start-Sleep -seconds 1
                }
            }
            while ($scanStack.Count -gt 0)

            $this.io.Log("$($deleteScanIds.Count) reports were downloaded.")

        }
    }


    # Send a report generation request for given scan ID
    [int] GenerateReport([int] $scanId) {
        $body = @{
            reportType = "PDF"
            scanId = "$scanId"        
        }
        
        $response = $this.cxSastRestClient.invokeAPI("/reports/sastScan", 'POST', $body, 0)
        if ($response) {
            return $response.reportId
        }

        return -1
    }

    # Check status of report (given report ID)
    [string] checkReport ([int] $reportId) {
        
        [String] $status = "none"
        
        $response = $this.cxSastRestClient.invokeAPI("/reports/sastScan/$reportId/status", 'GET', $null, 0)
        if ($response) {
            $status = $response.status.value
        }

        return $status
    }

    # Downloads report for given ID to given filename
    DownloadReport([int] $reportId, [String] $filename){        
        if ($script:v) {
            $this.io.Log("Downloading [$reportId] report to [$filename]")
        }
        $this.cxSastRestClient.invokeAPIAndSaveResponse("/reports/sastScan/$reportId", 'GET', $null, 0, $filename)
    }
}

# -----------------------------------------------------------------
# Scan Lock Implementation
# -----------------------------------------------------------------
Class ScanLockService {

    hidden [IO] $io
    hidden [DBClient] $dbClient
    hidden [DateTimeUtil] $dateUtil
    hidden [PSCustomObject] $drConfig

    # Constructs an ScanLockService
    ScanLockService ([DBClient] $dbClient, [PSCustomObject] $drConfig) {
        $this.io = [IO]::new()
        $this.dateUtil = [DateTimeUtil]::new()
        $this.dbClient = $dbClient
        $this.drConfig = $drConfig
    }

    # Unlock all scans
    UnlockScans() {
        if ($script:exec) {
            [String] $unlockScansSQL = "UPDATE cxdb.dbo.taskScans SET IsLocked=0 "
            $this.dbClient.ExecSQL($unlockScansSQL, @{})
        }
    }    

    # Lock scans
    [bool] LockScans() {

        if ($script:v) {
          $this.io.Log("Fetching scans from DB...")
        }

        [String] $totalScansSQL = "SELECT COUNT(*) AS nScans FROM cxdb.dbo.taskScans WHERE is_deprecated = 0"
        [PSObject] $totalScansResult = $this.dbClient.ExecSQL($totalScansSQL, @{})
        [int] $nTotalScans = 0
        if ($totalScansResult) {
          $nTotalScans = [int] $totalScansResult["nScans"]
        }

        # drConfig
        [Hashtable] $sqlParams = @{ }
        # Note the negative daysToRetain, resulting in subtraction
        # where this parameter is used.
        $sqlParams.Add("lookbackInDays", - $($this.drConfig.daysToRetain))

        # Scans that should be LOCKED (Retained)
        [String] $lockScansSQL =
        "SELECT ts.StartTime AS ScanDate, ts.id AS ScanId, p.Name AS ProjectName, p.id AS ProjectId
            FROM cxdb.dbo.taskScans ts JOIN cxdb.dbo.projects p ON ts.ProjectId = p.Id
            WHERE ts.startTime >= DATEADD(DAY, @lookbackInDays, GETDATE()) AND ts.is_deprecated = 0"

        if ($script:v) {
          $this.io.Log("Looking for scans that meet retention criteria.")
          $this.io.Log("CRITERIA: Keep scans from last [$($this.drConfig.daysToRetain)] day(s).")
        }
        [PSObject] $retainScanIds = $this.dbClient.ExecSQL($lockScansSQL, $sqlParams)
        
        if ($script:v) {
            $this.io.Log("Found [$nTotalScans] total scans.")
            if ($retainScanIds) {
                $this.io.Log("Found [$($retainScanIds.Count)] scans that matched RETENTION criteria.")
            }
        }

        [System.Collections.ArrayList] $scansToLock = @()

        if ($retainScanIds) {

            foreach ($result in $retainScanIds) {

                $scanId = [int]$result["ScanId"]
                $scansToLock.Add($scanId)

                if ($script:v) {
                  $projectId = $result["ProjectId"]
                  $projectName = $result["ProjectName"]
                  $scanDate = $result["ScanDate"]
                  $this.io.Log("Will retain scan [ProjectId: $projectId, Project: $projectName, ScanDate: $scanDate, ScanId: $scanId]")
                }
            }

            # Unlock all scans
            $this.UnlockScans()
            
            # Lock only scans that meet filter criteria
            $retainScanIds = $scansToLock -join ","
            if ($script:exec) {
                [String] $lockScansSQL = "UPDATE cxdb.dbo.taskScans SET IsLocked=1 WHERE id in ($retainScanIds)"
                $this.dbClient.ExecSQL($lockScansSQL, @{})
            }

            return $true
        }
        else {
            if ($script:v) {
                $this.io.Log("No scans matched retention criteria.")
            }
            return $false
        }
    
    }
}



# -----------------------------------------------------------------
# REST request body
# -----------------------------------------------------------------
Class RESTBody {

    [String] $grantType
    [String] $scope
    [String] $clientId
    [String] $clientSecret

    RESTBody(
        [String] $grantType,
        [String] $scope,
        [String] $clientId,
        [String] $clientSecret
    ) {
        $this.grantType = $grantType
        $this.scope = $scope
        $this.clientId = $clientId
        $this.clientSecret = $clientSecret
    }
}



# -----------------------------------------------------------------
# REST Client
# -----------------------------------------------------------------
Class RESTClient {

    [String] $baseUrl
    [RESTBody] $restBody

    hidden [String] $token
    hidden [IO] $io = [IO]::new()

    # Constructs a RESTClient based on given base URL and body
    RESTClient ([String] $cxHost, [RESTBody] $restBody) {
        $this.baseUrl = $cxHost + "/cxrestapi"
        $this.restBody = $restBody
    }

    <#
    # Logins to the CxSAST REST API
    # and returns an API token
    #>
    [bool] login ([String] $username, [String] $password) {
        [bool] $isLoginSuccessful = $False
        $body = @{
            username      = $username
            password      = $password
            grant_type    = $this.restBody.grantType
            scope         = $this.restBody.scope
            client_id     = $this.restBody.clientId
            client_secret = $this.restBody.clientSecret
        }

        [psobject] $response = $null
        try {
            $loginUrl = $this.baseUrl + "/auth/identity/connect/token"
            if ($script:v) {
              $this.io.Log("Logging into Checkmarx CxSAST...")
            }
            $response = Invoke-RestMethod -uri $loginUrl -method POST -body $body -contenttype 'application/x-www-form-urlencoded'
        }
        catch {
            if ($script:v) {
              $this.io.Log("$_")
            }
            $this.io.Log("Could not authenticate against Checkmarx REST API. Reason: HTTP [$($_.Exception.Response.StatusCode.value__)] - $($_.Exception.Response.StatusDescription).")
        }

        if ($response -and $response.access_token) {
            $isLoginSuccessful = $True
            # Track token internally
            $this.token = $response.token_type + " " + $response.access_token
        }


        return $isLoginSuccessful
    }

    <#
    # Invokes a given REST API
    #>
    [Object]  invokeAPI ([String] $requestUri, [String] $method, [Object] $body, [int] $apiResponseTimeoutSeconds) {
        return $this.invokeAPIAndSaveResponse([String] $requestUri, [String] $method, [Object] $body, [int] $apiResponseTimeoutSeconds, $null)
    }

    <#
    # Invokes a given REST API
    #>
    [Object] invokeAPIAndSaveResponse ([String] $requestUri, [String] $method, [Object] $body, [int] $apiResponseTimeoutSeconds, [String] $filename) {

        # Sanity : If not logged in, do not proceed
        if ( ! $this.token) {
            throw "Must execute login() first, prior to other API calls."
        }

        $headers = @{
            "Authorization" = $this.token
            "Accept"        = "application/json;v=1.0"
        }

        $response = $null

        try {
            $uri = $this.baseUrl + $requestUri
            if ($method -ieq "GET") {
                if ($filename) {
                    $response = Invoke-RestMethod -Uri $uri -Method $method -Headers $headers -TimeoutSec $apiResponseTimeoutSeconds -OutFile $filename
                }
                else {
                    $response = Invoke-RestMethod -Uri $uri -Method $method -Headers $headers -TimeoutSec $apiResponseTimeoutSeconds
                }
            }
            else {
                $response = Invoke-RestMethod -Uri $uri -Method $method -Headers $headers -Body $body -TimeoutSec $apiResponseTimeoutSeconds
            }
        }
        catch {
            $this.io.Log("REST API call failed : [$($_.exception.Message)]")
            $this.io.Log("Status Code: $($_.exception.Response.StatusCode)")
            if ($script:v) {
              $this.io.Log("$_")
            }
        }

        return $response
    }
}



# -----------------------------------------------------------------
# Data Retention Execution
# -----------------------------------------------------------------
Class DataRetention {

    hidden [IO] $io
    hidden [PSObject] $config
    hidden [int] $numOfScansToKeep = 0
    hidden [RESTClient] $cxSastRestClient

    DataRetention([PSObject] $config) {
        $this.io = [IO]::new()
        $this.config = $config
    }

    # Executes data retention
    Execute() {

        # Create a RESTBody specific to CxSAST REST API calls
        $cxSastRestBody = [RESTBody]::new($script:CX_REST_GRANT_TYPE, $script:CX_REST_SCOPE, $script:CX_REST_CLIENT_ID, $script:CX_REST_CLIENT_SECRET)
        # Create a REST Client for CxSAST REST API
        $this.cxSastRestClient = [RESTClient]::new($this.config.cx.host, $cxSastRestBody)
        # Login to the CxSAST server
        [bool] $isLoginOk = $this.cxSastRestClient.login($this.config.cx.username, $this.config.cx.password)

        if ($isLoginOk -eq $True) {
          if ($script:v) {
            $this.io.Log("Login was successful.")
          }
          $this.StartDataRetention($this.config.dataRetention.durationLimitHours)
        }

    }

    # Call data retention start
    [Object] StartDataRetention ([int] $dataRetentionDurationLimitHrs) {
        $this.io.Log("Initiated data retention. The process will run in the background and may take a while, depending on criteria used.")

        $dataRetentionParams = @{
          NumOfSuccessfulScansToPreserve = 0
          durationLimitInHours = $dataRetentionDurationLimitHrs
        }
        [String] $apiUrl = "/sast/dataRetention/byNumberOfScans"
        [PSObject] $resp = $null
        if ($script:exec) {
            $resp = $this.cxSastRestClient.invokeAPI($apiUrl, 'POST', $dataRetentionParams, 0)
        }
        else {
          $this.io.Log("Dry-run. No scans removed.")
        }
        return $resp
    }

}


# ========================================== #
# ============ Execution Entry ============= #
# ========================================== #

[PSCustomObject] $config = [Config]::new(".\rbc_data_retention_config.json").GetConfig()

# Override config from command line params, if provided
if ($dbUser) { $config.cx.db.username = $dbUser }
if ($dbPass) { $config.cx.db.password = $dbPass }
if ($cxUser) { $config.cx.username = $cxUser }
if ($cxPass) { $config.cx.password = $cxPass }
if ($cxHost) { $config.cx.host = $cxHost }
if ($runLimitHours) { $config.dataRetention.durationLimitHours = $runLimitHours }
if ($config.reports.nParallel -lt 1) {
    $config.reports.nParallel = [int32]::MaxValue
}

[IO] $io = [IO]::new()
$io.WriteHeader()

if (!$exec) {
    $io.Log("")
    $io.Log("===========================================================================")
    $io.Log("========== THIS IS A DRY RUN (default). No changes will be made. ==========")
    $io.Log("==========                                                       ==========")
    $io.Log("========== To execute data retention, use -exec parameter.       ==========")
    if (!$v) {
      $io.Log("==========       -v for verbose output.                          ==========")
    }
    $io.Log("===========================================================================")
    $io.Log("")
}

[bool] $runDR = $false

try 
{
    [DBClient] $dbClient = [DBClient]::new($config.cx.db.instance, $config.cx.db.username, $config.cx.db.password)
    [ScanLockService] $scanLockService = [ScanLockService]::new($dbClient, $config.dataRetention)
    [ReportService] $reportService = [ReportService]::new($dbClient, $config)
    [DataRetention] $dataRetention = [DataRetention]::new($config)
    [bool] $runDR = $scanLockService.LockScans()
    if ($runDR) {
        if (!$noreports) {
            $reportService.GenerateReports()
        }
        $dataRetention.Execute()
    }
}
catch {
    $io.Log("$_")    
    exit -1
}

