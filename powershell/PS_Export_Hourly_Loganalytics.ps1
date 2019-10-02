
[CmdletBinding()]
Param (
  #Query parameters
  [Parameter(Mandatory = $true)][ValidateSet('Alert', 'AuditLogs', 'AzureActivity', 'ContainerLog', 'KubeEvents', 'SecurityAlert', 'SecurityEvent')][string]$SearchCategory,
  [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][DateTime]$StartUTCTime,
  [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][DateTime]$EndUTCTime,
  [Parameter(Mandatory = $false)][Validaterange(1,600)][int]$Timeout = 180,
  #Azure TenantId
  [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$TenantId,
  #Automation Account ApplicationId
  [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$AAApplicationId,
  #Automation Account CertificateThumbprint
  [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$AACertificateThumbprint,
  #Automation Account and LogAnalytics SubscriptionId
  [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SubscriptionId,
  #Keyvault for the LogAnalytics API SP
  [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SPKeyvaultName,
  #LogAnalytics WorkspaceId
  [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$WorkspaceId,
  #Target Storage Account and Share for archiving the logs
  [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$StorageAccountName,
  [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$StorageResourceGroup,
  [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$StorageFileshareName
)

#region functions
Function ConvertFrom-LogAnalyticsJson
{

    [CmdletBinding()]
    [OutputType([Object])]
    Param (
        [parameter(Mandatory=$true)]
        [Object]$data
    )

    $count = 0
    foreach ($table in $data.Tables) {
        $count += $table.Rows.Count
    }

    $objectView = New-Object object[] $count
    $i = 0;
    foreach ($table in $data.Tables) {
        foreach ($row in $table.Rows) {
            # Create a dictionary of properties
            $properties = @{}
            for ($columnNum=0; $columnNum -lt $table.Columns.Count; $columnNum++) {
                $properties[$table.Columns[$columnNum].name] = $row[$columnNum]
            }
            # Then create a PSObject from it. This seems to be *much* faster than using Add-Member
            $objectView[$i] = (New-Object PSObject -Property $properties)
            $null = $i++
        }
    }

    $objectView
}

Function Get-AADToken
{
  Param (
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$TenantId,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ClientId,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ClientSecret,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$OMSAPIResourceURI
  )
    #Get AAD Token
    Write-Verbose "Requesting Azure AD oAuth token"

    #URI to get oAuth Access Token
    $oAuthURI = "https://login.microsoftonline.com/$TenantId/oauth2/token"

    #oAuth token request
    $body = 'grant_type=client_credentials'
    $body += '&client_id=' + $ClientId
    $body += '&client_secret=' + [Uri]::EscapeDataString($ClientSecret)
    $body += '&resource=' + [Uri]::EscapeDataString($OMSAPIResourceURI)

    $response = Invoke-RestMethod -Method POST -Uri $oAuthURI -Headers @{} -Body $body
    $AADToken = "Bearer $($response.access_token)"
    $AADToken
}

Function Invoke-OMSKustoSearchCount
{
  Param (
    [Parameter(Mandatory = $true)][string]$AADToken,

    [Parameter(Mandatory = $true)]
      [ValidateScript({
      try {
        [System.Guid]::Parse($_) | Out-Null
        $true
      } catch {
        $false
      }
    })]
    [string]$WorkspaceId,

    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SearchCategory,
    [Parameter(Mandatory = $false)][Validaterange(1,600)][int]$Timeout = 180,
    [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][string]$ISO8601TimeSpan
  )
  #Constructing queries
  $arrSearchResults = @()
  $SearchCount = 0
  
  #Query for retrieving the number of events for a search category
  $CountQuery = "$SearchCategory | count"
  $OMSAPIResourceURI = "https://api.loganalytics.io"
  $OMSAPISearchURI = "$OMSAPIResourceURI/v1/workspaces/$WorkspaceId/query"
  
  #request header
  $RequestHeader = @{
    'Authorization' = $AADToken
    'Content-Type' = "application/json"
    'prefer' = "wait=$Timeout, v1-response=true"
  }

  #intial query request
  Write-Verbose "invoking intial search request using query `"$CountQuery`""
  Write-Verbose "Timespan: '$ISO8601TimeSpan'"

  #Construct REST request body
  $RequestBody = @{
    "query" = $CountQuery
  }
  If ($PSBoundParameters.ContainsKey('ISO8601TimeSpan'))
  {
    $RequestBody.Add('timespan', $ISO8601TimeSpan)
  }

  $RequestBodyJSON = ConvertTo-Json -InputObject $RequestBody

  #Invoke search REST request
  try{
    $SearchRequest = Invoke-RestMethod -Uri $OMSAPISearchURI -Headers $RequestHeader -Body $RequestBodyJSON -Method Post -Verbose
    Write-Verbose "Parsing Log Analytics Query REST API Results."
    $arrSearchResults += ConvertFrom-LogAnalyticsJson $SearchRequest
    $SearchCount = $arrSearchResults[0].Count
    Write-Verbose "Search Count Result: $SearchCount"
  }
  catch{
    #Print Respone Code if not equal 200 OK
    $responsecode = "$($_.Exception.Response.StatusCode.value__) $($_.Exception.Response.StatusDescription)"
    Write-Warning "Error: Search Count return code: $responsecode"
    $SearchCount = -1
  }
  
  #Return the result
  $SearchCount
}

Function Invoke-OMSKustoSearchQuery
{
  Param (
    [Parameter(Mandatory = $true)][string]$AADToken,

    [Parameter(Mandatory = $true)]
      [ValidateScript({
      try {
        [System.Guid]::Parse($_) | Out-Null
        $true
      } catch {
        $false
      }
    })]
    [string]$WorkspaceId,

    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SearchCategory,
    [Parameter(Mandatory = $false)][Validaterange(1,600)][int]$Timeout = 180,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][int]$RowNumber,
    [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][string]$ISO8601TimeSpan
  )

  #Constructing queries
  $arrSearchResults = @()
  
  #Query for retrieving the events for a search category. Only retrieve max 15000 events per query to avoid overflow
  $InitialQueryTemplate = "set truncationmaxsize=104857600; $SearchCategory | sort by TimeGenerated asc | extend rn=row_number() | where rn > {0} | where rn <= {1}"
  [string]$InitialQuery = [string]::Format($InitialQueryTemplate, $RowNumber, $RowNumber+15000)
  $OMSAPIResourceURI = "https://api.loganalytics.io"
  $OMSAPISearchURI = "$OMSAPIResourceURI/v1/workspaces/$WorkspaceId/query"
    
  #request header
  $RequestHeader = @{
    'Authorization' = $AADToken
    'Content-Type' = "application/json"
    'prefer' = "wait=$Timeout, v1-response=true"
  }

  #intial query request
  Write-Verbose "invoking intial search request using query `"$InitialQuery`""
  Write-Verbose "Timespan: '$ISO8601TimeSpan'"

  #Construct REST request body
  $RequestBody = @{
    "query" = $InitialQuery
  }
  If ($PSBoundParameters.ContainsKey('ISO8601TimeSpan'))
  {
    $RequestBody.Add('timespan', $ISO8601TimeSpan)
  }

  $RequestBodyJSON = ConvertTo-Json -InputObject $RequestBody
  try{
    #Invoke search REST request
    #$SearchRequest = Invoke-WebRequest -UseBasicParsing -Uri $OMSAPISearchURI -Headers $RequestHeader -Body $RequestBodyJSON -Method Post -Verbose
    $SearchRequest = Invoke-RestMethod -Uri $OMSAPISearchURI -Headers $RequestHeader -Body $RequestBodyJSON -Method Post -Verbose

    #process result
    Write-Verbose "Parsing Log Analytics Query REST API Results."
    $arrSearchResults += ConvertFrom-LogAnalyticsJson $SearchRequest
    Write-Verbose "Query Result size: $($arrSearchResults.length)"

    #process error
    $objResponse = $SearchRequest.error
    If ($objResponse -ne $null){
      Write-Warning "Error: Some error messages returned with the request: $objResponse"
      Write-Warning " - Error Code: $($objResponse.code)"
      Write-Warning " - Error Message: $($objResponse.message)"
      Write-Warning " - Inner Error code: $($objResponse.details.innererror.code)"
      Write-Warning " - Inner Error Message: $($objResponse.details.innererror.message)"
    }
  }
  catch{
    #Print Respone Code if not equal 200 OK
    $responsecode = "$($_.Exception.Response.StatusCode.value__) $($_.Exception.Response.StatusDescription)"
    Write-Warning "Error: Search Query return code: $responsecode"
  }
  
  $arrSearchResults
}

Function Get-QueryTimeSpan
{
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][DateTime]$StartUTCTime,
    [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][DateTime]$EndUTCTime
  )

  $StartYear = $StartUTCTime.Year
  $StartMonth = '{0:D2}' -f $StartUTCTime.Month
  $StartDay  = '{0:D2}' -f $StartUTCTime.Day
  $StartHour  = '{0:D2}' -f $StartUTCTime.Hour
  $StartMinute = '{0:D2}' -f 0
  $StartSecond = '{0:D2}' -f 0

  $EndYear = $EndUTCTime.Year
  $EndMonth = '{0:D2}' -f $EndUTCTime.Month
  $EndDay  = '{0:D2}' -f $EndUTCTime.Day
  $EndHour  = '{0:D2}' -f $EndUTCTime.Hour
  $EndMinute = '{0:D2}' -f 0
  $EndSecond = '{0:D2}' -f 0

  $ISO8601TimeSpanTemplate = "{0}-{1}-{2}T{3}:{4}:{5}Z/{6}-{7}-{8}T{9}:{10}:{11}Z"
  $ISO8601TimeSpan = [System.String]::Format($ISO8601TimeSpanTemplate, $StartYear, $StartMonth, $StartDay, $StartHour, $StartMinute, $StartSecond, $EndYear, $EndMonth, $EndDay, $EndHour, $EndMinute, $EndSecond)
  $ISO8601TimeSpan
}

Function Export-ResultToFile
{
  [CmdletBinding()]
  Param (
    
    [Parameter(Mandatory = $true)][psobject[]]$Logs,
    [Parameter(Mandatory = $true)][ValidateScript({Test-Path $_})][string]$OutputDir,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$FileName,
    [Parameter(Mandatory = $true)][ValidateSet('JSON', 'CSV')][string]$OutputFormat
  )

  $OutputFilePath = Join-Path $OutputDir $FileName
  Write-Verbose "Exporting to '$OutputFilePath'..."
  Switch ($OutputFormat)
  {
    'CSV' {$Logs | Export-CSV -LiteralPath $OutputFilePath -NoTypeInformation -Force}
    'JSON' {ConvertTo-JSON -InputObject $Logs | Out-File $OutputFilePath -Force}
  }
  $OutputFilePath
}
#endregion

#Main

Write-Output "************************************************Start the Program************************************************"
Write-Output "Program Start Time: $((get-date).ToUniversalTime())"

#Validate the input parameter
If ($StartUTCTime -gt $EndUTCTime)
{
  #Error Timespan specified
  Write-Warning "Error: End UTC Time is earlier than Start UTC Time...End the Program..."
  Break
}

#Login to the AA
"Logging in to Azure..."

Add-AzureRmAccount `
      -ServicePrincipal `
      -TenantId $TenantId `
      -ApplicationId $AAApplicationId `
      -CertificateThumbprint $AACertificateThumbprint `

#Login to the Subscription
$rmAccount = Set-AzureRmContext -SubscriptionId $SubscriptionId

if (!$rmAccount){
  Write-Warning "Error: Automation Account Login Failed...End the Program..."
  Break
}

Write-Output "Successfully logged in $(Get-Date)"

#Parameter to get oAuth Access Token using Read-LogAnalytics Application SP
$AppIDKeyVault = Get-AzureKeyVaultSecret -VaultName $SPKeyvaultName -Name "Read-LogAnalytics-sp-appid"
$ClientId = $AppIDKeyVault.SecretValueText
$PasswordKeyVault = Get-AzureKeyVaultSecret -VaultName $SPKeyvaultName -Name "Read-LogAnalytics-sp-password"
$ClientSecret = $PasswordKeyVault.SecretValueText
$OMSAPIResourceURI = "https://api.loganalytics.io"

#Get AAD token
$LastAADTokenGenerationTime = (get-date).ToUniversalTime()
$AADToken = Get-AADToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -OMSAPIResourceURI $OMSAPIResourceURI

#Create local directory for log files
$foldername = ".\TempOutput\$WorkspaceId\$SearchCategory"
#Remove the directory if exists
If ((test-path $foldername)) {
   Remove-Item $foldername -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $foldername | Out-Null
Write-Verbose "Folder $foldername on host created"

#Work out the search time span
$UTCNow = (get-date).ToUniversalTime()
If (!$PSBoundParameters.ContainsKey('StartUTCTime') -AND !$PSBoundParameters.ContainsKey('EndUTCTime'))
{
  #If start time and end time not specified, use 30 day as it is the retention period set
  $StartUTCTime = $UTCNow.Date.AddDays(-30)
  $EndUTCTime = $UTCNow.Date.AddDays(-29)
  Write-Verbose "Start UTC Time not specified. using the default retention value which is 30 day ago: '$StartUTCTime'"
  Write-Verbose "End UTC Time not specified. using the default retention value which is 29 day ago: '$EndUTCTime'"
}
ElseIf (!$PSBoundParameters.ContainsKey('StartUTCTime'))
{
  #If start time not specified, use 1 day before end time
  $StartUTCTime = $EndUTCTime.Date.AddDays(-1)
  Write-Verbose "Start UTC Time not specified. using the value which is 1 day before EndUTCTime: '$StartUTCTime'"
}
ElseIf (!$PSBoundParameters.ContainsKey('EndUTCTime'))
{
  #If end time not specified, use 1 day after start time
  $EndUTCTime = $StartUTCTime.Date.AddDays(1)
  Write-Verbose "End UTC Time not specified. using the value which is 1 day after StartUTCTime: '$EndUTCTime'"
}

$QueryTimeSpan = Get-QueryTimeSpan -StartUTCTime $StartUTCTime -EndUTCTime $EndUTCTime
Write-Output "Start Processing the Log Analytics Export for $SearchCategory with Timespan $QueryTimeSpan..."
$CurrentProcessingUTCTime = $StartUTCTime

#Processing query for each hour
While($CurrentProcessingUTCTime -lt $EndUTCTime){

Write-Output "---------------------------------------------------------------------------------------------------------------"
Write-Output "Query Start Time: $((get-date).ToUniversalTime())"
$ISO8601TimeSpan = Get-QueryTimeSpan -StartUTCTime $CurrentProcessingUTCTime -EndUTCTime $CurrentProcessingUTCTime.AddHours(1)
Write-Output "Log Analytics search request ISO 8601 time span: '$ISO8601TimeSpan'."

#Invoke search API
Write-Output "Invoking search request pre-check. Search query: `"$SearchCategory | count`" ... This could take a while"
$SearchCount = Invoke-OMSKustoSearchCount -AADToken $AADToken -WorkspaceId $WorkspaceId -SearchCategory $SearchCategory -ISO8601TimeSpan $ISO8601TimeSpan -Timeout $Timeout

#Process search count result
  If($SearchCount -eq -1){
      Write-Warning "Error: Search Count Failed for $SearchCategory with Timespan $ISO8601TimeSpan, skipping this query..."
  }
  else{
      Write-Output "Total number of event count for the query: $SearchCount"
      Write-Output "Invoking search request. Search query: `"$SearchCategory`"... This could take a while"
      $retrycount = 0
      $queryiteration = 0
      $TotalRetrievedCount = 0
      $TotalRetrievedResult = @()
      $arrLogFiles = @()

      While ($TotalRetrievedCount -lt $SearchCount){
        $SearchResult = @()
        $SearchResult += Invoke-OMSKustoSearchQuery -AADToken $AADToken -WorkspaceId $WorkspaceId -SearchCategory $SearchCategory -ISO8601TimeSpan $ISO8601TimeSpan -RowNumber $TotalRetrievedCount -Timeout $Timeout
        if ($SearchResult.count -eq 0){
            if ($retrycount -gt 0){
                Write-Warning "Error: No results returned in this iteration after retried for 2nd time, ending the run"
                Break
            }else{
                $retrycount++
                Write-Warning "Error: No results returned in this iteration for 1st time, retry now"
                Continue
            }
        }
        $retrycount = 0
        $queryiteration = $queryiteration + 1
        Write-Output "Total number of rows returned in this Iteration $queryiteration`: $($SearchResult.count)"
        $TotalRetrievedResult += $SearchResult
        $TotalRetrievedCount = $TotalRetrievedCount + $SearchResult.count

      
        #Write each query iteration results to a seperate file
        $FileName = "$SearchCategory-Hourly-$($ISO8601TimeSpan.replace(':', '.').split('.')[0])-file$queryiteration`.JSON" 
        $OutputFilePath = Join-Path $FolderName $FileName
        Write-Output $OutputFilePath 
        ConvertTo-JSON -InputObject $SearchResult | Out-File $OutputFilePath -Force
        $FileSize = (Get-Item $OutputFilePath).length/1MB
        Write-Output "Size of file is $FileSize MB" 
        $arrLogFiles += $OutputFilePath

        #Get new AAD token if the elspsed time is larger than 50 mins since last AAD token generation
        If((get-date).ToUniversalTime() -gt $LastAADTokenGenerationTime.AddMinutes(50)){
            $LastAADTokenGenerationTime = (get-date).ToUniversalTime()
            $AADToken = Get-AADToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -OMSAPIResourceURI $OMSAPIResourceURI
        }
      }

      Write-Output "Total number of rows returned by event in $queryiteration iterations: $($TotalRetrievedResult.count)"
      Write-Output "Total number of rows returned by count in $queryiteration iterations: $TotalRetrievedCount"

      #zip and upload files if exists
      if($arrLogFiles){

          #Zip the JSON files
          $ZipFileName = "$SearchCategory-Hourly-$($ISO8601TimeSpan.replace(':', '.').split('.')[0])`.zip" 
          Write-Verbose "Creating zip file"
          $CreateZip = Compress-Archive -LiteralPath $arrLogFiles -DestinationPath $(Join-Path $FolderName $ZipFileName) -CompressionLevel Optimal -Force

          #Delete all individual JSON files after zip
          Write-Verbose "Deleting JSON files"
          Remove-Item $arrLogFiles -Force
      
          #Upload file to Storage Account
          $retrycount = 0
          #Retry for connecting to Storage Account for at most 2 times
          While (!$StorageAccount -AND $retrycount -lt 2){
            $StorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $StorageResourceGroup -Name $StorageAccountName
            $retrycount++
          }
          if($StorageAccount){
            if(!$(Get-AzureStorageFile -Context $StorageAccount.Context -ShareName $StorageFileshareName -Path $SearchCategory)){
                New-AzureStorageDirectory -Context $StorageAccount.Context -ShareName $StorageFileshareName -Path $SearchCategory
            }
            Write-Verbose "Uploading zip file to Storage Account"
            Set-AzureStorageFileContent -Context $StorageAccount.Context -ShareName $StorageFileshareName -Source $(Join-Path $FolderName $ZipFileName) -Path "$SearchCategory\$ZipFileName" -Force
          }
          else{
            Write-Warning "Error: Storage Account cannot be connected, no file was uploaded"
          }
     }
   }

   $CurrentProcessingUTCTime = $CurrentProcessingUTCTime.AddHours(1)
   Write-Output "Query End Time: $((get-date).ToUniversalTime())"

   #Get new AAD token if the elspsed time is larger than 50 mins since last AAD token generation
   If((get-date).ToUniversalTime() -gt $LastAADTokenGenerationTime.AddMinutes(50)){
      $LastAADTokenGenerationTime = (get-date).ToUniversalTime()
      $AADToken = Get-AADToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -OMSAPIResourceURI $OMSAPIResourceURI
   }

}

Write-Output "Completed the Log Analytics Export for $SearchCategory with Timespan $QueryTimeSpan..."

#Remove all local files created
Remove-Item $foldername -Recurse -Force

Write-Output "Program End Time: $((get-date).ToUniversalTime())"
Write-Output "************************************************End the Program************************************************"
#EndMain