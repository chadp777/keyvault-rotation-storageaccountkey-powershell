using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

function RegenerateSas($keyId, $providerAddress){
    Write-Host "Regenerating key. Id: $keyId Resource Id: $providerAddress"
    
    $storageAccountName = ($providerAddress -split '/')[8]
    $resourceGroupName = ($providerAddress -split '/')[4]
    
    #regenerate sas uri
    $context = (Get-AzStorageAccount -ResourceGroupName $resourceGroupName -AccountName $storageAccountName).context
    Write "Context: $context"
    $newSasValue = New-AzStorageAccountSASToken -Context $context -Service Blob,Table -ResourceType Service,Container,Object -Permission "rwlcu" `
    -ExpiryTime (Get-Date).AddDays(61)

    return $newSasValue
}

function AddSecretToKeyVault($keyVaultName,$secretName,$newAccessKeyValue,$exprityDate,$tags){
    
    $secretvalue = ConvertTo-SecureString "$newAccessKeyValue" -AsPlainText -Force
    Set-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretName -SecretValue $secretvalue -Tag $tags -Expires $expiryDate

}

function GetAlternateCredentialId($keyId){
    $validCredentialIdsRegEx = 'key[1-2]'
    
    If($keyId -NotMatch $validCredentialIdsRegEx){
        throw "Invalid credential id: $keyId. Credential id must follow this pattern:$validCredentialIdsRegEx"
    }
    If($keyId -eq 'key1'){
        return "key2"
    }
    Else{
        return "key1"
    }
}

function RoatateSecret($keyVaultName,$secretName){
    #Retrieve Secret
    $secret = (Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretName)
    Write-Host "Secret Retrieved"
    
    #Retrieve Secret Info
    $validityPeriodDays = $secret.Tags["ValidityPeriodDays"]
    $credentialId=  $secret.Tags["CredentialId"]
    $providerAddress = $secret.Tags["ProviderAddress"]
    
    Write-Host "Secret Info Retrieved"
    Write-Host "Validity Period: $validityPeriodDays"
    Write-Host "Credential Id: $credentialId"
    Write-Host "Provider Address: $providerAddress"

    #Get Credential Id to rotate - alternate credential
    $alternateCredentialId = GetAlternateCredentialId $credentialId
    Write-Host "Alternate credential id: $alternateCredentialId"

    #Regenerate alternate SAS URI in provider
    $newAccessKeyValue = RegenerateKey $alternateCredentialId $providerAddress
    Write-Host "SAS URI regenerated. SAS URI Id: $alternateCredentialId Resource Id: $providerAddress"

    #Add new SAS URI to Key Vault
    $newSecretVersionTags = @{}
    $newSecretVersionTags.ValidityPeriodDays = $validityPeriodDays
    $newSecretVersionTags.CredentialId=$alternateCredentialId
    $newSecretVersionTags.ProviderAddress = $providerAddress

    $expiryDate = (Get-Date).AddDays([int]$validityPeriodDays).ToUniversalTime()
    AddSecretToKeyVault $keyVaultName $secretName $newAccessKeyValue $expiryDate $newSecretVersionTags

    Write-Host "New SAS URI added to Key Vault. Secret Name: $secretName"
}


# Write to the Azure Functions log stream.
Write-Host "HTTP trigger function processed a request."

Try{
    #Validate request paramaters
    $keyVaultName = $Request.Query.keyVaultName
    $secretName = $Request.Query.SecretName
    if (-not $keyVaultName -or -not $secretName ) {
        $status = [HttpStatusCode]::BadRequest
        $body = "Please pass a keyVaultName and SecretName on the query string"
        break
    }
    
    Write-Host "Key Vault Name: $keyVaultName"
    Write-Host "Secret Name: $secretName"
    
    #Rotate secret
    Write-Host "Rotation started. Secret Name: $secretName"
    RoatateSecret $keyVaultName $secretName

    $status = [HttpStatusCode]::Ok
    $body = "Secret Rotated Successfully"
     
}
Catch{
    $status = [HttpStatusCode]::InternalServerError
    $body = "Error during secret rotation"
    Write-Error "Secret Rotation Failed: $_.Exception.Message"
}
Finally
{
    # Associate values to output bindings by calling 'Push-OutputBinding'.
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $status
        Body = $body
    })
}

