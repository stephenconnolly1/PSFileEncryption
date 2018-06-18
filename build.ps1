
<# 
Script to build the FileEncryption module
ConstrainedLanguage mode will not allow you to use the Get-FileHash cmdlet as it's a script modulethat invokes methods on raw types.
#>

# Uncomment this line to ensure you are running in constrained language mode, in line with policy on the target device
# $ExecutionContext.SessionState.LanguageMode="ConstrainedLanguage"
Write-Host "Building ..." 
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$modulePath = (Get-Childitem env:\PSModulePath).Value | %{$_ -Split ';' } | where-object {$_ -like '*User*'}
write-host $modulePath
$modulePath = Join-Path -Path $modulePath -ChildPath 'FileEncryption\'
if (-not (Test-Path $modulePath)) { mkdir $modulePath }
& c:\windows\Microsoft.Net\Framework\v4.0.30319\csc.exe -nologo -reference:C:\WINDOWS\Microsoft.Net\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll -target:library -out:$modulePath\FileEncryption.dll *.cs
if (-not $?) { Write-Error "Failed to compile" } 
Write-Host "Module built"
Get-Module -ListAvailable
Import-Module FileEncryption

# Perform a round trip encrypt and decrypt operation to check the encrypted and decrypted files are OK
Write-Host "Testing module"
$testFile = $MyInvocation.MyCommand.Definition # This script
Write-Host ("Encrypting: {0}" -f $testFile)
$password = ConvertTo-SecureString -String '098usdf9uIUHOUYG&^7y987y897' -Force -AsPlainText
Encrypt-File -InputFile $testFile -OutputFile "${testFile}.crypt" -Password $password -Verbose  
Decrypt-File -InputFile "${testFile}.crypt" -OutputFile "${testFile}.decrypt" -Password $password -Verbose 

# Attempting to check file integrity
if ($ExecutionContext.SessionState.LanguageMode="FullLanguage") {
    Write-Host "Checking integrity of round trip"
    Get-Childitem "${testFile}*"  | Get-FileHash -Algorithm MD5  |FT -Property Hash, @{Name='File'; Expression={Split-Path -Leaf $_.Path} }
    Write-Host "Check that the Hashes of original and decrypted files are the same"    
}

