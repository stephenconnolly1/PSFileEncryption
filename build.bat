@echo off
pushd %~dp0
c:\windows\Microsoft.Net\Framework\v4.0.30319\csc.exe -nologo -reference:C:\WINDOWS\Microsoft.Net\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll -target:library -out:D:\Users\sconnoll\Documents\WindowsPowerShell\Modules\FileEncryption\FileEncryption.dll *.cs || (
    echo Error compiling code
    goto :end
)

PowerShell.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -Command "& {$VerbosePreference='Continue'; Import-Module FileEncryption; $password = ConvertTo-SecureString -String 'mykeymykeymykeymykeymykeymykey123' -Force -AsPlainText; Encrypt-File -InputFile boot2docker.iso -OutputFile boot2docker.iso.crypt -Password $password }"
PowerShell.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -Command "& {$VerbosePreference='Continue'; Import-Module FileEncryption; $password = ConvertTo-SecureString -String 'mykeymykeymykeymykeymykeymykey123' -Force -AsPlainText; Decrypt-File -InputFile boot2docker.iso.crypt -OutputFile boot2docker.iso.decrypt -Password $password }"
REM Test that the round trip leaves the original and en-de-crypted file identical.
PowerShell.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -Command "& { get-childitem *.iso* | Get-FileHash -Algorithm MD5 }"
:end
