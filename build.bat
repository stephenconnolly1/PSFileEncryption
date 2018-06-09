@echo off
pushd %~dp0
c:\windows\Microsoft.Net\Framework\v4.0.30319\csc.exe -nologo -reference:C:\WINDOWS\Microsoft.Net\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll -target:library -out:D:\Users\sconnoll\Documents\WindowsPowerShell\Modules\FileEncryption\FileEncryption.dll *.cs || (
    echo Error compiling code
    goto :end
)

PowerShell.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -Command "& {$VerbosePreference='Continue'; Import-Module FileEncryption; $key = Get-CryptoKey $(ConvertTo-SecureString -String 'mykeymykeymykeymykeymykeymykey123' -Force -AsPlainText); $ciphertext = Encrypt-Bytes -ClearText (0x1,0x2,0x3,0x4) -Key $key; write-output $ciphertext; $plaintext = Decrypt-Bytes -CipherText $ciphertext -Key $key; $plaintext }"
:end
