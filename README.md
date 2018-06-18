# PowerShell fileEncryption module
A PowerShell module to perform symmetric AES based file encryption and decryption using a key 
derived from a user-provided password

The module is designed to work in Constrained PowerShell Language environments where native methods of 
.NET objects is forbidden. The module is therefore written in C# code and compiled 

## Build instructions
It is possible to build the module locally using the provided build.ps1 file. The script will compile the single code file
into DLL and will attempt to place that in the user's PowerShell module folder within their profile, so no system-level
access is required to install the module.

To build the module

 - From GitHub, download the source code as a .zip file.
 - Right Click the downloaded zip file and select __Properties__.
 - On the General tab check __Unblock__ and click __OK__.
 - Right Click the .zip file and select __Extract All...__.
 - Open a Windows DOS command prompt and change directory to the directory containing the downloaded code
 - Run the following command
   
    `powershell -nologo -noprofile -executionPolicy bypass -file build.ps1`

 - The module will be built and copied into a folder within the user's `$PSModulePath` 
 - Open a PowerShell window and type `Get-Module -ListAvailable`. The FileEncryption module should be listed.

## Usage
<PRE>
    Import-Module FileEncryption
    $Password = Read-Host -AsSecureString
    Encrypt-File -InputFile <i>infile</i> -OutputFile <i>outfile</i> -Password $Password
    Decrypt-File -InputFile <i>infile</i> -OutputFile <i>outfile</i> -Password $Password
</PRE>
