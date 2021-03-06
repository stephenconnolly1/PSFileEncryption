
/*
Cmdlet to encrypt a file using a password, similar to OpenSSL symmetric encryption function.
The Password is salted and used to generated an encryption key and an initialization vector.
The Salt and IV is generated each time a file is encrypted to guard against known-plaintext
attacks. 
The password Salt and IV are stored as a header in the encrypted file. The salt allows the 
Key to be regenerated reliably from the password and the IV is used for the decryption of the remainder 
of the file.
 */
using System;
using System.IO;
using System.Text;
using System.Security;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Management.Automation;
using Microsoft.PowerShell.Commands;
/*
USAGE:
$pwd = Read-Host -AsSecureString
Encrypt-File -InputFile $infile -OutputFile $outfile -Password $pwd
*/
[Cmdlet("Encrypt", 
        "File", 
        DefaultParameterSetName="LiteralParameterSet",
        SupportsShouldProcess = true
        )]
public class EncryptFileCommand : PSCmdlet {
    [Parameter(
        Position=0,
        Mandatory=true    
    )]
    [ValidateNotNullOrEmpty]
    public String InputFile
    {
        get {return inputFile;}
        set {inputFile = value;}
    }
    private String inputFile; 

    [Parameter(
        Position=1,
        Mandatory=true
    )]
    [ValidateNotNullOrEmpty]
    public String OutputFile
    {
        get {return outputFile;}
        set {outputFile = value;}
    }
    private String outputFile; 

    [Parameter(
        Position=2,
        Mandatory=true
    )]
    public SecureString Password
    {
        get {return password;}
        set {password = value;}
    }
    private SecureString password;

    protected override void ProcessRecord()
    {
        byte[] salt = new byte[64/8]; 
        byte[] myKey = new byte[KeyDeriver.AESKeySize/8];
        byte[] myIV = new byte[128/8];

        try 
        {
            if (!KeyDeriver.IsPasswordComplex(password, this) )
            {
                throw new ArgumentException(
                    String.Format("Password is not complex enough. It should be {0} characters long and have at least one upper, lower, digit and punctuation character", KeyDeriver.minPasswordLength)
                    );
            }

            // Resolve file paths
            // This will hold information about the provider containing
            // the items that this path string might resolve to.                
            ProviderInfo provider;
            // This will be used by the method that processes literal paths
            PSDriveInfo drive;
            string inputFilePath = this.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
                        inputFile, out provider, out drive);
            if (KeyDeriver.IsFileSystemPath(provider, inputFilePath, this) == false) 
            {   
                return;
            }

            string outputFilePath = this.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
                        outputFile, out provider, out drive);
            if (KeyDeriver.IsFileSystemPath(provider, outputFilePath, this) == false) 
            {   
                return;
            }
            if (! ShouldProcess(String.Format("{0}->{1}", inputFilePath, outputFilePath ), "Encrypt"))
            {   
                return;
            }
            WriteVerbose(String.Format("Encrypting {0} to {1}", inputFilePath, outputFilePath));

            using(AesManaged Aes = new AesManaged() )
            {
                // Generate random salt and IV for each encryption session to avoid plaintext attacks
                salt = KeyDeriver.CreateRandomSalt(64/8);
                myIV = KeyDeriver.CreateRandomSalt(128/8);
                // Make key derivation expensive to slow down brute force attacks
                myKey = KeyDeriver.GetKey(password, salt);
                Aes.Key = myKey;
                Aes.IV = myIV;
                Aes.Padding = PaddingMode.PKCS7;
                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = Aes.CreateEncryptor();

                // Create the streams used for encryption.
                using (FileStream fsCrypt = new FileStream(outputFilePath, FileMode.Create))
                {
                    // Write these (non-secret) bits of data to the stream so the decryptor can decrypt!! 
                    fsCrypt.Write(salt, 0, salt.Length);
                    fsCrypt.Write(Aes.IV, 0, Aes.IV.Length);
                    using (CryptoStream cryptoStream = new CryptoStream(fsCrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (FileStream fsIn = new FileStream(inputFilePath, FileMode.Open))
                        {
                            // Write the data to the stream
                            Int64 fileSizeInBytes = (new FileInfo(inputFile)).Length;
                            int read = 0;
                            // Buffer to optimize encryption but avoid memory exhaustion
                            byte[] buffer = new byte[Aes.BlockSize*1024];
                            Int64 bytesRead = 0;
                            while ( (read = fsIn.Read(buffer, 0, buffer.Length)) > 0 )
                            {
                                bytesRead += read;
                                WriteDebug(String.Format("Read {0} bytes", read));
                                WriteProgress(new ProgressRecord(1, inputFilePath, String.Format("{0} B of {1}", bytesRead, fileSizeInBytes)));
                                // for the last block, only write the correct number of bytes
                                cryptoStream.Write(buffer, 0, read);
                            }
                        }
                    } 
                }
            }
        }
        catch (Exception e) 
        {
            WriteError(new ErrorRecord(e, e.StackTrace, ErrorCategory.DeviceError, null ));
        }
        finally 
        {
            Array.Clear(salt, 0, salt.Length); 
            Array.Clear(myKey, 0, myKey.Length);
            Array.Clear(myIV, 0, myIV.Length);
        }
    }
}

/*
USAGE:
$pwd = Read-Host -AsSecureString
Decrypt-File -InputFile $infile -OutputFile $outfile -Password $pwd
*/
[Cmdlet("Decrypt", "File", DefaultParameterSetName="PatternParameterSet")]
public class DecryptFileCommand : PSCmdlet {
    [Parameter(
        Position=0,
        Mandatory=true
    )]
    public String InputFile
    {
        get {return inputFile;}
        set {inputFile = value;}
    }
    private String inputFile; 

    [Parameter(
        Position=1,
        Mandatory=true
    )]
    public String OutputFile
    {
        get {return outputFile;}
        set {outputFile = value;}
    }
    private String outputFile; 

    [Parameter(
        Position=2,
        Mandatory=true
    )]
    public SecureString Password
    {
        get {return password;}
        set {
                password = value;
        }
    }
    private SecureString password;


    protected override void ProcessRecord()
    {
        byte[] salt = new byte[8]; 
        byte[] myKey = new byte[KeyDeriver.AESKeySize/8];
        byte[] myIV = new byte[128/8];

        try
        {
            if (!KeyDeriver.IsPasswordComplex(password, this) )
            {
                throw new ArgumentException(
                    String.Format("Password is not complex enough. It should be {0} characters long and have at least one upper, lower, digit and punctuation character", KeyDeriver.minPasswordLength)
                    );
            }
            // Resolve file paths
            // This will hold information about the provider containing
            // the items that this path string might resolve to.                
            ProviderInfo provider;
            // This will be used by the method that processes literal paths
            PSDriveInfo drive;
            string inputFilePath = this.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
                        inputFile, out provider, out drive);
            if (KeyDeriver.IsFileSystemPath(provider, inputFilePath, this) == false) 
            {   
                return;
            }

            string outputFilePath = this.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
                        outputFile, out provider, out drive);
            if (KeyDeriver.IsFileSystemPath(provider, outputFilePath, this) == false) 
            {   
                return;
            }
            if (! ShouldProcess(String.Format("{0}->{1}", inputFilePath, outputFilePath ), "Encrypt"))
            {   
                return;
            }
            WriteVerbose(String.Format("Decrypting {0} to {1}", inputFilePath, outputFilePath));

            using(AesManaged Aes = new AesManaged() )
            {
            // read the salt from the file header
            using (FileStream fsIn = new FileStream(inputFilePath, FileMode.Open))
            {
                fsIn.Read(salt, 0, salt.Length);
                myKey = KeyDeriver.GetKey(password, salt);
                // read the IV from the file header (don't reuse the IV or the Salt)
                fsIn.Read(myIV, 0, myIV.Length);
                Aes.IV = myIV;
                Aes.Key = myKey;
                Aes.Padding = PaddingMode.PKCS7;
                // Create an encryptor to perform the stream transform.
                ICryptoTransform decryptor = Aes.CreateDecryptor();
                int offset = salt.Length + myIV.Length;

                // Create the streams used for encryption.
                using (FileStream fsCrypt = new FileStream(outputFilePath, FileMode.Create))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(fsCrypt, decryptor, CryptoStreamMode.Write))
                    {
                            // Write the data to the stream
                            Int64 fileSizeInBytes = (new FileInfo(inputFile)).Length;
                            int read = 0;
                            // Buffer to optimize decryption but avoid memory exhaustion
                            byte[] buffer = new byte[Aes.BlockSize*1024];
                            Int64 bytesRead = 0;
                            fsIn.Seek(offset, SeekOrigin.Begin);
                            while ( (read = fsIn.Read(buffer, 0, buffer.Length)) > 0 )
                            {
                                bytesRead += read;
                                WriteDebug(String.Format("Read {0} bytes", read));
                                WriteProgress(new ProgressRecord( 1, inputFilePath, String.Format("{0} B of {1}", bytesRead, fileSizeInBytes)));
                                // for the last block, only write the correct number of bytes
                                cryptoStream.Write(buffer, 0, read);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) 
        {
            WriteError(new ErrorRecord(e, "There was an error", ErrorCategory.DeviceError, null ));
        } finally
        {
            Array.Clear(salt, 0, salt.Length); 
            Array.Clear(myKey, 0, myKey.Length);
            Array.Clear(myIV, 0, myIV.Length);
        }
    }
}

public class KeyDeriver {
    public const int AESKeySize = 256; // in bits
    public const int minPasswordLength = 8;
    /* 
    Create a pseudo random byte array value of arbitrary length 
    */
    public static byte[] CreateRandomSalt(int length)
    {
        // Create a buffer
        byte[] randBytes;

        if (length >= 1)
        {
            randBytes = new byte[length];
        }
        else
        {
            randBytes = new byte[1];
        }

        // Create a new RNGCryptoServiceProvider.
        RNGCryptoServiceProvider rand = new RNGCryptoServiceProvider();

        // Fill the buffer with random bytes.
        rand.GetBytes(randBytes);

        // return the bytes.
        return randBytes;
    }

    /* Returns a byte array containing a (secret) 128-bit key derived from the password and salt.*/
    public static byte[] GetKey(SecureString password, byte[] salt)
    { 
        
        using (Rfc2898DeriveBytes rdb = new Rfc2898DeriveBytes(SecureStringToByteArray(password), salt, 1024))
        {
            return rdb.GetBytes(KeyDeriver.AESKeySize/8); // Key 
        }
    }

    public static byte[] SecureStringToByteArray(SecureString value) 
    {
        IntPtr valuePtr = IntPtr.Zero;
        try {
            valuePtr = Marshal.SecureStringToGlobalAllocUnicode(value);
            ASCIIEncoding ascii = new ASCIIEncoding();
            return ascii.GetBytes(Marshal.PtrToStringUni(valuePtr) );
        } finally {
            Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
        }
    }

    public static bool IsFileSystemPath(ProviderInfo provider, string path, PSCmdlet context )
    {
        bool isFileSystem = true;
        // check that this provider is the filesystem
        if (provider.ImplementingType != typeof(FileSystemProvider))
        {
            // create a .NET exception wrapping our error text
            ArgumentException ex = new ArgumentException(path +
                " does not resolve to a path on the FileSystem provider.");
            // wrap this in a powershell errorrecord
            ErrorRecord error = new ErrorRecord(ex, "InvalidProvider",
                ErrorCategory.InvalidArgument, path);
            // write a non-terminating error to pipeline
            // TODO pass in a context to allow logging
            context.WriteError(error);
            // tell our caller that the item was not on the filesystem
            isFileSystem = false;
        }
        return isFileSystem;
    }
    public static bool IsPasswordComplex(SecureString password, PSCmdlet context)
    {
        bool hasUpper = false;
        bool hasLower = false;
        bool hasDigit = false;
        bool hasPunctuation = false;
        bool hasNonPrint = false;
        bool isLongEnough = false;

        byte[] toValidate = SecureStringToByteArray(password);
        
        if (toValidate.Length >= KeyDeriver.minPasswordLength) isLongEnough = true;

        foreach(byte chr in toValidate)
        {
            if  (chr <= 31  || chr >= 127)
            {
                // don't allow non-print chrs
                hasNonPrint = true;
                break;
            }
            if  (48 <= chr  && chr <= 57) 
            {
                hasDigit=true;
                continue;
            } 
            if (65 <= chr && chr <= 90)
            {
                hasUpper = true;
                continue;
            }
            if (97 <= chr && chr <= 122)
            {
                hasLower = true;
                continue;
            }
            else
            {
                // other printable chr, so must be punctuation
                hasPunctuation = true;
            }
        }
        // Clean up the heap
        Array.Clear(toValidate, 0, toValidate.Length);
        string msg = @"
        hasUpper: {0}
        hasLower: {1}
        hasDigit: {2}
        hasPunctuation: {3}
        hasNonPrint: {4}
        isLongEnough: {5}
        ";
        context.WriteVerbose(String.Format(msg, hasUpper, hasLower, hasDigit, hasPunctuation, hasNonPrint, isLongEnough));
        if (hasNonPrint || !isLongEnough) return false;
        return hasDigit && hasUpper && hasLower && hasPunctuation; 
    }
}
