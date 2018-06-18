
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

/*
USAGE:
$pwd = Read-Host -AsSecureString
Encrypt-File -InputFile $infile -OutputFile $outfile -Password $pwd
*/
[Cmdlet("Encrypt", "File", DefaultParameterSetName="PatternParameterSet")]
public class EncryptFileCommand : PSCmdlet {
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
        set {password = value;}
    }
    private SecureString password;

    protected override void ProcessRecord()
    {
        byte[] salt = new byte[64/8]; 
        byte[] myKey = new byte[128/8];
        byte[] myIV = new byte[128/8];

        try 
        {
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
                WriteVerbose("Salt: " + String.Join(",", salt));
                WriteDebug("Key: " + String.Join(",", Aes.Key));
                WriteVerbose("IV: "+ String.Join(",", Aes.IV));
                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = Aes.CreateEncryptor();

                // Create the streams used for encryption.
                using (FileStream fsCrypt = new FileStream(outputFile, FileMode.Create))
                {
                    // Write these (non-secret) bits of data to the stream so the decryptor can decrypt!! 
                    fsCrypt.Write(salt, 0, salt.Length);
                    fsCrypt.Write(Aes.IV, 0, Aes.IV.Length);
                    using (CryptoStream cryptoStream = new CryptoStream(fsCrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (FileStream fsIn = new FileStream(inputFile, FileMode.Open))
                        {
                            // Write the data to the stream
                            Int64 fileSizeInBytes = new FileInfo(inputFile).Length;
                            int read = 0;
                            // Buffer to optimize encryption but avoid memory exhaustion
                            byte[] buffer = new byte[Aes.BlockSize*1024];
                            Int64 bytesRead = 0;
                            while ( (read = fsIn.Read(buffer, 0, buffer.Length)) > 0 )
                            {
                                bytesRead += read;
                                WriteDebug(String.Format("Read {0} bytes", read));
                                WriteProgress(new ProgressRecord(1, inputFile, String.Format("{0} B of {1}", bytesRead, fileSizeInBytes)));
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
        set {password = value;}
    }
    private SecureString password;

    protected override void ProcessRecord()
    {
        byte[] salt = new byte[8]; 
        byte[] myKey = new byte[128/8];
        byte[] myIV = new byte[128/8];

        try
        {
            using(AesManaged Aes = new AesManaged() )
            {
            // read the salt from the file header
            using (FileStream fsIn = new FileStream(inputFile, FileMode.Open))
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
                using (FileStream fsCrypt = new FileStream(outputFile, FileMode.Create))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(fsCrypt, decryptor, CryptoStreamMode.Write))
                    {
                            // Write the data to the stream
                            Int64 fileSizeInBytes = new FileInfo(inputFile).Length;
                            int read = 0;
                            // Buffer to optimize decryption but avoid memory exhaustion
                            byte[] buffer = new byte[Aes.BlockSize*1024];
                            Int64 bytesRead = 0;
                            fsIn.Seek(offset, SeekOrigin.Begin);
                            while ( (read = fsIn.Read(buffer, 0, buffer.Length)) > 0 )
                            {
                                bytesRead += read;
                                WriteDebug(String.Format("Read {0} bytes", read));
                                WriteProgress(new ProgressRecord( 1, inputFile, String.Format("{0} B of {1}", bytesRead, fileSizeInBytes)));
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
            return rdb.GetBytes(128/8); // Key 
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
}