using System;
using System.IO;
using System.Text;
using System.Security;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Management.Automation;


/*
USAGE:
$key = Get-CryptoKey $(ConvertTo-SecureString 'asdfasdf' -AsPlainText -Force)
*/
[Cmdlet(VerbsCommon.Get, "CryptoKey", DefaultParameterSetName="PatternParameterSet")]
public class GetKeyCommand : PSCmdlet {
    [Parameter(
        Position=0,
        Mandatory=true
    )]
    public SecureString Key
    {
        get {return key;}
        set {key = value;}
    }
    private SecureString key;

    protected override void ProcessRecord()
    {
        WriteVerbose("Processing Key ...");
        IntPtr valuePtr = IntPtr.Zero;
        try {
          valuePtr = Marshal.SecureStringToGlobalAllocUnicode(key);
          ASCIIEncoding ascii = new ASCIIEncoding();
          Byte[] encodedKey = ascii.GetBytes(Marshal.PtrToStringUni(valuePtr) );
          WriteVerbose(String.Format("Key Length: {0}", encodedKey.Length));
          if (encodedKey.Length > 32)
          {
              Array.Resize(ref encodedKey, 32);
          }
          if (encodedKey.Length < 32)
          {
              int toPad = 32-encodedKey.Length;
              WriteVerbose(String.Format("Padding {0} characters", toPad));
              Array.Resize(ref encodedKey, 32);
              for (int i = (32 - toPad); i < 32; i++)
              {
                  encodedKey[i] = 0x0;
              }
          }
          WriteObject(encodedKey);
        }
        catch (Exception e)
        {
          WriteError (new ErrorRecord(e, "Key Padding Error", ErrorCategory.InvalidOperation, key));
        }
        finally
        {
          Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
        }
    }
}

/*
USAGE:
$CipherText = Encrypt-Bytes -ClearText $bytes -CryptoKey $key
*/
[Cmdlet("Encrypt", "Bytes", DefaultParameterSetName="PatternParameterSet")]
public class EncryptBytesCommand : PSCmdlet {
    [Parameter(
        Position=0,
        Mandatory=true
    )]
    public Byte[] Key
    {
        get {return key;}
        set {key = value;}
    }
    private Byte[] key;

    [Parameter(
        Position=1,
        Mandatory=true
    )]
    public Byte[] ClearText
    {
        get {return clearText;}
        set {clearText = value;}
    }
    private Byte[] clearText;

    protected override void ProcessRecord()
    {
        using(AesManaged Aes = new AesManaged() )
        {
            Aes.Key = key;
            Aes.Padding = PaddingMode.PKCS7;
            Byte[] myIV = new Byte[128/8];
            Array.Copy(key, myIV, 128/8);
            Aes.IV = myIV;
            WriteVerbose(String.Join(",", Aes.Key));
            WriteVerbose(String.Join(",", Aes.IV));
            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = Aes.CreateEncryptor();

            // Create the streams used for encryption.
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    using (BinaryWriter binaryWriter = new BinaryWriter(cryptoStream))
                    {
                        // Write the data to the stream
                        binaryWriter.Write(clearText, 0, clearText.Length);
                    }
                    WriteObject(memoryStream.ToArray());
                }
            }
        }
    }
}

//
/*
USAGE:
$PlainText = Decrypt-Bytes -CipherText $bytes -CryptoKey $key
*/
[Cmdlet("Decrypt", "Bytes", DefaultParameterSetName="PatternParameterSet")]
public class DecryptBytesCommand : PSCmdlet {
    [Parameter(
        Position=0,
        Mandatory=true
    )]
    public Byte[] Key
    {
        get {return key;}
        set {key = value;}
    }
    private Byte[] key;

    [Parameter(
        Position=1,
        Mandatory=true
    )]
    public Byte[] CipherText
    {
        get {return cipherText;}
        set {cipherText = value;}
    }
    private Byte[] cipherText;

    protected override void ProcessRecord()
    {
        using(AesManaged Aes = new AesManaged() )
        {
            WriteVerbose(String.Format("Decrypting.. Array Size:{0}", cipherText.Length ) );
            Aes.Key = key;
            Aes.Padding = PaddingMode.PKCS7;
            Byte[] myIV = new Byte[128/8];
            Array.Copy(key, myIV, 128/8);
            Aes.IV = myIV;
            WriteVerbose(String.Join(",", Aes.Key));
            WriteVerbose(String.Join(",", Aes.IV));
            // Create a decryptor to perform the stream transform.
            ICryptoTransform decryptor = Aes.CreateDecryptor();

            // Create the streams used for encryption.
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                {
                    using (BinaryWriter binaryWriter = new BinaryWriter(cryptoStream))
                    {
                        // Read the data from the ciphertext
                        binaryWriter.Write(cipherText, 0, cipherText.Length);
                    }
                    WriteObject(memoryStream.ToArray());
                }
            }
        }
    }
}

/*
USAGE:
Encrypt-File -InputFile $infile -OutputFile $outfile -CryptoKey $key
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
        Position=3,
        Mandatory=true
    )]
    public Byte[] Key
    {
        get {return key;}
        set {key = value;}
    }
    private Byte[] key;

    protected override void ProcessRecord()
    {
        using(AesManaged Aes = new AesManaged() )
        {
            Aes.Key = key;
            Aes.Padding = PaddingMode.PKCS7;
            Byte[] myIV = new Byte[128/8];
            Array.Copy(key, myIV, 128/8);
            Aes.IV = myIV;
            WriteVerbose(String.Join(",", Aes.Key));
            WriteVerbose(String.Join(",", Aes.IV));
            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = Aes.CreateEncryptor();

            // Create the streams used for encryption.
            using (FileStream fsCrypt = new FileStream(outputFile, FileMode.Create))
            {
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
                            WriteDebug(String.Format("Read {0} bytes",read));
                            WriteProgress(new ProgressRecord( 1, inputFile, String.Format("{0} B of {1}", bytesRead, fileSizeInBytes)));
                            // for the last block, only write the correct number of bytes
                            cryptoStream.Write(buffer, 0, read);
                        }
                    }
                }
            }
        }
    }
}

/*
USAGE:
Decrypt-File -InputFile $infile -OutputFile $outfile -CryptoKey $key
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
        Position=3,
        Mandatory=true
    )]
    public Byte[] Key
    {
        get {return key;}
        set {key = value;}
    }
    private Byte[] key;

    protected override void ProcessRecord()
    {
        using(AesManaged Aes = new AesManaged() )
        {
            Aes.Key = key;
            Aes.Padding = PaddingMode.PKCS7;
            Byte[] myIV = new Byte[128/8];
            Array.Copy(key, myIV, 128/8);
            Aes.IV = myIV;
            WriteVerbose(String.Join(",", Aes.Key));
            WriteVerbose(String.Join(",", Aes.IV));
            // Create an encryptor to perform the stream transform.
            ICryptoTransform decryptor = Aes.CreateDecryptor();

            // Create the streams used for encryption.
            using (FileStream fsCrypt = new FileStream(outputFile, FileMode.Create))
            {
                using (CryptoStream cryptoStream = new CryptoStream(fsCrypt, decryptor, CryptoStreamMode.Write))
                {
                    using (FileStream fsIn = new FileStream(inputFile, FileMode.Open))
                    {
                        // Write the data to the stream
                        Int64 fileSizeInBytes = new FileInfo(inputFile).Length;
                        int read = 0;
                        // Buffer to optimize decryption but avoid memory exhaustion
                        byte[] buffer = new byte[Aes.BlockSize*1024];
                        Int64 bytesRead = 0;
                        while ( (read = fsIn.Read(buffer, 0, buffer.Length)) > 0 )
                        {
                            bytesRead += read;
                            WriteDebug(String.Format("Read {0} bytes",read));
                            WriteProgress(new ProgressRecord( 1, inputFile, String.Format("{0} B of {1}", bytesRead, fileSizeInBytes)));
                            // for the last block, only write the correct number of bytes
                            cryptoStream.Write(buffer, 0, read);
                        }
                    }
                }
            }
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

    /*Returns a byte array containing a (secret) 128-bit key and an IV in the encryption  */
    public byte[] GetKeyAndIV(string password, byte[] salt)
    { 
        using (PasswordDeriveBytes pdb = new PasswordDeriveBytes(password, salt))
        {
            return pdb.CryptDeriveKey("TripleDES", "SHA1", (128/8) + 8, salt); 
        }
    }
} 

/* TODO
// Derive a random salt (8 bytes) value for this encryption session use CreateRandomSalt from https://msdn.microsoft.com/en-us/library/system.security.cryptography.passwordderivebytes(v=vs.110).aspx 
// Derive a session key (128 bits) and an IV (8 bits) from from the (user-supplied) password key and the salt using PasswordDeriveBytes() 
// Check that the derived bytearray is always the same if using the same salt and password (needed for decryption)
// write the salt and IV to the start of the output stream - they aren't secret
// Encrypt the file using the key and from the password and random salt value 
// To decrypt...

*/