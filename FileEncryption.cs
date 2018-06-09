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
            Aes.IV = new byte[128/8];
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
            Aes.IV = new byte[128/8];
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
