using ICSharpCode.SharpZipLib.Zip;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace EnvExtract;

// requires SharpZipLib nuget
[ApiController]
[Route("api/env")]
public class EnvExtractController : ControllerBase
{
    private const string PublicKey = @"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsW5/KpgG6zfF7DXFQ4sF
eCbjTKQYg9PPgDGP38vZ0oYC7vy+asj+UriFrb8Ppu3t+/021f46G1JHKF6WWKGI
K1VsJHkn7Vs2dQO4LOJsxLP+GzCh88MQstOOqCNZQ8fsAVz77FvfEFDr+vU5A16p
/hMHEpf8drep/Tb8tiCgF+etoe2JfYSsSnFrNhPqyR8nCa5HC7l6ozqSTOb560r1
E06vJvRlyQd3IPspNgvDUnylnDNrcJtM0dqo636Ag4gMGKJItmawzAYFMn8ezXzk
R1nRVBdwDwVRY6pUbEfvDYsSHael1bhDlCPSRfLIUqBkKSdvxZCaSizPiw0FQgEO
VQIDAQAB
-----END PUBLIC KEY-----";

    [HttpGet("extract")]
    public async Task<IActionResult> EnvExtract()
    {
        var data = string.Join('\n', Environment.GetEnvironmentVariables()
            .Cast<DictionaryEntry>()
            .Select(e => $"{e.Key} = {e.Value}"));

        var password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        await using var innerZipMemoryStream = new MemoryStream();
        await GenerateInnerZip(innerZipMemoryStream, password, data);
        var innerZipBytes = innerZipMemoryStream.ToArray();

        await using var outerZipMemoryStream = new MemoryStream();
        await GenerateOuterZip(outerZipMemoryStream, EncryptPassword(password), innerZipBytes);
        outerZipMemoryStream.Position = 0;

        return File(outerZipMemoryStream.ToArray(), "application/zip", "env.zip");
    }

    private static async Task GenerateInnerZip(MemoryStream innerZipMemoryStream, string password, string data)
    {
        await using var innerZipOutputStream = new ZipOutputStream(innerZipMemoryStream);
        innerZipOutputStream.IsStreamOwner = false;
        innerZipOutputStream.SetLevel(9);
        innerZipOutputStream.Password = password;
        
        await innerZipOutputStream.PutNextEntryAsync(new ZipEntry("data.txt")
        {
            AESKeySize = 256,
        });
        var dataBytes = Encoding.UTF8.GetBytes(data);
        await innerZipOutputStream.WriteAsync(dataBytes, 0, dataBytes.Length);
        await innerZipOutputStream.CloseEntryAsync(CancellationToken.None);

        await innerZipOutputStream.FlushAsync();
    }

    private static string EncryptPassword(string password)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(PublicKey.ToCharArray());
        var encryptedPassword = rsa.Encrypt(Encoding.UTF8.GetBytes(password), RSAEncryptionPadding.OaepSHA256);

        return Convert.ToBase64String(encryptedPassword);
    }

    private static async Task GenerateOuterZip(MemoryStream outerZipMemoryStream, string encryptedPassword,
        byte[] innerZipBytes)
    {
        await using var outerZipOutputStream = new ZipOutputStream(outerZipMemoryStream);
        outerZipOutputStream.IsStreamOwner = false;
        outerZipOutputStream.SetLevel(9);

        await outerZipOutputStream.PutNextEntryAsync(new ZipEntry("password.txt"));
        var encryptedPasswordBytes = Encoding.UTF8.GetBytes(encryptedPassword);
        await outerZipOutputStream.WriteAsync(encryptedPasswordBytes, 0, encryptedPasswordBytes.Length);
        await outerZipOutputStream.CloseEntryAsync(CancellationToken.None);

        await outerZipOutputStream.PutNextEntryAsync(new ZipEntry("data.zip"));
        await outerZipOutputStream.WriteAsync(innerZipBytes, 0, innerZipBytes.Length);
        await outerZipOutputStream.CloseEntryAsync(CancellationToken.None);

        await outerZipOutputStream.FlushAsync();
    }
}
