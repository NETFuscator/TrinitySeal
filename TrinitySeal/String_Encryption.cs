using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace TrinitySeal {
    internal class String_Encryption {
        internal static string EncryptString(string plainText, byte[] key, byte[] iv) {
            using (var encryptor = Aes.Create()) {
                encryptor.Mode = CipherMode.CBC;
                encryptor.Key = key;
                encryptor.IV = iv;

                using (var memoryStream = new MemoryStream()) {
                    using (var aesEncryptor = encryptor.CreateEncryptor()) {
                        using (var cryptoStream = new CryptoStream(memoryStream, aesEncryptor, CryptoStreamMode.Write)) {

                            byte[] plainBytes = Encoding.ASCII.GetBytes(plainText);

                            cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                            cryptoStream.FlushFinalBlock();

                            byte[] cipherBytes = memoryStream.ToArray();

                            return Convert.ToBase64String(cipherBytes, 0, cipherBytes.Length);
                        }
                    }
                }
            }
        }

        internal static string DecryptString(string cipherText, byte[] key, byte[] iv) {
            using (var encryptor = Aes.Create()) {
                encryptor.Mode = CipherMode.CBC;
                encryptor.Key = key;
                encryptor.IV = iv;

                using (var memoryStream = new MemoryStream()) {
                    using (var aesDecryptor = encryptor.CreateDecryptor()) {
                        using (var cryptoStream = new CryptoStream(memoryStream, aesDecryptor, CryptoStreamMode.Write)) {

                            byte[] cipherBytes = Convert.FromBase64String(cipherText);

                            cryptoStream.Write(cipherBytes, 0, cipherBytes.Length);
                            cryptoStream.FlushFinalBlock();

                            byte[] plainBytes = memoryStream.ToArray();

                            return Encoding.ASCII.GetString(plainBytes, 0, plainBytes.Length);
                        }
                    }
                }
            }
        }
    }
}
