using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace TrinitySeal {
    internal class Handler {
        private static byte[] DateTimeSalt = { 113, 89, 244, 75, 122, 148, 231, 235, 67, 190, 135, 104, 127 };

        public static string Payload_DECRYPT(string value) =>
            String_Encryption.DecryptString(
                value,
                SHA256.Create().ComputeHash(Encoding.ASCII.GetBytes(Encoding.Default.GetString(Convert.FromBase64String(Seal.Key)))),
                Encoding.ASCII.GetBytes(Encoding.Default.GetString(Convert.FromBase64String(Seal.Salt))));

        public static string Payload_ENCRYPT(string value) =>
            String_Encryption.EncryptString(
                value,
                SHA256.Create().ComputeHash(Encoding.ASCII.GetBytes(Encoding.Default.GetString(Convert.FromBase64String(Seal.Key)))),
                Encoding.ASCII.GetBytes(Encoding.Default.GetString(Convert.FromBase64String(Seal.Salt))));

        public static string EncryptDateTime(string text) {
            using (var symmetricAlgorithm = Aes.Create()) {
                using (var deriveBytes = new Rfc2898DeriveBytes("datexd", DateTimeSalt)) {
                    symmetricAlgorithm.Key = deriveBytes.GetBytes(32);
                    symmetricAlgorithm.IV = deriveBytes.GetBytes(16);
                    symmetricAlgorithm.Padding = PaddingMode.PKCS7;

                    using (var memoryStream = new MemoryStream()) {
                        using (var stream = new CryptoStream(memoryStream, symmetricAlgorithm.CreateEncryptor(), CryptoStreamMode.Write)) {
                            byte[] bytes = Encoding.Unicode.GetBytes(text);
                            stream.Write(bytes, 0, bytes.Length);
                        }

                        return Convert.ToBase64String(memoryStream.ToArray());
                    }
                }
            }
        }
    }
}