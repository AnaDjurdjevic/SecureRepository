using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Numerics;



namespace SecureRepository
{
    internal  class Util
    {
        public static byte[] EncryptAes(byte[] plainText, byte[] key, byte[] iv)
        {
            Aes aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Padding = PaddingMode.PKCS7;
            ICryptoTransform encryptor = aes.CreateEncryptor();
            byte[] encryptedBytes = encryptor.TransformFinalBlock(plainText, 0, plainText.Length);
            return encryptedBytes;
        }

        public static byte[] DecryptAes(byte [] cipher, byte[] key, byte[] iv) 
        {
            Aes aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Padding= PaddingMode.PKCS7;
            ICryptoTransform decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(cipher, 0, cipher.Length);
        }


        public static (byte[], byte[]) GenerateRNG()
        {
            byte[] key = RandomNumberGenerator.GetBytes(32);
            byte[] iv = RandomNumberGenerator.GetBytes(16);
            return (key, iv);
        }

        public static void WriteAesParameters((byte[], byte[]) parameters, string path, RSA rsa)
        {
            byte[] aesKey = parameters.Item1;
            byte[] aesIV = parameters.Item2;

            byte[] encryptedKey = rsa.Encrypt(aesKey, RSAEncryptionPadding.Pkcs1);
            byte[] encryptedIV = rsa.Encrypt(aesIV, RSAEncryptionPadding.Pkcs1);

            using (BinaryWriter writer = new BinaryWriter(File.Open(path, FileMode.Create)))
            {
                writer.Write(encryptedKey.Length);
                writer.Write(encryptedKey);
                writer.Write(encryptedIV.Length);
                writer.Write(encryptedIV);
            }
        }

        public static (byte[], byte[]) ReadAesParameters(string path, RSA rsa)
        {
            byte[] encryptedKey, encryptedIV;

            using (BinaryReader reader = new BinaryReader(File.Open(path, FileMode.Open)))
            {
                int encryptedKeyLength = reader.ReadInt32();
                encryptedKey = reader.ReadBytes(encryptedKeyLength);

                int encryptedIVLength = reader.ReadInt32();
                encryptedIV = reader.ReadBytes(encryptedIVLength);
            }

            byte[] aesKey = rsa.Decrypt(encryptedKey, RSAEncryptionPadding.Pkcs1);
            byte[] aesIV = rsa.Decrypt(encryptedIV, RSAEncryptionPadding.Pkcs1);

            return (aesKey, aesIV);
        }
        public static byte[] EncryptRSA(string original, RSA rsa)
        {
            byte[] originalBytes = System.Text.Encoding.UTF8.GetBytes(original);
            byte[] encryptedBytes = rsa.Encrypt(originalBytes, RSAEncryptionPadding.Pkcs1);
            return encryptedBytes;
        }

        public static string DecryptRSA(byte[] cipher, RSA rsa)
        {
            byte[] decryptedBytes = rsa.Decrypt(cipher, RSAEncryptionPadding.Pkcs1);
            string decryptedCipher = Encoding.UTF8.GetString(decryptedBytes);
            return decryptedCipher;
        }

        public static string CreateAndSign(User user, X509Certificate2 certificateCA)
        {
            RSA rsa = RSA.Create(4096);
            Aes aes = Aes.Create();
            X500DistinguishedName Dname = new X500DistinguishedName($"CN ={user.Username}");
            CertificateRequest request = new CertificateRequest(Dname, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
            byte[] serialNumberBytes = Guid.NewGuid().ToByteArray();
            BigInteger serialNumber = new BigInteger(serialNumberBytes); 
            var signedUserCertificate = request.Create(certificateCA, DateTime.Now, DateTime.Now.AddMonths(6),Encoding.UTF8.GetBytes(serialNumber.ToString()));
            var exportedSignedUserCertificate = signedUserCertificate.Export(X509ContentType.Pkcs12);
            if(Directory.Exists(Const.pathCertificates)== false)
            {
                Directory.CreateDirectory(Const.pathCertificates);
            }
            if (Directory.Exists(Const.pathAesParams) == false)
            {
                Directory.CreateDirectory(Const.pathAesParams);
            }
            if (Directory.Exists(Const.pathPrivKeys) == false)
            {
                Directory.CreateDirectory(Const.pathPrivKeys);
            }
            string pathNew = Const.pathCertificates + $"Certificate{user.Username}.cer";
            File.WriteAllBytes(pathNew, exportedSignedUserCertificate);
            File.WriteAllBytes(Const.pathPrivKeys + $"{user.Username}.key", rsa.ExportRSAPrivateKey());
            WriteAesParameters((aes.Key, aes.IV),Const.pathAesParams + $"{user.Username}Aes.param",rsa);
            return pathNew;
        }
        public static bool CheckCertificate(X509Certificate2 certificateCA, X509Certificate2 certificateUser)
        {
            DateTime currentDate = DateTime.Now;
            bool notExpired = currentDate < certificateUser.NotAfter;
            BigInteger serial;
            CertificateRevocationListBuilder CRL = new CertificateRevocationListBuilder();
            bool notRevoked = true;
            if (File.Exists(Const.pathCRL))
            {
                CRL = CertificateRevocationListBuilder.Load(File.ReadAllBytes(Const.pathCRL), out serial);
                notRevoked = !(CRL.RemoveEntry(certificateUser.SerialNumberBytes.ToArray()));
            }
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

            chain.ChainPolicy.ExtraStore.Add(certificateCA);
            bool chainValid = chain.Build(certificateUser);
            bool signedByCA = chainValid && chain.ChainElements[0].Certificate.Issuer == certificateCA.Subject;
            return notRevoked && notExpired && chainValid && signedByCA;
            throw new NotImplementedException();
        }

        public static List<User> LoadUsers(string path)
        {
            List<User> users = new List<User>();
            if (File.Exists(path))
            {
                string[] data = File.ReadAllLines(path);
                for (int i = 0; i < data.Length; i++)
                {
                    User user = new User();
                    string[] components = data[i].Split('#');
                    user.Username = components[0];
                    user.HashedPassword = Convert.FromBase64String(components[1]);
                    user.Salt = Convert.FromBase64String(components[2]);
                    users.Add(user);
                }
            }
            return users;
        }

        public static void AddUser(User user, string path)
        {
            string HashedPasswordBase64 = Convert.ToBase64String(user.HashedPassword);
            string SaltBase64 = Convert.ToBase64String(user.Salt);
            string data = user.Username + "#" + HashedPasswordBase64 + "#" + SaltBase64 + Environment.NewLine;
            File.AppendAllText(path, data);
        }
        
        public static bool CheckUsername(string username, X509Certificate2 certificateUser)
        {
            string commonName = certificateUser.GetNameInfo(X509NameType.SimpleName, false);
            if (commonName.Equals(username))
                return true;
            return false;
        }
        public static bool VerifyPassword(User user, string input)
        {
            byte[] hashedInput = HashPassword(input, user.Salt);
            return user.HashedPassword.SequenceEqual(hashedInput);
        }

        public static byte[] HashPassword(string password, byte[] salt)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] saltedPassword = passwordBytes.Concat(salt).ToArray();

            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(saltedPassword);
                return hash;
            }
        }

        public static void SuspendCertificate(X509Certificate2 certificateCA, X509Certificate2 certificateUser)
        {
            CertificateRevocationListBuilder CRL = new CertificateRevocationListBuilder();
            BigInteger serial;
            if (File.Exists(Const.pathCRL))
            {
                CRL = CertificateRevocationListBuilder.Load(File.ReadAllBytes(Const.pathCRL),out serial);
            }
            byte[] serialNumberBytes = Guid.NewGuid().ToByteArray();
            BigInteger serialNumber = BigInteger.Abs(new BigInteger(serialNumberBytes));
            CRL.AddEntry(certificateUser.SerialNumberBytes.ToArray(), DateTime.Now, X509RevocationReason.CertificateHold);
            byte[] crl = CRL.Build(certificateCA, serialNumber, DateTime.Now.AddMonths(1), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, DateTime.Now);
            File.WriteAllBytes(Const.pathCRL, crl);
        }

        public static bool ReactivateCertificate(X509Certificate2 certificateCA, X509Certificate2 certificateUser)
        {
            CertificateRevocationListBuilder CRL = new CertificateRevocationListBuilder();
            BigInteger serial;
            CRL = CertificateRevocationListBuilder.Load(File.ReadAllBytes(Const.pathCRL), out serial);
            if(CRL.RemoveEntry(certificateUser.SerialNumberBytes.ToArray()))
            {
                byte[] serialNumberBytes = Guid.NewGuid().ToByteArray();
                BigInteger serialNumber = BigInteger.Abs(new BigInteger(serialNumberBytes));
                byte[] crl = CRL.Build(certificateCA, serialNumber, DateTime.Now.AddMonths(1), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, DateTime.Now);
                File.WriteAllBytes(Const.pathCRL, crl);
                return true;
            }
            return false;
        }

    }
}
