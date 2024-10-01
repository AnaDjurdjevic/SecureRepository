using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static SecureRepository.Util;

namespace SecureRepository
{
    internal class DocumentInterface
    {
        public static void ShowDocuments(User user)
        {
            byte[] privateKeyBytes = File.ReadAllBytes(Const.pathPrivKeys + $"{user.Username}.key");
            RSA rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(privateKeyBytes, out _);
            Aes aes = Aes.Create();
            (byte[], byte[]) parameters = ReadAesParameters(Const.pathAesParams + $"{user.Username}Aes.param",rsa);
            aes.Key = parameters.Item1;
            aes.IV = parameters.Item2;
            FileSystem fs = new FileSystem(user);
            fs.ReadFromFileSystem(parameters);
            PerformFunctions(fs,rsa, parameters);
        }

        public static void PerformFunctions(FileSystem fs,RSA rsa, (byte[], byte[]) param)
        {
            string choice;
            do
            {
                Console.Write("Izaberite opciju:\n1 Download dokumenata\n2 Upload dokumenta\n3 Zavrsetak rada sa dokumentima\n");
                choice = Console.ReadLine();
                switch (choice)
                {
                    case "1":
                        {
                            try
                            {
                                DownloadDocument(rsa, param, fs);
                            }catch (CryptographicException ex) 
                            { 
                                Console.WriteLine("Izvrsena je neovlastena izmjena izabranog dokumenta."); 
                            }
                            break;
                        }
                    case "2":
                        {
                            try
                            {
                                UploadDocument(rsa, param, fs);
                            }
                            catch(Exception ex) { Console.WriteLine("Nepostojeci fajl."); }
                            break;
                        }
                }
            } while (!choice.Equals("3"));

        }
        public static void UploadDocument(RSA rsa, (byte[], byte[]) param, FileSystem fs)
        {
            Document document = new Document();
            Console.WriteLine("Unesite putanju dokumenta:");
            string path = Console.ReadLine();
            if (File.Exists(path))
            {
                document.OriginalDocumentName = Path.GetFileName(path);
                byte[] content = File.ReadAllBytes(path);
                int numSegments = new Random().Next(4, 10);
                byte[][] segments = Split(content, numSegments);
                document.DigitalSignature= new byte[numSegments][];
                document.PathToSegment = new string[numSegments];
                for (int i = 0; i < numSegments; i++)
                {
                    document.DigitalSignature[i] = rsa.SignData(segments[i], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    byte[] encryptedSegment = EncryptAes(segments[i], param.Item1, param.Item2);
                    string path1 = Convert.ToBase64String(SHA512.HashData(Encoding.UTF8.GetBytes($"{document.OriginalDocumentName}{new Random().Next()}"))).Replace("/", "");
                    string newPath = Const.pathAllDocuments + $"Directory{new Random().Next(1, 11)}\\" + path1;
                    File.WriteAllBytes(newPath,encryptedSegment);
                    document.PathToSegment[i] = newPath;
                }
                fs.WriteToFileSystem(param, document);
            }
        }

        public static void DownloadDocument(RSA rsa, (byte[], byte[]) param, FileSystem fs)
        {
            Console.WriteLine("Vasi dokumenti:");
            for (int i = 0; i < fs.Documents.Count; i++)
            {
                Console.WriteLine($"{i + 1}. " + fs.Documents[i].OriginalDocumentName);
            }
            Console.WriteLine("Unesite redni broj dokumenta koji zelite da preuzmete:");
            string input = Console.ReadLine();
            if(int.TryParse(input, out int number)&&number<=fs.Documents.Count())
            {
                byte[] content = Array.Empty<byte>();
                bool isSignatureValid = true;
                for(int i = 0; i < fs.Documents[number-1].PathToSegment.Length; i++)
                {
                    byte [] segmentContent = File.ReadAllBytes(fs.Documents[number - 1].PathToSegment[i]);
                    byte[] decryptedSegmentContent = DecryptAes(segmentContent,param.Item1,param.Item2);
                    if (VerifySignature(decryptedSegmentContent, fs.Documents[number - 1].DigitalSignature[i],rsa))
                    {
                        content = content.Concat<byte>(decryptedSegmentContent).ToArray();
                    }
                    else
                    {
                        Console.WriteLine("Izvrsena je neovlastena izmjena izabranog dokumenta");
                        isSignatureValid= false;
                        i = fs.Documents[number - 1].PathToSegment.Length;
                    }
                }
                if (isSignatureValid)
                {
                    if (Directory.Exists(Const.pathDownloadedDocuments) == false)
                    {
                        Directory.CreateDirectory(Const.pathDownloadedDocuments);
                    }
                    string newPath = Const.pathDownloadedDocuments + $"{fs.Documents[number - 1].OriginalDocumentName}";
                    File.WriteAllBytes(newPath, content);
                    Console.WriteLine($"Dokument je kreiran na sledecoj putanji: {newPath}");
                }
            }
            else
            {
                Console.WriteLine("Neispravan unos.");
            }
        }

        public static bool VerifySignature(byte[] contentToVerify, byte[] digitalSignature, RSA rsa)
        {
            byte[] newSignature=rsa.SignData(contentToVerify, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            if(CompareTwoByteArrays(digitalSignature,newSignature))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        internal static bool CompareTwoByteArrays(byte[] one, byte[] two)
        {
            if (one.Length != two.Length)
                return false;
            for (int i = 0; i < one.Length; i++)
            {
                if (one[i] != two[i])
                {
                    return false;
                }

            }
            return true;
        }

        public static byte[][] Split(byte[]content, int number)
        {
            int length = content.Length;
            byte[][] result = new byte[number][];
            if(length%number == 0)
            {
                int characters = length / number;
                for (int i = 0;i<number;i++)
                {
                    result[i] = new byte[characters];
                    Array.Copy(content,i*characters, result[i], 0, characters);
                }
            }
            else
            {
                int characters = length/number;
                int rest = length % number;
                for(int i = 0;i<number;i++)
                {
                    result[i] = new byte[characters];
                    Array.Copy(content, i * characters, result[i], 0, characters);
                }
                Array.Resize(ref result[number - 1], characters + rest);
                Array.Copy(content, length - rest-1, result[number - 1], result[number-1].Length-1-rest,rest);
            }
            return result;
        }

    }
}
