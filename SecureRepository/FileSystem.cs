using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static SecureRepository.Util;

namespace SecureRepository
{
    internal class FileSystem
    {
        public User User;
        public string Path;
        public List<Document> Documents;
        public FileSystem(User user) 
        {
            this.User = user;
            if(Directory.Exists(Const.pathUsersFS)==false)
            {
                Directory.CreateDirectory(Const.pathUsersFS);
            }
            Path = Const.pathUsersFS + $"{user.Username}.fs";
            Documents = new List<Document>();
        }
        public void WriteToFileSystem((byte[], byte[]) parameters,Document document)
        {
            string newContent = "";
            Documents.Add(document);
            foreach(Document doc in Documents)
            {
                newContent += doc.OriginalDocumentName;
                for(int j = 0; j<doc.PathToSegment.Length; j++)
                {
                    newContent += "#" + doc.PathToSegment[j] + "|" + Convert.ToBase64String(doc.DigitalSignature[j]);
                }
                newContent += Environment.NewLine;
            }
            
            byte[] toWrite = EncryptAes(Encoding.UTF8.GetBytes(newContent), parameters.Item1,parameters.Item2);
            File.WriteAllBytes(Path, toWrite);
        }
        public void ReadFromFileSystem((byte[], byte[]) parameters)
        {
            if (File.Exists(Path))
            {
                byte[] data = File.ReadAllBytes(Path);
                byte[] decryptedData = DecryptAes(data, parameters.Item1, parameters.Item2);
                string[] docs = Encoding.UTF8.GetString(decryptedData).Split(Environment.NewLine);
                for (int i = 0; i < docs.Length-1; i++)
                {
                    Document document = new Document();
                    string[] components = docs[i].Split("#");
                    document.DigitalSignature = new byte[components.Length - 1][];
                    document.PathToSegment = new string[components.Length - 1];
                    document.OriginalDocumentName = components[0];
                    for (int j = 1; j < components.Length; j++)
                    {
                        string[] elements = components[j].Split("|");
                        document.PathToSegment[j-1] = elements[0];
                        document.DigitalSignature[j-1] = Convert.FromBase64String(elements[1]);
                    }
                    Documents.Add(document);
                }
                Console.WriteLine("Vasi dokumenti:");
                for (int i = 0; i < Documents.Count;i++)
                {
                    Console.WriteLine($"{i+1}. " + Documents[i].OriginalDocumentName);
                }
            }
            else
            {
                Console.WriteLine("Nema dokumenata za prikaz.");
            }
        }
    }
}
