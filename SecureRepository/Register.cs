using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using static SecureRepository.Util;
using static SecureRepository.DocumentInterface;

namespace SecureRepository
{
    internal static class Register
    {
        internal static void RegisterR(List<User> users,X509Certificate2 certificateCA)
        {
            User user = new User();
            do
            {
                Console.WriteLine("Unesite korisnicko ime:");
                user.Username = Console.ReadLine();
                if (users.Contains(user))
                {
                    Console.WriteLine($"Korisnicko ime {user.Username} je zauzeto. Unesite ponovo.");
                }
            } while (users.Contains(user));
            Console.WriteLine("Unesite lozinku:");
            Console.ForegroundColor = ConsoleColor.Black;
            string password = Console.ReadLine();
            Console.ForegroundColor = ConsoleColor.White;
            user.Salt = RandomNumberGenerator.GetBytes(16);
            user.HashedPassword = HashPassword(password,user.Salt);
            AddUser(user, Const.pathUsers);
            Console.WriteLine("Vas sertifikat: " + CreateAndSign(user, certificateCA));
            ShowDocuments(user);
        }
    }
}
