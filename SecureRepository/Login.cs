using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using static SecureRepository.Util;
using static SecureRepository.DocumentInterface;

namespace SecureRepository
{
    internal static class Login
    {
        internal static void LoginP(List<User> users, X509Certificate2 certificateCA)
        {
            Console.WriteLine("Unesite putanju sertifikata");
            string path = Console.ReadLine();
            X509Certificate2 certificateUser = new X509Certificate2(path);
            if (CheckCertificate(certificateCA, certificateUser))
            {
                User user = new User();
                bool checkerPassword = false;
                bool checkerUsername = false;
                int count = 0;
                do
                {
                    Console.WriteLine("Unesite korisnicko ime:");
                    user.Username = Console.ReadLine();
                    Console.WriteLine("Unesite lozinku:");
                    Console.ForegroundColor = ConsoleColor.Black;
                    string input = Console.ReadLine();
                    Console.ForegroundColor = ConsoleColor.White;
                    if (users.Contains(user))
                    {
                        user = users.Find(u => u.Equals(user));
                        checkerPassword = VerifyPassword(user, input);
                        checkerUsername = CheckUsername(user.Username, certificateUser);
                    }
                    if(checkerPassword==false || checkerUsername==false)
                    {
                        Console.WriteLine("Unijeli ste pogresne kredencijale.");
                        count++;
                    }
                } while (count < 3 && (checkerUsername == false || checkerPassword == false));
                if(checkerUsername==false || checkerPassword == false)
                {
                    SuspendCertificate(certificateCA, certificateUser);
                    Console.WriteLine("Vas sertifikat je suspendovan.");
                    Console.WriteLine("Unesite tacne kredencijale kako biste reaktivirali sertifikat.");
                    Console.WriteLine("Unesite korisnicko ime:");
                    user.Username = Console.ReadLine();
                    Console.WriteLine("Unesite lozinku:");
                    Console.ForegroundColor = ConsoleColor.Black;
                    string input = Console.ReadLine();
                    Console.ForegroundColor = ConsoleColor.White;
                    if (users.Contains(user))
                    {
                        user = users.Find(u => u.Equals(user));
                        checkerPassword = VerifyPassword(user, input);
                        checkerUsername = CheckUsername(user.Username, certificateUser);
                    }
                    if (checkerPassword == false || checkerUsername == false)
                    {
                        Console.WriteLine("Unijeli ste pogresne kredencijale.");
                        Console.WriteLine("Registrujte se ponovo.");
                        Register.RegisterR(users,certificateCA);
                    }
                    else
                    {
                        ReactivateCertificate(certificateCA, certificateUser);
                        ShowDocuments(user);
                    }
                }
                else if (checkerUsername==true && checkerPassword ==true)
                {
                    ShowDocuments(user);
                }

            }
            else
            {
                Console.WriteLine("Uneseni sertifikat nije validan.");
            }
        }

    }
}
