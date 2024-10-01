
using SecureRepository;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Serialization;
using static SecureRepository.Util;
string choice;
List<User> users = LoadUsers(Const.pathUsers);
X509Certificate2 certificateCA = new X509Certificate2(Const.path, Const.password);
do
{
    Console.Write("Izaberite opciju:\n1 Registracija\n2 Prijava\n3 Odjava\n");
    choice = Console.ReadLine();
    switch (choice)
    {
        case "2":
            {
                Login.LoginP(users, certificateCA);
                break;
            }
        case "1":
            {
                Register.RegisterR(users, certificateCA);
                break;
            }
        case "3":
            {
                break;
            }
        default:
            Console.WriteLine("Neispravan unos.");
            break;

    }
} while (!choice.Equals("3"));

