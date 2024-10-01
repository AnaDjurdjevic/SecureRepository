using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureRepository
{
    internal static class Const
    {
        internal const string password = "sigurnost";
        internal static string path = Path.GetFullPath(@"..\..\..\") + "CA.cer";
        internal static string pathUsers = Path.GetFullPath(@"..\..\..\") + "Users.data";
        internal static string pathCertificates = Path.GetFullPath(@"..\..\..\..\") + "Certificates\\";
        internal static string pathCRL = Path.GetFullPath(@"..\..\..\") + "CRL.crl";
        internal static string pathCRLNum = Path.GetFullPath(@"..\..\..\") + "CRL.num";
        internal static string pathPrivKeys = Path.GetFullPath(@"..\..\..\..\") + "PrivateKeys\\";
        internal static string pathAesParams = Path.GetFullPath(@"..\..\..\..\") + "AesParams\\";
        internal static string pathUsersFS = Path.GetFullPath(@"..\..\..\..\") + "UsersFileSystem\\";
        internal static string pathAllDocuments = Path.GetFullPath(@"..\..\..\..\") + "Documents\\";
        internal static string pathDownloadedDocuments = Path.GetFullPath(@"..\..\..\..\") + "Downloaded Documents\\";

    }
}
