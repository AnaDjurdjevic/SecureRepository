using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecureRepository
{
    internal class User
    {
        public string Username { get; set; }
        public byte[] HashedPassword { get; set; }
        public byte[] Salt { get; set; }
        
        public override bool Equals(object ? obj)
        {
            if(obj == null)
                return false;
            if (obj is User user)
                return user.Username.Equals(this.Username);
            return false;

        }

        public override int GetHashCode()
        {
            throw new NotImplementedException();
        }
    }
}
