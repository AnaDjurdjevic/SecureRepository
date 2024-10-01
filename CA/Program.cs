using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static System.Net.Mime.MediaTypeNames;


RSA rsa = RSA.Create(4096);
X500DistinguishedName Dname = new X500DistinguishedName("CN = CA");
CertificateRequest request = new CertificateRequest(Dname, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.NonRepudiation, true));
var signedCertificate = request.CreateSelfSigned(DateTime.Now, DateTime.Now.AddYears(1));
var exportedSignedCertificate = signedCertificate.Export(X509ContentType.Pkcs12, "sigurnost");
File.WriteAllBytes("CA.cer", exportedSignedCertificate);