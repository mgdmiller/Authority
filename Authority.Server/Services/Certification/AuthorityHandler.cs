using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Authority.Server.Helpers;
using Authority.Server.Models.Requests;
using Authority.Server.Services.Certification.Data;

namespace Authority.Server.Services.Certification
{
    public class AuthorityHandler
    {
        private const string DefaultCsrDir = "csr";
        private const string DefaultKeyDir = "private";
        private const string DefaultCertsDir = "certs";

        public AuthorityManifest Manifest { get; }
        public string Directory { get; }

        public AuthorityHandler(AuthorityManifest manifest, string directory)
        {
            Manifest = manifest;
            Directory = directory;
        }

        public CertificateRequest CreateRequest(CertificateCreateRequest request)
        {
            var subjBuilder = new StringBuilder();

            subjBuilder.AppendFormat("C={0},", request.Country);
            subjBuilder.AppendFormat("S={0},", request.State);
            subjBuilder.AppendFormat("L={0},", request.Locality);
            subjBuilder.AppendFormat("O={0},", request.Organization);
            subjBuilder.AppendFormat("OU={0},", request.Department);
            subjBuilder.AppendFormat("CN={0},", request.CommonName);
            subjBuilder.AppendFormat("EMAIL={0}", request.Email);

            var sanBuilder = new SubjectAlternativeNameBuilder();
            var csrStoreDir = Path.Combine(Directory, Manifest.Directories.TryGetValue("csr", DefaultCsrDir));
            var keyStoreDir = Path.Combine(Directory, Manifest.Directories.TryGetValue("private", DefaultKeyDir));
            var rsa = RSA.Create(2048);
            var generator = X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1);
            var subject = new X500DistinguishedName(subjBuilder.ToString());
            var csr = new CertificateRequest(
                subject,
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1
            );

            foreach (var s in request.San.Split("\r\n"))
                sanBuilder.AddDnsName(s);

            csr.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, false));

            csr.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                    true));

            csr.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection
                    {
                        new("1.3.6.1.5.5.7.3.1"),
                        new("1.3.6.1.5.5.7.3.2")
                    },
                    true));

            csr.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(csr.PublicKey, false));

            csr.CertificateExtensions.Add(sanBuilder.Build());

            var csrRequest = ExportCertificateRequest(csr, generator);
            var privateKey = ExportPrivateKey(rsa);

            if (!System.IO.Directory.Exists(csrStoreDir))
                System.IO.Directory.CreateDirectory(csrStoreDir);

            if (!System.IO.Directory.Exists(keyStoreDir))
                System.IO.Directory.CreateDirectory(keyStoreDir);

            File.WriteAllText(Path.Combine(csrStoreDir, $"{request.Id}.csr"), csrRequest);
            File.WriteAllText(Path.Combine(keyStoreDir, $"{request.Id}.key"), privateKey);

            return csr;
        }

        public X509Certificate2 CreateCertificate(Guid id, CertificateRequest request, string password)
        {
            var rsa = RSA.Create();
            var keyStoreDir = Path.Combine(Directory, Manifest.Directories.TryGetValue("private", DefaultKeyDir));
            var certsStoreDir = Path.Combine(Directory, Manifest.Directories.TryGetValue("certs", DefaultCertsDir));
            var certPrivateKeyFile = Path.Combine(keyStoreDir, $"{id}.key");
            var caCrtFile = Path.Combine(Directory, Manifest.Certificate);
            var nbf = DateTimeOffset.Now.AddDays(-1);
            var expr = DateTimeOffset.Now.AddDays(365);
            var serial = Encoding.UTF8.GetBytes(id.ToString("N"));
            var caCertificate = new X509Certificate2(caCrtFile, password);
            var certificate = request.Create(caCertificate, nbf, expr, serial);
            var certificateContent = ExportCertificate(certificate);

            rsa.ImportFromPem(File.ReadAllText(certPrivateKeyFile));
            certificate = certificate.CopyWithPrivateKey(rsa);

            if (!System.IO.Directory.Exists(certsStoreDir))
                System.IO.Directory.CreateDirectory(certsStoreDir);

            File.WriteAllText(Path.Combine(certsStoreDir, $"{id}.crt"), certificateContent);

            return certificate;
        }

        private static string ExportCertificate(X509Certificate2 certificate)
        {
            return new StringBuilder()
                .AppendLine("-----BEGIN CERTIFICATE-----")
                .AppendLine(Convert.ToBase64String(certificate.RawData, Base64FormattingOptions.InsertLineBreaks))
                .AppendLine("-----END CERTIFICATE-----")
                .ToString();
        }


        private static string ExportCertificateRequest(CertificateRequest csr, X509SignatureGenerator generator)
        {
            const int lineLength = 64;
            var offset = 0;
            var csrRequestBuilder = new StringBuilder().AppendLine("-----BEGIN CERTIFICATE REQUEST-----");

            var csrContent = csr.CreateSigningRequest(generator);
            var base64 = Convert.ToBase64String(csrContent);

            while (offset < base64.Length)
            {
                var lineEnd = Math.Min(offset + lineLength, base64.Length);
                csrRequestBuilder.AppendLine(base64.Substring(offset, lineEnd - offset));
                offset = lineEnd;
            }

            return csrRequestBuilder.AppendLine("-----END CERTIFICATE REQUEST-----").ToString();
        }

        private static string ExportPrivateKey(RSA rsa)
        {
            const int lineLength = 64;
            var offset = 0;
            var privateKeyBytes = rsa.ExportRSAPrivateKey();
            var builder = new StringBuilder().AppendLine("-----BEGIN RSA PRIVATE KEY-----");
            var base64PrivateKeyString = Convert.ToBase64String(privateKeyBytes);

            while (offset < base64PrivateKeyString.Length)
            {
                var lineEnd = Math.Min(offset + lineLength, base64PrivateKeyString.Length);
                builder.AppendLine(base64PrivateKeyString.Substring(offset, lineEnd - offset));
                offset = lineEnd;
            }

            return builder.AppendLine("-----END RSA PRIVATE KEY-----").ToString();
        }
    }
}