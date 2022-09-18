using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Authority.Server.Helpers
{
    public static class CertificateHelpers
    {
        public static byte[] ExportCertToPem(this X509Certificate2 certificate) =>
            PemEncoding.Write("CERTIFICATE", certificate.RawData)
                .Select(x => (byte)x)
                .ToArray();

        public static byte[] ExportPrivateKeyToPem(this X509Certificate2 certificate) =>
            PemEncoding.Write("PRIVATE KEY", certificate.GetRSAPrivateKey()?.ExportPkcs8PrivateKey())
                .Select(x => (byte)x)
                .ToArray();

        public static byte[] ExportPublicKeyToPem(this X509Certificate2 certificate) =>
            PemEncoding.Write("PUBLIC KEY", certificate.GetRSAPublicKey()?.ExportPkcs8PrivateKey())
                .Select(x => (byte)x)
                .ToArray();
    }
}