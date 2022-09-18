using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Authority.Server.Models.Requests;
using Authority.Server.Services.Certification.Data;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;

namespace Authority.Server.Services.Certification
{
    public class CoreCertificationService : ICertificationService
    {
        private const string LocationDefault = "Authorities";
        private const string ManifestName = "authority.json";

        private readonly List<AuthorityHandler> _authorities = new();

        public IEnumerable<string> Authorities => _authorities.Select(x => x.Manifest.Name);

        public CoreCertificationService(IConfiguration configuration)
        {
            foreach (var authorityFile in Directory.EnumerateFiles(
                         configuration.GetValue("caBase", LocationDefault),
                         ManifestName,
                         SearchOption.AllDirectories))
            {
                var manifestContent = File.ReadAllText(authorityFile);
                var manifest = JsonConvert.DeserializeObject<AuthorityManifest>(manifestContent);
                var handler = new AuthorityHandler(manifest, Path.GetDirectoryName(authorityFile));

                _authorities.Add(handler);
            }
        }

        public CertificateRequest CreateRequest(string ca, CertificateCreateRequest request) =>
            _authorities.First(x => x.Manifest.Name == ca).CreateRequest(request);

        public X509Certificate2 SignRequest(string ca, Guid id, CertificateRequest request, string caKeyPassword) =>
            _authorities.First(x => x.Manifest.Name == ca).CreateCertificate(id, request, caKeyPassword);
    }
}