using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Authority.Server.Models.Requests;

namespace Authority.Server.Services
{
    public interface ICertificationService
    {
        public IEnumerable<string> Authorities { get; }

        public CertificateRequest CreateRequest(string ca, CertificateCreateRequest request);
        public X509Certificate2 SignRequest(string ca, Guid id, CertificateRequest request, string caKeyPassword);
    }
}