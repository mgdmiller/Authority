using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography.X509Certificates;
using Authority.Server.Helpers;
using Authority.Server.Models.Requests;
using Authority.Server.Services;
using Microsoft.AspNetCore.Mvc;

namespace Authority.Server.Controllers
{
    public class RequestsController : Controller
    {
        private readonly ICertificationService _certification;

        public RequestsController(ICertificationService certification)
        {
            _certification = certification;
        }

        /// <summary>
        /// Create new certificate request
        /// </summary>
        /// <param name="ca"></param>
        [HttpGet]
        public IActionResult New(string ca)
        {
            return View(
                new CertificateCreateRequest
                {
                    Authorities = _certification.Authorities,
                    Authority = ca,
                    Id = Guid.NewGuid()
                }
            );
        }

        [HttpPost]
        public IActionResult New(string ca, CertificateCreateRequest request)
        {
            if (!ModelState.IsValid)
                return View(request);

            var csr = _certification.CreateRequest(ca, request);
            var cert = _certification.SignRequest(ca, request.Id, csr, request.Password);

            var zipFileMemoryStream = new MemoryStream();
            var archive = new ZipArchive(zipFileMemoryStream, ZipArchiveMode.Create, leaveOpen: true);

            void AddFile(string name, byte[] content)
            {
                var entry = archive.CreateEntry(name);

                using var entryStream = entry.Open();
                using var fileStream = new MemoryStream(content);
                fileStream.CopyTo(entryStream);
            }

            AddFile($"{request.CommonName}.key", cert.ExportPrivateKeyToPem());
            AddFile($"{request.CommonName}.crt", cert.ExportCertToPem());

            zipFileMemoryStream.Seek(0, SeekOrigin.Begin);

            return File(zipFileMemoryStream.ToArray(), "application/octet-stream", $"{request.CommonName}.zip");
        }
    }
}