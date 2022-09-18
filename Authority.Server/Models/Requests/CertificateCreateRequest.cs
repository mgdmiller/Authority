using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Authority.Server.Models.Requests
{
    public class CertificateCreateRequest
    {
        public IEnumerable<string> Authorities { get; set; }
        [Required] public Guid Id { get; set; }
        [Required] public string Authority { get; set; }
        [Required] public string Country { get; set; } = "RU";
        [Required] public string State { get; set; } = "SFD";
        [Required] public string Locality { get; set; } = "Rostov-on-Don";
        [Required] public string Organization { get; set; } = "Acme corp.";
        [Required] public string Department { get; set; } = "Information Technology";
        [Required] public string CommonName { get; set; } = "acme.corp";
        [Required, EmailAddress] public string Email { get; set; }
        [Required] public string Password { get; set; }
        public string San { get; set; } = "*.acme.com\r\nfoo.acme.com";
    }
}