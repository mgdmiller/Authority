using System.Collections.Generic;

namespace Authority.Server.Services.Certification.Data
{
    public class AuthorityManifest
    {
        public string Name { get; }
        public string Certificate { get; }
        public string Key { get; }
        public bool IsPublic { get; }
        public bool IsEnabled { get; }
        public IDictionary<string, string> Directories { get; }
        public IEnumerable<string> ExtendedUsage { get; }

        public AuthorityManifest(string name, string certificate, string key, bool isPublic, bool isEnabled, 
            IDictionary<string, string> directories, IEnumerable<string> extendedUsage)
        {
            Name = name;
            Certificate = certificate;
            Key = key;
            IsPublic = isPublic;
            IsEnabled = isEnabled;
            ExtendedUsage = extendedUsage;
            Directories = directories ?? new Dictionary<string, string>();
        }
    }
}