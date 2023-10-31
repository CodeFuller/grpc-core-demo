namespace Common
{
    public class ConnectionSettings
    {
        public string ServerHostName { get; set; }

        public int ServerPortNumber { get; set; }

        public SecurityType SecurityType { get; set; }

        public string CertificateIssuer { get; set; }

        public string ServerCertificateSubject => $"O=CodeFuller, CN={ServerHostName}";

        public string ClientCertificateSubject { get; set; }

        public string CertificateForClientFileName { get; set; }

        public string PfxFilePassword { get; set; }

        public string SubjectOfCertificateInStore => ServerHostName;

        public bool ValidateServerCertificate { get; set; }
    }
}
