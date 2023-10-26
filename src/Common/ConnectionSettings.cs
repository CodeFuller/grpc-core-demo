namespace Common
{
    public static class ConnectionSettings
    {
        public static string ServerHostName => "IHARM-WIN-BLR.cucorp.controlup.com";

        public static int ServerPortNumber => 9999;

        public static SecurityType SecurityType => SecurityType.GeneratedCertificateDeliveredViaHttp;

        public static string CertificateIssuer => "O=CodeFuller, CN=GrpcCoreDemo";

        public static string ServerCertificateSubject => $"O=CodeFuller, CN={ServerHostName}";

        public static string ClientCertificateSubject => "O=CodeFuller, CN=GrpcCoreDemo";

        public static string CertificateForClientFileName => "certificate-for-client.crt";

        public static string PfxFilePassword => "Qwerty123";

        public static string SubjectOfCertificateInStore => ServerHostName;

        public static bool ValidateServerCertificate => true;

        public static void ConfigureLogging()
        {
            // System.Environment.SetEnvironmentVariable("GRPC_VERBOSITY", "debug");
            // System.Environment.SetEnvironmentVariable("GRPC_TRACE", "handshaker");
        }
    }
}
