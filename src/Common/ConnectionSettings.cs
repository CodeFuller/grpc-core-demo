namespace Common
{
    public static class ConnectionSettings
    {
        public static string HostName => "IHARM-WIN-BLR.cucorp.controlup.com";

        public static int PortNumber => 9999;

        public static SecurityType SecurityType => SecurityType.GeneratedCertificate;

        public static string CertificateIssuer => "O=CodeFuller, CN=GrpcCoreDemo";

        public static string CertificateForClient { get; set; }

        public static void ConfigureLogging()
        {
            // System.Environment.SetEnvironmentVariable("GRPC_VERBOSITY", "debug");
            // System.Environment.SetEnvironmentVariable("GRPC_TRACE", "handshaker");
        }
    }
}
