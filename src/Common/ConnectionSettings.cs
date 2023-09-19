using System.Security.AccessControl;

namespace Common
{
    public static class ConnectionSettings
    {
        public static string HostName => "IHARM-WIN-BLR.cucorp.controlup.com";

        public static int PortNumber => 9999;

        public static SecurityType SecurityType => SecurityType.GeneratedCertificate;

        public static string CertificateIssuer => "O=CodeFuller, CN=GrpcCoreDemo";

        public static string ServerCertificateSubject => $"O=CodeFuller, CN={HostName}";

        public static string ClientCertificateSubject => "O=CodeFuller, CN=GrpcCoreDemo";

        public static string CertificateForClientFileName => "certificate-for-client.crt";

        public static void ConfigureLogging()
        {
            // System.Environment.SetEnvironmentVariable("GRPC_VERBOSITY", "debug");
            // System.Environment.SetEnvironmentVariable("GRPC_TRACE", "handshaker");
        }
    }
}
