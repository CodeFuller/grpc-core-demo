using System.Security.AccessControl;

namespace Common
{
    public static class ConnectionSettings
    {
        public static string ServerHostName => "IHARM-WIN-BLR.cucorp.controlup.com";

        public static int ServerPortNumber => 9999;

        public static SecurityType SecurityType => SecurityType.GeneratedCertificate;

        public static string CertificateIssuer => "O=CodeFuller, CN=GrpcCoreDemo";

        public static string ServerCertificateSubject => $"O=CodeFuller, CN={ServerHostName}";

        public static string ClientCertificateSubject => "O=CodeFuller, CN=GrpcCoreDemo";

        public static string CertificateForClientFileName => "certificate-for-client.crt";

        public static void ConfigureLogging()
        {
            // System.Environment.SetEnvironmentVariable("GRPC_VERBOSITY", "debug");
            // System.Environment.SetEnvironmentVariable("GRPC_TRACE", "handshaker");
        }
    }
}
