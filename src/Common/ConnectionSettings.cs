namespace Common
{
    public enum SecurityType
    {
        Unknown,
        Insecure,
        FromDisk,
        FromDiskRootOnly,
        FromDiskSameCertificate,
        FromStore,
        Generated,
        GeneratedWithoutClientAuthentication,
        GeneratedWithIssuedCertificate,
        US156551,
    }

    public static class ConnectionSettings
    {
        // CF MEGATEMP
        // public static string HostName => "IHARM-WIN-BLR.cucorp.controlup.com";
        // public static string HostName => "IgorM-Dev1.qa.local";
        // public static string HostName => "IGORM-DEV1.qa.local";
        public static string HostName => "localhost";

        public static int PortNumber => 443;

        public static bool UseSsl => true;

        // CF MEGATEMP
        // public static SecurityType SecurityType => SecurityType.GeneratedWithIssuedCertificate;
        public static SecurityType SecurityType => SecurityType.FromDisk;
    }
}
