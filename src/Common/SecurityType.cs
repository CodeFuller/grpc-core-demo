namespace Common
{
    public enum SecurityType
    {
        Insecure,
        CertificateFromDisk,
        GeneratedCertificateDeliveredViaFilesystem,
        GeneratedCertificateDeliveredViaHttp,
    }
}
