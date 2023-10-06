namespace Common
{
    public enum SecurityType
    {
        Insecure,
        CertificateFromDisk,
        CertificateFromDiskDeliveredViaHttp,
        GeneratedCertificateDeliveredViaHttp,
        GeneratedCertificateDeliveredViaFilesystem,
    }
}
