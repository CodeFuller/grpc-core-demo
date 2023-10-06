namespace Common
{
    public enum SecurityType
    {
        Insecure,
        CertificateFromDisk,
        CertificateFromDiskDeliveredViaHttp,
        GeneratedCertificateDeliveredViaFilesystem,
        GeneratedCertificateDeliveredViaHttp,
    }
}
