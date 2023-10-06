namespace Common
{
    public enum SecurityType
    {
        Insecure,
        CertificateFromDisk,
        CertificateFromPfxOnDiskDeliveredViaHttp,
        GeneratedCertificateDeliveredViaHttp,
        GeneratedCertificateDeliveredViaFilesystem,
    }
}
