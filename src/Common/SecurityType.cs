namespace Common
{
    public enum SecurityType
    {
        Insecure,
        CertificateFromDisk,
        CertificateFromPfxOnDiskDeliveredViaHttp,
        CertificateFromStoreDeliveredViaHttp,
        GeneratedCertificateDeliveredViaHttp,
        GeneratedCertificateDeliveredViaFilesystem,
    }
}
