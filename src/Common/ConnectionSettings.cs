using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace Common
{
    public static class ConnectionSettings
    {
        public static string HostName => "IHARM-WIN-BLR.cucorp.controlup.com";

        public static int PortNumber => 9999;

        public static SecurityType SecurityType => SecurityType.GeneratedCertificate;

        public static string CertificateIssuer => "CN=GrpcCoreDemo, O=CodeFuller";

        public static string PrivateKey => @"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAp5u9/eIbFKjafgxdKzp4jA4jwXTIWantWJO+vKdz+RLh7L0/
qhc3aqGObwc4E2o96aj+mf5QYqAHBRtBDE2uomrXH1v/EVJOTlX+0k22Tr44CxLA
JTCK2nztuLWxUzYEsp7twV3GkAhO/s1BdjV7baIAVdU++vOPn5yFIbd2YXoY0vYT
ILuBEUKQepgq/5/35hspRXReg9ouMul/xDHTGiVKdlFaqgGJHaybthNTCK342w1R
Sj9XjM1e35UMQttmyTl0Ig8ZWrevprzWhQzUi4jh37zkkKkZNsPwUWAnTgddJXZd
k596lbcF6q6sQe5lx6GIhCVFi+JsS71/b50WPQIDAQABAoIBAAb3wge+cRrEREUO
NYdZCG7mHZVqyfN0TYIrrjfAjGEz6EGDwpRLH8omijnSZoHkHkvK8z6qpGPdPD15
mxQsXJCy+Vt74xgwwEGgcJYElgoi/Uh0kJlbMcKQg/90Sjln2v0j/0VVJS6SsdoE
5W5JHeb6X6Ix2crr+jIL+zriGiFGNVp9CuYts7ZzPVgoUbMtEkPK82CVkkX+mGIw
q9+MRCrPo6ghuRKmZY+La6vLviCBUXAshtlgrBWKkWIEkhQ8B9IA7z0R4VenRgh4
UXCPYa8hVnpb2NC9uesit3cj225YUpx/kHRzrbL/DRc74zKC7VwMfZxMy1UNCwBo
vZSO9U8CgYEA44h8KtmV45eYLW1WaP7JHZpTqY/pFfrqf0Bl12a5Ufrafvkeg4Lc
uqc7Up0WTk6kRpuzKmjWyw3TrwROe4m++enSyAtFZKLff0mBTl80NpcuSZ4e1P17
td5nw2VSrx3OTlXmQbBliEBGytrKw7UmO7zLLhx027k89RWG3Y3pFO8CgYEAvJP2
4zrsHtjOiOGYl6B0nuy3Xk1kTWotDVo+TsBmWXaB3BhLZG/flWLaaLIPlU+thlIl
3Bh33kUgmCuGEx0rpFqnz+9oFmOApUb6PJES5cmZWfDflUZb+nMIWgmSy4+SF1TI
6dnpXB5mZ0qeYgFsnDVqkEPZ+q4bVhg3ep/U/5MCgYAT/odiwJISWNzviP8h5NnJ
dylI6jOCUfVPT1pjrkw0rwWKSNvslJBO+qkU3mb6ZKC876uz21icqU9jvs4ivv0A
OxLhr1Pevw1CwzPQrj8JWQmhQHrXHptDZRLbMcktSEI70gKU3Spe6b8OzmEpB38f
mryEBc4jDMkVhFnAmFrWEwKBgQCOSquxG+XNBNUbDfbg+o7k2EMoogb8LxCdkamQ
LLdN7BDirWY9+/heNUAOXcVKadvKjbPJlqDkE48bo0PAqnMiydD0InaM5jnM/HiX
OPRkdTEEX6+laHjAywnTPoQIm2WluzD625WtD7c/W1uVIfP9DoVBJCGXeMZhuVYr
bez/hwKBgDKzcpNah3W4njTnn4DFbHZAld/W0IlYJ25geKf8HGHbMXRwlZEL5to6
RdKLMmU4wd7ASoc3UjcS6aT2sxd84ys0fghaW5FdH0zTpvjjN+NOpbtfsPT9MlXm
L9vu+XxzLPtRa2dlpfUO8jnFejX55m4qmBmTe3GUaXiFQBwRaUGt
-----END RSA PRIVATE KEY-----
";

        public static void ConfigureLogging()
        {
            // System.Environment.SetEnvironmentVariable("GRPC_VERBOSITY", "debug");
            // System.Environment.SetEnvironmentVariable("GRPC_TRACE", "handshaker");
        }

        public static AsymmetricCipherKeyPair GetAsymmetricCipherKeyPair()
        {
            using (var reader = new StringReader(PrivateKey))
            {
                var pemReader = new PemReader(reader);
                return (AsymmetricCipherKeyPair)pemReader.ReadObject();
            }
        }

        private static string GeneratePrivateKey()
        {
            var random = new SecureRandom();

            var keyGenerationParameters = new KeyGenerationParameters(random, 2048);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);

            var keyPair = keyPairGenerator.GenerateKeyPair();

            using (TextWriter textWriter = new StringWriter())
            {
                var pemWriter = new PemWriter(textWriter);
                pemWriter.WriteObject(keyPair.Private);

                return textWriter.ToString();
            }
        }
    }
}
