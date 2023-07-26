using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Common;
using Common.Certificates;
using Google.Protobuf.Reflection;
using Grpc.Core;
using GrpcCoreDemo.Grpc;
using log4net;
using log4net.Config;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Ocsp;
using System.Net;
using System.Net.Security;
using System.Reflection;
using X509Certificate = System.Security.Cryptography.X509Certificates.X509Certificate;
using System.Xml.Linq;
using Org.BouncyCastle.Crypto.Operators;
using System.Runtime.Remoting.Messaging;

namespace ServerApp
{
    public static class Program
    {
        private static readonly ILog Log = LogManager.GetLogger("ServerApp.Program");

/*
        public static X509Certificate2 GenerateRootCertificate(string subject, string signatureAlgorithm, int strength)
        {
            try
            {
                const int DefaultValidity = 5;
                var random = new SecureRandom();
                var certificateGenerator = new X509V3CertificateGenerator();

                var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
                certificateGenerator.SetSerialNumber(serialNumber);

                certificateGenerator.SetIssuerDN(new X509Name($"O=ControlUp, CN={subject}"));
                certificateGenerator.SetSubjectDN(new X509Name($"O=ControlUp, CN={subject}"));
                certificateGenerator.SetNotBefore(DateTime.UtcNow.Date);
                certificateGenerator.SetNotAfter(DateTime.UtcNow.Date.AddYears(DefaultValidity));

                var keyGenerationParameters = new KeyGenerationParameters(random, strength);
                var keyPairGenerator = new RsaKeyPairGenerator();
                keyPairGenerator.Init(keyGenerationParameters);

                var subjectKeyPair = keyPairGenerator.GenerateKeyPair();
                certificateGenerator.SetPublicKey(subjectKeyPair.Public);

                var issuerKeyPair = subjectKeyPair;

                var certificate = certificateGenerator.Generate(issuerKeyPair.Private, random);
                return new X509Certificate2(certificate.GetEncoded());
            }
            catch (Exception ex)
            {
                throw;
            }
        }
*/

        public class CertificatesPair
        {
            public X509Certificate2 CertificateWithPrivateKey { get; set; }

            public X509Certificate2 CertificateWithoutPrivateKey { get; set; }
        }

        // https://stackoverflow.com/questions/22230745/generate-a-self-signed-certificate-on-the-fly
        public static CertificatesPair GenerateSelfSignedCertificate(string issuerName, string commonName, AsymmetricKeyParameter issuerPrivateKey)
        {
            const int keyStrength = 2048;
            const string signatureAlgorithm = "SHA256WithRSA";
            const int defaultValidityInYears = 5;

            var random = new SecureRandom();
            var certificateGenerator = new X509V3CertificateGenerator();

            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            certificateGenerator.SetIssuerDN(new X509Name(issuerName));
            certificateGenerator.SetSubjectDN(new X509Name($"O=ControlUp, CN={commonName}"));
            certificateGenerator.SetNotBefore(DateTime.UtcNow.Date);
            certificateGenerator.SetNotAfter(DateTime.UtcNow.Date.AddYears(defaultValidityInYears));

            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);

            var certificateKeyPair = keyPairGenerator.GenerateKeyPair();
            certificateGenerator.SetPublicKey(certificateKeyPair.Public);

            var signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, issuerPrivateKey);
            var certificate = certificateGenerator.Generate(signatureFactory);

            var certificateWithoutPrivateKey = new X509Certificate2(certificate.GetEncoded());

            var store = new Pkcs12StoreBuilder().Build();
            store.SetKeyEntry("key", new AsymmetricKeyEntry(certificateKeyPair.Private), new[] { new X509CertificateEntry(certificate) });
            var password = Guid.NewGuid().ToString();

            using (var ms = new MemoryStream())
            {
                store.Save(ms, password.ToCharArray(), random);
                var certificateWithPrivateKey = new X509Certificate2(ms.ToArray(), password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);

                return new CertificatesPair
                {
                    CertificateWithPrivateKey = certificateWithPrivateKey,
                    CertificateWithoutPrivateKey = certificateWithoutPrivateKey,
                };
            }
        }

        // CF TEMP: This could is not required in Console.
        private static AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            var keyGenerationParameters = new KeyGenerationParameters(random, 2048);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);

            return keyPairGenerator.GenerateKeyPair();
        }

        private static AsymmetricCipherKeyPair CreateKeyPair(string keyContent)
        {
            using (var reader = new StringReader(keyContent))
            {
                var pemReader = new PemReader(reader);
                return (AsymmetricCipherKeyPair)pemReader.ReadObject();
            }
        }

        public static X509Certificate2 GenerateCACertificate(string subjectName, AsymmetricCipherKeyPair issuerKeyPair)
        {
            const string signatureAlgorithm = "SHA256WithRSA";

            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            var certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Issuer and Subject Name
            var subjectDN = new X509Name(subjectName);
            var issuerDN = new X509Name(subjectName);
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Valid For
            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            certificateGenerator.SetPublicKey(issuerKeyPair.Public);

            // Selfsign certificate
            var signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, issuerKeyPair.Private);
            var certificate = certificateGenerator.Generate(signatureFactory);
            return new X509Certificate2(certificate.GetEncoded());
        }

/*
        public static Tuple<X509Certificate2, X509Certificate2> GenerateControlUpCertificate(string subject, string signatureAlgorithm, int strength)
        {
            X509Certificate2 certificate = null; ;
            try
            {
                const int DefaultValidity = 5;
                var random = new SecureRandom();
                var certificateGenerator = new X509V3CertificateGenerator();

                var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
                certificateGenerator.SetSerialNumber(serialNumber);

                certificateGenerator.SetIssuerDN(new X509Name($"O=ControlUp, CN={subject}"));
                certificateGenerator.SetSubjectDN(new X509Name($"O=ControlUp, CN={subject}"));
                certificateGenerator.SetNotBefore(DateTime.UtcNow.Date);
                certificateGenerator.SetNotAfter(DateTime.UtcNow.Date.AddYears(DefaultValidity));

                var keyGenerationParameters = new KeyGenerationParameters(random, strength);
                var keyPairGenerator = new RsaKeyPairGenerator();
                keyPairGenerator.Init(keyGenerationParameters);

                var subjectKeyPair = keyPairGenerator.GenerateKeyPair();
                certificateGenerator.SetPublicKey(subjectKeyPair.Public);

                var issuerKeyPair = subjectKeyPair;

                var signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, issuerKeyPair.Private);
                var bouncyCert = certificateGenerator.Generate(signatureFactory);

                Pkcs12Store store = new Pkcs12StoreBuilder().Build();
                store.SetKeyEntry($"{subject}_key", new AsymmetricKeyEntry(subjectKeyPair.Private), new[] { new X509CertificateEntry(bouncyCert) });
                var password = Guid.NewGuid().ToString();//("x");

                using (var ms = new MemoryStream())
                {
                    store.Save(ms, password.ToCharArray(), random);
                    certificate = new X509Certificate2(ms.ToArray(), password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
                }

                var rootCertificate = new X509Certificate2(bouncyCert.GetEncoded());
                return new Tuple<X509Certificate2, X509Certificate2>(rootCertificate, certificate);
            }
            catch (Exception ex)
            {
                throw;
            }
        }
*/

        private class CustomCredentials : ChannelCredentials
        {
            public override void InternalPopulateConfiguration(ChannelCredentialsConfiguratorBase configurator, object state)
            {
                // Grpc.Core.Internal.DefaultChannelCredentialsConfigurator c;

                // configurator.SetSslCredentials(state, rootCertificates, keyCertificatePair, verifyPeerCallback);
                // throw new NotImplementedException();
                return;
            }
        }

        public static int Main(string[] args)
        {
            try
            {
                XmlConfigurator.Configure(new FileInfo("log4net.config"));

                ServicePointManager.ServerCertificateValidationCallback += OnCertificateValidationError;

                Log.Info($"Using security type: {ConnectionSettings.SecurityType}");
                Log.Info($"Host name: {ConnectionSettings.HostName}");

                var keyContent = KeyHelper.GetRootKey();
                var issuerPrivateKey = CreateKeyPair(keyContent);
                // var issuerPrivateKey = GenerateKeyPair();

                // var serverCertificates = GenerateCertificates(issuerPrivateKey, commonName: "localhost");
                // var clientCertificates = GenerateCertificates(issuerPrivateKey, commonName: "localhost");
                // var serverCertificates = GenerateCertificates(issuerPrivateKey, commonName: ConnectionSettings.HostName);
                // var clientCertificates = serverCertificates;

                // CF MEGATEMP: Replace commonName with cuMonitor
                // var rootCertificates = GenerateCertificates(issuerPrivateKey, commonName: "cuAgent");
                // var serverCertificates = GenerateCertificates(issuerPrivateKey, commonName: ConnectionSettings.HostName);

                X509Certificate2 monitorCertificate;
                CertificatesPair grpcCertificates;

                if (ConnectionSettings.SecurityType == SecurityType.Generated || ConnectionSettings.SecurityType == SecurityType.GeneratedWithIssuedCertificate || ConnectionSettings.SecurityType == SecurityType.GeneratedWithoutClientAuthentication)
                {
                    monitorCertificate = SslCredentialReader.GetMonitorCertificate();
                    // var monitorKeyPair = new KeyCertificatePair(monitorCertificate.ExportX509CertificateAsPEM(), monitorCertificate.ExportX509PrivateRSAKey());
                    var monitorPrivateKey = monitorCertificate.ExportX509PrivateRSAKey();

                    grpcCertificates = GenerateCertificates(CreateKeyPair(monitorPrivateKey), commonName: ConnectionSettings.HostName);
                }
                else
                {
                    monitorCertificate = null;
                    grpcCertificates = null;
                }

                // var a = grpcCertificates.CertificateWithoutPrivateKey.ExportCertificate();
                // var b = grpcCertificates.CertificateWithPrivateKey.ExportCertificate();
                // var eq = a == b;

                Log.Info("Starting server ...");

                var server = new Server
                {
                    Services = { Greeter.BindService(new GreeterService()) },
                    Ports =
                    {
                        new ServerPort(ConnectionSettings.HostName, ConnectionSettings.PortNumber, GetServerCredentials(monitorCertificate, grpcCertificates?.CertificateWithPrivateKey)),
                    }
                };

                server.Start();

                Log.Info("Press enter for exit");
                // Console.Read();

                RunClient(grpcCertificates?.CertificateWithoutPrivateKey, grpcCertificates?.CertificateWithoutPrivateKey);

                Log.Info("Exiting ...");

                return 0;
            }
            catch (Exception e)
            {
                Log.Error("ServerApp has failed", e);

                return e.HResult;
            }
        }

        private static bool OnCertificateValidationError(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslpolicyerrors)
        {
            return false;
        }

        private static CertificatesPair GenerateCertificates(AsymmetricCipherKeyPair issuerKeyPair, string commonName)
        {
            if (ConnectionSettings.SecurityType == SecurityType.Generated ||
                ConnectionSettings.SecurityType == SecurityType.GeneratedWithoutClientAuthentication ||
                ConnectionSettings.SecurityType == SecurityType.GeneratedWithIssuedCertificate)
            {
                Log.Info("Generating certificates ...");

                const string issuerName = "O=ControlUp, CN=ControlUp Real-Time CA";

                // var issuerCertificate = GenerateCACertificate(subjectName: issuerName, issuerKeyPair);

                return GenerateSelfSignedCertificate(issuerName: issuerName, commonName: commonName, issuerKeyPair.Private);
            }

            return null;
        }

        private static void SetupGrpcProxy(string address, string proxyUriScheme)
        {
            var serviceUrl = new Uri($"{proxyUriScheme}://{address}");

            var systemProxy = WebRequest.GetSystemWebProxy();
            var proxyUrl = systemProxy.GetProxy(serviceUrl);
            var proxyIsBypassed = systemProxy.IsBypassed(serviceUrl);

            if (proxyIsBypassed || proxyUrl == null)
            {
                Log.Info($"Using no proxy for gRPC server at {address}");
            }
            else
            {
                Log.Info($"Using proxy '{proxyUrl}' for gRPC server at {address}");
                Environment.SetEnvironmentVariable("grpc_proxy", proxyUrl.OriginalString);
            }
        }

        // CF TEMP
        private static void RunClient(X509Certificate2 rootCertificate, X509Certificate2 selfCertificate)
        {
            SetupGrpcProxy($"{ConnectionSettings.HostName}:{ConnectionSettings.PortNumber}", Uri.UriSchemeHttps);

            //Environment.SetEnvironmentVariable("grpc_proxy", "http://IHARM-WIN-BLR-PROXY.cucorp.controlup.com:8080");
            // Environment.SetEnvironmentVariable("grpc_proxy", "http://squid2.smartx.dom:3128");
            // Environment.SetEnvironmentVariable("grpc_proxy", "http://squid2.smartx.dom:3128");
            // Environment.SetEnvironmentVariable("grpc_proxy", String.Empty);
            // Environment.SetEnvironmentVariable("https_proxy", "http://squid2.smartx.dom:3128");

            var channel = new Channel(ConnectionSettings.HostName, ConnectionSettings.PortNumber, GetClientCredentials(rootCertificate, selfCertificate));
            var client = new Greeter.GreeterClient(channel);

            Log.Info("Subscribing to greeting notifications ...");
            using (var stream = client.SubscribeToGreetingNotifications(new SubscribeToGreetingNotificationsRequest()))
            using (var cancellationTokenSource = new CancellationTokenSource())
            {
                var task = ProcessGreetingNotifications(stream.ResponseStream, cancellationTokenSource.Token);

                // Small delay before subscription is completed.
                Thread.Sleep(TimeSpan.FromMilliseconds(500));

                Log.Info("Sending request to server ...");
                var response = client.SayHello(new HelloRequest { Name = "CodeFuller" });
                Log.Info($"Result: '{response.Message}'");
            }
        }

        private static async Task ProcessGreetingNotifications(IAsyncStreamReader<GreetingNotification> stream, CancellationToken cancellationToken)
        {
            while (await stream.MoveNext(cancellationToken))
            {
                var notification = stream.Current;
                Log.Info($"Callback called: '{notification.Name}'");
            }
        }

        private static ServerCredentials GetServerCredentials(X509Certificate2 rootCertificate, X509Certificate2 certificate)
        {
            switch (ConnectionSettings.SecurityType)
            {
                case SecurityType.Insecure:
                    return ServerCredentials.Insecure;

                case SecurityType.FromDisk:
                    return GetSslServerCredentialsFromDisk();

                case SecurityType.FromDiskRootOnly:
                    return GetSslServerCredentialsFromDiskRootOnly();

                case SecurityType.FromStore:
                    return SslCredentialReader.CreateSslServerCredentialsFromStore();

                case SecurityType.Generated:
                    return GetServerCredentialsFromCertificate(rootCertificate, certificate);

                case SecurityType.GeneratedWithoutClientAuthentication:
                    return GetServerCredentialsFromCertificateWithoutClientAuthentication(rootCertificate);

                case SecurityType.GeneratedWithIssuedCertificate:
                    return GetServerCredentialsFromCertificateWithIssuedCertificate(rootCertificate, certificate);

                case SecurityType.US156551:
                    return GetSslServerCredentialsForUS156551();

                default:
                    throw new NotSupportedException($"Security type is not supported: {ConnectionSettings.SecurityType}");
            }
        }

        private static ServerCredentials GetSslServerCredentialsFromDisk()
        {
            // https://stackoverflow.com/questions/37714558
            var rootCertificate = File.ReadAllText(@"c:\temp\certificates\ca.crt");
            var certificateChain = File.ReadAllText(@"c:\temp\certificates\server.crt");
            var serverKey = File.ReadAllText(@"c:\temp\certificates\server.key");
            var keyPair = new KeyCertificatePair(certificateChain, serverKey);

            return new SslServerCredentials(new List<KeyCertificatePair> { keyPair }, rootCertificate, SslClientCertificateRequestType.RequestAndRequireAndVerify);
        }

        private static ServerCredentials GetSslServerCredentialsFromDiskRootOnly()
        {
            var rootCertificate = File.ReadAllText(@"c:\temp\certificates\server.crt");
            var serverKey = File.ReadAllText(@"c:\temp\certificates\server.key");
            var keyPair = new KeyCertificatePair(rootCertificate, serverKey);

            return new SslServerCredentials(new List<KeyCertificatePair> { keyPair });
        }

        private static ServerCredentials GetServerCredentialsFromCertificate(X509Certificate2 rootCertificate, X509Certificate2 certificate)
        {
            var keyPair = new KeyCertificatePair(certificate.ExportX509CertificateAsPEM(), certificate.ExportX509PrivateRSAKey());
            return new SslServerCredentials(new[] { keyPair }, rootCertificate.ExportX509CertificateAsPEM(), SslClientCertificateRequestType.RequestAndRequireAndVerify);
        }

        private static ServerCredentials GetServerCredentialsFromCertificateWithoutClientAuthentication(X509Certificate2 certificate)
        {
            var keyPair = new KeyCertificatePair(certificate.ExportX509CertificateAsPEM(), certificate.ExportX509PrivateRSAKey());
            return new SslServerCredentials(new[] { keyPair });
        }

        private static ServerCredentials GetServerCredentialsFromCertificateWithIssuedCertificate(X509Certificate2 rootCertificate, X509Certificate2 certificate)
        {
            var keyPair = new KeyCertificatePair(certificate.ExportX509CertificateAsPEM(), certificate.ExportX509PrivateRSAKey());
            return new SslServerCredentials(new[] { keyPair }, rootCertificate.ExportX509CertificateAsPEM(), SslClientCertificateRequestType.DontRequest);
        }

        private static ServerCredentials GetSslServerCredentialsForUS156551()
        {
            // var rootCertificate = File.ReadAllText(@"c:\work\_days\2023.07.18\KEY\grpc-ca.crt");
            var certificateChain = File.ReadAllText(@" c:\work\_days\2023.07.18\KEY\grpc-server.crt");
            var serverKey = File.ReadAllText(@"c:\work\_days\2023.07.18\KEY\grpc-server.key");
            var keyPair = new KeyCertificatePair(certificateChain, serverKey);

            // CF TEMP: Use client auth?
            // return new SslServerCredentials(new List<KeyCertificatePair> { keyPair }, rootCertificate, SslClientCertificateRequestType.RequestAndRequireAndVerify);
            return new SslServerCredentials(new List<KeyCertificatePair> { keyPair });
        }

        private static KeyCertificatePair GenerateKeyCertificatePair(string rootCertificate)
        {
            // CF TEMP
            return null;
        }

        public static X509Certificate2 GenerateServerCertificate(AsymmetricKeyParameter rootPrivateKey, string subject)
        {
/*
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            var certificateGenerator = new X509V3CertificateGenerator();

            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            const string signatureAlgorithm = "SHA256WithRSA";
            certificateGenerator.SetSignatureAlgorithm(signatureAlgorithm);

            // Issuer and Subject Name
            var subjectDN = new X509Name(subjectName);
            var issuerDN = new X509Name(issuerName);
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Valid For
            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // Subject Public Key
            AsymmetricCipherKeyPair subjectKeyPair;
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Generating the Certificate
            var issuerKeyPair = subjectKeyPair;

            // Selfsign certificate
            var certificate = certificateGenerator.Generate(issuerPrivKey, random);

            // Corresponding private key
            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(subjectKeyPair.Private);


            Pkcs12Store store = new Pkcs12StoreBuilder().Build();
            store.SetKeyEntry($"cuAgent_key", new AsymmetricKeyEntry(subjectKeyPair.Private), new[] { new X509CertificateEntry(certificate) });
            var password = Guid.NewGuid().ToString();//("x");

            using (var ms = new System.IO.MemoryStream())
            {
                store.Save(ms, password.ToCharArray(), random);
                return new X509Certificate2(ms.ToArray(), password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
            }
*/

            throw new NotImplementedException();
        }

        private static ChannelCredentials GetClientCredentials(X509Certificate2 rootCertificate, X509Certificate2 certificate)
        {
            switch (ConnectionSettings.SecurityType)
            {
                case SecurityType.Insecure:
                    return ChannelCredentials.Insecure;

                case SecurityType.FromDisk:
                    return GetSslClientCredentialsFromDisk();

                case SecurityType.FromDiskRootOnly:
                    return GetSslClientCredentialsFromDiskRootOnly();

                case SecurityType.FromDiskSameCertificate:
                    return GetSslClientCredentialsFromDiskSameCertificate();

                case SecurityType.FromStore:
                    return SslCredentialReader.CreateSslClientCredentialsFromStore(VerifyPeerCallback);

                case SecurityType.Generated:
                    return GetClientCredentialsFromGeneratedCertificate(rootCertificate, certificate);

                case SecurityType.GeneratedWithoutClientAuthentication:
                    return GetClientCredentialsFromCertificateWithoutClientAuthentication(rootCertificate);

                case SecurityType.GeneratedWithIssuedCertificate:
                    return GetClientCredentialsFromCertificateWithIssuedCertificate(rootCertificate, certificate);

                case SecurityType.US156551:
                    return GetSslClientCredentialsForUS156551();

                default:
                    throw new NotSupportedException($"Security type is not supported: {ConnectionSettings.SecurityType}");
            }
        }

        private static SslCredentials GetClientCredentialsFromGeneratedCertificate(X509Certificate2 rootCertificate, X509Certificate2 certificate)
        {
            var keyPair = new KeyCertificatePair(certificate.ExportX509CertificateAsPEM(), certificate.ExportX509PrivateRSAKey());

            return new SslCredentials(rootCertificate.ExportX509CertificateAsPEM(), keyPair, VerifyPeerCallback);
        }

        private static SslCredentials GetClientCredentialsFromCertificateWithoutClientAuthentication(X509Certificate2 rootCertificate)
        {
            return new SslCredentials(rootCertificate.ExportX509CertificateAsPEM(), null, VerifyPeerCallback);
        }

        private static SslCredentials GetClientCredentialsFromCertificateWithIssuedCertificate(X509Certificate2 rootCertificate, X509Certificate2 certificate)
        {
            return new SslCredentials(certificate.ExportX509CertificateAsPEM(), null, VerifyPeerCallback);
        }

        private static SslCredentials GetSslClientCredentialsFromDisk()
        {
            var rootCertificate = File.ReadAllText(@"c:\temp\certificates\ca.crt");
            var certificateChain = File.ReadAllText(@"c:\temp\certificates\client.crt");
            var clientKey = File.ReadAllText(@"c:\temp\certificates\client.key");

            return new SslCredentials(rootCertificate, new KeyCertificatePair(certificateChain, clientKey), VerifyPeerCallback);
        }

        private static SslCredentials GetSslClientCredentialsFromDiskRootOnly()
        {
            var rootCertificate = File.ReadAllText(@"c:\temp\certificates\ca.crt");

            return new SslCredentials(rootCertificate, null, VerifyPeerCallback);
        }

        private static SslCredentials GetSslClientCredentialsFromDiskSameCertificate()
        {
            var rootCertificate = File.ReadAllText(@"c:\temp\certificates\ca.crt");

            return new SslCredentials(rootCertificate);
        }

        private static SslCredentials GetSslClientCredentialsForUS156551()
        {
            var rootCertificate = File.ReadAllText(@"c:\work\_days\2023.07.18\KEY\grpc-ca.crt");

            return new SslCredentials(rootCertificate);
        }

        private static bool VerifyPeerCallback(VerifyPeerContext context)
        {
            Log.Info($"VerifyPeerCallback('{context.TargetName}', '{context.PeerPem}')");
            return true;
        }
    }
}
