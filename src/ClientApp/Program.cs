using System;
using System.IO;
using Grpc.Core;
using GrpcCoreDemo.Grpc;
using log4net;
using log4net.Config;

namespace ClientApp
{
    public static class Program
    {
        private static readonly ILog Log = LogManager.GetLogger("ClientApp.Program");

        public static int Main(string[] args)
        {
            try
            {
                XmlConfigurator.Configure(new FileInfo("log4net.config"));

                Log.Info("Creating service client ...");

                var channel = new Channel("127.0.0.1:9999", ChannelCredentials.Insecure);
                var client = new Greeter.GreeterClient(channel);

                Log.Info("Sending request to server ...");
                var response = client.SayHello(new HelloRequest { Name = "CodeFuller" });
                Log.Info($"Result: '{response.Message}'");

                Log.Info("Exiting ...");

                return 0;
            }
            catch (Exception e)
            {
                Log.Error("ClientApp has failed", e);

                return e.HResult;
            }
        }
    }
}
