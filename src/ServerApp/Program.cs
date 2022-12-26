using System;
using System.IO;
using Grpc.Core;
using GrpcCoreDemo.Grpc;
using log4net;
using log4net.Config;

namespace ServerApp
{
    public static class Program
    {
        private static readonly ILog Log = LogManager.GetLogger("ServerApp.Program");

        public static int Main(string[] args)
        {
            try
            {
                XmlConfigurator.Configure(new FileInfo("log4net.config"));

                Log.Info("Starting server ...");

                var server = new Server
                {
                    Services = { Greeter.BindService(new GreeterService()) },
                    Ports = { new ServerPort("localhost", 9999, ServerCredentials.Insecure) }
                };

                server.Start();

                Log.Info("Press enter for exit");
                Console.Read();

                Log.Info("Exiting ...");

                return 0;
            }
            catch (Exception e)
            {
                Log.Error("ServerApp has failed", e);

                return e.HResult;
            }
        }
    }
}
