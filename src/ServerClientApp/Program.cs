using System;
using System.IO;
using ClientApp.Shared;
using log4net;
using log4net.Config;
using ServerApp.Shared;

namespace ServerClientApp
{
    public static class Program
    {
        private static readonly ILog Log = LogManager.GetLogger("ServerClientApp");

        public static int Main()
        {
            try
            {
                XmlConfigurator.Configure(new FileInfo("log4net.config"));

                ServerHelper.StartServer();

                ClientHelper.RunClient();

                Log.Info("Press Enter for exit");
                Console.ReadLine();

                Log.Info("Exiting ...");

                return 0;
            }
            catch (Exception e)
            {
                Log.Error("ServerClientApp has failed", e);

                return e.HResult;
            }
        }
    }
}
