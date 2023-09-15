using System;
using System.IO;
using ClientApp.Shared;
using log4net;
using log4net.Config;

namespace ClientApp
{
    public static class Program
    {
        private static readonly ILog Log = LogManager.GetLogger("ClientApp");

        public static int Main()
        {
            try
            {
                XmlConfigurator.Configure(new FileInfo("log4net.config"));

                ClientHelper.RunClient();

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
